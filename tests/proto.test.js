"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { loadServer, listen, closeServer, openSocket, delay } = require("./helpers");

test("token enforcement, relay sanitization, oversized frame", async (t) => {
  const { mod, restoreEnv } = loadServer({
    QUADRAMA_MAX_JOINS_PER_MIN: "1000",
    QUADRAMA_MAX_CONNS_PER_IP: "200",
  });
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  await t.test("non-join messages without token fail with auth_failed", async () => {
    const a = await openSocket(addr);
    a.send_({ type: "join", code: "tk1" });
    const j = await a.until((m) => m.type === "joined");
    assert.equal(j.type, "joined");

    a.send_({ type: "chat", header: {}, payload: {} }); // no token
    const r = await a.until((m) => m.type === "auth_failed");
    assert.equal(r.reason, "token_missing");

    a.send_({ type: "chat", header: {}, payload: {}, token: "x".repeat(20) });
    const r2 = await a.until((m) => m.type === "auth_failed");
    assert.equal(r2.reason, "token_mismatch");

    a.close();
    await delay(50);
  });

  await t.test("server never relays the token", async () => {
    const a = await openSocket(addr);
    const b = await openSocket(addr);
    a.send_({ type: "join", code: "tk2" });
    const ja = await a.until((m) => m.type === "joined");
    b.send_({ type: "join", code: "tk2" });
    await b.until((m) => m.type === "joined");

    // drain peer_joined on a
    await a.until((m) => m.type === "peer_joined");

    // send chat with valid token from a
    a.send_({ type: "chat", header: { dh: "x", pn: 0, n: 0 }, payload: { nonce: "n", boxed: "b" }, token: ja.token });
    const relayed = await b.until((m) => m.type === "chat");
    assert.equal(relayed.type, "chat");
    assert.ok(!("token" in relayed), "server must not relay the token field");

    a.close(); b.close();
    await delay(80);
  });

  await t.test("unknown message types are silently dropped", async () => {
    const a = await openSocket(addr);
    a.send_({ type: "join", code: "tk3" });
    const j = await a.until((m) => m.type === "joined");
    a.send_({ type: "garbage", token: j.token });
    // Wait briefly and ensure no error message comes back
    let got;
    try {
      got = await a.until((m) => m.type === "auth_failed" || m.type === "rate_limited", 200);
    } catch (e) {
      got = null;
    }
    assert.equal(got, null, "unknown types should not generate a reply");
    a.close();
    await delay(50);
  });

  await t.test("oversized frame is dropped by maxPayload", async () => {
    const a = await openSocket(addr);
    a.send_({ type: "join", code: "tk4" });
    await a.until((m) => m.type === "joined");

    // Send a frame larger than WS_MAX_PAYLOAD (32 KiB)
    const big = "x".repeat(64 * 1024);
    a.send(big);
    // ws should close the connection with 1009 (Message Too Big)
    const closed = await a.until((m) => m.__closed, 2000);
    assert.equal(closed.__closed, true);
    await delay(50);
  });
});

test("origin allow-list", async (t) => {
  const { mod, restoreEnv } = loadServer({
    QUADRAMA_ALLOWED_ORIGINS: "https://quadrama.ch",
    QUADRAMA_MAX_JOINS_PER_MIN: "1000",
    QUADRAMA_MAX_CONNS_PER_IP: "200",
  });
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  await t.test("allowed origin passes", async () => {
    const a = await openSocket(addr, { Origin: "https://quadrama.ch" });
    a.send_({ type: "join", code: "or1" });
    const j = await a.until((m) => m.type === "joined");
    assert.equal(j.type, "joined");
    a.close();
    await delay(50);
  });

  await t.test("disallowed origin is rejected at upgrade", async () => {
    let err;
    try {
      await openSocket(addr, { Origin: "https://attacker.example" });
    } catch (e) {
      err = e;
    }
    assert.ok(err, "expected upgrade rejection");
  });
});
