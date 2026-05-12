"use strict";

// Extra tests added by the autonomous review (autonomous/product-security-review).
// These cover the I-01 … I-04 changes plus a handful of pre-existing
// behaviours that were never explicitly asserted.

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const WebSocket = require("ws");
const { loadServer, listen, closeServer, httpRequest, openSocket, delay } = require("./helpers");

test("HEAD / returns headers without a body", async (t) => {
  const { mod, restoreEnv } = loadServer();
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  const res = await httpRequest(addr, { path: "/", method: "HEAD" });
  assert.equal(res.status, 200);
  assert.match(res.headers["content-type"] || "", /text\/html/);
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["x-frame-options"], "DENY");
  assert.equal(res.headers["referrer-policy"], "no-referrer");
  // HEAD must not include a body.
  assert.equal(res.body, "");
});

test("Permissions-Policy locks down powerful-feature APIs (I-03)", async (t) => {
  const { mod, restoreEnv } = loadServer();
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  const res = await httpRequest(addr, { path: "/" });
  const pp = res.headers["permissions-policy"] || "";
  for (const directive of [
    "camera=()",
    "microphone=()",
    "geolocation=()",
    "payment=()",
    "usb=()",
    "interest-cohort=()",
    "browsing-topics=()",
    "display-capture=()",
    "publickey-credentials-get=()",
  ]) {
    assert.ok(pp.includes(directive), `Permissions-Policy missing ${directive}: ${pp}`);
  }
});

test("response does not leak a Server: header", async (t) => {
  const { mod, restoreEnv } = loadServer();
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  const res = await httpRequest(addr, { path: "/" });
  // Node's default http.Server does not set Server / X-Powered-By; this test
  // exists so any future regression (a middleware adding fingerprinting
  // headers) is caught immediately.
  assert.equal(res.headers["server"], undefined);
  assert.equal(res.headers["x-powered-by"], undefined);
});

test("WS upgrade allow-list rejects non-/, non-/ws paths (I-02)", async (t) => {
  const { mod, restoreEnv } = loadServer({
    QUADRAMA_MAX_CONNS_PER_IP: "200",
  });
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  // "/" — must work (current test helpers use this path).
  const a = await openSocket(addr);
  a.send_({ type: "join", code: "upath-ok" });
  await a.until((m) => m.type === "joined", 2000);
  a.close();
  await delay(50);

  // "/something-else" — upgrade must be rejected before the WebSocket opens.
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://${addr.address}:${addr.port}/something-else`);
    let opened = false;
    ws.on("open", () => {
      opened = true;
      ws.close();
      reject(new Error("upgrade was accepted for /something-else"));
    });
    ws.on("error", () => {
      if (!opened) resolve();
    });
    ws.on("unexpected-response", (_req, res) => {
      // 400 from upgradePathAllowed
      assert.ok(res.statusCode === 400 || res.statusCode === 404, `unexpected status ${res.statusCode}`);
      resolve();
    });
    ws.on("close", () => {
      if (!opened) resolve();
    });
  });
});

test("WS upgrade allow-list accepts /ws and /ws/ (I-02)", async (t) => {
  const { mod, restoreEnv } = loadServer({
    QUADRAMA_MAX_CONNS_PER_IP: "200",
  });
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  for (const path of ["/ws", "/ws/"]) {
    await new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://${addr.address}:${addr.port}${path}`);
      ws.on("open", () => {
        ws.close();
        resolve();
      });
      ws.on("error", reject);
    });
  }
});

test("token comparison is length-tolerant (I-01)", async (t) => {
  const { mod, restoreEnv } = loadServer({
    QUADRAMA_MAX_JOINS_PER_MIN: "1000",
    QUADRAMA_MAX_CONNS_PER_IP: "200",
  });
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  const a = await openSocket(addr);
  a.send_({ type: "join", code: "tok-len" });
  const j = await a.until((m) => m.type === "joined", 2000);
  // Send chat with a token that is the right shape but a completely
  // different length than the issued one. The server must reject with
  // `token_mismatch` rather than throwing on length asymmetry.
  const wrongShort = "a".repeat(9);
  const wrongLong = "b".repeat((j.token || "").length + 7);
  a.send_({ type: "chat", header: {}, payload: {}, token: wrongShort });
  const r1 = await a.until((m) => m.type === "auth_failed", 2000);
  assert.equal(r1.reason, "token_mismatch");

  a.send_({ type: "chat", header: {}, payload: {}, token: wrongLong });
  const r2 = await a.until((m) => m.type === "auth_failed", 2000);
  assert.equal(r2.reason, "token_mismatch");

  a.close();
  await delay(50);
});

test("origin allow-list is permissive when unset (default)", async (t) => {
  const { mod, restoreEnv } = loadServer();
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  // Without QUADRAMA_ALLOWED_ORIGINS, *any* Origin must be accepted (matches
  // the prior behaviour the README documents as the default).
  const ws = await openSocket(addr, { Origin: "https://random.example" });
  ws.send_({ type: "join", code: "or-default" });
  const j = await ws.until((m) => m.type === "joined", 2000);
  assert.equal(j.type, "joined");
  ws.close();
  await delay(50);
});
