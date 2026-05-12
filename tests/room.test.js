"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { loadServer, listen, closeServer, openSocket, delay } = require("./helpers");

async function joinAndAwait(ws, code) {
  ws.send_({ type: "join", code });
  return ws.until(
    (m) => m.type === "joined" || m.type === "join_denied" || m.__closed,
    2000
  );
}

test("room protocol", async (t) => {
  const { mod, restoreEnv } = loadServer({
    QUADRAMA_MAX_JOINS_PER_MIN: "1000",
    QUADRAMA_MAX_CONNS_PER_IP: "200",
  });
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  await t.test("first peer joins and receives token", async () => {
    const a = await openSocket(addr);
    const m = await joinAndAwait(a, "alpha");
    assert.equal(m.type, "joined");
    assert.equal(m.code, "alpha");
    assert.equal(m.locked, false);
    assert.ok(typeof m.token === "string" && m.token.length >= 8);
    a.close();
    await delay(50);
  });

  await t.test("second peer locks the room 1:1", async () => {
    const a = await openSocket(addr);
    const b = await openSocket(addr);
    const ma = await joinAndAwait(a, "beta");
    const mb = await joinAndAwait(b, "beta");
    assert.equal(ma.locked, false);
    assert.equal(mb.locked, true);
    a.close(); b.close();
    await delay(50);
  });

  await t.test("third peer is denied with reason room_locked", async () => {
    const a = await openSocket(addr);
    const b = await openSocket(addr);
    const c = await openSocket(addr);
    await joinAndAwait(a, "gamma");
    await joinAndAwait(b, "gamma");
    const mc = await joinAndAwait(c, "gamma");
    assert.equal(mc.type, "join_denied");
    assert.equal(mc.reason, "room_locked");
    a.close(); b.close(); c.close();
    await delay(50);
  });

  await t.test("either peer leaving tombstones the room (CP38)", async () => {
    const a = await openSocket(addr);
    const b = await openSocket(addr);
    await joinAndAwait(a, "delta");
    await joinAndAwait(b, "delta");
    a.close();
    await delay(80);
    const c = await openSocket(addr);
    const mc = await joinAndAwait(c, "delta");
    assert.equal(mc.type, "join_denied");
    assert.equal(mc.reason, "room_dead");
    b.close(); c.close();
    await delay(50);
  });

  await t.test("lone-peer leave tombstones the room (CP39)", async () => {
    const a = await openSocket(addr);
    await joinAndAwait(a, "epsilon");
    a.close();
    await delay(80);
    const b = await openSocket(addr);
    const mb = await joinAndAwait(b, "epsilon");
    assert.equal(mb.type, "join_denied");
    assert.equal(mb.reason, "room_dead");
    b.close();
    await delay(50);
  });

  await t.test("rejects bad room code (too long, empty)", async () => {
    const a = await openSocket(addr);
    const m1 = await joinAndAwait(a, "");
    assert.equal(m1.reason, "bad_room_code");
    const longCode = "x".repeat(33);
    const m2 = await joinAndAwait(a, longCode);
    assert.equal(m2.reason, "bad_room_code");
    a.close();
    await delay(50);
  });
});
