"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { loadServer, listen, closeServer, openSocket, delay } = require("./helpers");

test("rate limits", async (t) => {
  const { mod, restoreEnv } = loadServer();
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  await t.test("per-IP max simultaneous connections (5)", async () => {
    const open = [];
    try {
      for (let i = 0; i < 5; i++) open.push(await openSocket(addr));
      const sixth = await openSocket(addr);
      try {
        // Server accepts the WS upgrade and *then* closes with 4029.
        const closed = await sixth.until((m) => m.__closed, 1500);
        assert.equal(closed.__closed, true);
        assert.equal(closed.code, 4029);
      } finally {
        sixth.close();
      }
    } finally {
      for (const ws of open) ws.close();
      // Give the server's `close` handlers time to decrement the conn counter.
      await delay(150);
    }
  });

  await t.test("per-IP join rate (10/min) triggers rate_limited", async () => {
    const a = await openSocket(addr);
    try {
      let denied = 0;
      for (let i = 0; i < 12; i++) {
        a.send_({ type: "join", code: `rl-${i}` });
        const m = await a.until(
          (msg) => msg.type === "joined" || msg.type === "join_denied",
          2000
        );
        if (m.type === "join_denied" && m.reason === "rate_limited") denied++;
      }
      assert.ok(denied >= 1, `expected at least one rate-limited join, got ${denied}`);
    } finally {
      a.close();
      await delay(100);
    }
  });
});
