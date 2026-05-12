"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { loadServer, listen, closeServer, httpRequest } = require("./helpers");

test("static file server", async (t) => {
  const { mod, restoreEnv } = loadServer();
  const addr = await listen(mod.server);
  t.after(async () => {
    await closeServer(mod.server);
    restoreEnv();
  });

  await t.test("serves index.html with security headers", async () => {
    const res = await httpRequest(addr, { path: "/" });
    assert.equal(res.status, 200);
    assert.match(res.headers["content-type"] || "", /text\/html/);
    assert.equal(res.headers["x-content-type-options"], "nosniff");
    assert.equal(res.headers["x-frame-options"], "DENY");
    assert.equal(res.headers["referrer-policy"], "no-referrer");
    assert.match(res.headers["content-security-policy"] || "", /default-src 'self'/);
    assert.match(res.headers["content-security-policy"] || "", /frame-ancestors 'none'/);
    assert.equal(res.headers["cache-control"], "no-store");
    assert.match(res.body, /Quadrama/i);
    // No external CDN references in shipped HTML (a privacy invariant —
    // every page load must be self-contained, no third-party fetches).
    assert.doesNotMatch(res.body, /<(link|script)[^>]+(href|src)=["']https?:\/\//i);
    assert.doesNotMatch(res.body, /<i class="fas/);
    // app.js carries SRI
    assert.match(res.body, /<script src="\.\/app\.js"\s+integrity=/);
  });

  await t.test("rejects path traversal", async () => {
    const cases = [
      "/../server.js",
      "/..%2Fserver.js",
      "/public/../server.js",
      "/%2e%2e/server.js",
    ];
    for (const p of cases) {
      const res = await httpRequest(addr, { path: p });
      assert.ok(
        res.status === 403 || res.status === 404,
        `path ${p} returned ${res.status}, expected 403/404`
      );
      assert.doesNotMatch(res.body, /relay/, `path ${p} leaked server.js content`);
    }
  });

  await t.test("denies unknown extensions", async () => {
    const res = await httpRequest(addr, { path: "/foo.env" });
    assert.equal(res.status, 404);
  });

  await t.test("rejects non-GET methods", async () => {
    const res = await httpRequest(addr, { path: "/", method: "POST" });
    assert.equal(res.status, 405);
    assert.equal(res.headers["allow"], "GET, HEAD");
  });
});
