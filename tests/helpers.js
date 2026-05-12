"use strict";

const path = require("path");
const http = require("http");
const WebSocket = require("ws");

// Reload server.js fresh per call so its in-memory rooms/deadRooms maps are
// empty for each test file. The module's http server is created but never
// listened on at module-load time (require.main !== module), so we get a
// clean instance.
function loadServer(env = {}) {
  for (const k of Object.keys(require.cache)) {
    if (k.endsWith(path.sep + "server.js") && k.startsWith(path.resolve(__dirname, ".."))) {
      delete require.cache[k];
    }
  }
  const prev = {};
  for (const [k, v] of Object.entries(env)) {
    prev[k] = process.env[k];
    process.env[k] = v;
  }
  const mod = require(path.resolve(__dirname, "..", "server.js"));
  return {
    mod,
    restoreEnv() {
      for (const [k, v] of Object.entries(prev)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    },
  };
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

function httpRequest(addr, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: addr.address,
        port: addr.port,
        method: options.method || "GET",
        path: options.path || "/",
        headers: options.headers || {},
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

/**
 * Single-handler WebSocket wrapper.
 *  ws.send_(obj)           — send a JSON object
 *  await ws.recv()         — pop the next message (waits if none queued)
 *                            returns { __closed: true, code, reason } on close
 *  await ws.until(pred, t) — recv until predicate matches, with timeout
 */
function openSocket(addr, headers = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://${addr.address}:${addr.port}`, { headers });
    const queue = [];
    const waiters = [];
    let opened = false;

    const push = (item) => {
      const w = waiters.shift();
      if (w) w(item);
      else queue.push(item);
    };

    ws.on("open", () => {
      opened = true;
      ws.send_ = (obj) => ws.send(JSON.stringify(obj));
      ws.recv = () =>
        new Promise((res) => {
          if (queue.length) return res(queue.shift());
          waiters.push(res);
        });
      ws.until = async (pred, timeoutMs = 2000) => {
        const deadline = Date.now() + timeoutMs;
        for (;;) {
          const left = deadline - Date.now();
          if (left <= 0) throw new Error("until() timeout");
          const msg = await Promise.race([
            ws.recv(),
            new Promise((_, rej) => setTimeout(() => rej(new Error("until() timeout")), left)),
          ]);
          if (pred(msg)) return msg;
        }
      };
      resolve(ws);
    });

    ws.on("message", (m) => {
      try { push(JSON.parse(m.toString())); } catch { /* ignore non-JSON */ }
    });
    ws.on("close", (code, reason) => {
      push({ __closed: true, code, reason: reason && reason.toString() });
      if (!opened) reject(new Error(`closed before open: code=${code}`));
    });
    ws.on("error", (e) => {
      if (!opened) reject(e);
    });
  });
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = { loadServer, listen, closeServer, httpRequest, openSocket, delay };
