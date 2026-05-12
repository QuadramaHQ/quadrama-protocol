// server.js
// Quadrama relay (mini-messenger-v3) — pure E2EE relay.
//
// Original protocol markers preserved:
//   CP36: per-connection rate limiting + 1:1 room lock
//   CP37: server-issued room token enforced on every non-join message
//   CP38: tombstone after a room has held two peers and any of them leaves
//   CP39: tombstone after the first lone peer leaves
//   CP40: per-IP rate limiting (max simultaneous connections + joins per minute)
//   FIX:  cache last hs/hs_ack per peer, replay to newcomers (handshake race)
//
// Hardening review 2026-05-11 (hardening/autonomous-full-review):
//   H-01: WebSocket maxPayload cap (defence against single-frame DoS)
//   H-02: optional Origin allow-list via QUADRAMA_ALLOWED_ORIGINS
//   H-03: X-Real-IP only honoured when QUADRAMA_TRUST_PROXY=1; unknown IPs
//         are now tracked (no rate-limit bypass), the X-Real-IP header is
//         parsed strictly (first token only)
//   H-04: log redaction by default — IPs, room codes and reasons only
//         surface when QUADRAMA_VERBOSE=1
//   H-05: defence-in-depth security headers on static responses
//         (CSP, nosniff, no-referrer, COOP, no-store on HTML)
//   H-06: path-traversal hardening via path.resolve + prefix check, plus
//         a whitelist of allowed extensions
//   H-07: graceful shutdown on SIGINT/SIGTERM (clears intervals, closes WSS)
//   H-08: misleading "127.0.0.1" boot log fixed (server binds 0.0.0.0)
//
// Autonomous review 2026-05-11 (autonomous/product-security-review):
//   I-01: token comparison via crypto.timingSafeEqual (length-checked)
//         removes a theoretical timing oracle on the per-room token
//   I-02: WS upgrade path allow-list ("/", "/ws", "/ws/") — reduces
//         attack surface for opportunistic scanners; the reference
//         client targets "/ws"
//   I-03: expanded Permissions-Policy disabling powerful-feature
//         APIs the app never uses (geolocation/camera/microphone/usb/…)
//
// Invariant: this process must never see plaintext, never store messages,
// never persist anything across restarts.

"use strict";

const http = require("http");
const path = require("path");
const fs = require("fs");
const WebSocket = require("ws");
const crypto = require("crypto");

// ---------- Configuration (env-driven, safe defaults) ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
const HOST = process.env.HOST || "0.0.0.0";

const TRUST_PROXY = process.env.QUADRAMA_TRUST_PROXY === "1";
const VERBOSE = process.env.QUADRAMA_VERBOSE === "1";

const ALLOWED_ORIGINS = (process.env.QUADRAMA_ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// 32 KiB is well above any legitimate Quadrama frame (handshake ≈ 400 B,
// padded chat bucket ≤ 1 KiB) and small enough to make a single-frame
// memory-exhaustion attempt unprofitable.
const WS_MAX_PAYLOAD = 32 * 1024;

// Per-connection rate limit (CP36).
const RL = {
  windowMs: 1000,
  maxMsgsPerWindow: 50,
  maxBytesPerWindow: 50_000,
};

// Per-IP limits (CP40). Defaults are tuned for production; tests may raise
// them via environment variables. Values are validated to fall in a sane
// range so a typo cannot silently disable a limit.
function envInt(name, def, min, max) {
  const raw = process.env[name];
  if (raw == null || raw === "") return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < min || n > max) return def;
  return Math.floor(n);
}
const IP_RL = {
  maxConnsPerIp: envInt("QUADRAMA_MAX_CONNS_PER_IP", 5, 1, 10_000),
  maxJoinsPerWindow: envInt("QUADRAMA_MAX_JOINS_PER_MIN", 10, 1, 100_000),
  joinWindowMs: envInt("QUADRAMA_JOIN_WINDOW_MS", 60_000, 1_000, 3_600_000),
};

// Heartbeat.
const HB = {
  intervalMs: 12_000,
  graceMisses: 2,
};

// Tombstone behaviour. `null` = keep forever until restart.
const DEAD_TTL_MS = null;

// ---------- Tiny structured logger ----------
function vlog(...args) {
  if (VERBOSE) console.log(...args);
}
function ilog(...args) {
  console.log(...args);
}

// ---------- Static file server ----------
const PUBLIC_DIR = path.resolve(__dirname, "public");

const MIME = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
});

// Conservative CSP for defence-in-depth. It allows only same-origin
// scripts/styles/connect. `'unsafe-inline'` for style is required because
// `index.html` carries its design as an inline <style> block; this is
// documented in TECHNICAL.md. No `'unsafe-eval'`, no remote origins.
const BASELINE_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self' ws: wss:",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join("; ");

function setSecurityHeaders(res, isHtml) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  // Quadrama never asks for any of these capabilities. Disabling them
  // explicitly stops a future regression (a wandering dependency or an
  // unexpected piece of vendored code) from silently gaining access.
  // Unknown directives are ignored by browsers, so listing extras is safe.
  res.setHeader(
    "Permissions-Policy",
    [
      "accelerometer=()",
      "autoplay=()",
      "browsing-topics=()",
      "camera=()",
      "display-capture=()",
      "fullscreen=()",
      "geolocation=()",
      "gyroscope=()",
      "hid=()",
      "idle-detection=()",
      "interest-cohort=()",
      "magnetometer=()",
      "microphone=()",
      "midi=()",
      "payment=()",
      "picture-in-picture=()",
      "publickey-credentials-get=()",
      "screen-wake-lock=()",
      "serial=()",
      "usb=()",
      "xr-spatial-tracking=()",
    ].join(", ")
  );
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", BASELINE_CSP);
  if (isHtml) {
    res.setHeader("Cache-Control", "no-store");
  } else {
    res.setHeader("Cache-Control", "public, max-age=300, must-revalidate");
  }
}

function serveStatic(req, res) {
  // Strip query string and fragment; method check.
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { Allow: "GET, HEAD" });
    res.end();
    return;
  }

  let urlPath = (req.url || "/").split("?")[0].split("#")[0];
  if (urlPath === "/") urlPath = "/index.html";

  // Allow only files with a known extension. Anything else → 404.
  const ext = path.extname(urlPath).toLowerCase();
  if (!MIME[ext]) {
    res.writeHead(404);
    res.end("Not Found");
    return;
  }

  // Defence in depth: resolve to absolute path and require it to live
  // inside PUBLIC_DIR (prevents path traversal even if URL decoding
  // produces relative segments).
  const decoded = (() => {
    try {
      return decodeURIComponent(urlPath);
    } catch {
      return urlPath;
    }
  })();
  const requested = path.resolve(PUBLIC_DIR, "." + decoded);
  if (requested !== PUBLIC_DIR && !requested.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.readFile(requested, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not Found");
      return;
    }
    setSecurityHeaders(res, ext === ".html");
    res.writeHead(200, { "Content-Type": MIME[ext] });
    res.end(req.method === "HEAD" ? "" : data);
  });
}

const server = http.createServer(serveStatic);

// ---------- WebSocket setup ----------
// `clientTracking: true` keeps `wss.clients` populated for the heartbeat.
// `maxPayload` enforces a hard frame ceiling before our JSON parser ever
// touches the data (H-01).
const wss = new WebSocket.Server({
  noServer: true,
  maxPayload: WS_MAX_PAYLOAD,
  clientTracking: true,
});

// Origin allow-list (H-02). When unset, behaviour is permissive (matches the
// previous default — Quadrama needs to work for users who have not provisioned
// a list). When set, only listed origins may upgrade.
function originAllowed(req) {
  if (ALLOWED_ORIGINS.length === 0) return true;
  const origin = req.headers.origin || "";
  return ALLOWED_ORIGINS.includes(origin);
}

// Allow WS upgrade on the root path and on "/ws" (with or without trailing
// slash). The reference client connects to "/ws/"; tests open the socket
// at "/". Anything else is rejected at the socket — opportunistic scanners
// that probe arbitrary URLs no longer succeed with an upgrade. (I-02)
const WS_UPGRADE_PATHS = new Set(["/", "/ws", "/ws/"]);
function upgradePathAllowed(req) {
  const url = (req.url || "/").split("?")[0].split("#")[0];
  return WS_UPGRADE_PATHS.has(url);
}

server.on("upgrade", (req, socket, head) => {
  // Only the WS endpoint is upgraded. Anything else is HTTP.
  if (!upgradePathAllowed(req)) {
    socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    socket.destroy();
    return;
  }
  if (!originAllowed(req)) {
    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});

// ---------- Room state ----------
/**
 * rooms: code -> {
 *   token: string,
 *   locked: boolean,
 *   everHadTwo: boolean,
 *   everHadOne: boolean,
 *   peers: Set<ws>,
 *   hsCache: Map<peerId, { hs?:object, hs_ack?:object }>
 * }
 */
const rooms = new Map();

/**
 * deadRooms: code -> { deadAt:number, reason:string, until:number|null }
 */
const deadRooms = new Map();

// ---------- Helpers ----------
function randToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function wsSend(ws, obj) {
  if (ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify(obj));
}

function nowMs() {
  return Date.now();
}

// ---------- IP handling (H-03) ----------
// Parse the client IP strictly. X-Real-IP is only consulted when the operator
// has explicitly enabled TRUST_PROXY; otherwise the TCP peer address wins.
// If neither yields a usable address we fall through to a single shared bucket
// ("unknown") so unknown-IP clients are still subject to per-bucket limits —
// the previous code allowed *unbounded* connections from such clients.
function clientIp(req) {
  if (TRUST_PROXY) {
    const raw = req.headers["x-real-ip"];
    if (typeof raw === "string" && raw.length > 0) {
      // Allow only a single token (no comma-separated chains).
      const first = raw.split(",")[0].trim();
      if (first) return first;
    }
    const fwd = req.headers["x-forwarded-for"];
    if (typeof fwd === "string" && fwd.length > 0) {
      const first = fwd.split(",")[0].trim();
      if (first) return first;
    }
  }
  const sock = req.socket && req.socket.remoteAddress;
  return (sock && String(sock).trim()) || "unknown";
}

/**
 * ipState: ip -> { conns, joins, joinWinStart }
 */
const ipState = new Map();

function ipConnect(ip) {
  let st = ipState.get(ip);
  if (!st) {
    st = { conns: 0, joins: 0, joinWinStart: nowMs() };
    ipState.set(ip, st);
  }
  st.conns += 1;
  if (st.conns > IP_RL.maxConnsPerIp) {
    st.conns -= 1;
    return false;
  }
  return true;
}

function ipDisconnect(ip) {
  const st = ipState.get(ip);
  if (!st) return;
  st.conns = Math.max(0, st.conns - 1);
  if (st.conns === 0 && st.joins === 0) ipState.delete(ip);
}

function ipHitJoinLimit(ip) {
  let st = ipState.get(ip);
  if (!st) {
    st = { conns: 0, joins: 0, joinWinStart: nowMs() };
    ipState.set(ip, st);
  }
  const now = nowMs();
  if (now - st.joinWinStart > IP_RL.joinWindowMs) {
    st.joins = 0;
    st.joinWinStart = now;
  }
  st.joins += 1;
  return st.joins > IP_RL.maxJoinsPerWindow;
}

const ipCleanupInterval = setInterval(() => {
  for (const [ip, st] of ipState.entries()) {
    if (st.conns === 0 && st.joins === 0) ipState.delete(ip);
  }
}, 120_000);
ipCleanupInterval.unref?.();

// ---------- Per-connection state + rate limit (CP36) ----------
function initClientState(ws, ip) {
  ws._mm = {
    id: crypto.randomBytes(4).toString("hex"),
    ip,
    room: null,
    joinedAt: 0,
    rl: { winStart: nowMs(), msgs: 0, bytes: 0, strikes: 0 },
    hb: { isAlive: true, lastPongAt: nowMs(), missed: 0 },
  };
}

function getIp(ws) {
  return ws._mm?.ip || "unknown";
}

function hitRateLimit(ws, bytes) {
  const st = ws._mm?.rl;
  if (!st) return false;
  const t = nowMs();
  if (t - st.winStart > RL.windowMs) {
    st.winStart = t;
    st.msgs = 0;
    st.bytes = 0;
  }
  st.msgs += 1;
  st.bytes += bytes;
  if (st.msgs > RL.maxMsgsPerWindow || st.bytes > RL.maxBytesPerWindow) {
    st.strikes += 1;
    wsSend(ws, { type: "rate_limited" });
    return true;
  }
  return false;
}

// ---------- Tombstone GC ----------
const deadRoomInterval = setInterval(() => {
  if (DEAD_TTL_MS === null) return;
  const now = nowMs();
  for (const [code, d] of deadRooms.entries()) {
    if (d.until && now >= d.until) deadRooms.delete(code);
  }
}, 30_000);
deadRoomInterval.unref?.();

// ---------- Room helpers ----------
function ensureRoom(code) {
  let r = rooms.get(code);
  if (!r) {
    r = {
      token: randToken(18),
      locked: false,
      everHadTwo: false,
      everHadOne: false,
      peers: new Set(),
      hsCache: new Map(),
    };
    rooms.set(code, r);
  }
  return r;
}

function isDeadRoom(code) {
  const d = deadRooms.get(code);
  if (!d) return false;
  if (DEAD_TTL_MS === null) return true;
  if (!d.until) return true;
  return nowMs() < d.until;
}

function markRoomDead(code, reason) {
  if (deadRooms.has(code)) return;
  const deadAt = nowMs();
  const until = DEAD_TTL_MS === null ? null : deadAt + DEAD_TTL_MS;
  deadRooms.set(code, { deadAt, reason: reason || "room_dead", until });
}

function sweepRoomPeers(code) {
  const r = rooms.get(code);
  if (!r) return 0;
  for (const peer of Array.from(r.peers)) {
    if (!peer || peer.readyState !== WebSocket.OPEN) {
      try { r.peers.delete(peer); } catch {}
      try { r.hsCache.delete(peer?._mm?.id); } catch {}
    }
  }
  if (!isDeadRoom(code) && r.peers.size < 2) r.locked = false;
  return r.peers.size;
}

function closeAllPeers(roomCode, closeCode = 4000, closeReason = "room_dead") {
  const r = rooms.get(roomCode);
  if (!r) return;
  for (const peer of r.peers) {
    if (peer.readyState === WebSocket.OPEN) {
      wsSend(peer, { type: "room_dead", code: roomCode, reason: closeReason });
    }
  }
  for (const peer of r.peers) {
    try { peer.close(closeCode, closeReason); } catch {}
  }
}

function killRoom(roomCode, reason) {
  const r = rooms.get(roomCode);
  markRoomDead(roomCode, reason || "peer_left");
  if (r) {
    closeAllPeers(roomCode, 4001, reason || "peer_left");
    rooms.delete(roomCode);
    vlog(`[room] killed (${reason || "peer_left"})`);
  }
}

function relayToRoomExcept(ws, code, obj) {
  const r = rooms.get(code);
  if (!r) return;
  sweepRoomPeers(code);
  for (const peer of r.peers) {
    if (peer !== ws && peer.readyState === WebSocket.OPEN) {
      wsSend(peer, obj);
    }
  }
}

function replayHandshakeCacheTo(ws, code) {
  const r = rooms.get(code);
  if (!r) return;
  sweepRoomPeers(code);
  for (const peer of r.peers) {
    if (peer === ws) continue;
    const pid = peer?._mm?.id;
    if (!pid) continue;
    const cached = r.hsCache.get(pid);
    if (!cached) continue;
    if (cached.hs) wsSend(ws, cached.hs);
    if (cached.hs_ack) wsSend(ws, cached.hs_ack);
  }
}

function joinRoom(ws, code) {
  leaveRoom(ws, "switch_room");

  const ip = getIp(ws);
  if (ipHitJoinLimit(ip)) {
    wsSend(ws, { type: "join_denied", reason: "rate_limited" });
    vlog("[cp40] join rate limited");
    return;
  }

  if (isDeadRoom(code)) {
    ws._mm.room = null;
    wsSend(ws, { type: "join_denied", reason: "room_dead" });
    return;
  }

  const r = ensureRoom(code);
  sweepRoomPeers(code);

  if (r.locked && r.peers.size >= 2) {
    ws._mm.room = null;
    wsSend(ws, { type: "join_denied", reason: "room_locked" });
    return;
  }

  r.peers.add(ws);
  r.everHadOne = true;
  ws._mm.room = code;
  ws._mm.joinedAt = nowMs();

  if (r.peers.size >= 2) {
    r.locked = true;
    r.everHadTwo = true;
  }

  wsSend(ws, { type: "joined", code, token: r.token, locked: r.locked });
  vlog(`[room] joined peers=${r.peers.size} locked=${r.locked}`);

  relayToRoomExcept(ws, code, { type: "peer_joined" });
  replayHandshakeCacheTo(ws, code);
}

function leaveRoom(ws, why = "left") {
  const code = ws._mm?.room;
  if (!code) return;

  const r = rooms.get(code);
  ws._mm.room = null;
  if (!r) return;

  try { r.peers.delete(ws); } catch {}
  try { r.hsCache.delete(ws?._mm?.id); } catch {}

  sweepRoomPeers(code);

  if (r.everHadTwo) {
    killRoom(code, "peer_left_room_one_shot");
    return;
  }

  if (r.everHadOne && r.peers.size === 0) {
    killRoom(code, "peer_left_room_one_shot_first_join");
    return;
  }

  if (r.peers.size === 0) rooms.delete(code);
  if (r.peers.size < 2) r.locked = false;
}

function validateToken(ws, msg) {
  const code = ws._mm?.room;
  if (!code) return { ok: false, reason: "not_in_room" };
  if (isDeadRoom(code)) return { ok: false, reason: "room_dead" };

  const r = rooms.get(code);
  if (!r) return { ok: false, reason: "room_missing" };
  if (!msg || typeof msg !== "object") return { ok: false, reason: "bad_msg" };

  const token = msg.token;
  if (typeof token !== "string" || token.length < 8) return { ok: false, reason: "token_missing" };
  // Constant-time compare (I-01). `timingSafeEqual` requires equal-length
  // buffers; the length pre-check rejects mismatches without touching
  // crypto and prevents the comparison itself from leaking length info.
  if (token.length !== r.token.length) return { ok: false, reason: "token_mismatch" };
  const a = Buffer.from(token, "utf8");
  const b = Buffer.from(r.token, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: "token_mismatch" };
  }

  return { ok: true, room: r, code };
}

// ---------- Heartbeat ----------
function hbMarkPong(ws) {
  if (!ws._mm?.hb) return;
  ws._mm.hb.isAlive = true;
  ws._mm.hb.lastPongAt = nowMs();
  ws._mm.hb.missed = 0;
}

const hbInterval = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws || ws.readyState !== WebSocket.OPEN) continue;

    if (!ws._mm?.hb) {
      ws._mm = ws._mm || {};
      ws._mm.hb = { isAlive: true, lastPongAt: nowMs(), missed: 0 };
    }

    if (ws._mm.hb.isAlive === false) {
      ws._mm.hb.missed = (ws._mm.hb.missed || 0) + 1;
      if (ws._mm.hb.missed >= HB.graceMisses) {
        try { ws.terminate(); } catch {}
        continue;
      }
    }

    ws._mm.hb.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, HB.intervalMs);
hbInterval.unref?.();

// ---------- Connection handler ----------
wss.on("connection", (ws, req) => {
  const ip = clientIp(req);

  if (!ipConnect(ip)) {
    vlog("[cp40] too many connections (ip rejected)");
    try { ws.close(4029, "too_many_connections"); } catch {}
    return;
  }

  initClientState(ws, ip);

  ws.on("pong", () => hbMarkPong(ws));

  ws.on("message", (data) => {
    const raw = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    if (hitRateLimit(ws, raw.length)) return;

    const msg = safeJsonParse(raw.toString("utf8"));
    if (!msg || typeof msg.type !== "string") return;

    const t = msg.type;

    if (t === "join") {
      const code = String(msg.code || "").trim();
      if (!code || code.length > 32) {
        wsSend(ws, { type: "join_denied", reason: "bad_room_code" });
        return;
      }
      joinRoom(ws, code);
      return;
    }

    const vt = validateToken(ws, msg);
    if (!vt.ok) {
      if (vt.reason === "room_dead") {
        wsSend(ws, { type: "join_denied", reason: "room_dead" });
        return;
      }
      wsSend(ws, { type: "auth_failed", reason: vt.reason });
      return;
    }

    if (t === "hs" || t === "hs_ack" || t === "chat" || t === "kc") {
      // Deliberate whitelist of relayed fields. Anything else is dropped.
      const out = {
        type: t,
        from: typeof msg.from === "string" ? msg.from.slice(0, 64) : null,
        header: msg.header ?? null,
        payload: msg.payload ?? null,
        v: msg.v ?? null,
        ctx: msg.ctx ?? null,
        tag: msg.tag ?? null,
        // NB: `token` is intentionally not relayed.
      };

      const pid = ws?._mm?.id;
      if (pid) {
        const cache = vt.room.hsCache.get(pid) || {};
        if (t === "hs") cache.hs = out;
        if (t === "hs_ack") cache.hs_ack = out;
        vt.room.hsCache.set(pid, cache);
      }

      relayToRoomExcept(ws, vt.code, out);
      return;
    }
    // unknown types are silently ignored
  });

  ws.on("close", () => {
    ipDisconnect(getIp(ws));
    leaveRoom(ws, "ws_close");
  });

  ws.on("error", () => {
    ipDisconnect(getIp(ws));
    leaveRoom(ws, "ws_error");
  });
});

// ---------- Lifecycle ----------
function listen() {
  return new Promise((resolve) => {
    server.listen(PORT, HOST, () => {
      const addr = server.address();
      const printedHost = addr && typeof addr === "object" ? addr.address : HOST;
      const printedPort = addr && typeof addr === "object" ? addr.port : PORT;
      ilog(`[ok] Quadrama relay listening on http://${printedHost}:${printedPort}`);
      ilog(`[ok] WebSocket on ws://${printedHost}:${printedPort}`);
      ilog(`[info] verbose=${VERBOSE ? "on" : "off"} trust_proxy=${TRUST_PROXY ? "on" : "off"} allowed_origins=${ALLOWED_ORIGINS.length || "any"}`);
      ilog(`[info] tombstone_ttl=${DEAD_TTL_MS === null ? "until-restart" : DEAD_TTL_MS + "ms"}`);
      resolve();
    });
  });
}

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  ilog(`[shutdown] ${signal} received, closing`);
  try { clearInterval(hbInterval); } catch {}
  try { clearInterval(deadRoomInterval); } catch {}
  try { clearInterval(ipCleanupInterval); } catch {}

  for (const ws of wss.clients) {
    try { ws.close(1001, "server_shutdown"); } catch {}
  }

  // Short drain so the 1001 close frames have a chance to flush before the
  // process exits. Pure relay has no other in-flight state to wait on.
  await new Promise((resolve) => setTimeout(resolve, 300));

  try { wss.close(); } catch {}
  try {
    await new Promise((resolve) => server.close(() => resolve()));
  } catch {}
  process.exit(0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// Surface unhandled errors instead of crashing silently.
process.on("uncaughtException", (err) => {
  ilog("[uncaught]", err && err.message ? err.message : String(err));
});
process.on("unhandledRejection", (reason) => {
  ilog("[rejection]", reason && reason.message ? reason.message : String(reason));
});

if (require.main === module) {
  listen();
}

// Export for tests.
module.exports = { server, wss, listen, shutdown, rooms, deadRooms, ipState };
