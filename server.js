// server.js
// mini-messenger-v3 relay
// CP37: Room-Token enforced (room-scoped token required for hs/hs_ack/chat/kc after join)
// CP36: basic inbound rate limiting + room lock (1:1) + safe relaying
// CP38: ROOM-DEATH / TOMBSTONE
// CP39: ONE-SHOT ON FIRST JOIN
// CP40: IP-based rate limiting (max connections + join attempts per IP)
//
// FIX (NEW): HS/HS_ACK REPLAY ON JOIN
//  - Buffer last hs + hs_ack per peer in room
//  - When a new peer joins, replay cached hs/hs_ack from existing peers to the newcomer
//  - Prevents "first hs sent while alone -> lost -> peer FP stays —" deadlock
//
// Notes: This is a relay only; clients do E2EE.

const http = require("http");
const path = require("path");
const fs = require("fs");
const WebSocket = require("ws");
const crypto = require("crypto");

const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;

const server = http.createServer((req, res) => {
  // Serve static from ./public
  let urlPath = req.url || "/";
  if (urlPath === "/") urlPath = "/index.html";
  const safePath = path.normalize(urlPath).replace(/^(\.\.(\/|\\|$))+/, "");
  const filePath = path.join(__dirname, "public", safePath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not Found");
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const ct =
      ext === ".html" ? "text/html; charset=utf-8" :
      ext === ".js" ? "application/javascript; charset=utf-8" :
      ext === ".css" ? "text/css; charset=utf-8" :
      "application/octet-stream";
    res.writeHead(200, { "Content-Type": ct });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });

// ---- Room state ----
/**
 * rooms: code -> {
 *   token: string,
 *   locked: boolean,        // lock to 1:1 once 2 peers joined
 *   everHadTwo: boolean,    // CP38
 *   everHadOne: boolean,    // CP39
 *   peers: Set<ws>,
 *   hsCache: Map<peerId, { hs?:object, hs_ack?:object }>
 * }
 */
const rooms = new Map();

/**
 * deadRooms: code -> { deadAt:number, reason:string, until:number|null }
 * If present, join is denied as room_dead.
 */
const deadRooms = new Map();

// CP38: how long to keep tombstones in memory.
// - null => keep forever until server restart
// - number => ms TTL
const DEAD_TTL_MS = null; // keep forever by default

function randToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function wsSend(ws, obj) {
  if (ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify(obj));
}

function nowMs() { return Date.now(); }

// ---- Simple inbound rate limit (CP36-ish) ----
const RL = {
  windowMs: 1000,
  maxMsgsPerWindow: 50,   // per client, per second
  maxBytesPerWindow: 50_000,
};

// ---- CP40: IP-based rate limiting ----
/**
 * ipState: ip -> {
 *   conns: number,         // active connections from this IP
 *   joins: number,         // join attempts in current window
 *   joinWinStart: number,  // start of join window
 * }
 */
const IP_RL = {
  maxConnsPerIp: 5,         // max simultaneous connections per IP
  maxJoinsPerWindow: 10,    // max join attempts per IP per window
  joinWindowMs: 60_000,     // 1 minute window for join attempts
};

const ipState = new Map();

function getIp(ws) {
  return ws._mm?.ip || "unknown";
}

function ipConnect(ip) {
  if (!ip || ip === "unknown") return true;
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
  if (!ip || ip === "unknown") return;
  const st = ipState.get(ip);
  if (!st) return;
  st.conns = Math.max(0, st.conns - 1);
  if (st.conns === 0 && st.joins === 0) ipState.delete(ip);
}

function ipHitJoinLimit(ip) {
  if (!ip || ip === "unknown") return false;
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
  if (st.joins > IP_RL.maxJoinsPerWindow) {
    return true;
  }
  return false;
}

// Cleanup ipState periodically
setInterval(() => {
  for (const [ip, st] of ipState.entries()) {
    if (st.conns === 0) ipState.delete(ip);
  }
}, 120_000).unref?.();

function initClientState(ws, ip) {
  ws._mm = {
    id: crypto.randomBytes(4).toString("hex"),
    ip: ip || "unknown",
    room: null,
    joinedAt: 0,
    rl: {
      winStart: nowMs(),
      msgs: 0,
      bytes: 0,
      strikes: 0,
    },
    hb: {
      isAlive: true,
      lastPongAt: nowMs(),
      missed: 0
    }
  };
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

// ---- Tombstone cleanup ----
function cleanupDeadRooms() {
  if (DEAD_TTL_MS === null) return;
  const now = nowMs();
  for (const [code, d] of deadRooms.entries()) {
    if (d.until && now >= d.until) deadRooms.delete(code);
  }
}
setInterval(cleanupDeadRooms, 30_000).unref?.();

// ---- Room helpers ----
function ensureRoom(code) {
  let r = rooms.get(code);
  if (!r) {
    r = {
      token: randToken(18),
      locked: false,
      everHadTwo: false,
      everHadOne: false,
      peers: new Set(),
      hsCache: new Map()
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
  const until = (DEAD_TTL_MS === null) ? null : (deadAt + DEAD_TTL_MS);
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
    try {
      if (peer.readyState === WebSocket.OPEN) {
        wsSend(peer, { type: "room_dead", code: roomCode, reason: closeReason });
      }
    } catch {}
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
    console.log(`[room] killed: ${roomCode} (${reason || "peer_left"})`);
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

  // CP40: IP join rate limit
  const ip = getIp(ws);
  if (ipHitJoinLimit(ip)) {
    wsSend(ws, { type: "join_denied", reason: "rate_limited" });
    console.log(`[cp40] join rate limited: ip=${ip}`);
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
  console.log(`[room] joined: ${code} peers=${r.peers.size} locked=${r.locked}`);

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
  if (token !== r.token) return { ok: false, reason: "token_mismatch" };

  return { ok: true, room: r, code };
}

// ---- Heartbeat / Zombie killer ----
const HB = {
  intervalMs: 12_000,
  graceMisses: 2
};

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

wss.on("connection", (ws, req) => {
  const ip = (req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown").trim();

  if (!ipConnect(ip)) {
    console.log(`[cp40] too many connections: ip=${ip}`);
    try { ws.close(4029, "too_many_connections"); } catch {}
    return;
  }

  initClientState(ws, ip);

  ws.on("pong", () => {
    hbMarkPong(ws);
  });

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
      const out = {
        type: t,
        from: msg.from || null,
        header: msg.header || null,
        payload: msg.payload || null,
        v: msg.v || null,
        ctx: msg.ctx || null,
        tag: msg.tag || null
        // DO NOT relay token
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

    // ignore unknown
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

server.listen(PORT, () => {
  console.log(`[ok] HTTP server on http://127.0.0.1:${PORT}`);
  console.log(`[ok] WS server on ws://127.0.0.1:${PORT}`);
  console.log(`[info] Tombstone TTL: ${DEAD_TTL_MS === null ? "infinite(until restart)" : DEAD_TTL_MS + "ms"}`);
  console.log(`[info] CP38 active: room dies after everHadTwo -> any leave`);
  console.log(`[info] CP39 active: room dies after everHadOne -> last leave`);
  console.log(`[info] Heartbeat active (ping every ${HB.intervalMs}ms, terminate after ${HB.graceMisses} misses)`);
  console.log(`[info] FIX active: hs/hs_ack cached + replayed on join`);
  console.log(`[info] CP40 active: IP rate limiting (max ${IP_RL.maxConnsPerIp} conns, max ${IP_RL.maxJoinsPerWindow} joins/min per IP)`);
});
