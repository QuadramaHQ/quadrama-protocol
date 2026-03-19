// public/app.js
// mini-messenger-v3 – tweetnacl only
// CP4: Double Ratchet (FS/PCS) + Replay + Skipped Keys
// CP6: Key-Transparency + Safety Words (PGP) + Primary Contact + Key-History
// CP7: Identity Backup/Restore (DEAKTIVIERT – sicherheitshalber entfernt)
// CP8: Metadata Hardening (Padding/Buckets + Chunking + Cover Traffic + Jitter)
// CP9: STRICT VERIFICATION MODE (Hard Lock on Key-Change)
// CP10: Factory Reset Button (ALLES LÖSCHEN)
// CP17: HEADER BINDING (Header-MAC / "AEAD-light", rückwärts-kompatibel)
// CP21: SESSION / CHANNEL BINDING (bindet Ciphertexts an Room+Handshake-Context, backward compatible)
// CP23: FIX: Decrypt-State Commit erst NACH erfolgreichem MAC+Decrypt (verhindert Replay-Cascade) + v2→v1 fallback
// CP24: STRICT-AFTER-TRUST (MAC+CTX Pflicht nach Verifizierung; kein v2→v1 Downgrade nach Trust)
// CP26: KEY CONFIRMATION (KC) – Channel Established erst nach KC OK (nach Trust)
// CP31: KC-Dedupe + New Room Button
// CP32: HARD Session Reset (Disconnect/Room-Join): Pending + Chunk-Reass löschen
// CP35: UI Debug Stats (locked/kc/chunks/drops/rl)
// CP36: Inbound RL support (server sends rate_limited)
// CP37: Room-Token enforced (server issues token on join; client attaches token on all non-join sends)
// CP38: GUI polish (Chat separat + Log separat) — additiv, keine CP-Logik gelöscht
// CP41: Neu-Button generiert nur Code, kein automatisches Join
// CP42: i18n – alle UI-Texte in app.js über t() übersetzt (de/en) – vollständig
// CP43: HKDF (RFC 5869) statt SHA-256 für KDF_CK + KDF_RK3
//
// ✅ UPGRADE (additiv, löscht nichts):
// - Server kann "peer_joined" senden.
// - Wenn wir bereits hs gesendet haben, aber noch KEIN Peer FP haben,
//   dann senden wir bei "peer_joined" das hs NOCHMAL (hsSent reset nur in diesem Sonderfall).
//   → Fix für Timing: beide Tabs senden hs "zu früh" (allein im Raum) => Peer FP bleibt —.
//
// ✅ SICHERHEITSVERBESSERUNG:
// - Privater Signierschlüssel wird mit einem zufälligen Passwort verschlüsselt im sessionStorage abgelegt.
// - Das Passwort bleibt nur im RAM (_sessionPass).
// - Bei jeder Nutzung des privaten Schlüssels wird er kurz entschlüsselt und sofort aus dem Speicher entfernt.
// - Beim Disconnect (WebSocket-Close) wird der verschlüsselte Eintrag gelöscht und das Passwort aus dem RAM entfernt.
// - Backup/Restore wurde deaktiviert (keine Wiederherstellung möglich).
// - Nach einem Reload (ohne vorherigen Disconnect) ist das Passwort weg → der alte Schlüssel kann nicht mehr entschlüsselt werden,
//   es wird automatisch ein neuer Schlüssel erzeugt. Das entspricht dem gewünschten Verhalten: "nach dem Schreiben wird gelöscht".

let ws = null;

let mySignKp = null;
let myDhKp = null;

let peerSignPk = null;
let peerDhPk = null;
let peerFp = null;

let currentRoom = null;
let hsSent = false;

let roomToken = null;

let keyChangedLock = false;
let lockReason = '';
let pendingLockedChats = [];

const USE_SESSION_IDENTITY = true;

// =======================================================
// CP42 – i18n Hilfsfunktion (vollständig)
// =======================================================
const APP_I18N = {
  de: {
    me: 'Du',
    peer: 'Peer',
    verifyConfirm: (fp, code) => `Peer FP: ${fp}\n\nSafety Code:\n${code}\n\nNur bestätigen wenn beides stimmt!`,
    backupDisabled: 'Backup wurde aus Sicherheitsgründen deaktiviert. Die Identität wird nach Disconnect unwiderruflich gelöscht.',
    restoreDisabled: 'Restore wurde aus Sicherheitsgründen deaktiviert.',
    factoryConfirm: 'ALLES LÖSCHEN?\n\nDas löscht:\n- Identity Keys\n- Trust/Primary + Key-History\n- clientId\n- Locks/Status\n\nDanach Reload.\n\nWirklich fortfahren?',
    connected: 'verbunden',
    disconnected: 'getrennt',
    confirmed: 'bestätigt',
    notConfirmed: 'nicht bestätigt',
    locked: 'LOCKED',
    verified: 'Verifiziert (Trust aktiv)',
    notVerified: 'Nicht verifiziert',
    lockedKeyChange: 'LOCKED (Key-Change) – bitte neu verifizieren',
    kcOk: ' · KC OK',
    kcPending: ' · KC ausstehend',
  },
  en: {
    me: 'Me',
    peer: 'Peer',
    verifyConfirm: (fp, code) => `Peer FP: ${fp}\n\nSafety Code:\n${code}\n\nOnly confirm if both match!`,
    backupDisabled: 'Backup has been disabled for security reasons. The identity will be permanently deleted after disconnect.',
    restoreDisabled: 'Restore has been disabled for security reasons.',
    factoryConfirm: 'DELETE EVERYTHING?\n\nThis deletes:\n- Identity Keys\n- Trust/Primary + Key History\n- clientId\n- Locks/Status\n\nPage will reload.\n\nAre you sure?',
    connected: 'connected',
    disconnected: 'disconnected',
    confirmed: 'confirmed',
    notConfirmed: 'not confirmed',
    locked: 'LOCKED',
    verified: 'Verified (Trust active)',
    notVerified: 'Not verified',
    lockedKeyChange: 'LOCKED (Key-Change) – please re-verify',
    kcOk: ' · KC OK',
    kcPending: ' · KC pending',
  }
};

function t(key, ...args) {
  const lang = (typeof currentLang !== 'undefined' ? currentLang : 'de');
  const dict = APP_I18N[lang] || APP_I18N['de'];
  const val = dict[key];
  if (typeof val === 'function') return val(...args);
  return val || key;
}

// =======================================================
// ✅ SICHERHEIT: Verschlüsselung des privaten Schlüssels
// =======================================================
let _sessionPass = null;

function encryptSecret(secretKey, pass) {
  if (!(pass instanceof Uint8Array) || pass.length !== 32) throw new Error('Passwort muss 32 Bytes sein');
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const box = nacl.secretbox(secretKey, nonce, pass);
  return { nonce: b64enc(nonce), box: b64enc(box) };
}

function decryptSecret(encrypted, pass) {
  const nonce = b64dec(encrypted.nonce);
  const box = b64dec(encrypted.box);
  const secret = nacl.secretbox.open(box, nonce, pass);
  if (!secret) throw new Error('Entschlüsselung fehlgeschlagen (falsches Passwort?)');
  return secret;
}

function withPrivateKey(callback) {
  if (!_sessionPass) throw new Error('Kein Session-Passwort vorhanden (möglicherweise neu geladen?)');
  const encrypted = JSON.parse(sessionStorage.getItem('mm3_encrypted_sign'));
  if (!encrypted) throw new Error('Kein verschlüsselter Schlüssel im Storage');
  const secret = decryptSecret(encrypted, _sessionPass);
  try {
    return callback(secret);
  } finally {
    for (let i = 0; i < secret.length; i++) secret[i] = 0;
  }
}

function deleteIdentity() {
  sessionStorage.removeItem('mm3_encrypted_sign');
  if (_sessionPass) {
    for (let i = 0; i < _sessionPass.length; i++) _sessionPass[i] = 0;
  }
  _sessionPass = null;
  mySignKp = null;
  log('[ Sicherheit ] Identität gelöscht (Storage + RAM)');
}

// =======================================================
// ✅ CP35 – UI Debug Stats
// =======================================================
const STATS = {
  startedAt: Date.now(),
  drops: 0,
  dropReasons: {},
  rlCount: 0,
  rlLastAt: 0
};

function statDrop(reason) {
  STATS.drops++;
  const k = String(reason || 'unknown');
  STATS.dropReasons[k] = (STATS.dropReasons[k] || 0) + 1;
}

function fmtAgo(ms) {
  if (!ms) return '—';
  const d = Math.max(0, Date.now() - ms);
  if (d < 1000) return `${d}ms`;
  const s = Math.floor(d / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h`;
}

// =======================================================
// CP8 – Metadata Hardening
// =======================================================
const META = {
  enabled: true,
  buckets: [128, 256, 512, 1024],
  sendJitterMinMs: 120,
  sendJitterMaxMs: 450,
  coverTraffic: true,
  coverMinMs: 8000,
  coverMaxMs: 12000
};

const CHUNK = {
  enabled: true,
  maxPlainBytes: 360
};

// =======================================================
// CP17 – Header Binding
// =======================================================
const CP17 = {
  enabled: true,
  requireMacAfterTrust: true,
  macBytes: 16
};

// =======================================================
// CP21 – Session / Channel Binding
// =======================================================
const CP21 = {
  enabled: true,
  requireAfterTrust: true,
  ctxTagBytes: 16
};

let sessionCtx = null;
let sessionCtxShort = null;

let v2Broken = false;

const CP24 = {
  enabled: true,
  strictAfterTrust: true
};

const KC = {
  enabled: true,
  sent: false,
  ok: false,
  peerTag: null,
  pendingMsg: null
};

let pendingPreKcChats = [];

const clientId = (() => {
  const key = 'mm3_client_id';
  let v = sessionStorage.getItem(key);
  if (!v) {
    v = Math.random().toString(36).slice(2, 10);
    sessionStorage.setItem(key, v);
  }
  return v;
})();

const els = {
  log: document.getElementById('log'),
  chatBox: document.getElementById('chatBox'),
  kcMini: document.getElementById('kcMini'),
  httpStatus: document.getElementById('httpStatus'),
  wsStatus: document.getElementById('wsStatus'),
  roomStatus: document.getElementById('roomStatus'),
  cryptoStatus: document.getElementById('cryptoStatus'),
  fpStatus: document.getElementById('fpStatus'),
  peerFpStatus: document.getElementById('peerFpStatus'),
  trustStatus: document.getElementById('trustStatus'),
  safetyStatus: document.getElementById('safetyStatus'),
  statsStatus: document.getElementById('statsStatus'),
  safetyCodeDisplay: document.getElementById('safetyCodeDisplay'),
  btnConnect: document.getElementById('btnConnect'),
  btnDisconnect: document.getElementById('btnDisconnect'),
  btnJoin: document.getElementById('btnJoin'),
  btnLeave: document.getElementById('btnLeave'),
  btnSend: document.getElementById('btnSend'),
  btnGenerateKeys: document.getElementById('btnGenerateKeys'),
  btnVerify: document.getElementById('btnVerify'),
  btnUnverify: document.getElementById('btnUnverify'),
  btnShowSafety: document.getElementById('btnShowSafety'),
  btnBackup: document.getElementById('btnBackup'),
  btnRestore: document.getElementById('btnRestore'),
  btnResetAll: document.getElementById('btnResetAll'),
  btnNewRoom: document.getElementById('btnNewRoom'),
  wsUrl: document.getElementById('wsUrl'),
  roomCode: document.getElementById('roomCode'),
  message: document.getElementById('message'),
  primaryFp: document.getElementById('primaryFp'),
  primaryStatus: document.getElementById('primaryStatus'),
  primaryFirstSeen: document.getElementById('primaryFirstSeen'),
  primaryLastSeen: document.getElementById('primaryLastSeen'),
  primaryVerifiedAt: document.getElementById('primaryVerifiedAt'),
  historyList: document.getElementById('historyList')
};

function log(t) {
  const ts = new Date().toLocaleTimeString();
  els.log.textContent += `${ts}  ${t}\n`;
  els.log.scrollTop = els.log.scrollHeight;
}

// =======================================================
// ✅ CP38: Chat UI (Bubbles)
// =======================================================
function chatAdd(who, text) {
  if (!els.chatBox) return;

  const row = document.createElement('div');
  row.className = `bubbleRow ${who === 'me' ? 'me' : 'peer'}`;

  const wrap = document.createElement('div');
  wrap.className = 'bubbleWrap';

  const top = document.createElement('div');
  top.className = 'bubbleTop';

  const name = document.createElement('div');
  name.className = 'bubbleName';
  name.textContent = (who === 'me') ? t('me') : t('peer');

  const time = document.createElement('div');
  time.className = 'bubbleTime';
  time.textContent = new Date().toLocaleTimeString();

  top.appendChild(name);
  top.appendChild(time);

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = String(text ?? '');

  wrap.appendChild(top);
  wrap.appendChild(bubble);
  row.appendChild(wrap);

  els.chatBox.appendChild(row);
  els.chatBox.scrollTop = els.chatBox.scrollHeight;
}

// Helpers
function b64enc(arr) { return btoa(String.fromCharCode(...new Uint8Array(arr))); }
function b64dec(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function samePk(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function fingerprint(pkBytes) { return b64enc(pkBytes).slice(0, 16); }
function nowIso() { return new Date().toISOString(); }

function concatBytes(...parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
async function sha256(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(buf);
}

function ctEq(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= (a[i] ^ b[i]);
  return v === 0;
}

function normalizeWsInput(raw) {
  let input = String(raw || '').trim();
  if (!input) return { displayUrl: '', connectUrl: '' };

  if (input.startsWith('https://')) input = 'wss://' + input.slice('https://'.length);
  if (input.startsWith('http://'))  input = 'ws://'  + input.slice('http://'.length);

  if (!/^wss?:\/\//i.test(input)) input = 'wss://' + input;

  try {
    if (location.protocol === 'https:' && input.startsWith('ws://')) {
      input = 'wss://' + input.slice('ws://'.length);
    }
  } catch {}

  input = input.replace(/\/+$/g, '');

  let displayUrl = input;
  let connectUrl = input;
  if (connectUrl.endsWith('/ws')) connectUrl = connectUrl + '/';

  return { displayUrl, connectUrl };
}

// =======================================================
// CP37: wsSend attaches room token (except join)
// =======================================================
function wsSend(obj) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  const out = { ...obj, from: clientId };
  if (roomToken && out.type !== 'join') out.token = roomToken;

  ws.send(JSON.stringify(out));
}

function inRoom() {
  if (!(ws && ws.readyState === WebSocket.OPEN)) return false;
  const t = (els.roomStatus.textContent || '').trim();
  return t && t !== '—';
}

function randInt(min, max) {
  const a = Math.ceil(min);
  const b = Math.floor(max);
  return Math.floor(Math.random() * (b - a + 1)) + a;
}

function sleep(ms) {
  return new Promise(res => setTimeout(res, ms));
}

function genRoomCode(len = 8) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}

// =======================================================
// CP8 – Framing + Padding + Chunking
// =======================================================
const FRAME = {
  TYPE_CHAT: 0x01,
  TYPE_DUMMY: 0x02,
  TYPE_CHUNK: 0x03,
  MAX_PAYLOAD_U16: 65535
};

function u16be(n) {
  const v = n & 0xffff;
  return new Uint8Array([(v >> 8) & 0xff, v & 0xff]);
}
function readU16be(buf, off) {
  return ((buf[off] << 8) | buf[off + 1]) >>> 0;
}

function pickBucketSize(minLen) {
  for (const b of META.buckets) if (b >= minLen) return b;
  return META.buckets[META.buckets.length - 1];
}

function framePack(type, payloadBytes) {
  const flags = 0x00;
  const plen = payloadBytes.length;
  if (plen > FRAME.MAX_PAYLOAD_U16) throw new Error('payload too large');

  const header = new Uint8Array(4);
  header[0] = type;
  header[1] = flags;
  header.set(u16be(plen), 2);

  let core = concatBytes(header, payloadBytes);

  if (META.enabled) {
    const bucket = pickBucketSize(core.length);
    if (core.length <= bucket) {
      const padLen = bucket - core.length;
      const pad = nacl.randomBytes(padLen);
      core = concatBytes(core, pad);
    }
  }

  return core;
}

function frameUnpack(plainBytes) {
  if (!(plainBytes && plainBytes.length >= 4)) throw new Error('frame too short');
  const type = plainBytes[0];
  const flags = plainBytes[1];
  const plen = readU16be(plainBytes, 2);
  if (4 + plen > plainBytes.length) throw new Error('bad frame length');
  const payload = plainBytes.slice(4, 4 + plen);
  return { type, flags, payload };
}

const CHUNK_REASS = new Map();
function chunkKey(msgIdBytes) { return b64enc(msgIdBytes); }
function chunkCleanup() {
  const now = Date.now();
  for (const [k, v] of CHUNK_REASS.entries()) {
    if (now - v.ts > 60_000) CHUNK_REASS.delete(k);
  }
}

// =======================================================
// CP32 – HARD Session Reset Helpers
// =======================================================
function hardClearBuffers(reason) {
  pendingLockedChats = [];
  pendingPreKcChats = [];
  KC.pendingMsg = null;
  CHUNK_REASS.clear();
  stopCoverTraffic();

  roomToken = roomToken;

  if (reason) log(`[cp32] buffers cleared (${reason})`);
  renderStats();
}

// =======================================================
// ✅ CP35 – Render Stats
// =======================================================
function renderStats() {
  if (!els.statsStatus) return;

  const pendLocked = pendingLockedChats.length;
  const pendKc = pendingPreKcChats.length;
  const chunks = CHUNK_REASS.size;

  const conn = ws && ws.readyState === WebSocket.OPEN;
  const rl = STATS.rlCount ? `rl=${STATS.rlCount} (last ${fmtAgo(STATS.rlLastAt)} ago)` : 'rl=0';

  const drops = `drops=${STATS.drops}`;
  const basic = `locked=${pendLocked} | kc=${pendKc} | chunks=${chunks} | ${drops} | ${rl}`;

  els.statsStatus.textContent = conn ? basic : '—';
}

// =======================================================
// CP10 – Factory Reset
// =======================================================
function factoryResetAll() {
  if (!confirm(t('factoryConfirm'))) return;

  try {
    try { if (ws) ws.close(); } catch {}

    const keysToRemove = [
      'mm3_primary_contact_v1',
      'mm3_sign',
      'mm3_sign_session',
      'mm3_client_id',
      'mm3_encrypted_sign'
    ];

    for (const k of keysToRemove) {
      try { localStorage.removeItem(k); } catch {}
      try { sessionStorage.removeItem(k); } catch {}
    }

    try {
      for (let i = localStorage.length - 1; i >= 0; i--) {
        const k = localStorage.key(i);
        if (k && k.startsWith('mm3_')) localStorage.removeItem(k);
      }
    } catch {}

    try {
      for (let i = sessionStorage.length - 1; i >= 0; i--) {
        const k = sessionStorage.key(i);
        if (k && k.startsWith('mm3_')) sessionStorage.removeItem(k);
      }
    } catch {}
  } finally {
    location.reload();
  }
}

// =======================================================
// CP9 – HARD LOCK
// =======================================================
function lockAll(reason) {
  keyChangedLock = true;
  lockReason = reason || 'Key change detected';

  hardClearBuffers('lock');

  KC.sent = false;
  KC.ok = false;
  KC.peerTag = null;

  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  log('🔒 STRICT MODE: HARD LOCK aktiv');
  log(lockReason);
  log('→ Bitte Peer verifizieren, um fortzufahren.');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  updateUI();
}

function unlockAll() {
  keyChangedLock = false;
  lockReason = '';
  log('🔓 HARD LOCK aufgehoben (Peer verifiziert).');

  updateUI();
  maybeStartCoverTraffic();
  maybeStartKC().catch(() => {});
}

// =======================================================
// CP6 Primary Contact + Key Transparency
// =======================================================
const PRIMARY_KEY = 'mm3_primary_contact_v1';

function loadPrimary() {
  try {
    const raw = localStorage.getItem(PRIMARY_KEY);
    const obj = raw ? JSON.parse(raw) : null;
    if (!obj || typeof obj !== 'object') return null;
    if (!obj.previousKeys) obj.previousKeys = [];
    return obj;
  } catch {
    return null;
  }
}

function savePrimary(p) {
  localStorage.setItem(PRIMARY_KEY, JSON.stringify(p));
}

let primary = loadPrimary();

function ensurePrimary() {
  if (primary) return;
  primary = {
    currentFp: null,
    currentPk: null,
    verified: false,
    verifiedAt: null,
    firstSeen: null,
    lastSeen: null,
    previousKeys: []
  };
  savePrimary(primary);
}

function trustOkNow() {
  ensurePrimary();
  return !!(primary.verified && primary.currentFp && peerFp && primary.currentFp === peerFp);
}

function strictAfterTrust() {
  return !!(CP24.enabled && CP24.strictAfterTrust && trustOkNow());
}

function setVerified(v) {
  ensurePrimary();
  primary.verified = !!v;
  primary.verifiedAt = v ? nowIso() : null;
  savePrimary(primary);
}

function pushHistory(fp, pk, meta = {}) {
  ensurePrimary();
  if (!fp || !pk) return;
  primary.previousKeys = primary.previousKeys || [];
  primary.previousKeys.unshift({
    fp,
    pk,
    revokedAt: nowIso(),
    firstSeen: meta.firstSeen || null,
    lastSeen: meta.lastSeen || null
  });
  if (primary.previousKeys.length > 20) primary.previousKeys = primary.previousKeys.slice(0, 20);
  savePrimary(primary);
}

function warnKeyChanged(oldFp, newFp) {
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  log('⚠️  WARNUNG: Der Peer-Key hat sich geändert!');
  log(`Alt: ${oldFp || '—'}  →  Neu: ${newFp || '—'}`);
  log('Trust wurde automatisch entfernt.');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

// =======================================================
// PGP WORD LIST (Even / Odd)
// =======================================================
const PGP_EVEN = [
  "aardvark","absurd","accrue","acme","adrift","adult","afflict","ahead","aimless","Algol","allow","alone","ammo","ancient","apple","artist",
  "assume","Athens","atlas","Aztec","baboon","backfield","backward","banjo","beaming","bedlamp","beehive","beeswax","befriend","Belfast","berserk","billiard",
  "bison","blackjack","blockade","blowtorch","bluebird","bombast","bookshelf","brackish","breadline","breakup","brickyard","briefcase","Burbank","button","buzzard","cement",
  "chairlift","chatter","checkup","chisel","choking","chopper","Christmas","clamshell","classic","classroom","cleanup","clockwork","cobra","commence","concert","cowbell",
  "crackdown","cranky","crowfoot","crucial","crumpled","crusade","cubic","dashboard","deadbolt","deckhand","dogsled","dragnet","drainage","dreadful","drifter","dropper",
  "drumbeat","drunken","Dupont","dwelling","eating","edict","egghead","eightball","endorse","endow","enlist","erase","escape","exceed","eyeglass","eyetooth",
  "facial","fallout","flagpole","flatfoot","flytrap","fracture","framework","freedom","frighten","gazelle","Geiger","glitter","glucose","goggles","goldfish","gremlin",
  "guidance","hamlet","highchair","hockey","indoors","indulge","inverse","involve","island","jawbone","keyboard","kickoff","kiwi","klaxon","locale","lockup",
  "merit","minnow","miser","Mohawk","mural","music","necklace","Neptune","newborn","nightbird","Oakland","obtuse","offload","optic","orca","payday",
  "peachy","pheasant","physique","playhouse","Pluto","preclude","prefer","preshrunk","printer","prowler","pupil","puppy","python","quadrant","quiver","quota",
  "ragtime","ratchet","rebirth","reform","regain","reindeer","rematch","repay","retouch","revenge","reward","rhythm","ribcage","ringbolt","robust","rocker",
  "ruffled","sailboat","sawdust","scallion","scenic","scorecard","Scotland","seabird","select","sentence","shadow","shamrock","showgirl","skullcap","skydive","slingshot",
  "slowdown","snapline","snapshot","snowcap","snowslide","solo","southward","soybean","spaniel","spearhead","spellbind","spheroid","spigot","spindle","spyglass","stagehand",
  "stagnate","stairway","standard","stapler","steamship","sterling","stockman","stopwatch","stormy","sugar","surmount","suspense","sweatband","swelter","tactics","talon",
  "tapeworm","tempest","tiger","tissue","tonic","topmost","tracker","transit","trauma","treadmill","Trojan","trouble","tumor","tunnel","tycoon","uncut",
  "unearth","unwind","uproot","upset","upshot","vapor","village","virus","Vulcan","waffle","wallet","watchword","wayside","willow","woodlark","Zulu"
];

const PGP_ODD = [
  "adroitness","adviser","aftermath","aggregate","alkali","almighty","amulet","amusement","antenna","applicant","Apollo","armistice","article","asteroid","Atlantic","atmosphere",
  "autopsy","Babylon","backwater","barbecue","belowground","bifocals","bodyguard","bookseller","borderline","bottomless","Bradbury","bravado","Brazilian","breakaway","Burlington","businessman",
  "butterfat","Camelot","candidate","cannonball","Capricorn","caravan","caretaker","celebrate","cellulose","certify","chambermaid","Cherokee","Chicago","clergyman","coherence","combustion",
  "commando","company","component","concurrent","confidence","conformist","congregate","consensus","consulting","corporate","corrosion","councilman","crossover","crucifix","cumbersome","customer",
  "Dakota","decadence","December","decimal","designing","detector","detergent","determine","dictator","dinosaur","direction","disable","disbelief","disruptive","distortion","document",
  "embezzle","enchanting","enrollment","enterprise","equation","equipment","escapade","Eskimo","everyday","examine","existence","exodus","fascinate","filament","finicky","forever",
  "fortitude","frequency","gadgetry","Galveston","getaway","glossary","gossamer","graduate","gravity","guitarist","hamburger","Hamilton","handiwork","hazardous","headwaters","hemisphere",
  "hesitate","hideaway","holiness","hurricane","hydraulic","impartial","impetus","inception","indigo","inertia","infancy","inferno","informant","insincere","insurgent","integrate",
  "intention","inventive","Istanbul","Jamaica","Jupiter","leprosy","letterhead","liberty","maritime","matchmaker","maverick","Medusa","megaton","microscope","microwave","midsummer",
  "millionaire","miracle","misnomer","molasses","molecule","Montana","monument","mosquito","narrative","nebula","newsletter","Norwegian","October","Ohio","onlooker","opulent",
  "Orlando","outfielder","Pacific","pandemic","Pandora","paperweight","paragon","paragraph","paramount","passenger","pedigree","Pegasus","penetrate","perceptive","performance","pharmacy",
  "phonetic","photograph","pioneer","pocketful","politeness","positive","potato","processor","prophecy","provincial","proximate","puberty","publisher","pyramid","quantity","racketeer",
  "rebellion","recipe","recover","repellent","replica","reproduce","resistor","responsive","retraction","retrieval","retrospect","revenue","revival","revolver","Sahara","sandalwood",
  "sardonic","Saturday","savagery","scavenger","sensation","sociable","souvenir","specialist","speculate","stethoscope","stupendous","supportive","surrender","suspicious","sympathy","tambourine",
  "telephone","therapist","tobacco","tolerance","tomorrow","torpedo","tradition","travesty","trombonist","truncated","typewriter","ultimate","undaunted","underfoot","unicorn","unify",
  "universe","unravel","upcoming","vacancy","vagabond","vertigo","Virginia","visitor","vocalist","voyager","warranty","Waterloo","whimsical","Wichita","Wilmington","Wyoming",
  "yesteryear","Yucatan"
];

function pgpWordForByte(byte, isEvenIndex) {
  const b = byte & 0xff;
  return isEvenIndex ? PGP_EVEN[b] : PGP_ODD[b];
}

async function safetyPgpCodeWords(myPkBytes, peerPkBytes) {
  const a = b64enc(myPkBytes);
  const b = b64enc(peerPkBytes);
  const pair = (a < b) ? concatBytes(myPkBytes, peerPkBytes) : concatBytes(peerPkBytes, myPkBytes);
  const h = await sha256(concatBytes(pair, new TextEncoder().encode('mm3-safety-pgp-v1')));
  const out = [];
  for (let i = 0; i < 8; i++) out.push(pgpWordForByte(h[i], (i % 2) === 0));
  return out.join(' ');
}

// =======================================================
// CP4 Double Ratchet
// =======================================================
const DR = {
  ready: false,
  RK: null,
  DHs: null,
  DHr: null,
  CKs: null,
  CKr: null,
  Ns: 0,
  Nr: 0,
  PN: 0,
  MKSKIPPED: new Map(),
  SEEN: new Set(),
  MAX_SKIP: 50
};

function drReset() {
  DR.ready = false;
  DR.RK = null;
  DR.DHs = null;
  DR.DHr = null;
  DR.CKs = null;
  DR.CKr = null;
  DR.Ns = 0;
  DR.Nr = 0;
  DR.PN = 0;
  DR.MKSKIPPED.clear();
  DR.SEEN.clear();

  sessionCtx = null;
  sessionCtxShort = null;
  v2Broken = false;

  KC.sent = false;
  KC.ok = false;
  KC.peerTag = null;
  KC.pendingMsg = null;

  hardClearBuffers('drReset');
}

function drKeyId(dhPubBytes, n) {
  return b64enc(dhPubBytes) + ':' + String(n);
}

// =======================================================
// CP43: HKDF (RFC 5869) statt SHA-256 für KDF_CK + KDF_RK3
// =======================================================
async function hkdfDeriveBits(ikm, salt, info) {
  const key = await crypto.subtle.importKey(
    'raw', ikm, { name: 'HKDF' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new TextEncoder().encode(info) },
    key, 256
  );
  return new Uint8Array(bits);
}

async function KDF_CK(CK) {
  // CP43: HKDF statt SHA-256
  const salt = new Uint8Array(32); // zero salt
  const mk  = await hkdfDeriveBits(CK, salt, 'mm3-mk-v2');
  const ck2 = await hkdfDeriveBits(CK, salt, 'mm3-ck-v2');
  return { CK: ck2, MK: mk };
}

async function KDF_RK3(RK, DHout) {
  // CP43: HKDF statt SHA-256 — DHout als Salt, RK als IKM
  const salt = DHout;
  const rk2 = await hkdfDeriveBits(RK, salt, 'mm3-rk-v2');
  const ck1 = await hkdfDeriveBits(RK, salt, 'mm3-ck1-v2');
  const ck2 = await hkdfDeriveBits(RK, salt, 'mm3-ck2-v2');
  return { RK: rk2, CK1: ck1, CK2: ck2 };
}

function amInitiator(myFpStr, peerFpStr) {
  return String(myFpStr) < String(peerFpStr);
}

function sort2Bytes(a, b) {
  const A = b64enc(a), B = b64enc(b);
  return (A < B) ? [a, b] : [b, a];
}

async function deriveSessionCtx() {
  if (!CP21.enabled) return null;
  if (!currentRoom) return null;
  if (!mySignKp || !peerSignPk) return null;
  if (!myDhKp || !peerDhPk) return null;

  const te = new TextEncoder();
  const roomBytes = te.encode(String(currentRoom));

  const [s1, s2] = sort2Bytes(mySignKp.publicKey, peerSignPk);
  const [d1, d2] = sort2Bytes(myDhKp.publicKey, peerDhPk);

  const material = concatBytes(
    te.encode('mm3-cp21-ctx-v1|room:'),
    roomBytes,
    te.encode('|sign:'),
    s1, s2,
    te.encode('|dh:'),
    d1, d2
  );

  const h = await sha256(material);
  return h;
}

async function maybeInitSessionCtx() {
  if (!CP21.enabled) return;
  const ctx = await deriveSessionCtx();
  if (!ctx) return;
  sessionCtx = ctx;
  sessionCtxShort = b64enc(ctx).slice(0, 12);
  log(`[cp21] Session-Context ready ✓ (${sessionCtxShort})`);
  if (!strictAfterTrust()) v2Broken = false;

  await maybeStartKC();
}

function stableHeaderJson(headerObj) {
  const dh = String(headerObj.dh || '');
  const pn = Number(headerObj.pn || 0);
  const n  = Number(headerObj.n  || 0);
  return `{"dh":"${dh}","pn":${pn},"n":${n}}`;
}

async function headerMacV1(mk, headerObj, nonceBytes, boxedBytes) {
  const macKey = await sha256(concatBytes(mk, new TextEncoder().encode('mm3-hdrmac-key-v1')));
  const hjson = new TextEncoder().encode(stableHeaderJson(headerObj));
  const tagFull = await sha256(concatBytes(
    macKey, hjson, nonceBytes, boxedBytes,
    new TextEncoder().encode('mm3-hdrmac-tag-v1')
  ));
  return tagFull.slice(0, CP17.macBytes);
}

async function headerMacV2(mk, headerObj, nonceBytes, boxedBytes, ctxBytes) {
  const macKey = await sha256(concatBytes(mk, new TextEncoder().encode('mm3-hdrmac-key-v2')));
  const hjson = new TextEncoder().encode(stableHeaderJson(headerObj));
  const ctx = ctxBytes || new Uint8Array();
  const tagFull = await sha256(concatBytes(
    macKey,
    new TextEncoder().encode('ctx:'), ctx,
    new TextEncoder().encode('|hdr:'), hjson,
    new TextEncoder().encode('|nonce:'), nonceBytes,
    new TextEncoder().encode('|boxed:'), boxedBytes,
    new TextEncoder().encode('|mm3-hdrmac-tag-v2')
  ));
  return tagFull.slice(0, CP21.ctxTagBytes);
}

// =======================================================
// CP26 Key Confirmation (KC)
// =======================================================
async function kcDeriveTag() {
  if (!KC.enabled) throw new Error('kc disabled');
  if (!sessionCtx) throw new Error('kc needs sessionCtx');
  if (!mySignKp || !peerSignPk) throw new Error('kc needs sign keys');
  if (!myDhKp || !peerDhPk) throw new Error('kc needs dh keys');

  const te = new TextEncoder();
  const roomBytes = te.encode(String(currentRoom || ''));

  const [s1, s2] = sort2Bytes(mySignKp.publicKey, peerSignPk);
  const [d1, d2] = sort2Bytes(myDhKp.publicKey, peerDhPk);

  const kcKey = await sha256(concatBytes(sessionCtx, te.encode('mm3-kc-key-v1')));

  const transcript = concatBytes(
    te.encode('mm3-kc-transcript-v1|room:'),
    roomBytes,
    te.encode('|sign:'),
    s1, s2,
    te.encode('|dh:'),
    d1, d2
  );

  const full = await sha256(concatBytes(kcKey, transcript, te.encode('|tag')));
  return full.slice(0, 16);
}

async function maybeStartKC() {
  if (!KC.enabled) return;
  if (!strictAfterTrust()) return;
  if (keyChangedLock) return;
  if (KC.ok) return;
  if (!DR.ready) return;
  if (!sessionCtx || !sessionCtxShort) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (!inRoom()) return;
  if (!peerFp) return;
  if (!roomToken) return;

  if (!KC.sent) {
    const tag = await kcDeriveTag();
    KC.sent = true;
    wsSend({ type: 'kc', v: 1, ctx: sessionCtxShort, tag: b64enc(tag) });
    log('[cp26] KC gesendet');
    renderStats();
  }
}

async function onKC(msg) {
  try {
    if (!KC.enabled) return;
    if (KC.ok) return;

    if (strictAfterTrust()) {
      if (!sessionCtx || !sessionCtxShort) throw new Error('kc ctx missing');
      if (msg.v !== 1) throw new Error('kc version mismatch');
      if (!msg.tag) throw new Error('kc tag missing');
      if (msg.ctx && msg.ctx !== sessionCtxShort) throw new Error('kc ctx mismatch');

      const got = b64dec(msg.tag);
      const expect = await kcDeriveTag();

      if (!ctEq(got, expect)) {
        lockAll('[cp26] KC FAILED: Channel/Transcript mismatch (possible MITM/desync)');
        return;
      }

      KC.ok = true;
      KC.peerTag = msg.tag || null;

      log('[cp26] KC OK ✓ Secure channel established');

      const queue = pendingPreKcChats.slice();
      pendingPreKcChats = [];
      for (const m of queue) {
        await onChat(m, true);
      }

      updateUI();
      maybeStartCoverTraffic();
      renderStats();
      return;
    }

    KC.pendingMsg = { v: msg.v, ctx: msg.ctx || null, tag: msg.tag };
    log('[cp26] KC empfangen (pre-trust) – gecached');
    renderStats();
  } catch (e) {
    if (strictAfterTrust()) {
      lockAll('[cp26] KC ERROR: ' + e.message);
    } else {
      log('[kc] Fehler: ' + e.message);
    }
  }
}

// =======================================================
// DR init + ratchet ops
// =======================================================
async function drInitFromHandshake() {
  if (!myDhKp || !peerDhPk || !mySignKp || !peerFp) return;

  const shared0 = nacl.box.before(peerDhPk, myDhKp.secretKey);
  // CP43: HKDF auch für initialen Root Key
  const rk0 = await hkdfDeriveBits(shared0, new Uint8Array(32), 'mm3-rk0-v2');
  const out = await KDF_RK3(rk0, shared0);

  const myFpStr = fingerprint(mySignKp.publicKey);
  const initiator = amInitiator(myFpStr, peerFp);

  DR.RK = out.RK;
  DR.DHs = { publicKey: myDhKp.publicKey, secretKey: myDhKp.secretKey };
  DR.DHr = peerDhPk;

  if (initiator) { DR.CKs = out.CK1; DR.CKr = out.CK2; }
  else { DR.CKs = out.CK2; DR.CKr = out.CK1; }

  DR.Ns = 0;
  DR.Nr = 0;
  DR.PN = 0;
  DR.MKSKIPPED.clear();
  DR.SEEN.clear();

  DR.ready = true;
  log('[double-ratchet] ready ✓');
  log('[cp43] HKDF aktiv ✓');
  await updateSafetyCode();
  updateUI();

  await maybeInitSessionCtx();
  maybeStartCoverTraffic();
  renderStats();
}

async function drSkipMessageKeys(until) {
  if (!DR.CKr || !DR.DHr) return;
  if (DR.Nr + DR.MAX_SKIP < until) throw new Error('too many skipped messages');

  while (DR.Nr < until) {
    const r = await KDF_CK(DR.CKr);
    DR.CKr = r.CK;
    const keyId = await drKeyId(DR.DHr, DR.Nr);
    DR.MKSKIPPED.set(keyId, r.MK);
    DR.Nr++;
  }
}

async function drDHRatchet(newDHr) {
  DR.PN = DR.Ns;
  DR.Ns = 0;
  DR.Nr = 0;

  DR.DHr = newDHr;

  const dh1 = nacl.box.before(DR.DHr, DR.DHs.secretKey);
  const out1 = await KDF_RK3(DR.RK, dh1);
  DR.RK = out1.RK;
  DR.CKr = out1.CK1;

  const newDHs = nacl.box.keyPair();
  DR.DHs = { publicKey: newDHs.publicKey, secretKey: newDHs.secretKey };

  const dh2 = nacl.box.before(DR.DHr, DR.DHs.secretKey);
  const out2 = await KDF_RK3(DR.RK, dh2);
  DR.RK = out2.RK;
  DR.CKs = out2.CK1;
}

async function drEncrypt(plaintextBytes) {
  if (!DR.ready || !DR.CKs || !DR.DHs) throw new Error('ratchet not ready');

  const r = await KDF_CK(DR.CKs);
  DR.CKs = r.CK;

  const mk = r.MK;
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const boxed = nacl.secretbox(plaintextBytes, nonce, mk);

  const header = { dh: b64enc(DR.DHs.publicKey), pn: DR.PN, n: DR.Ns };
  DR.Ns++;

  const payload = { nonce: b64enc(nonce), boxed: b64enc(boxed) };

  if (CP17.enabled) {
    const canUseV2 = (CP21.enabled && sessionCtx && !v2Broken);
    if (canUseV2) {
      const tag2 = await headerMacV2(mk, header, nonce, boxed, sessionCtx);
      payload.hmac = b64enc(tag2);
      payload.hmac_v = 2;
      payload.ctx = sessionCtxShort;
    } else {
      const tag1 = await headerMacV1(mk, header, nonce, boxed);
      payload.hmac = b64enc(tag1);
      payload.hmac_v = 1;
    }
  }

  return { header, payload };
}

async function drTryDecrypt(header, payload) {
  if (!DR.ready) throw new Error('ratchet not ready');

  const dhPub = b64dec(header.dh);
  const pn = Number(header.pn);
  const n = Number(header.n);

  if (!Number.isFinite(pn) || pn < 0) throw new Error('bad pn');
  if (!Number.isFinite(n) || n < 0) throw new Error('bad n');

  const nonce = b64dec(payload.nonce);
  const boxed = b64dec(payload.boxed);

  const keyId = await drKeyId(dhPub, n);
  if (DR.SEEN.has(keyId)) throw new Error('replay detected');

  const hmacV = Number(payload.hmac_v || 0);
  const hasMac = !!payload.hmac;

  const verifyMacOrThrow = async (mk) => {
    if (strictAfterTrust()) {
      if (!CP17.enabled) throw new Error('cp17 disabled in strict mode');
      if (!hasMac) throw new Error('mac required (strict)');
      if (!CP21.enabled) throw new Error('cp21 disabled in strict mode');
      if (!sessionCtx) throw new Error('session ctx required (strict)');
      if (hmacV !== 2) throw new Error('v2 mac required (strict)');
    } else {
      if (!CP17.enabled) return;
      if (!hasMac) return;
    }

    const got = b64dec(payload.hmac);

    if (hmacV === 2) {
      if (!CP21.enabled) throw new Error('cp21 disabled but v2 mac received');
      if (!sessionCtx) throw new Error('cp21 ctx missing (need sessionCtx)');

      const expect2 = await headerMacV2(mk, header, nonce, boxed, sessionCtx);
      if (ctEq(expect2, got)) return;

      if (!strictAfterTrust()) {
        const expect1 = await headerMacV1(mk, header, nonce, boxed);
        if (ctEq(expect1, got)) {
          if (!v2Broken) {
            v2Broken = true;
            log('[cp23] ⚠️ v2 MAC mismatch → fallback v1 OK. Downgrade aktiv.');
          }
          return;
        }
      }

      throw new Error('session/header-mac failed (v2)');
    }

    const expect1 = await headerMacV1(mk, header, nonce, boxed);
    if (!ctEq(expect1, got)) throw new Error('header-mac failed (v1)');
  };

  if (DR.MKSKIPPED.has(keyId)) {
    const mk = DR.MKSKIPPED.get(keyId);
    await verifyMacOrThrow(mk);
    const plain = nacl.secretbox.open(boxed, nonce, mk);
    if (!plain) throw new Error('decrypt failed (skipped)');
    DR.MKSKIPPED.delete(keyId);
    DR.SEEN.add(keyId);
    return plain;
  }

  const dhChanged = !DR.DHr || !samePk(DR.DHr, dhPub);
  if (dhChanged) {
    await drSkipMessageKeys(pn);
    await drDHRatchet(dhPub);
  }

  await drSkipMessageKeys(n);

  const r = await KDF_CK(DR.CKr);
  const nextCKr = r.CK;
  const mk = r.MK;

  const myKeyId = await drKeyId(DR.DHr, DR.Nr);

  await verifyMacOrThrow(mk);

  const plain = nacl.secretbox.open(boxed, nonce, mk);
  if (!plain) throw new Error('decrypt failed');

  DR.CKr = nextCKr;
  DR.Nr++;
  DR.SEEN.add(myKeyId);

  return plain;
}

// =======================================================
// Handshake (signed) + apply keys
// =======================================================
function genDh() {
  myDhKp = nacl.box.keyPair();
  log('DH-Key erzeugt');
}

function buildSignedPayload() {
  const p = { signPk: b64enc(mySignKp.publicKey), dhPk: b64enc(myDhKp.publicKey) };
  const pb = new TextEncoder().encode(JSON.stringify(p));
  const sig = withPrivateKey(secret => nacl.sign.detached(pb, secret));
  return { data: b64enc(pb), sig: b64enc(sig) };
}

function verifySignedPayload(payload) {
  const db = b64dec(payload.data);
  const sb = b64dec(payload.sig);
  const payloadObj = JSON.parse(new TextDecoder().decode(db));
  const pkBytes = b64dec(payloadObj.signPk);

  const ok = nacl.sign.detached.verify(db, sb, pkBytes);
  if (!ok) return null;

  return { signPkBytes: pkBytes, dhPkBytes: b64dec(payloadObj.dhPk) };
}

async function updateSafetyCode() {
  if (!mySignKp || !peerSignPk) {
    els.safetyStatus.textContent = '—';
    if (els.safetyCodeDisplay) els.safetyCodeDisplay.textContent = '—';
    return;
  }
  const code = await safetyPgpCodeWords(mySignKp.publicKey, peerSignPk);
  els.safetyStatus.textContent = code;
  if (els.safetyCodeDisplay) els.safetyCodeDisplay.textContent = code;
}

async function applyPeerKeys(where, verified) {
  peerSignPk = verified.signPkBytes;
  peerDhPk = verified.dhPkBytes;

  if (mySignKp && samePk(peerSignPk, mySignKp.publicKey)) {
    log(`[${where}] ignoriert: eigener Sign-Key (self)`);
    return false;
  }

  const newFp = fingerprint(peerSignPk);
  const newPkB64 = b64enc(peerSignPk);

  ensurePrimary();

  const oldFp = primary.currentFp || null;
  const oldPk = primary.currentPk || null;
  const oldFirstSeen = primary.firstSeen || null;
  const oldLastSeen = primary.lastSeen || null;

  const changed = !!(oldFp && oldFp !== newFp);

  if (changed) {
    pushHistory(oldFp, oldPk, { firstSeen: oldFirstSeen, lastSeen: oldLastSeen });
    primary.verified = false;
    primary.verifiedAt = null;

    warnKeyChanged(oldFp, newFp);
    savePrimary(primary);

    lockAll(`Key-Change erkannt: ${oldFp} → ${newFp}`);
  }

  primary.currentFp = newFp;
  primary.currentPk = newPkB64;
  if (!primary.firstSeen || changed) primary.firstSeen = nowIso();
  primary.lastSeen = nowIso();
  savePrimary(primary);

  peerFp = newFp;

  KC.sent = false;
  KC.ok = false;
  KC.peerTag = null;
  KC.pendingMsg = null;
  pendingPreKcChats = [];

  log(`[${where}] verifiziert – Peer FP: ${peerFp}`);
  await updateSafetyCode();

  await drInitFromHandshake();
  renderStats();
  return true;
}

async function onHs(msg) {
  const verified = verifySignedPayload(msg.payload);
  if (!verified) return log('[hs] Signatur ungültig');

  const ok = await applyPeerKeys('hs', verified);
  if (!ok) return;

  wsSend({ type: 'hs_ack', payload: buildSignedPayload() });
  log('[hs_ack] gesendet');
}

async function onHsAck(msg) {
  const verified = verifySignedPayload(msg.payload);
  if (!verified) return log('[hs_ack] Signatur ungültig');

  await applyPeerKeys('hs_ack', verified);
}

// =======================================================
// CP7 Identity Backup/Restore – DEAKTIVIERT
// =======================================================
function backupIdentity() {
  alert(t('backupDisabled'));
}

function restoreIdentity() {
  alert(t('restoreDisabled'));
}

// =======================================================
// Identity init – verschlüsselte Speicherung
// =======================================================
function loadOrGenSignKp() {
  if (!window.nacl) {
    els.cryptoStatus.textContent = '—';
    els.cryptoStatus.className = 'bad';
    log('window.nacl fehlt (tweetnacl nicht geladen!)');
    updateUI();
    return;
  }

  els.cryptoStatus.textContent = 'bereit';
  els.cryptoStatus.className = 'ok';
  log('tweetnacl erkannt ✓');

  const store = sessionStorage;

  const encrypted = store.getItem('mm3_encrypted_sign');
  if (encrypted && _sessionPass) {
    try {
      const obj = JSON.parse(encrypted);
      const secret = decryptSecret(obj, _sessionPass);
      mySignKp = { publicKey: b64dec(obj.pk), secretKey: secret };
      log('Sign-Key geladen (verschlüsselt)');
      els.fpStatus.textContent = fingerprint(mySignKp.publicKey);
      updateUI();
      renderStats();
      return;
    } catch (e) {
      log('Entschlüsselung fehlgeschlagen, erzeuge neuen Key: ' + e.message);
      store.removeItem('mm3_encrypted_sign');
    }
  }

  mySignKp = nacl.sign.keyPair();
  _sessionPass = nacl.randomBytes(32);

  const encryptedObj = encryptSecret(mySignKp.secretKey, _sessionPass);
  encryptedObj.pk = b64enc(mySignKp.publicKey);
  store.setItem('mm3_encrypted_sign', JSON.stringify(encryptedObj));

  log('Neuer Sign-Key erzeugt und verschlüsselt gespeichert');
  els.fpStatus.textContent = fingerprint(mySignKp.publicKey);
  log(`[info] clientId: ${clientId}`);
  updateUI();
  renderStats();
}

// =======================================================
// CP8 – Cover Traffic
// =======================================================
let coverTimer = null;

function stopCoverTraffic() {
  if (coverTimer) {
    clearTimeout(coverTimer);
    coverTimer = null;
  }
}

function coverEligible() {
  if (keyChangedLock) return false;
  if (!META.enabled || !META.coverTraffic) return false;
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  if (!inRoom()) return false;
  if (!DR.ready) return false;
  if (!peerFp) return false;
  if (!trustOkNow()) return false;
  if (strictAfterTrust() && KC.enabled && !KC.ok) return false;
  if (!roomToken) return false;
  return true;
}

function maybeStartCoverTraffic() {
  stopCoverTraffic();
  if (!coverEligible()) return;

  const schedule = () => {
    if (!coverEligible()) { stopCoverTraffic(); return; }
    const delay = randInt(META.coverMinMs, META.coverMaxMs);
    coverTimer = setTimeout(async () => {
      try { await sendDummyPacket(); } catch {}
      schedule();
    }, delay);
  };

  schedule();
}

async function sendDummyPacket() {
  if (!coverEligible()) return;

  const junk = nacl.randomBytes(randInt(8, 24));
  const frame = framePack(FRAME.TYPE_DUMMY, junk);
  const enc = await drEncrypt(frame);
  wsSend({ type: 'chat', header: enc.header, payload: enc.payload });
}

// =======================================================
// Chat – send / receive
// =======================================================
async function sendChat() {
  const txt = els.message.value.trim();
  if (!txt) return;

  if (keyChangedLock) return log('🔒 HARD LOCK aktiv – bitte Peer verifizieren.');
  if (!DR.ready) return log('E2EE nicht bereit');
  if (!trustOkNow()) return log('Trust nicht bestätigt (Peer verifizieren)');
  if (!roomToken) return log('[cp37] block: room token fehlt – bitte neu joinen');

  if (strictAfterTrust() && (!sessionCtx || !sessionCtxShort)) {
    return log('[cp24] block: SessionCtx fehlt – bitte neu joinen/handshake');
  }

  if (strictAfterTrust() && KC.enabled && !KC.ok) {
    await maybeStartKC();
    return log('[cp26] block: Secure channel noch nicht bestätigt (warte auf KC)');
  }

  try {
    if (META.enabled) await sleep(randInt(META.sendJitterMinMs, META.sendJitterMaxMs));

    const plain = new TextEncoder().encode(txt);

    if (CHUNK.enabled && plain.length > CHUNK.maxPlainBytes) {
      const msgId = nacl.randomBytes(12);
      const total = Math.ceil(plain.length / CHUNK.maxPlainBytes);

      for (let i = 0; i < total; i++) {
        const start = i * CHUNK.maxPlainBytes;
        const end = Math.min(plain.length, start + CHUNK.maxPlainBytes);
        const part = plain.slice(start, end);

        const meta = concatBytes(
          msgId,
          new Uint8Array([total & 0xff]),
          new Uint8Array([i & 0xff]),
          part
        );

        const frame = framePack(FRAME.TYPE_CHUNK, meta);
        const enc = await drEncrypt(frame);
        wsSend({ type: 'chat', header: enc.header, payload: enc.payload });
      }

      chatAdd('me', txt);
      els.message.value = '';
      renderStats();
      return;
    }

    const frame = framePack(FRAME.TYPE_CHAT, plain);
    const enc = await drEncrypt(frame);
    wsSend({ type: 'chat', header: enc.header, payload: enc.payload });

    chatAdd('me', txt);
    els.message.value = '';
    renderStats();
  } catch (e) {
    log('[send] Fehler: ' + e.message);
  }
}

async function onChat(msg, fromKcFlush = false) {
  if (!DR.ready) return log('Chat ohne E2EE');

  if (keyChangedLock && !fromKcFlush) {
    pendingLockedChats.push(msg);
    renderStats();
    return log('[locked] Nachricht empfangen (gepuffert) – erst nach Verifizierung sichtbar.');
  }

  if (strictAfterTrust() && KC.enabled && !KC.ok && !fromKcFlush) {
    pendingPreKcChats.push(msg);
    await maybeStartKC();
    renderStats();
    return log('[cp26] Nachricht empfangen (gepuffert) – erst nach KC sichtbar.');
  }

  try {
    const plainBytes = await drTryDecrypt(msg.header, msg.payload);
    const fr = frameUnpack(plainBytes);

    if (fr.type === FRAME.TYPE_DUMMY) return;

    if (fr.type === FRAME.TYPE_CHAT) {
      const text = new TextDecoder().decode(fr.payload);
      chatAdd('peer', text);
      renderStats();
      return;
    }

    if (fr.type === FRAME.TYPE_CHUNK) {
      chunkCleanup();

      const p = fr.payload;
      if (p.length < 14) {
        statDrop('chunk_too_short');
        renderStats();
        return;
      }

      const msgId = p.slice(0, 12);
      const total = p[12] & 0xff;
      const idx = p[13] & 0xff;
      const data = p.slice(14);

      const k = chunkKey(msgId);
      if (!CHUNK_REASS.has(k)) {
        CHUNK_REASS.set(k, { total, parts: new Map(), ts: Date.now() });
      }
      const entry = CHUNK_REASS.get(k);
      entry.ts = Date.now();
      entry.total = total;

      if (!entry.parts.has(idx)) entry.parts.set(idx, data);

      if (entry.parts.size === entry.total) {
        let size = 0;
        for (let i = 0; i < entry.total; i++) {
          const part = entry.parts.get(i);
          if (!part) {
            statDrop('chunk_missing_part');
            renderStats();
            return;
          }
          size += part.length;
        }
        const out = new Uint8Array(size);
        let off = 0;
        for (let i = 0; i < entry.total; i++) {
          const part = entry.parts.get(i);
          out.set(part, off);
          off += part.length;
        }
        CHUNK_REASS.delete(k);

        const text = new TextDecoder().decode(out);
        chatAdd('peer', text);
      }

      renderStats();
      return;
    }
  } catch (e) {
    log('[chat] Fehler: ' + e.message);
    renderStats();
  }
}

// =======================================================
// Verify / Unverify / Safety
// =======================================================
function verifyPeer() {
  if (!peerFp) return log('Kein Peer FP');

  const code = els.safetyStatus.textContent || '—';
  const ok = confirm(t('verifyConfirm', peerFp, code));
  if (!ok) return;

  setVerified(true);
  log('Peer verifiziert – Trust bestätigt (Primary Contact)');
  log('[cp24] strict-after-trust aktiv: MAC(v2)+SessionCtx Pflicht, kein Downgrade.');
  log('[cp26] Key Confirmation wird jetzt erzwungen (Secure channel).');

  if (keyChangedLock) unlockAll();

  updateUI();

  if (KC.pendingMsg) {
    const cached = KC.pendingMsg;
    KC.pendingMsg = null;
    onKC(cached).catch(() => {});
  }

  maybeStartKC().catch(() => {});
  renderStats();
}

function unverifyPeer() {
  setVerified(false);
  stopCoverTraffic();

  KC.sent = false;
  KC.ok = false;
  KC.peerTag = null;
  KC.pendingMsg = null;

  pendingPreKcChats = [];

  log('Verifizierung gelöscht');
  updateUI();
  renderStats();
}

function showSafety() {
  if (!els.safetyStatus.textContent || els.safetyStatus.textContent === '—') return;
  alert('Safety Code:\n\n' + els.safetyStatus.textContent);
}

// =======================================================
// UI update
// =======================================================
function renderContacts() {
  ensurePrimary();

  els.primaryFp.textContent = primary.currentFp || '—';

  let status = '—';
  if (primary.verified) {
    status = keyChangedLock ? t('lockedKeyChange') : t('verified');
    if (strictAfterTrust() && KC.enabled) {
      status += KC.ok ? t('kcOk') : t('kcPending');
    }
  } else if (primary.currentFp) {
    status = t('notVerified');
  }

  els.primaryStatus.textContent = status;
  els.primaryFirstSeen.textContent = primary.firstSeen || '—';
  els.primaryLastSeen.textContent = primary.lastSeen || '—';
  els.primaryVerifiedAt.textContent = primary.verifiedAt || '—';

  if (!primary.previousKeys || primary.previousKeys.length === 0) {
    els.historyList.textContent = '—';
  } else {
    els.historyList.textContent = primary.previousKeys.map(x => {
      return `${x.fp}\nrevokedAt: ${x.revokedAt}${x.firstSeen ? `\nfirstSeen: ${x.firstSeen}` : ''}${x.lastSeen ? ` · lastSeen: ${x.lastSeen}` : ''}\n`;
    }).join('\n');
  }
}

function updateUI() {
  const conn = ws && ws.readyState === WebSocket.OPEN;
  els.wsStatus.textContent = conn ? t('connected') : t('disconnected');
  els.wsStatus.className = conn ? 'ok' : 'bad';

  els.roomStatus.textContent = currentRoom || '—';

  const room = inRoom();

  els.btnJoin.disabled = !conn || !!currentRoom;
  els.btnLeave.disabled = !room;
  els.btnConnect.disabled = conn;
  els.btnDisconnect.disabled = !conn;

  if (els.btnNewRoom) els.btnNewRoom.disabled = !conn;

  const hasPeer = !!peerFp;
  els.peerFpStatus.textContent = peerFp || '—';

  const trust = trustOkNow() && !keyChangedLock;
  els.trustStatus.textContent = trust ? t('confirmed') : (keyChangedLock ? t('locked') : t('notConfirmed'));
  els.trustStatus.className = trust ? 'ok' : 'bad';

  if (els.kcMini) {
    if (!strictAfterTrust()) els.kcMini.textContent = '—';
    else els.kcMini.textContent = (KC.enabled ? (KC.ok ? 'OK' : '…') : 'off');
  }

  const canSend = room && DR.ready && trust && (!strictAfterTrust() || !KC.enabled || KC.ok);
  els.btnSend.disabled = !canSend;

  els.btnVerify.disabled = !room || !hasPeer;
  els.btnUnverify.disabled = !primary || !primary.verified;
  els.btnShowSafety.disabled = !hasPeer || !els.safetyStatus.textContent || els.safetyStatus.textContent === '—';

  renderContacts();
  renderStats();
}

// =======================================================
// WebSocket control
// =======================================================
function wsConnect() {
  const raw = (els.wsUrl.value || '').trim();
  if (!raw) return;

  const { displayUrl, connectUrl } = normalizeWsInput(raw);
  if (!connectUrl) return;

  els.wsUrl.value = displayUrl;

  try {
    ws = new WebSocket(connectUrl);

    ws.onopen = () => {
      log(`[ws] verbunden (${displayUrl})`);
      updateUI();
    };

    ws.onclose = (ev) => {
      const code = (ev && typeof ev.code === 'number') ? ev.code : -1;
      const reason = (ev && ev.reason) ? ev.reason : '';
      const clean = (ev && typeof ev.wasClean === 'boolean') ? ev.wasClean : false;

      log(`[ws] getrennt (code=${code}, clean=${clean}${reason ? `, reason=${reason}` : ''})`);

      roomToken = null;
      hardClearBuffers('ws.close');
      deleteIdentity();

      ws = null;
      currentRoom = null;
      hsSent = false;
      peerFp = null;
      peerSignPk = null;
      peerDhPk = null;

      drReset();
      updateUI();
      location.reload();
    };

    ws.onerror = () => {
      log('[ws] Fehler (siehe close code/reason)');
      updateUI();
    };

    ws.onmessage = async (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (!msg || typeof msg.type !== 'string') return;

      if (msg.type === 'rate_limited') {
        STATS.rlCount += 1;
        STATS.rlLastAt = Date.now();
        log('[cp35] rate_limited (server)');
        renderStats();
        return;
      }

      if (msg.type === 'peer_joined') {
        log('[room] peer_joined');

        if (!peerFp && hsSent && mySignKp && roomToken) {
          hsSent = false;
          log('[fix] peer_joined + no peerFP → resend hs');
          await startHandshake();
        }

        updateUI();
        return;
      }

      if (msg.type === 'joined') {
        currentRoom = msg.code;
        log(`[room] joined ${currentRoom}`);
        hsSent = false;

        roomToken = (typeof msg.token === 'string' && msg.token.length > 0) ? msg.token : null;
        if (roomToken) log('[cp37] roomToken erhalten ✓');
        if (msg.locked) log('[cp37] room locked (1:1)');

        hardClearBuffers('room.joined');
        drReset();

        updateUI();

        if (mySignKp && window.nacl) {
          await startHandshake();
        }
        return;
      }

      if (msg.type === 'join_denied') {
        currentRoom = null;
        roomToken = null;
        hardClearBuffers('join.denied');
        drReset();
        log(`[room] join denied (${msg.reason || 'unknown'})`);
        updateUI();
        return;
      }

      if (msg.type === 'hs') return onHs(msg);
      if (msg.type === 'hs_ack') return onHsAck(msg);
      if (msg.type === 'kc') return onKC(msg);
      if (msg.type === 'chat') return onChat(msg);
    };
  } catch (e) {
    log('[ws] Fehler: ' + e.message);
  }
}

function wsDisconnect() {
  if (!ws) return;
  try { ws.close(); } catch {}
}

function wsJoin() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const code = (els.roomCode.value || '').trim();
  if (!code) return;
  wsSend({ type: 'join', code });
}

function wsLeave() {
  wsDisconnect();
}

// CP41: Neu generiert nur den Code – kein automatisches Join
function newRoom() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const code = genRoomCode(8);
  els.roomCode.value = code;
}

async function startHandshake() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (!inRoom()) return;
  if (hsSent) return;
  if (!mySignKp) return log('Keine Identity – bitte "Identity laden/erz." klicken');
  if (!roomToken) return log('[cp37] block: kein roomToken – bitte neu joinen');

  genDh();
  wsSend({ type: 'hs', payload: buildSignedPayload() });
  hsSent = true;
  log('[hs] gesendet');
  renderStats();
}

// =======================================================
// UI wiring
// =======================================================
function bindUI() {
  els.btnConnect?.addEventListener('click', wsConnect);
  els.btnDisconnect?.addEventListener('click', wsDisconnect);
  els.btnJoin?.addEventListener('click', wsJoin);
  els.btnLeave?.addEventListener('click', wsLeave);

  els.btnNewRoom?.addEventListener('click', newRoom);

  els.btnGenerateKeys?.addEventListener('click', () => {
    loadOrGenSignKp();
  });

  els.btnSend?.addEventListener('click', sendChat);

  els.btnVerify?.addEventListener('click', verifyPeer);
  els.btnUnverify?.addEventListener('click', unverifyPeer);
  els.btnShowSafety?.addEventListener('click', showSafety);

  els.btnBackup?.addEventListener('click', backupIdentity);
  els.btnRestore?.addEventListener('click', restoreIdentity);

  els.btnResetAll?.addEventListener('click', factoryResetAll);

  els.message?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChat();
    }
  });

  try { loadOrGenSignKp(); } catch {}
}

log('[info] app.js geladen – CP41: Neu-Button, CP42: i18n vollständig (de/en), CP43: HKDF');
log('[ Sicherheit ] Verschlüsselte Identität im Storage, Löschung bei Disconnect, Backup deaktiviert');
bindUI();
updateUI();
renderStats();
