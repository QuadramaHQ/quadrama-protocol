# Quadrama — Technical Documentation

For developers and security researchers who want to understand the
internals. Read alongside `THREAT_MODEL.md` and `SECURITY.md`.

---

## Architecture

Quadrama is a single Node process that serves a static SPA *and* relays
WebSocket frames between two peers. There is no database, no message
broker, no build step.

**Server (`server.js`)**
- Plain `node:http` + `ws` 8.x.
- Static handler for `public/` with strict security headers
  (`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `X-Frame-Options`, `Content-Security-Policy`, `Cache-Control`).
- WebSocket relay: opaque blobs only — the relay process never sees
  plaintext, never persists messages.
- Per-IP and per-connection rate limits.
- Tombstoned rooms cannot be reused.
- Graceful `SIGINT` / `SIGTERM` shutdown.
- Configurable via environment (see `SECURITY.md`).

**Client (`public/app.js`)**
- Vanilla JavaScript. Monolithic for auditability — every cryptographic
  decision lives in one file.
- All cryptography in the browser via `tweetnacl` + Web Crypto.
- Identity Sign-Key encrypted-at-rest in `sessionStorage` with a
  random 32-byte password held only in RAM.
- On disconnect, the identity is wiped and the page reloads so no
  JavaScript state survives.

---

## Cryptographic Protocol

### Key Types

| Key | Algorithm | Purpose |
|---|---|---|
| Identity key | Ed25519 (`nacl.sign`) | Signs handshake payloads |
| Ephemeral DH key | X25519 (`nacl.box`) | Handshake key exchange |
| Root + chain keys | HKDF-SHA-256 (`crypto.subtle`) | Double-Ratchet KDFs |
| Message body key | XSalsa20-Poly1305 (`nacl.secretbox`) | Per-message AEAD |

### Handshake

1. Each client generates an Ed25519 identity keypair and an X25519 DH
   keypair.
2. Client A sends `hs` containing a signed payload that covers both its
   `signPk` and `dhPk` together — preventing key-substitution attacks
   on the DH key.
3. Client B verifies the signature, mirrors with a signed `hs_ack`.
4. Both sides compute `nacl.box.before(peerDhPk, mySecretKey)` and feed
   it into HKDF to obtain the initial root key.

The server caches the most recent `hs` / `hs_ack` per peer and replays
them to a newcomer (FIX), so a peer that arrives second cannot be left
without the first peer's handshake.

### Double Ratchet

- `KDF_RK3(RK, DHout)` derives `(newRK, CK1, CK2)` via HKDF.
- `KDF_CK(CK)` derives `(newCK, MK)` via HKDF with a zero-salt.
- Body encryption: `nacl.secretbox(plain, nonce, MK)`.
- Skipped message keys: stored in `MKSKIPPED`, capped at 50 entries.
- Replay: each successful decrypt records `(dh, n)` in `SEEN`; matches
  are rejected before decrypt is attempted.

The KDF parameterisation puts `RK` as IKM and `DHout` as salt. Both
inputs are 256-bit high-entropy, so HKDF's security guarantees hold;
the order differs from the Signal spec for historical reasons. There
is no security impact.

### Header MAC (CP17 / CP21)

Every relayed ciphertext carries a MAC over its header:

- **v1**: `MAC = SHA-256(MK || "key1") || SHA-256( MK || header || nonce || ciphertext || "tag1" )` truncated to 16 bytes.
- **v2**: as v1 but the input also includes `sessionCtx` —
  `SHA-256( sessionCtx, "|hdr:", header, "|nonce:", nonce, "|boxed:", ciphertext )`. The 16-byte tag is a domain-separated truncation.

After verification (`strictAfterTrust`), **v2 is mandatory** — the
fallback path to v1 is gated by `!strictAfterTrust()` and is therefore
unreachable for verified channels.

### Session Context (CP21)

Computed once both sides know each other's keys and the room code:

```
sessionCtx = SHA-256(
  "mm3-cp21-ctx-v1|room:" || room
  || "|sign:" || sort(signPk_A, signPk_B)
  || "|dh:"   || sort(dhPk_A,   dhPk_B)
)
```

The v2 header MAC binds every ciphertext to this context, so a message
captured from one (room, peer-pair, handshake) cannot be replayed into
another.

### Key Confirmation (CP26)

After trust is established, both sides derive a tag from a
domain-separated SHA-256 over `sessionCtx`, the room and the sorted
public-key pair, and exchange it via `type: "kc"`. Until both tags
match, message sending is blocked and incoming chats are buffered into
`pendingPreKcChats` for replay on success.

### Safety Code

```
words = pgp_words(
  SHA-256( sort(signPk_me, signPk_peer) || "mm3-safety-pgp-v1" )[0..7]
)
```

8 PGP words from the standard even/odd word lists. Must be compared
out-of-band (telephone, in person) to prevent MITM.

### Key-Change Hard Lock (CP9)

If the peer's `signPk` differs from the recorded primary contact, the
client enters a hard lock. Messages received during the lock are
**dropped** (counted, not buffered — buffering ciphertext across a
key-change is unsafe and the original buffer was never replayed).
Re-verification clears the lock.

### Ephemeral identity at rest

- The 64-byte Ed25519 secret key is encrypted with `nacl.secretbox`
  using a 32-byte password generated from `nacl.randomBytes`.
- The encrypted blob is written to `sessionStorage`, the password
  lives only in the variable `_sessionPass`.
- On `ws.close`, `deleteIdentity()` zeroes the password and removes
  the blob, then `location.reload()` discards JS state.
- A page reload loses the password and therefore the identity.
  The next page load mints a fresh keypair; existing peers see this
  as a key change and re-verification is required.

---

## Server Protocol

### Message Types

| Type | Direction | Description |
|---|---|---|
| `join` | C → S | Join a room (no token required) |
| `joined` | S → C | Room joined, includes server-issued token |
| `join_denied` | S → C | Reason: `bad_room_code`, `room_locked`, `room_dead`, `rate_limited` |
| `peer_joined` | S → C | Second peer entered |
| `hs` | C → S → C | Handshake (relayed; signed payload) |
| `hs_ack` | C → S → C | Handshake ack (relayed; signed payload) |
| `kc` | C → S → C | Key Confirmation tag (relayed) |
| `chat` | C → S → C | Encrypted message (relayed) |
| `auth_failed` | S → C | `token_missing` or `token_mismatch` |
| `rate_limited` | S → C | Per-connection rate limit hit |
| `room_dead` | S → C | Room has been tombstoned |

### Server-relayed payload whitelist

For `hs` / `hs_ack` / `kc` / `chat` the relay forwards **only**:

```
{ type, from, header, payload, v, ctx, tag }
```

`from` is truncated to 64 bytes. `token` is consumed by the server and
**never** relayed. All other fields are silently dropped.

### Room Lifecycle

- Rooms lock to 1:1 once two peers have joined (CP36).
- Any peer leaving after the room has held two peers permanently
  tombstones the room (CP38).
- A first lone peer leaving before a second peer joins also tombstones
  the room (CP39).
- Tombstoned codes cannot be re-used until the relay restarts (no TTL
  by default).
- A server-issued token is required for every non-`join` message
  (CP37); a missing or mismatching token returns `auth_failed`.

### Rate limits

- Per-connection: 50 messages / s, 50 KB / s, with a `rate_limited`
  notice on breach.
- Per-IP: 5 simultaneous connections, 10 joins per 60-second window
  (configurable; see `SECURITY.md`).
- WebSocket frame cap: 32 KiB — oversized frames close the connection.

### WebSocket upgrade

The relay accepts WebSocket upgrades **only** at `/`, `/ws`, and `/ws/`.
Other paths return `400 Bad Request` at the socket — opportunistic
scanners that probe arbitrary URLs do not get an upgraded socket and
therefore do not consume room state or rate-limit budget.

### Token comparison

`validateToken()` compares the client-supplied room token against the
server-issued token using `crypto.timingSafeEqual` after an explicit
length check. The compare runs in constant time relative to the token
content; the length pre-check rejects mismatched lengths without
touching crypto. This removes a theoretical timing oracle that even
TLS jitter only partially masks.

### Static handler

- Path traversal: `decodeURIComponent` → `path.resolve(PUBLIC_DIR, …)`
  → prefix-check.
- Only files with extensions `.html .js .css .svg .ico .png .jpg .jpeg
  .woff .woff2` are served. Anything else returns 404.
- Methods other than `GET` / `HEAD` return 405.
- Security headers are set on every response (see top of this file).
- The CSP allows `'unsafe-inline'` for `style-src` because the design
  ships as an inline `<style>` block in `index.html`. No script CSP
  exceptions; no remote `script-src` or `connect-src` other than
  `'self'` and `ws://` / `wss://`.
- `Permissions-Policy` explicitly disables every powerful-feature API
  the app does not need: geolocation, camera, microphone, payment, usb,
  hid, serial, midi, accelerometer / gyroscope / magnetometer,
  display-capture, screen-wake-lock, idle-detection,
  publickey-credentials-get, picture-in-picture, autoplay, fullscreen,
  xr-spatial-tracking, plus the prior interest-cohort / browsing-topics
  pair. Listing these explicitly stops future regressions if an
  imported third-party file ever asked for one of them.

---

## Client Hardening

- All user-controlled and peer-controlled strings flow into the DOM
  via `textContent` only. No `innerHTML`, `eval`, or `Function`.
- All randomness uses `crypto.getRandomValues` via
  `secureRandomBytes` / `secureRandomInt`. `Math.random` is not used
  anywhere in the cryptographic or session code paths.
- Trust state is "hard-locked" the instant the peer fingerprint
  changes; messages received during the lock are dropped (counted,
  not buffered).
- Backup / Restore of the identity is intentionally disabled — the
  ephemeral-identity model relies on the identity not surviving a
  session.
- The WS URL field defaults to the **same origin** the page was served
  from (`${ws|wss}://${location.host}/ws`). The HTML retains the
  reference `wss://quadrama.ch/ws` value as a no-JS fallback only —
  the moment `app.js` boots, it rewrites the field. A self-host user
  therefore does not accidentally connect to the reference public
  relay by clicking **Connect** without editing the field. The field
  remains fully editable for users who want to point the client at
  a different relay.

---

## Infrastructure expectations

The relay is designed to sit behind a reverse proxy that provides TLS,
HSTS, and additional rate limiting. The relay's own behaviour is
**also** safe to expose directly, with the caveat that:

- `X-Real-IP` / `X-Forwarded-For` are *ignored* unless
  `QUADRAMA_TRUST_PROXY=1` is set.
- Origin enforcement is disabled unless `QUADRAMA_ALLOWED_ORIGINS` is
  set.

The reference deployment is `quadrama.ch`, served from a Swiss-hosted
virtual server (Hosttech AG) over TLS 1.2 / 1.3 with HSTS, behind Nginx.

---

## Known Limitations

- Tombstones live in memory — lost on restart (intentional; pull-based
  garbage collection is preferred to a persistent state file).
- No multi-device support.
- No file transfer.
- No group chat.
- No external security audit to date. The in-tree review (see
  `docs/AUDIT_SUMMARY.md`) is internal and is **not** a substitute for
  third-party cryptographic review.
- The Quadrama relay process emits no logs by default; an operator
  enabling `QUADRAMA_VERBOSE=1` will surface IPs and room codes in
  stdout. The hosting provider's TLS layer may keep short-term access
  logs; that is documented on the Datenschutz page.

---

For security vulnerabilities, see `../SECURITY.md`.
For threats and assumptions, see `THREAT_MODEL.md`.
For test coverage and the internal audit summary, see
`AUDIT_SUMMARY.md`.
