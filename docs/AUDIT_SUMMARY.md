# Quadrama — Audit Summary

This document summarises the internal review of Quadrama against its
documented security and privacy claims. It is **not** a substitute for
a formal third-party cryptographic audit. The full underlying review
material is kept in the project's working notes and is not published;
this summary distils the load-bearing results.

## 1. Scope

| Area | What was reviewed |
|---|---|
| Relay server | `server.js`: WebSocket lifecycle, field-whitelist, 1:1 lock + tombstones, per-IP and per-connection rate limits, static handler, security headers, log policy. |
| Browser client | `public/app.js`: identity generation, handshake, Double Ratchet, Header-MAC v2, Session-Context, Key Confirmation, Safety Code, replay protection, key-change hard lock, DOM safety (no `innerHTML`, `eval`, `Function`). |
| Browser storage | What is written to `localStorage` / `sessionStorage`; lifetime of the in-RAM key; behaviour on tab close / reload. |
| Shipped HTML | `public/index.html` (CSP, SRI, inline-style policy), `public/datenschutz.html`, `public/impressum.html`. |
| Tests | `tests/*.js` — relay invariants, room lifecycle, rate limits, static-handler hardening, protocol negatives. |
| Dependencies | `npm audit` baseline; vendored `tweetnacl.min.js` pinned by SRI. |

## 2. Cryptographic primitives in use

| Purpose | Algorithm | Implementation |
|---|---|---|
| Identity signing | Ed25519 | `nacl.sign` |
| Handshake key agreement | X25519 | `nacl.box` |
| Root + chain key derivation | HKDF-SHA-256 | Web Crypto (`crypto.subtle`) |
| Message body AEAD | XSalsa20-Poly1305 | `nacl.secretbox` |
| Header MAC (v2) | SHA-256 over Session-Context, header, nonce, ciphertext | Web Crypto |
| Safety Code | 8 PGP words derived from sorted identity pair + domain tag | `public/app.js` |

The Double Ratchet uses a KDF parameterisation where `RK` is HKDF
input keying material and `DHout` is the salt. Both inputs are
256-bit high-entropy; HKDF's security guarantees hold. The ordering
differs from the Signal specification for historical reasons; there
is no security impact.

## 3. Findings — what holds

| Claim on the live site | Verification |
|---|---|
| No account, no phone number, no cookies | No login UI; `Set-Cookie` is never set; `document.cookie` is never written. |
| Server only forwards, stores no chat history | The relay's whitelist for relayed frames is `{ type, from, header, payload, v, ctx, tag }`; nothing else is forwarded. No disk write of payload occurs. |
| End-to-end encryption in the browser | All cryptographic operations execute in the client; the relay only sees opaque ciphertext + headers. |
| Strict 1:1 rooms | The third joiner is denied with `room_locked`; both single-leave (CP39) and post-pair-leave (CP38) tombstone the room. |
| Server-issued token | Every non-`join` message validates against a server-issued room token using `crypto.timingSafeEqual`; tokens are never relayed to peers. |
| Identity is ephemeral | The Ed25519 secret key is held only inside an encrypted `sessionStorage` blob with the password kept in RAM. On `ws.close`, the password is wiped and the page reloads. |
| Safety Code (8 PGP words) | Derived from `SHA-256(sort(signPk_me, signPk_peer) ‖ domain-tag)`. Must be compared out-of-band. |
| Strict-after-trust | After verification, Header-MAC v2 (with Session-Context) is required; v1 fallback is gated off. |
| Key Confirmation | After trust is set, the channel is not "established" until both KC tags derived from Session-Context match. |
| Key-change hard lock | Any change in peer fingerprint triggers a hard lock; ciphertext received while locked is **dropped**, not buffered (the original buffer was unsafe and was removed). |

## 4. Findings — what was changed during review

| Issue | Fix |
|---|---|
| Third-party CDN fetch (Font Awesome via cdnjs) | Replaced by an inline SVG icon sprite; the page is now fully self-contained. |
| `Math.random()` in session / room-code paths | Migrated to `crypto.getRandomValues` via `secureRandomBytes` / `secureRandomInt`. |
| Spoofable `X-Real-IP` and unknown-IP bypass | Trusted only when `QUADRAMA_TRUST_PROXY=1`; unknown-IP clients are still rate-limited. |
| Missing WebSocket `maxPayload` | Hard cap at 32 KiB. |
| Static handler hardening | `path.resolve` + prefix check; method allow-list; extension allow-list. |
| Security headers shipped server-side | CSP, HSTS-compatible defaults, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-*-Policy`, `Cache-Control: no-store` on HTML. |
| Subresource Integrity | Every shipped script (`app.js`, `i18n.js`, `tweetnacl.min.js`) has an `integrity=` attribute that matches the on-disk file. |
| Quiet-by-default logging | `vlog()` gates every per-IP / per-room log line behind `QUADRAMA_VERBOSE=1`. |
| Token comparison timing | `crypto.timingSafeEqual` with an explicit length pre-check. |
| WebSocket Origin allow-list | Optional via `QUADRAMA_ALLOWED_ORIGINS`. |
| Privacy / imprint pages | Now factually accurate: no false "cookies for login", correct hosting provider, no jargon on the legal page. |

## 5. Test posture

Test runner: `node --test`. Six test files, **30 / 30 tests pass**.

| File | Verifies |
|---|---|
| `tests/proto.test.js` | Field whitelist on relayed frames; rejection of malformed `join`; token enforcement on non-`join`; oversized frame rejection. |
| `tests/room.test.js` | 1:1 lock; third-joiner denial; tombstoning on leave (both branches); rejoin denial after tombstone. |
| `tests/ratelimit.test.js` | Per-IP join limit; per-connection message-rate limit; reconnect resets counters. |
| `tests/static.test.js` | HTML served with security headers; path traversal rejected; unknown extensions returned as 404; non-GET methods returned as 405. |
| `tests/extra.test.js` | Origin allow-list when configured; static cache-policy on HTML; misc protocol edge cases. |
| `tests/helpers.js` | Shared boot/teardown helpers. |

`npm audit --omit=dev` reports **0 vulnerabilities**.

## 6. Live observational test (data-leak canary)

A live end-to-end test was run against the deployed instance:

1. A unique 71-byte canary string was sent as a chat message between
   two browser tabs that had completed the full handshake + KC flow.
2. All WebSocket frames in both directions were captured.
3. The canary appeared in **zero of 27 captured frames** in plaintext
   or any of five plausible obfuscation variants.
4. A filesystem and journal grep on the relay turned up **zero**
   occurrences of the canary anywhere the relay process can write.

Conclusion: the relay cannot observe message content under normal
operation.

## 7. Hosting

The reference deployment runs in Switzerland on a Hosttech AG
virtual server, behind Nginx with TLS 1.2 / 1.3 (Let's Encrypt) and
HSTS. The relay's own `access_log` is disabled at the proxy layer
and the Node process emits no per-connection logs by default. The
hosting provider's TLS layer may keep short-term access data; this
is acknowledged on the user-facing Datenschutz page.

Self-hosters are not subject to this configuration. The
`SECURITY.md` operator guide lists the relevant environment flags.

## 8. Known limitations (not audited / out of scope)

- No formal external cryptographic audit has been performed.
- A malicious browser extension or device-level malware can defeat
  any browser messenger and is out of scope.
- Quadrama is not metadata-anonymous: the relay (and any TLS-layer
  proxy in front of it) can observe that a connection happened, plus
  the size and timing of frames. Tor or similar tooling is the user's
  responsibility.
- No multi-device support, no group chat, no file transfer, no
  offline messages — deliberately.
- A page reload destroys identity. This is a feature of the
  ephemeral-identity model, not a bug.

## 9. Reproducing the tests

```
git clone https://github.com/QuadramaHQ/quadrama-protocol.git
cd quadrama-protocol
npm install
npm test
npm audit --omit=dev
```

To verify SRI on the shipped scripts:

```
openssl dgst -sha384 -binary public/app.js          | openssl base64 -A
openssl dgst -sha256 -binary public/i18n.js         | openssl base64 -A
openssl dgst -sha256 -binary public/tweetnacl.min.js | openssl base64 -A
```

The resulting strings must match the `integrity=` attributes in
`public/index.html`.

---

For deeper protocol detail see `TECHNICAL.md`. For the threat model
see `THREAT_MODEL.md`. To report a vulnerability see `../SECURITY.md`.
