# Quadrama — Threat Model

This document captures who Quadrama defends against, what it defends, and
the limits of those defences. It is intentionally narrow: Quadrama is a
1:1 ephemeral browser messenger, not a Signal replacement.

## 1. Assets

| Asset | Value |
|---|---|
| Plaintext message bodies (current + past) | High |
| Long-term identity public keys (`signPk`) | Medium (linkability across sessions if reused) |
| Local primary-contact record + key-history (`localStorage`) | Low (per-device, never leaves the browser) |
| Encrypted identity secret (`sessionStorage`, per-tab, RAM-only password) | Medium |
| Room codes (short-lived, secret until exchanged) | Medium |
| Server uptime | Low (relay is fungible — self-hostable) |
| User network metadata (IP, timing) | Out-of-scope at the network layer |

## 2. Adversaries considered

### A1. Passive network observer (between client and server)
Sees TLS-wrapped traffic only. Can observe **timing and frame sizes**;
Quadrama mitigates with padded buckets, chunking, jittered cover traffic
(opt-in, on after trust + KC). Cannot read plaintext or keys.

### A2. Active network attacker
Can drop, reorder, or attempt to inject frames on the TLS channel — the
TLS layer defeats injection. At the application layer:
- The Double-Ratchet header MAC (v2) binds every ciphertext to a session
  context derived from `(room, sorted-signPk-pair, sorted-dhPk-pair)`.
- Replay is rejected by the `SEEN` set per `(dh, n)`.
- Cross-room or cross-session ciphertext fails the v2 MAC.

### A3. Malicious or compromised server (Quadrama relay)
Sees opaque blobs (`type`, `from`, `header`, `payload`, `v`, `ctx`,
`tag`). The Whitelist in `server.js` permits **only** those fields to
flow between peers; `token` is consumed by the server and never relayed.

Cannot:
- Decrypt messages (no symmetric or asymmetric secret reaches the
  server).
- Substitute peer keys without breaking the Ed25519 signature in
  `hs` / `hs_ack` (the signed payload covers both `signPk` and `dhPk`).
- Pretend to be the peer — the Safety Code (8 PGP words over
  `sort(signPk_a, signPk_b)`) will mismatch.
- Replay a `peer_joined` to admit a third peer — rooms lock to 1:1 on
  the *second* successful join, and tombstone permanently on any
  subsequent leave.

Can:
- Drop connections (denial of service).
- Refuse to relay (denial of service).
- Learn that a connection happened, the room code, and the size /
  timing of relayed frames if it inspects its own memory. The relay
  process does **not** log these by default — `QUADRAMA_VERBOSE` opts
  the operator in.

### A4. Attacker with browser-tab JS access
Owns the page. All cryptographic state is in memory. There is no
defence here — if you can run JS in the tab, you can extract keys.
This is true for every browser messenger; Quadrama is no exception.

### A5. Attacker with later access to the *device*
- `sessionStorage` ephemeral identity: encrypted with a 32-byte
  random password held only in RAM. After the tab is closed or the
  WebSocket disconnects, the password is wiped, the encrypted blob
  becomes unrecoverable.
- `localStorage` primary contact + key-history: present until
  "Factory Reset" is invoked. A device-level attacker (forensics)
  can read it; this trades a small privacy footprint for the
  ability to detect peer-key changes between sessions (the core
  of Quadrama's key-transparency UX).

### A6. Other clients on the same room
Constrained by the protocol: there can only be two peers in a room,
the room is one-shot, and both must complete the signed handshake.
A malicious peer can lie about what *their* user typed, but cannot
read another room's traffic or impersonate the user's claimed
identity to a third party.

### A7. Off-path key-substitution attempt
Mitigated by the **Safety Code**. If users compare PGP words
out-of-band and both see the same 8 words, no MITM can be active.
The UI marks trust with a hard lock when the peer's `signPk`
changes; re-verification is required.

## 3. Out-of-scope threats

The following are explicitly **not** defended against:

- Endpoint compromise (malicious extensions, OS-level keyloggers).
- Side-channel attacks (cache timing, microarchitectural).
- Network metadata correlation (Tor / similar tooling is the user's
  responsibility).
- Sustained DoS at the TLS layer (the operator must deploy
  rate-limiting + capacity at the reverse proxy).
- Loss of the encrypted ephemeral identity due to a reload. This is by
  design: every reload yields a new identity; existing peers see this
  as a key-change and re-verification is required.
- Group chat, multi-device, file transfer — these features simply do
  not exist.

## 4. Invariants

The audit verified that the following invariants hold in code, not just
in documentation:

1. The server's relay function whitelists exactly seven fields and never
   surfaces the room token to a peer.
2. The server never reads, parses, or stores `payload` content.
3. The server's static handler refuses to serve files outside
   `public/`, refuses non-GET methods, refuses unknown extensions.
4. The static handler sets a strict baseline of security headers
   regardless of whether a reverse proxy adds more.
5. The WS server caps a single frame at 32 KiB.
6. Per-IP join rate (default 10/min) and simultaneous connections
   (default 5) are enforced.
7. A third peer attempting to join a locked room is denied with
   `reason: "room_locked"`.
8. After either peer leaves a room that ever had two members, the room
   is tombstoned and the same code cannot be reused until restart.
9. After a lone first peer leaves, the room is tombstoned identically.
10. Trust is "hard-locked" the instant the peer fingerprint changes,
    requiring an explicit user-driven re-verify; messages received
    while locked are *dropped* (counted, not buffered).
11. After verification, only the v2 Header-MAC (with Session-Context)
    is accepted; the v1 fallback is unreachable.
12. After verification, the channel is only deemed "established" once
    Key Confirmation tags match on both sides.

Tests in `tests/` cover invariants 1, 2, 3, 4, 5, 6, 7, 8, 9 directly.
Invariants 10, 11, 12 are exercised end-to-end in the browser; their
*code paths* were read line by line during the internal review (see
`AUDIT_SUMMARY.md`).

## 5. Residual risks (accepted)

1. **IP rate-limit collapse under NAT.** With `QUADRAMA_TRUST_PROXY=0`
   (default), all clients sharing a TCP source IP share one rate-limit
   bucket. A noisy NAT'd peer can exhaust the bucket for everyone on
   that network. Mitigation: deploy behind a reverse proxy that sets a
   trustworthy `X-Real-IP` and enable `QUADRAMA_TRUST_PROXY=1`.

2. **In-browser memory pressure from a malicious peer.** Even after the
   `MAX_SKIPPED_TOTAL = 1000` cap (F-23), an authenticated peer can
   still cause the *receive side* of the ratchet to do work proportional
   to the number of DH ratchet steps they send. This is bounded by the
   server's per-connection rate limit (50 msg/s, 50 KB/s) and by the
   user's ability to disconnect.

3. **Ephemeral identity loss on network blip.** `ws.onclose` triggers
   `location.reload()` and wipes the in-RAM password protecting the
   encrypted-at-rest identity in `sessionStorage`. This is intentional;
   peers must re-verify after any reload. Users on flaky networks see
   it as harsh.

4. **`'unsafe-inline'` in `style-src`.** `index.html` carries its design
   as a large inline `<style>` block. Removing `'unsafe-inline'` would
   require either externalising the stylesheet or hashing each inline
   block; both are tracked as future work but not required for the
   security model (no JS executes from styles in modern browsers when
   `script-src 'self'` is set and no `expression()`-style legacy
   constructs are used).
