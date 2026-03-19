# Quadrama — Technical Documentation

This document is intended for developers and security researchers who want to understand the internals of Quadrama.

---

## Architecture

Quadrama consists of two components:

**Server (server.js)**
- Node.js with the ws library
- Pure WebSocket relay — no database, no message storage, no logging
- Manages rooms, tokens, and connection state only
- Served behind Nginx with TLS

**Client (public/app.js)**
- Vanilla JavaScript — no framework, no build step
- All cryptography runs in the browser via tweetnacl + Web Crypto API
- Monolithic file for simplicity and auditability

---

## Cryptographic Protocol

### Key Types

| Key | Algorithm | Purpose |
|---|---|---|
| Identity key | Ed25519 (nacl.sign) | Signs handshake payloads |
| Ephemeral DH key | X25519 (nacl.box) | Handshake key exchange |
| Session keys | Derived via HKDF | Message encryption |

### Handshake

1. Each client generates an Ed25519 identity keypair and an X25519 DH keypair
2. Client A sends hs: signPk + dhPk signed with its identity key
3. Client B verifies the signature and responds with hs_ack
4. Both derive the shared secret: nacl.box.before(peerDhPk, myDhKp.secretKey)
5. Initial root key derived via HKDF from the shared secret

### Double Ratchet

Quadrama implements the Double Ratchet algorithm with:

- KDF_RK3: HKDF(RK, DHout) produces new RK, CK1, CK2 (RFC 5869)
- KDF_CK: HKDF(CK, zero_salt) produces new CK and MK (RFC 5869)
- Encryption: NaCl secretbox (XSalsa20-Poly1305)
- Skipped message keys: stored in MKSKIPPED map, max 50
- Replay protection: SEEN set per session

### Header MAC (CP17/CP21)

Every message includes a MAC over the header:

- v1: HMAC-SHA256(MK, header || nonce || ciphertext)
- v2: HMAC-SHA256(MK, sessionCtx || header || nonce || ciphertext)

After verification (strictAfterTrust), v2 is mandatory — no downgrade.

### Key Confirmation (CP26)

After trust is established, both clients derive a KC tag from the session transcript and exchange it. The secure channel is only considered established after successful KC verification.

### Safety Code

8 PGP words derived from SHA-256(sort(mySignPk, peerSignPk) || domain).
Must be compared out-of-band to prevent MITM attacks.

---

## Server Protocol

### Message Types

| Type | Direction | Description |
|---|---|---|
| join | Client to Server | Join a room |
| joined | Server to Client | Room joined, includes token |
| join_denied | Server to Client | Join refused |
| peer_joined | Server to Client | Second peer entered the room |
| hs | Relayed | Handshake |
| hs_ack | Relayed | Handshake acknowledgement |
| kc | Relayed | Key confirmation |
| chat | Relayed | Encrypted message |
| room_dead | Server to Client | Room has been tombstoned |

### Room Lifecycle

- Rooms are locked to 1:1 after two peers join (CP36)
- Any peer leaving permanently kills the room (CP38/CP39)
- Dead rooms are tombstoned — the same code can never be reused
- Room token required for all messages after join (CP37)

### Rate Limiting

- Per-connection: 50 messages/s, 50KB/s (CP36)
- Per-IP: max 5 simultaneous connections, max 10 joins/min (CP40)

---

## Security Hardening

### Client
- Private key encrypted in sessionStorage with random 32-byte password stored in RAM only
- Key deleted on disconnect
- No key backup or restore
- Hard lock on key change — requires re-verification (CP9)
- Strict mode after trust — no fallback, no downgrade (CP24)

### Server
- Runs as unprivileged user messenger
- systemd with NoNewPrivileges=true
- No access logs

### Infrastructure
- TLS 1.2/1.3 only
- HSTS with preload
- CSP without unsafe-inline
- Subresource Integrity (SRI) for all scripts
- X-Frame-Options: DENY
- X-Permitted-Cross-Domain-Policies: none

---

## Known Limitations

- Tombstones are stored in memory — lost on server restart
- No multi-device support
- No file transfer
- No group chat
- No external security audit to date

---

For security vulnerabilities, see SECURITY.md.
