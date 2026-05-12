# Quadrama

**Private. Secure. Simple.**

Quadrama is a free, open-source 1:1 end-to-end encrypted messenger that
runs entirely in the browser. No account, no phone number, no chat
history on the server.

Live demo: **<https://quadrama.ch>**

---

## Features

- **No account, no phone number, no cookies.** Open the page and start.
- **End-to-end encryption in the browser.** The relay only forwards
  opaque ciphertext.
- **No message storage.** The server is a pure relay; nothing persists.
- **Strict 1:1 rooms.** A third joiner is denied; rooms tombstone on
  leave.
- **No third-party fetches.** The page is self-contained — no CDN, no
  fonts service, no analytics.
- **Safety Code (8 PGP words)** so peers can verify each other
  out-of-band against a man-in-the-middle.
- **Open source — AGPL-3.0.** Audit it, fork it, self-host it.

---

## Security model in one paragraph

Identity is an ephemeral Ed25519 keypair, generated per browser tab and
encrypted at rest in `sessionStorage` with a random password held only
in RAM. Handshake exchanges X25519 keys; both parties feed the ECDH
result into HKDF-SHA-256 to seed a Double Ratchet. Message bodies are
sealed with XSalsa20-Poly1305; every ciphertext carries a SHA-256
header MAC bound to a session context (room code + sorted public keys)
so a frame from one (room, peer-pair) cannot be replayed into another.
After verification, both sides exchange Key Confirmation tags; until
both match the channel is not "established". Closing the tab wipes the
identity.

What the server **sees**: opaque WebSocket frames whose `{type, from,
header, payload, v, ctx, tag}` fields are forwarded blindly.
What the server **does not see**: plaintext, private keys, recovered
identities, message contents.

---

## Quick start

Run the relay locally:

```bash
git clone https://github.com/QuadramaHQ/quadrama-protocol.git
cd quadrama-protocol
npm install
node server.js          # then open http://127.0.0.1:8080/
```

### Tests

```bash
npm test                # 30 tests, ~3 s
npm audit --omit=dev    # 0 production vulnerabilities
```

### Operator hardening (optional)

`QUADRAMA_TRUST_PROXY=1` to honour `X-Real-IP`,
`QUADRAMA_ALLOWED_ORIGINS="https://example.com"` to lock the WebSocket
to a fixed origin, `QUADRAMA_VERBOSE=1` to enable diagnostic logging
(off by default). Details in [`SECURITY.md`](SECURITY.md).

---

## Documentation

- [`docs/TECHNICAL.md`](docs/TECHNICAL.md) — protocol, KDFs, headers,
  room lifecycle.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, adversaries,
  what Quadrama defends against and what it does not.
- [`docs/AUDIT_SUMMARY.md`](docs/AUDIT_SUMMARY.md) — internal review
  results, test coverage, live data-leak canary, known limitations.
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to send a patch.

---

## License

[AGPL-3.0](LICENSE). You are free to use, study, modify, and
redistribute the software under the terms of the licence.

---

*Quadrama is an independent open-source project. It is not affiliated
with any company or commercial service.*
