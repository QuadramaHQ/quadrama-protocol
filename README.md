# Quadrama

Quadrama is a secure 1:1 messaging protocol designed for end-to-end encrypted communication over an untrusted relay.

The system focuses on strong cryptographic guarantees, minimal exposure, and user-verifiable identity binding.

---

## Security at a Glance

- End-to-end encryption (E2EE)
- Authenticated key exchange
- Forward secrecy
- Post-compromise security (ratcheting)
- Replay protection
- User-verifiable safety codes
- Strict validation after verification

The relay server cannot access plaintext messages.

---

## Documentation

High-level protocol overview:
- [`docs/protocol.md`](docs/protocol.md)

Replay protection overview:
- [`docs/replay-protection.md`](docs/replay-protection.md)

Threat model:
- [`THREAT_MODEL.md`](THREAT_MODEL.md)

Security reporting:
- [`SECURITY.md`](SECURITY.md)

---

## Design Philosophy

Quadrama intentionally exposes only high-level protocol information publicly.

Implementation details, internal hardening logic, and security parameters are not part of the public specification.

---

© Quadrama
