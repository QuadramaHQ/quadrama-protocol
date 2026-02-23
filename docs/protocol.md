# Quadrama Protocol (High-Level Overview)

This document describes the public, high-level design of the Quadrama messaging protocol.

Implementation details, internal state machines, and parameter values are intentionally omitted.

---

## 1. Goals

Quadrama is designed to provide:

- End-to-end encrypted 1:1 communication
- Authenticated key agreement between peers
- Forward secrecy
- Post-compromise security (ratcheting)
- Replay protection
- User-verifiable identity binding
- Strict validation after trust establishment

The relay server is considered untrusted.

---

## 2. Architecture

Quadrama follows a client-to-client encryption model.

- Clients establish a shared secret using authenticated key exchange.
- After key agreement, all messages are encrypted and authenticated.
- The relay server only forwards opaque ciphertext.
- The server does not possess session keys.

The protocol is transport-agnostic. Current deployments use WebSockets as a relay channel.

---

## 3. Handshake Phase

During session initialization:

1. Each client generates ephemeral key material.
2. An authenticated key exchange establishes shared session secrets.
3. A verification phase binds the session to user identities.
4. Once verification is complete, strict validation rules are enforced.

After successful key agreement, message ratcheting begins.

---

## 4. Message Protection

All application messages are:

- Encrypted
- Authenticated
- Bound to the current session context

Messages that fail authentication or session validation are rejected.

---

## 5. Ratcheting

Quadrama uses a ratcheting mechanism to ensure:

- Forward secrecy (past messages remain secure if keys are compromised)
- Post-compromise recovery (future messages become secure again after new key exchange)

Exact ratchet internals are implementation details.

---

## 6. Identity Verification

Users may compare a short “Safety Code” out-of-band.

After manual verification:

- Strict validation is activated
- Downgrade attempts are rejected
- Session binding becomes mandatory

If a peer’s identity key changes, verification is automatically removed.

---

## 7. Replay and Ordering

Quadrama includes replay protection mechanisms.

Replayed, duplicated, or malformed messages are rejected.

Handling of out-of-order messages is implementation-specific.

---

## 8. Security Philosophy

Quadrama follows a minimal exposure approach:

- Public documentation explains security goals and principles.
- Sensitive implementation details are not publicly disclosed.
- Clients enforce strict validation after trust is established.

---

This document describes the conceptual design only.
It is not a formal cryptographic specification.
