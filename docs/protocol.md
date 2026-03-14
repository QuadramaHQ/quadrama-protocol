# Quadrama Protocol (High-Level Overview)

This document describes the public, high-level design of the Quadrama messaging protocol.

Implementation details, internal state machines, and specific parameter values are intentionally omitted.

---

## 1. Goals

Quadrama is designed to provide:

- **End-to-end encrypted** 1:1 communication  
- **Authenticated key agreement** between peers  
- **Forward secrecy** – past messages remain secure even if keys are later compromised  
- **Post-compromise security** – future messages become secure again after new key material is exchanged  
- **Replay protection**  
- **User-verifiable identity binding** via out-of-band Safety Codes  
- **Strict validation** after trust has been established  

The relay server is considered **untrusted** at all times.

---

## 2. Architecture

Quadrama follows a client-to-client encryption model:

- Clients establish a shared secret using authenticated key exchange  
- After key agreement, all messages are encrypted and authenticated  
- The relay server only forwards opaque ciphertext  
- The server never possesses session keys or decryption material  
- The protocol is transport-agnostic – current deployments use WebSockets as a relay channel

---

## 3. Handshake Phase

During session initialization:

- Each client generates ephemeral key material  
- An authenticated key exchange establishes shared session secrets  
- A verification phase binds the session to user identities  
- Once verification is complete, strict validation rules are enforced  
- After successful key agreement, message ratcheting begins

---

## 4. Message Protection

All application messages are:

- **Encrypted**  
- **Authenticated**  
- **Bound to the current session context**  

Messages that fail authentication or session validation are rejected without further processing.

---

## 5. Ratcheting

Quadrama uses a ratcheting mechanism to ensure:

- **Forward secrecy** – compromise of current keys does not reveal past messages  
- **Post-compromise recovery** – future messages become secure again after new key material is introduced  

Exact ratchet internals are implementation-specific and not publicly documented.

---

## 6. Identity Verification

Users may compare a short **Safety Code** out-of-band (e.g., in person or via a trusted channel).

After manual verification:

- Strict validation rules are activated  
- Protocol downgrade attempts are rejected  
- Session binding becomes mandatory  
- If a peer’s identity key ever changes, verification is automatically removed

---

## 7. Replay and Ordering

Quadrama includes replay protection mechanisms:

- Replayed, duplicated, or malformed messages are rejected  
- Handling of out-of-order messages is implementation-specific and does not affect security guarantees

---

## 8. Security Philosophy

Quadrama follows a **minimal exposure** approach:

- Public documentation explains **security goals and principles**  
- Sensitive implementation details are **not publicly disclosed**  
- Clients enforce **strict validation after trust is established**  

---

*This document describes the conceptual design only. It is not a formal cryptographic specification.*
