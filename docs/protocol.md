# Protocol Overview – Quadrama

This document describes the Quadrama end-to-end encrypted messaging
protocol at a conceptual level.

It is intended for transparency, security review, and technical discussion.
Implementation-specific details are deliberately omitted.

---

## 1. Overview

Quadrama is an asynchronous end-to-end encrypted messaging system designed
for operation in hostile network environments.

Primary goals include:

- Confidentiality of message contents
- Forward secrecy and post-compromise security
- Integrity and authenticity of messages
- Resistance to replay and downgrade attacks
- Clear separation of sessions and communication channels

The protocol assumes an attacker capable of observing, delaying,
reordering, replaying, and modifying network traffic.

---

## 2. Identities and Key Material

Each client maintains the following cryptographic material:

- A long-term identity key
- Ephemeral session keys
- Ratchet-derived message keys

Long-term identity keys are used exclusively for authentication
and trust establishment.

Message encryption is never performed directly using long-term keys.

---

## 3. Session Establishment (Conceptual Handshake)

The establishment of a new session follows these high-level steps:

1. Exchange of public identity information
2. Ephemeral key agreement for session creation
3. Derivation of shared secrets
4. Initialization of ratchet state

The handshake is designed such that:

- Compromise of past sessions does not affect new sessions
- Key material is not reused across sessions
- Future key compromise does not reveal past message contents

---

## 4. Message Encryption and Authentication

Each message is processed as follows:

- A fresh encryption key is derived from the ratchet state
- The message is encrypted using authenticated encryption
- Ciphertexts are bound to their session and channel context

This ensures that:

- Only intended recipients can decrypt messages
- Message tampering is detected
- Messages cannot be replayed across sessions or channels

---

## 5. Replay Protection

Protocol state is updated only **after successful message
authentication and decryption**.

This prevents:

- State advancement from invalid or replayed ciphertexts
- Replay cascades caused by packet reordering
- Ratchet desynchronization attacks

---

## 6. Key Confirmation and Trust Gating

Key confirmation is performed only after explicit trust establishment.

Once trust is established:

- Downgrade paths are disabled
- Legacy or fallback protocol modes are no longer accepted
- All messages must satisfy strict authentication requirements

This design prevents silent downgrade or reflection attacks
after a trust relationship is formed.

---

## 7. Session and Channel Binding

All encrypted messages are cryptographically bound to:

- A specific session
- A specific communication channel

This binding prevents cross-session and cross-channel
message injection and confusion attacks.

---

## 8. Metadata Considerations

While message contents are protected end-to-end, certain metadata
cannot be fully eliminated.

The protocol incorporates mitigations such as:

- Message padding
- Controlled message sizing
- Optional cover traffic mechanisms

Trade-offs between latency, bandwidth usage, and metadata protection
are explicitly acknowledged.

---

## 9. Non-Goals

The protocol does NOT aim to provide:

- Anonymity against global passive adversaries
- Resistance to nation-state scale traffic correlation
- Protection against compromised endpoints
- Defense against denial-of-service attacks

---

## 10. Scope and Limitations

This document describes protocol concepts only.

It does not grant authorization to test, probe, or attack
any live Quadrama systems or user accounts.

Security testing of production systems requires explicit
written permission.
