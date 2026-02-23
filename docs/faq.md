# Frequently Asked Questions (FAQ)

## What is Quadrama?

Quadrama is a secure 1:1 messaging protocol designed for end-to-end encrypted communication over an untrusted relay server.

---

## Can the server read my messages?

No.

Messages are encrypted end-to-end between clients.
The relay server only forwards encrypted data and does not possess session keys.

---

## What is a Safety Code?

The Safety Code is a short representation of the cryptographic identity binding between two peers.

By comparing the Safety Code out-of-band (e.g., in person or via a trusted channel), users can verify that no active attacker is intercepting the connection.

---

## What does “Verify” mean?

When you verify a peer:

- The client enforces strict validation rules.
- Downgrade attempts are rejected.
- Session binding becomes mandatory.

If the peer’s identity key changes, verification is automatically removed.

---

## What happens if a peer’s key changes?

If a peer’s identity key changes:

- Previous verification is invalidated.
- The session must be re-verified.

This protects against identity substitution attacks.

---

## Does Quadrama protect against malware?

No.

Quadrama does not protect against:

- Malware on your device
- Keyloggers
- Compromised operating systems
- Browser-level code injection

Security depends on a trusted client environment.

---

## Is Quadrama anonymous?

Quadrama focuses on encryption and session security.

It does not provide anonymity against a global network observer or metadata analysis.

---

## Why are technical details not fully documented?

Quadrama publicly documents high-level protocol design.

Certain implementation details are intentionally not disclosed to reduce attack surface and prevent misuse.

---

## Is Quadrama audited?

Quadrama is designed with strong security principles.

Formal audits may be conducted in the future.
