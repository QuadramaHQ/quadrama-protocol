# Replay Protection (High-Level)

Quadrama includes mechanisms to prevent replay and message duplication attacks.

This document describes the conceptual approach only.
Exact implementation parameters are not publicly disclosed.

---

## 1. Threat

An attacker may attempt to:

- Replay previously captured ciphertext
- Re-inject old valid messages
- Deliver duplicated packets
- Manipulate message ordering

Replay protection ensures that previously processed messages cannot be accepted again.

---

## 2. Design Principles

Quadrama implements replay defense using:

- Per-session message counters
- Authentication validation
- A cache of recently processed message identifiers
- Strict session binding

Messages that fail validation are rejected before decryption state changes.

---

## 3. Out-of-Order Handling

Quadrama supports limited out-of-order delivery.

Clients may temporarily store skipped message states to allow correct decryption once missing messages arrive.

Invalid or excessively delayed packets are rejected.

---

## 4. Session Binding

All protected messages are bound to:

- The active session context
- The current handshake state
- The established identity binding (if verified)

Messages that do not match the current session context are rejected.

---

## 5. Strict Mode After Verification

Once peers are verified:

- Session context validation becomes mandatory
- Downgrade attempts are rejected
- Relaxed compatibility paths are disabled

This prevents replay through protocol fallback.

---

## 6. Philosophy

Replay protection is enforced at multiple layers:

- Cryptographic authentication
- Session context binding
- Internal state validation

Quadrama rejects malformed or unexpected messages by default.

---

This document describes high-level protection concepts only.
Implementation details may vary between clients.
