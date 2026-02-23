# Threat Model (Public)

This document outlines the public threat model of the Quadrama protocol.

It defines which adversaries are considered and which scenarios are outside the scope of protection.

---

## 1. Security Goals

Quadrama aims to protect:

- Message confidentiality
- Message integrity
- Session authenticity
- Forward secrecy
- Protection against replay
- Protection against downgrade attacks after verification

The relay server is treated as untrusted.

---

## 2. Considered Adversaries

Quadrama is designed to resist:

### Passive Network Observers
Attackers who monitor network traffic but cannot modify packets.

### Active Network Attackers (MITM)
Attackers who attempt to intercept, modify, inject, or replay traffic between clients.

### Compromised Relay Server
A malicious or compromised relay operator attempting to inspect or manipulate messages.

### Replay Attackers
Adversaries attempting to re-inject previously valid ciphertexts.

---

## 3. Trust Assumptions

Quadrama assumes:

- Clients operate in a reasonably secure environment.
- The user verifies the Safety Code before establishing long-term trust.
- HTTPS transport provides baseline channel protection.

---

## 4. Out of Scope

Quadrama does not attempt to protect against:

- Malware or keyloggers on the client device
- Compromised operating systems
- Browser-level code injection (XSS)
- Social engineering attacks
- Physical device seizure without OS-level encryption
- Traffic analysis by a global passive adversary

---

## 5. Verification Model

Security against active attackers depends on:

- Proper user verification of Safety Codes
- Strict validation after trust is established
- Rejection of protocol downgrade attempts

If identity keys change, verification is automatically invalidated.

---

## 6. Design Philosophy

Quadrama follows a minimal exposure model:

- The relay cannot read plaintext messages.
- Session keys are never transmitted.
- Strict validation is enforced after identity verification.
- Sensitive implementation parameters are not publicly disclosed.

---

This threat model reflects the public design assumptions.
It is not a formal security proof.
