# Threat Model

## Goals
- Confidentiality of message contents
- Forward secrecy and post-compromise security
- Integrity and authenticity of messages
- Resistance to replay and downgrade attacks

## Non-Goals
- Protection against a global passive adversary
- Traffic analysis resistance at nation-state scale
- Endpoint compromise prevention
- User anonymity against targeted physical surveillance

## Assumptions
- Endpoints may be compromised
- The network is fully attacker-controlled
- Adversaries can delay, replay, drop, and reorder packets
- Cryptographic primitives are implemented correctly

## Adversary Capabilities
- Passive network observation
- Active man-in-the-middle attacks
- Message injection and replay
- Session confusion attempts

## Out of Scope
- Denial-of-service attacks
- Side-channel attacks on client hardware
- Social engineering attacks against users
