# Frequently Asked Questions (FAQ)

## What is Quadrama?
Quadrama is a secure 1:1 messaging application with end-to-end encryption.

## Can the server read my messages?
No.  
Messages are encrypted on your device and can only be decrypted by the recipient. The server only forwards encrypted data.

## What is a Safety Code?
The Safety Code is a short representation of the cryptographic identity binding between two peers.  
By comparing it out-of-band, users can verify that the connection is secure.

## What does “Verify” mean?
Verifying a peer confirms their identity. Once verified, the client enforces stricter security rules.  
If the peer’s identity key ever changes, verification is automatically removed.

## What happens if a peer’s key changes?
The previous verification is invalidated, and the session must be re-verified before communication can continue. This protects against identity substitution.

## Does Quadrama have Forward Secrecy?
Yes. Quadrama uses the Double Ratchet algorithm, which ensures that past messages cannot be decrypted if long-term keys are compromised later.

## Does Quadrama protect against malware?
No.  
Quadrama does not protect against:
- Malware or spyware on your device
- Keyloggers
- Compromised operating systems
- Physical access to an unlocked device

Security depends on a trusted device environment.

## Is Quadrama anonymous?
Quadrama focuses on encryption. It does not guarantee anonymity against a global network observer, but includes features to make traffic analysis more difficult.

## Why are some technical details not fully documented?
The core cryptographic mechanisms are documented. Certain implementation details are intentionally kept internal to maintain security boundaries.

## Is Quadrama audited?
Quadrama is built on established cryptographic principles. Independent audits are planned for the future.

## How can I report a security issue?
Please report security concerns to:  
**Quadrama.sec@outlook.com**
