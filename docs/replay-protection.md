# Replay Protection

Early versions of the protocol committed decrypt and ratchet state
before message authentication was fully verified.

Under packet reordering conditions, this allowed replay cascades
where previously observed ciphertexts could incorrectly advance
protocol state.

The current design commits decrypt state strictly after successful
MAC verification and decryption, ensuring that invalid or replayed
ciphertexts cannot influence protocol state.
