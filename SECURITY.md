# QuorumTrust Security Features

## Cryptographic Primitives

| Component | Algorithm | Library |
|---|---|---|
| Identity keys | Ed25519 | `theta_schemes` (thetacrypt) |
| Threshold signing | FROST (Flexible Round-Optimized Schnorr Threshold) | `theta_schemes::dl_schemes::signatures::frost` |
| Key agreement | X25519 ECDH | `x25519-dalek` |
| Authenticated encryption | ChaCha20Poly1305 AEAD | `chacha20poly1305` |
| Hashing | SHA-256, SHA-512 | `sha2` |

## FROST Threshold Signatures

QuorumTrust uses FROST t-of-n threshold signatures from the `thetacrypt` library (theta_schemes crate). All low-level FROST operations — key generation, commit, partial sign, assemble, verify — come directly from `theta_schemes::dl_schemes::signatures::frost`.

- **Threshold**: `t = floor(2n/3) + 1` for `n >= 2`; `t = 1` for `n = 1`.
- **Trigger**: FROST signing initiates automatically after a document finalization vote passes.
- **Dealer**: The genesis node (active member with the lexicographically lowest digest) acts as trusted dealer, generating all key shares.
- **Ceremony**: Two-round gossip-based protocol — commitments (Round 1), then partial signatures (Round 2), then deterministic assembly.
- **Verification**: The assembled group signature is verified against the group public key before storage and broadcast.

## Encrypted Key Transport

FROST key shares are distributed over the gossip network using per-recipient authenticated encryption.

### Scheme

1. **Key derivation**: Each node deterministically derives an X25519 keypair from its FROST identity secret key using `SHA-256("quorum-trust-x25519-derivation" || frost_secret)`.
2. **ECDH**: The dealer computes a shared secret with each recipient via `X25519(dealer_secret, recipient_public)`.
3. **Symmetric key**: `SHA-256(shared_secret || context)` where context is `frost-share-<session_id>` — unique per ceremony.
4. **Encryption**: ChaCha20Poly1305 AEAD with a deterministic nonce derived from `SHA-256("frost-share-nonce" || context || shared_secret)[:12]`.
5. **Output**: `nonce (12 bytes) || ciphertext` per recipient.

### Properties

- **Confidentiality**: Only the intended recipient can derive the shared secret and decrypt their key share.
- **Integrity**: ChaCha20Poly1305 is an AEAD cipher — tampering with the ciphertext causes decryption failure.
- **Context binding**: Each ceremony session produces unique symmetric keys and nonces, preventing cross-session replay.
- **No key reuse**: The deterministic nonce is safe because each `(session_id, sender, recipient)` tuple is unique (session_id is a UUID).

### Notes

- The ECDH shared secret is not verified with a key-confirmation MAC over both public keys. An active MITM substituting public keys during the gossip phase would be caught downstream: tampered shares produce invalid partial signatures, and the final FROST signature verification fails.
- The nonce is both derived deterministically and prepended to the ciphertext. The recipient reads the prepended nonce rather than recomputing it. This is redundant but harmless.

## Governance Sync Safety

- **Self-demotion guard**: A node never adopts a remote governance state that would remove itself from the active member set, preventing stale SyncResponses from demoting active members.
- **X25519 key preservation**: When adopting a remote governance state, all locally-known X25519 public keys are re-applied if the remote state was missing them.

## Message Authentication

All gossip messages are signed with the sender's Ed25519 identity key. The signature covers the message ID, sender digest, network name, message payload, and timestamp.

## Compression

Large gossip messages (> 1 KB) are Zlib-compressed at the application layer before transmission over UDP, with base64 encoding. Decompression is transparent on receipt.
