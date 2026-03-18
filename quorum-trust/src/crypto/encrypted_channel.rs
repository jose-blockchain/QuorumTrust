//! Encrypted key transport for FROST share distribution.
//! Uses X25519 ECDH + ChaCha20Poly1305 AEAD derived from each node's FROST identity key.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Derive a deterministic X25519 static secret from FROST secret key bytes.
/// Uses SHA-256 to produce 32 bytes, then x25519-dalek clamps internally.
pub fn derive_x25519_secret(frost_secret_bytes: &[u8]) -> X25519Secret {
    let mut hasher = Sha256::new();
    hasher.update(b"quorum-trust-x25519-derivation");
    hasher.update(frost_secret_bytes);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    X25519Secret::from(bytes)
}

/// Compute the X25519 public key from a FROST secret key's bytes.
pub fn derive_x25519_public(frost_secret_bytes: &[u8]) -> X25519Public {
    let secret = derive_x25519_secret(frost_secret_bytes);
    X25519Public::from(&secret)
}

/// X25519 public key as hex string (for storage in MemberIdentity).
pub fn x25519_public_hex(frost_secret_bytes: &[u8]) -> String {
    hex::encode(derive_x25519_public(frost_secret_bytes).as_bytes())
}

/// Encrypt `plaintext` for a recipient given our X25519 secret and their X25519 public key.
/// Returns nonce (12 bytes) || ciphertext.
pub fn encrypt_for_recipient(
    our_secret: &X25519Secret,
    recipient_public_hex: &str,
    plaintext: &[u8],
    context: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let recipient_bytes = hex::decode(recipient_public_hex)
        .map_err(|e| anyhow::anyhow!("bad x25519 public hex: {e}"))?;
    if recipient_bytes.len() != 32 {
        anyhow::bail!("x25519 public key must be 32 bytes");
    }
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&recipient_bytes);
    let recipient_pk = X25519Public::from(pk_array);

    let shared = our_secret.diffie_hellman(&recipient_pk);

    let mut key_hasher = Sha256::new();
    key_hasher.update(shared.as_bytes());
    key_hasher.update(context);
    let sym_key = key_hasher.finalize();

    let cipher = ChaCha20Poly1305::new_from_slice(&sym_key)
        .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;

    // Derive nonce from context hash (deterministic per ceremony)
    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(b"frost-share-nonce");
    nonce_hasher.update(context);
    nonce_hasher.update(shared.as_bytes());
    let nonce_hash = nonce_hasher.finalize();
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce_hash[..12]);
    let nonce = AeadNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;

    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data encrypted by `encrypt_for_recipient`.
/// `data` = nonce (12 bytes) || ciphertext.
pub fn decrypt_from_sender(
    our_secret: &X25519Secret,
    sender_public_hex: &str,
    data: &[u8],
    context: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if data.len() < 12 {
        anyhow::bail!("ciphertext too short");
    }
    let sender_bytes = hex::decode(sender_public_hex)
        .map_err(|e| anyhow::anyhow!("bad x25519 public hex: {e}"))?;
    if sender_bytes.len() != 32 {
        anyhow::bail!("x25519 public key must be 32 bytes");
    }
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&sender_bytes);
    let sender_pk = X25519Public::from(pk_array);

    let shared = our_secret.diffie_hellman(&sender_pk);

    let mut key_hasher = Sha256::new();
    key_hasher.update(shared.as_bytes());
    key_hasher.update(context);
    let sym_key = key_hasher.finalize();

    let cipher = ChaCha20Poly1305::new_from_slice(&sym_key)
        .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&data[..12]);
    let nonce = AeadNonce::from(nonce_bytes);
    let plaintext = cipher
        .decrypt(&nonce, &data[12..])
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice_secret_bytes = b"alice-frost-secret-key-material!";
        let bob_secret_bytes = b"bob-frost-secret-key-bytes-here!";

        let alice_secret = derive_x25519_secret(alice_secret_bytes);
        let bob_secret = derive_x25519_secret(bob_secret_bytes);
        let bob_public_hex = x25519_public_hex(bob_secret_bytes);
        let alice_public_hex = x25519_public_hex(alice_secret_bytes);

        let plaintext = b"secret FROST key share data";
        let context = b"ceremony-123";

        let encrypted = encrypt_for_recipient(&alice_secret, &bob_public_hex, plaintext, context).unwrap();
        let decrypted = decrypt_from_sender(&bob_secret, &alice_public_hex, &encrypted, context).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let alice_secret_bytes = b"alice-frost-secret-key-material!";
        let bob_secret_bytes = b"bob-frost-secret-key-bytes-here!";
        let eve_secret_bytes = b"eve-attacker-secret-key-bytes!!";

        let alice_secret = derive_x25519_secret(alice_secret_bytes);
        let eve_secret = derive_x25519_secret(eve_secret_bytes);
        let bob_public_hex = x25519_public_hex(bob_secret_bytes);
        let alice_public_hex = x25519_public_hex(alice_secret_bytes);

        let encrypted = encrypt_for_recipient(&alice_secret, &bob_public_hex, b"secret", b"ctx").unwrap();
        let result = decrypt_from_sender(&eve_secret, &alice_public_hex, &encrypted, b"ctx");
        assert!(result.is_err());
    }
}
