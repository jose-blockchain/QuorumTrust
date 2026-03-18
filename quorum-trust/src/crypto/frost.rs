use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

use theta_schemes::{
    dl_schemes::signatures::frost::{
        assemble, commit, partial_sign, verify,
        FrostPrivateKey, FrostPublicKey, FrostSignature, FrostSignatureShare, Nonce,
        PublicCommitment,
    },
    groups::group::GroupOperations,
    interface::{Serializable, Group, ThresholdScheme},
    keys::key_generator::KeyGenerator,
    keys::keys::PrivateKeyShare,
    rand::{RngAlgorithm, RNG},
};

use crate::crypto::identity::MemberIdentity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostKeyPair {
    pub public_key: Vec<u8>,
    pub secret_share: Vec<u8>,
    pub share_id: u16,
    pub threshold: u16,
    pub total_members: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub signature: Vec<u8>,
    pub signers: Vec<u16>,
    pub message_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    pub share_id: u16,
    pub share_data: Vec<u8>,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostCommitment {
    pub share_id: u16,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

/// Manages FROST threshold signature operations via thetacrypt (FROST-Ed25519-SHA512-v1).
/// Uses 1-of-1 key for single-node identity; supports t-of-n for future threshold signing.
pub struct FrostManager {
    private_key: FrostPrivateKey,
    member_pubkeys: HashMap<String, Vec<u8>>,
}

impl FrostManager {
    /// Create a new FrostManager with a 1-of-1 FROST key (single signer).
    pub fn new() -> Self {
        let mut rng = RNG::new(RngAlgorithm::OsRng);
        let shares = KeyGenerator::generate_keys(
            1,
            1,
            &mut rng,
            &ThresholdScheme::Frost,
            &Group::Ed25519,
            &None,
        )
        .expect("FROST key generation failed");
        let key = match &shares[0] {
            PrivateKeyShare::Frost(k) => k.clone(),
            _ => panic!("Expected Frost private key"),
        };
        Self {
            private_key: key,
            member_pubkeys: HashMap::new(),
        }
    }

    /// Load from serialized FrostPrivateKey bytes (e.g. from secret.key file).
    pub fn from_secret(secret_bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes_vec = secret_bytes.to_vec();
        let key = FrostPrivateKey::from_bytes(&bytes_vec)
            .map_err(|e| anyhow::anyhow!("Invalid FROST private key: {:?}", e))?;
        Ok(Self {
            private_key: key,
            member_pubkeys: HashMap::new(),
        })
    }

    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().expect("FROST key serialization")
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.private_key
            .get_public_key()
            .to_bytes()
            .expect("FROST public key serialization")
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn member_digest(&self) -> String {
        MemberIdentity::compute_digest(&self.public_key_hex())
    }

    /// Sign using FROST 1-of-1 protocol (commit -> partial_sign -> assemble).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut rng = RNG::new(RngAlgorithm::OsRng);
        let (comm, nonce) = commit(&self.private_key, &mut rng);
        let mut commitment_list = vec![comm];
        let share_id = self.private_key.get_share_id();
        let (share, group_commitment) = partial_sign(
            &nonce,
            &mut commitment_list,
            message,
            &self.private_key,
            share_id,
        )
        .expect("FROST partial sign failed");
        let shares = vec![share];
        let sig = assemble(&group_commitment, &self.private_key, &shares);
        sig.to_bytes().expect("FROST signature serialization")
    }

    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let pk_vec = public_key.to_vec();
        let pk = match FrostPublicKey::from_bytes(&pk_vec) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig_vec = signature.to_vec();
        let sig = match FrostSignature::from_bytes(&sig_vec) {
            Ok(s) => s,
            Err(_) => return false,
        };
        verify(&sig, &pk, message)
    }

    pub fn register_member(&mut self, member_id: &str, public_key: &[u8]) -> anyhow::Result<()> {
        let pk_vec = public_key.to_vec();
        let _ = FrostPublicKey::from_bytes(&pk_vec)
            .map_err(|e| anyhow::anyhow!("Invalid FROST public key: {:?}", e))?;
        self.member_pubkeys.insert(member_id.to_string(), pk_vec);
        Ok(())
    }

    pub fn verify_member_signature(
        &self,
        member_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let pk = match self.member_pubkeys.get(member_id) {
            Some(b) => b.as_slice(),
            None => return false,
        };
        self.verify(pk, message, signature)
    }

    /// X25519 public key hex derived from this node's FROST secret key.
    pub fn x25519_public_hex(&self) -> String {
        crate::crypto::encrypted_channel::x25519_public_hex(&self.secret_key_bytes())
    }

    /// X25519 static secret for ECDH operations.
    pub fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        crate::crypto::encrypted_channel::derive_x25519_secret(&self.secret_key_bytes())
    }

    /// Generate t-of-n FROST key shares for threshold signing.
    /// Returns Vec of (share_id, share_bytes, group_public_key_bytes).
    pub fn generate_group_keys(
        threshold: usize,
        total: usize,
    ) -> anyhow::Result<(Vec<u8>, Vec<(u16, Vec<u8>)>)> {
        let mut rng = RNG::new(RngAlgorithm::OsRng);
        let shares = KeyGenerator::generate_keys(
            threshold,
            total,
            &mut rng,
            &ThresholdScheme::Frost,
            &Group::Ed25519,
            &None,
        )
        .map_err(|e| anyhow::anyhow!("FROST keygen failed: {:?}", e))?;

        let group_pk_bytes = match &shares[0] {
            PrivateKeyShare::Frost(k) => k
                .get_public_key()
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("group pk serialize: {:?}", e))?,
            _ => anyhow::bail!("expected Frost key"),
        };

        let mut result = Vec::new();
        for share in &shares {
            match share {
                PrivateKeyShare::Frost(k) => {
                    let id = k.get_share_id();
                    let bytes = k
                        .to_bytes()
                        .map_err(|e| anyhow::anyhow!("share serialize: {:?}", e))?;
                    result.push((id, bytes));
                }
                _ => anyhow::bail!("expected Frost key"),
            }
        }
        Ok((group_pk_bytes, result))
    }

    /// Create a FROST commitment for a signing session.
    pub fn frost_commit(
        key_share_bytes: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let key = FrostPrivateKey::from_bytes(&key_share_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("bad key share: {:?}", e))?;
        let mut rng = RNG::new(RngAlgorithm::OsRng);
        let (comm, nonce) = commit(&key, &mut rng);
        let comm_bytes = comm
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("commitment serialize: {:?}", e))?;
        let nonce_bytes = nonce
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("nonce serialize: {:?}", e))?;
        Ok((comm_bytes, nonce_bytes))
    }

    /// Produce a FROST partial signature.
    pub fn frost_partial_sign(
        nonce_bytes: &[u8],
        commitment_list_bytes: &[Vec<u8>],
        message: &[u8],
        key_share_bytes: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let key = FrostPrivateKey::from_bytes(&key_share_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("bad key share: {:?}", e))?;
        let nonce = Nonce::from_bytes(&nonce_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("bad nonce: {:?}", e))?;
        let mut commitments: Vec<PublicCommitment> = commitment_list_bytes
            .iter()
            .map(|b| PublicCommitment::from_bytes(b).map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let share_id = key.get_share_id();
        let (share, group_comm) = partial_sign(&nonce, &mut commitments, message, &key, share_id)
            .map_err(|e| anyhow::anyhow!("partial_sign failed: {:?}", e))?;
        let share_bytes = share
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("share serialize: {:?}", e))?;
        let gc_bytes = group_comm.to_bytes();
        Ok((share_bytes, gc_bytes))
    }

    /// Assemble partial signatures into a full FROST threshold signature.
    pub fn frost_assemble(
        group_commitment_bytes: &[u8],
        key_share_bytes: &[u8],
        share_list_bytes: &[Vec<u8>],
    ) -> anyhow::Result<Vec<u8>> {
        let key = FrostPrivateKey::from_bytes(&key_share_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("bad key share: {:?}", e))?;
        let gc = theta_schemes::groups::group::GroupElement::from_bytes(
            group_commitment_bytes,
            &Group::Ed25519,
            None,
        );
        let shares: Vec<FrostSignatureShare> = share_list_bytes
            .iter()
            .map(|b| {
                FrostSignatureShare::from_bytes(b).map_err(|e| anyhow::anyhow!("{:?}", e))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let sig = assemble(&gc, &key, &shares);
        sig.to_bytes()
            .map_err(|e| anyhow::anyhow!("sig serialize: {:?}", e))
    }

    /// Verify a threshold FROST signature against a group public key.
    pub fn verify_group_signature(
        group_pk_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        let pk = match FrostPublicKey::from_bytes(&group_pk_bytes.to_vec()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match FrostSignature::from_bytes(&signature_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        verify(&sig, &pk, message)
    }

    /// Hash data for content-addressable references.
    pub fn hash_content(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

impl Default for FrostManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let manager = FrostManager::new();
        let message = b"hello world";
        let sig = manager.sign(message);
        assert!(manager.verify(&manager.public_key_bytes(), message, &sig));
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let manager = FrostManager::new();
        let sig = manager.sign(b"hello");
        assert!(!manager.verify(&manager.public_key_bytes(), b"world", &sig));
    }

    #[test]
    fn test_member_digest() {
        let manager = FrostManager::new();
        let digest = manager.member_digest();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_register_and_verify_member() {
        let member = FrostManager::new();
        let mut manager = FrostManager::new();

        manager
            .register_member("member1", &member.public_key_bytes())
            .unwrap();

        let msg = b"test message";
        let sig = member.sign(msg);
        assert!(manager.verify_member_signature("member1", msg, &sig));
    }

    #[test]
    fn test_threshold_2_of_3_signing() {
        let (group_pk, shares) = FrostManager::generate_group_keys(2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let message = b"document hash for signing";

        // Round 1: all signers commit
        let (comm1, nonce1) = FrostManager::frost_commit(&shares[0].1).unwrap();
        let (comm2, nonce2) = FrostManager::frost_commit(&shares[1].1).unwrap();

        // Only 2 signers participate (threshold = 2)
        let comm_list = vec![comm1.clone(), comm2.clone()];

        // Round 2: partial sign
        let (share1, _gc1) =
            FrostManager::frost_partial_sign(&nonce1, &comm_list, message, &shares[0].1).unwrap();
        let (share2, gc2) =
            FrostManager::frost_partial_sign(&nonce2, &comm_list, message, &shares[1].1).unwrap();

        // Assemble
        let sig =
            FrostManager::frost_assemble(&gc2, &shares[0].1, &[share1, share2]).unwrap();

        // Verify
        assert!(FrostManager::verify_group_signature(&group_pk, message, &sig));
        assert!(!FrostManager::verify_group_signature(&group_pk, b"wrong message", &sig));
    }

    #[test]
    fn test_from_secret_roundtrip() {
        let manager = FrostManager::new();
        let secret = manager.secret_key_bytes();
        let loaded = FrostManager::from_secret(&secret).unwrap();
        assert_eq!(manager.public_key_hex(), loaded.public_key_hex());
        let msg = b"roundtrip test";
        let sig = loaded.sign(msg);
        assert!(manager.verify(&manager.public_key_bytes(), msg, &sig));
    }
}
