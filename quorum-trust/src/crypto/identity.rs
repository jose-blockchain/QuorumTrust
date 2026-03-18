use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Represents a member's identity in the QuorumTrust network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MemberIdentity {
    pub digest: String,
    pub public_key_hex: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub x25519_public_key_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    PendingJoin,
    Expelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRecord {
    pub identity: MemberIdentity,
    pub status: MemberStatus,
    pub joined_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expelled_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl MemberIdentity {
    pub fn new(public_key_hex: &str, display_name: Option<String>) -> Self {
        let key = public_key_hex.trim();
        let digest = Self::compute_digest(key);
        Self {
            digest,
            public_key_hex: key.to_string(),
            display_name,
            x25519_public_key_hex: None,
        }
    }

    pub fn with_x25519(mut self, x25519_hex: String) -> Self {
        self.x25519_public_key_hex = Some(x25519_hex);
        self
    }

    pub fn compute_digest(public_key_hex: &str) -> String {
        let key = public_key_hex.trim();
        let mut hasher = Sha512::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..16])
    }

    pub fn short_id(&self) -> String {
        self.digest[..12].to_string()
    }

    pub fn display(&self) -> String {
        match &self.display_name {
            Some(name) => format!("{} ({})", name, self.short_id()),
            None => self.short_id(),
        }
    }
}

impl MemberRecord {
    pub fn new_genesis(identity: MemberIdentity) -> Self {
        Self {
            identity,
            status: MemberStatus::Active,
            joined_at: Some(chrono::Utc::now()),
            expelled_at: None,
        }
    }

    pub fn new_pending(identity: MemberIdentity) -> Self {
        Self {
            identity,
            status: MemberStatus::PendingJoin,
            joined_at: None,
            expelled_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let id = MemberIdentity::new("abcdef1234567890", Some("Alice".into()));
        assert!(!id.digest.is_empty());
        assert_eq!(id.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_digest_deterministic() {
        let d1 = MemberIdentity::compute_digest("key1");
        let d2 = MemberIdentity::compute_digest("key1");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_different_keys_different_digests() {
        let d1 = MemberIdentity::compute_digest("key1");
        let d2 = MemberIdentity::compute_digest("key2");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_digest_normalizes_whitespace() {
        let d1 = MemberIdentity::compute_digest("abc123");
        let d2 = MemberIdentity::compute_digest("abc123\n");
        let d3 = MemberIdentity::compute_digest("  abc123  ");
        assert_eq!(d1, d2);
        assert_eq!(d1, d3);
    }
}
