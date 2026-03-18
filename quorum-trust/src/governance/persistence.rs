//! Persistence for governance core data (members + accepted documents).
//! Proposals and vote history are not persisted.

use crate::governance::membership::GovernanceState;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSnapshot {
    pub network_name: String,
    pub members: HashMap<String, crate::crypto::identity::MemberRecord>,
    pub accepted_file_paths: HashSet<String>,
    #[serde(default)]
    pub epoch: u64,
}

impl GovernanceSnapshot {
    pub fn from_state(gov: &GovernanceState) -> Self {
        Self {
            network_name: gov.network_name.clone(),
            members: gov.members.clone(),
            accepted_file_paths: gov.accepted_file_paths.clone(),
            epoch: gov.epoch,
        }
    }

    pub fn into_state(self) -> GovernanceState {
        GovernanceState {
            network_name: self.network_name,
            members: self.members,
            proposals: HashMap::new(),
            rate_counters: HashMap::new(),
            accepted_file_paths: self.accepted_file_paths,
            epoch: self.epoch,
        }
    }
}

const GOVERNANCE_FILE: &str = "governance.json";

pub fn governance_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(GOVERNANCE_FILE)
}

pub fn save_governance(data_dir: &Path, gov: &GovernanceState) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = governance_path(data_dir);
    let snapshot = GovernanceSnapshot::from_state(gov);
    let json = serde_json::to_string_pretty(&snapshot)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Remove persisted governance so the node starts with a clean state.
/// Safe to call if the file does not exist (no-op).
pub fn clear_governance(data_dir: &Path) {
    let path = governance_path(data_dir);
    let _ = std::fs::remove_file(path);
}

pub fn load_governance(data_dir: &Path, network_name: &str) -> anyhow::Result<Option<GovernanceState>> {
    let path = governance_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let snapshot: GovernanceSnapshot = serde_json::from_str(&content)?;
    if snapshot.network_name != network_name {
        tracing::warn!(
            "Persisted governance network_name '{}' != config '{}', ignoring",
            snapshot.network_name,
            network_name
        );
        return Ok(None);
    }
    Ok(Some(snapshot.into_state()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::MemberIdentity;
    use tempfile::TempDir;

    #[test]
    fn test_persistence_roundtrip() {
        let dir = TempDir::new().unwrap();
        let id = MemberIdentity::new("pk_hex", Some("Alice".into()));
        let gov = GovernanceState::new_genesis("test-net", id);
        assert_eq!(gov.active_member_count(), 1);

        save_governance(dir.path(), &gov).unwrap();
        let loaded = load_governance(dir.path(), "test-net").unwrap().unwrap();
        assert_eq!(loaded.active_member_count(), 1);
        assert_eq!(loaded.network_name, "test-net");

        let wrong_net = load_governance(dir.path(), "other-net").unwrap();
        assert!(wrong_net.is_none());
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = load_governance(dir.path(), "any-net").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_governance_path() {
        let dir = TempDir::new().unwrap();
        let path = governance_path(dir.path());
        assert!(path.ends_with("governance.json"));
        assert!(path.parent().unwrap().ends_with(dir.path().file_name().unwrap()));
    }

    #[test]
    fn test_save_creates_directory() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("nested").join("data");
        let id = MemberIdentity::new("pk", None);
        let gov = GovernanceState::new_genesis("net", id);
        save_governance(&subdir, &gov).unwrap();
        assert!(subdir.exists());
        assert!(governance_path(&subdir).exists());
    }

    #[test]
    fn test_persistence_with_accepted_files() {
        let dir = TempDir::new().unwrap();
        let id = MemberIdentity::new("pk", Some("Alice".into()));
        let mut gov = GovernanceState::new_genesis("doc-net", id);
        gov.accepted_file_paths.insert("contracts/agreement.md".into());
        gov.accepted_file_paths.insert("docs/readme.md".into());

        save_governance(dir.path(), &gov).unwrap();
        let loaded = load_governance(dir.path(), "doc-net").unwrap().unwrap();
        assert!(loaded.is_network_file("contracts/agreement.md"));
        assert!(loaded.is_network_file("docs/readme.md"));
        assert!(!loaded.is_network_file("other.md"));
        assert_eq!(loaded.accepted_file_paths.len(), 2);
    }

    #[test]
    fn test_proposals_not_persisted() {
        use crate::governance::voting::ProposalType;

        let dir = TempDir::new().unwrap();
        let genesis = MemberIdentity::new("pk_genesis", Some("Genesis".into()));
        let genesis_digest = genesis.digest.clone();
        let mut gov = GovernanceState::new_genesis("net", genesis);
        let pid = gov
            .submit_proposal(
                ProposalType::AddFile {
                    path: "x.md".into(),
                    content: Some("# X".into()),
                    content_hash: "h".into(),
                },
                &genesis_digest,
            )
            .unwrap();
        assert!(!gov.proposals.is_empty());
        assert!(gov.proposals.contains_key(&pid));

        save_governance(dir.path(), &gov).unwrap();
        let loaded = load_governance(dir.path(), "net").unwrap().unwrap();
        assert!(loaded.proposals.is_empty());
    }

    #[test]
    fn test_persistence_with_multiple_members() {
        let dir = TempDir::new().unwrap();
        let genesis = MemberIdentity::new("genesis_pk", Some("Alice".into()));
        let mut gov = GovernanceState::new_genesis("multi-net", genesis);
        let bob = MemberIdentity::new("bob_pk", Some("Bob".into()));
        gov.members.insert(
            bob.digest.clone(),
            crate::crypto::identity::MemberRecord {
                identity: bob,
                status: crate::crypto::identity::MemberStatus::Active,
                joined_at: Some(chrono::Utc::now()),
                expelled_at: None,
            },
        );

        save_governance(dir.path(), &gov).unwrap();
        let loaded = load_governance(dir.path(), "multi-net").unwrap().unwrap();
        assert_eq!(loaded.active_member_count(), 2);
        let genesis_digest = MemberIdentity::compute_digest("genesis_pk");
        let bob_digest = MemberIdentity::compute_digest("bob_pk");
        assert!(loaded.is_active_member(&genesis_digest));
        assert!(loaded.is_active_member(&bob_digest));
    }

    #[test]
    fn test_clear_governance() {
        let dir = TempDir::new().unwrap();
        let id = MemberIdentity::new("pk", None);
        let gov = GovernanceState::new_genesis("net", id);
        save_governance(dir.path(), &gov).unwrap();
        assert!(governance_path(dir.path()).exists());

        clear_governance(dir.path());
        assert!(!governance_path(dir.path()).exists());
        assert!(load_governance(dir.path(), "net").unwrap().is_none());
    }

    #[test]
    fn test_persistence_epoch_roundtrip() {
        let dir = TempDir::new().unwrap();
        let id = MemberIdentity::new("pk", Some("A".into()));
        let mut gov = GovernanceState::new_genesis("epoch-net", id);
        gov.epoch = 42;

        save_governance(dir.path(), &gov).unwrap();
        let loaded = load_governance(dir.path(), "epoch-net").unwrap().unwrap();
        assert_eq!(loaded.epoch, 42);
    }

    #[test]
    fn test_persistence_expelled_member_preserved() {
        use crate::governance::voting::{ProposalType, Vote, VoteChoice};

        let dir = TempDir::new().unwrap();
        let genesis = MemberIdentity::new("genesis_pk", Some("Alice".into()));
        let genesis_digest = genesis.digest.clone();
        let mut gov = GovernanceState::new_genesis("expel-persist", genesis);

        let pid = gov.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: "bob_pk".into(),
                display_name: Some("Bob".into()),
            },
            &genesis_digest,
        ).unwrap();
        gov.cast_vote(&pid, Vote {
            voter_digest: genesis_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();

        let bob_digest = MemberIdentity::compute_digest("bob_pk");
        let expel_pid = gov.submit_proposal(
            ProposalType::ExpelMember { member_digest: bob_digest.clone() },
            &genesis_digest,
        ).unwrap();
        gov.cast_vote(&expel_pid, Vote {
            voter_digest: genesis_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        gov.cast_vote(&expel_pid, Vote {
            voter_digest: bob_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();

        save_governance(dir.path(), &gov).unwrap();
        let loaded = load_governance(dir.path(), "expel-persist").unwrap().unwrap();

        assert_eq!(loaded.active_member_count(), 1);
        assert_eq!(loaded.epoch, 2);
        let bob = loaded.members.get(&bob_digest).unwrap();
        assert_eq!(bob.status, crate::crypto::identity::MemberStatus::Expelled);
        assert!(bob.expelled_at.is_some());
    }

    #[test]
    fn test_overwrite_preserves_latest() {
        let dir = TempDir::new().unwrap();
        let id = MemberIdentity::new("pk", None);
        let mut gov = GovernanceState::new_genesis("net", id);
        save_governance(dir.path(), &gov).unwrap();

        gov.accepted_file_paths.insert("v2.md".into());
        save_governance(dir.path(), &gov).unwrap();

        let loaded = load_governance(dir.path(), "net").unwrap().unwrap();
        assert!(loaded.is_network_file("v2.md"));
    }
}
