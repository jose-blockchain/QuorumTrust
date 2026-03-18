use crate::crypto::identity::{MemberIdentity, MemberRecord, MemberStatus};
#[allow(unused_imports)]
use crate::governance::voting::{
    Proposal, ProposalStatus, ProposalType, Vote, VoteChoice,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The full governance state of a QuorumTrust network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceState {
    pub network_name: String,
    pub members: HashMap<String, MemberRecord>,
    pub proposals: HashMap<String, Proposal>,
    pub rate_counters: HashMap<String, DailyRateCounter>,
    #[serde(default)]
    pub accepted_file_paths: HashSet<String>,
    /// Monotonically increasing counter, bumped on every accepted proposal.
    #[serde(default)]
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyRateCounter {
    pub date: String,
    pub new_files: u32,
    pub file_updates: u32,
    pub total_requests: u32,
}

impl GovernanceState {
    pub fn new_genesis(network_name: &str, genesis_identity: MemberIdentity) -> Self {
        let mut members = HashMap::new();
        let record = MemberRecord::new_genesis(genesis_identity.clone());
        members.insert(genesis_identity.digest.clone(), record);

        Self {
            network_name: network_name.to_string(),
            members,
            proposals: HashMap::new(),
            rate_counters: HashMap::new(),
            accepted_file_paths: HashSet::new(),
            epoch: 0,
        }
    }

    /// Create an empty governance state for non-genesis nodes.
    /// They are expected to sync membership from existing peers.
    pub fn new_empty(network_name: &str) -> Self {
        Self {
            network_name: network_name.to_string(),
            members: HashMap::new(),
            proposals: HashMap::new(),
            rate_counters: HashMap::new(),
            accepted_file_paths: HashSet::new(),
            epoch: 0,
        }
    }

    pub fn active_members(&self) -> Vec<&MemberRecord> {
        self.members
            .values()
            .filter(|m| m.status == MemberStatus::Active)
            .collect()
    }

    pub fn active_member_count(&self) -> usize {
        self.active_members().len()
    }

    pub fn is_active_member(&self, digest: &str) -> bool {
        self.members
            .get(digest)
            .map(|m| m.status == MemberStatus::Active)
            .unwrap_or(false)
    }

    pub fn pending_members(&self) -> Vec<&MemberRecord> {
        self.members
            .values()
            .filter(|m| m.status == MemberStatus::PendingJoin)
            .collect()
    }

    pub fn expelled_members(&self) -> Vec<&MemberRecord> {
        self.members
            .values()
            .filter(|m| m.status == MemberStatus::Expelled)
            .collect()
    }

    pub fn submit_proposal(
        &mut self,
        proposal_type: ProposalType,
        proposer_digest: &str,
    ) -> Result<String, GovernanceError> {
        if !self.is_active_member(proposer_digest) {
            return Err(GovernanceError::NotActiveMember);
        }

        if let ProposalType::AddMember {
            ref public_key_hex, ..
        } = proposal_type
        {
            let target_digest = MemberIdentity::compute_digest(public_key_hex);
            if self.is_active_member(&target_digest) {
                return Err(GovernanceError::AlreadyMember);
            }
        }

        if let ProposalType::ExpelMember { ref member_digest } = proposal_type {
            if !self.is_active_member(member_digest) {
                return Err(GovernanceError::NotActiveMember);
            }
            if member_digest == proposer_digest {
                return Err(GovernanceError::CannotExpelSelf);
            }
        }

        let proposal = Proposal::new(proposal_type, proposer_digest);
        let id = proposal.id.clone();
        self.proposals.insert(id.clone(), proposal);
        Ok(id)
    }

    /// Insert a proposal received from gossip (uses the original proposal_id so votes match).
    pub fn insert_proposal_from_peer(
        &mut self,
        proposal_id: &str,
        proposal_type: ProposalType,
        proposer_digest: &str,
    ) {
        if self.proposals.contains_key(proposal_id) {
            return; // Already have it (e.g. from earlier sync)
        }
        if !self.is_active_member(proposer_digest) {
            return;
        }
        let proposal = Proposal::with_id(
            proposal_id.to_string(),
            proposal_type,
            proposer_digest,
        );
        self.proposals.insert(proposal_id.to_string(), proposal);
    }

    pub fn cast_vote(
        &mut self,
        proposal_id: &str,
        vote: Vote,
    ) -> Result<ProposalStatus, GovernanceError> {
        if !self.is_active_member(&vote.voter_digest) {
            return Err(GovernanceError::NotActiveMember);
        }

        let total = self.active_member_count();
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(GovernanceError::ProposalAlreadyResolved);
        }

        if !proposal.add_vote(vote) {
            return Err(GovernanceError::AlreadyVoted);
        }

        let status = proposal.resolve(total);
        if status == ProposalStatus::Accepted {
            let ptype = proposal.proposal_type.clone();
            self.apply_accepted_proposal(&ptype);
            self.epoch += 1;
        }

        Ok(status)
    }

    fn apply_accepted_proposal(&mut self, proposal_type: &ProposalType) {
        match proposal_type {
            ProposalType::AddMember {
                public_key_hex,
                display_name,
            } => {
                let identity =
                    MemberIdentity::new(public_key_hex, display_name.clone());
                let mut record = MemberRecord::new_pending(identity.clone());
                record.status = MemberStatus::Active;
                record.joined_at = Some(chrono::Utc::now());
                self.members.insert(identity.digest.clone(), record);
            }
            ProposalType::ExpelMember { member_digest } => {
                if let Some(member) = self.members.get_mut(member_digest) {
                    member.status = MemberStatus::Expelled;
                    member.expelled_at = Some(chrono::Utc::now());
                }
            }
            ProposalType::ChangeMemberName {
                member_digest,
                new_name,
            } => {
                if let Some(member) = self.members.get_mut(member_digest) {
                    member.identity.display_name = Some(new_name.clone());
                }
            }
            ProposalType::ChangeMemberKey {
                member_digest,
                new_public_key_hex,
            } => {
                if let Some(member) = self.members.get_mut(member_digest) {
                    let new_digest =
                        MemberIdentity::compute_digest(new_public_key_hex);
                    member.identity.public_key_hex = new_public_key_hex.clone();
                    member.identity.digest = new_digest.clone();
                    let record = member.clone();
                    self.members.remove(member_digest);
                    self.members.insert(new_digest, record);
                }
            }
            ProposalType::AddFile { path, .. } => {
                self.accepted_file_paths.insert(path.clone());
            }
            ProposalType::RemoveFile { path } => {
                self.accepted_file_paths.remove(path);
            }
            ProposalType::ChangeFileName { path, new_name } => {
                if self.accepted_file_paths.remove(path) {
                    let new_path = std::path::Path::new(path)
                        .parent()
                        .map(|p| p.join(new_name))
                        .and_then(|p| p.to_str().map(String::from))
                        .unwrap_or_else(|| format!("{new_name}"));
                    self.accepted_file_paths.insert(new_path);
                }
            }
            _ => {}
        }
    }

    pub fn pending_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Pending)
            .collect()
    }

    /// Count of pending proposals where the given member has not yet voted.
    /// Excludes AddMember proposals where member_digest is the target (they cannot vote).
    pub fn proposals_awaiting_vote(&self, member_digest: &str) -> usize {
        self.proposals
            .values()
            .filter(|p| {
                if p.status != ProposalStatus::Pending {
                    return false;
                }
                if p.votes.contains_key(member_digest) {
                    return false;
                }
                // Exclude AddMember where this user is the target (not a member yet)
                if let ProposalType::AddMember { ref public_key_hex, .. } = &p.proposal_type {
                    if MemberIdentity::compute_digest(public_key_hex.trim()) == member_digest {
                        return false;
                    }
                }
                true
            })
            .count()
    }

    pub fn check_rate_limit(
        &self,
        member_digest: &str,
        max_requests: u32,
    ) -> bool {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        match self.rate_counters.get(member_digest) {
            Some(counter) if counter.date == today => {
                counter.total_requests < max_requests
            }
            _ => true,
        }
    }

    pub fn is_network_file(&self, path: &str) -> bool {
        self.accepted_file_paths.contains(path)
    }

    pub fn increment_rate_counter(&mut self, member_digest: &str) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let counter = self
            .rate_counters
            .entry(member_digest.to_string())
            .or_insert_with(|| DailyRateCounter {
                date: today.clone(),
                new_files: 0,
                file_updates: 0,
                total_requests: 0,
            });
        if counter.date != today {
            counter.date = today;
            counter.new_files = 0;
            counter.file_updates = 0;
            counter.total_requests = 0;
        }
        counter.total_requests += 1;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error("not an active member")]
    NotActiveMember,
    #[error("already a member")]
    AlreadyMember,
    #[error("proposal not found")]
    ProposalNotFound,
    #[error("proposal already resolved")]
    ProposalAlreadyResolved,
    #[error("already voted on this proposal")]
    AlreadyVoted,
    #[error("rate limit exceeded")]
    RateLimitExceeded,
    #[error("cannot expel yourself")]
    CannotExpelSelf,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis_state() -> (GovernanceState, MemberIdentity) {
        let identity = MemberIdentity::new("genesis_pk_hex", Some("Genesis".into()));
        let state = GovernanceState::new_genesis("test-network", identity.clone());
        (state, identity)
    }

    #[test]
    fn test_genesis_has_one_active_member() {
        let (state, _) = genesis_state();
        assert_eq!(state.active_member_count(), 1);
    }

    #[test]
    fn test_add_second_member_genesis_approves() {
        let (mut state, genesis) = genesis_state();
        let proposal_id = state
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: "member2_pk".into(),
                    display_name: Some("Bob".into()),
                },
                &genesis.digest,
            )
            .unwrap();

        let vote = Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0u8; 64],
            timestamp: chrono::Utc::now(),
        };
        let status = state.cast_vote(&proposal_id, vote).unwrap();
        assert_eq!(status, ProposalStatus::Accepted);
        assert_eq!(state.active_member_count(), 2);
    }

    #[test]
    fn test_add_third_member_needs_both_votes() {
        let (mut state, genesis) = genesis_state();

        // Add second member
        let pid = state
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: "m2pk".into(),
                    display_name: None,
                },
                &genesis.digest,
            )
            .unwrap();
        state
            .cast_vote(
                &pid,
                Vote {
                    voter_digest: genesis.digest.clone(),
                    choice: VoteChoice::Accept,
                    signature: vec![0; 64],
                    timestamp: chrono::Utc::now(),
                },
            )
            .unwrap();

        let m2_digest = MemberIdentity::compute_digest("m2pk");

        // Propose third member
        let pid2 = state
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: "m3pk".into(),
                    display_name: None,
                },
                &genesis.digest,
            )
            .unwrap();

        // Only genesis votes -> not enough
        let status = state
            .cast_vote(
                &pid2,
                Vote {
                    voter_digest: genesis.digest.clone(),
                    choice: VoteChoice::Accept,
                    signature: vec![0; 64],
                    timestamp: chrono::Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // Second member votes -> accepted
        let status = state
            .cast_vote(
                &pid2,
                Vote {
                    voter_digest: m2_digest,
                    choice: VoteChoice::Accept,
                    signature: vec![0; 64],
                    timestamp: chrono::Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(status, ProposalStatus::Accepted);
        assert_eq!(state.active_member_count(), 3);
    }

    #[test]
    fn test_expel_member() {
        let (mut state, genesis) = genesis_state();

        // Add member
        let pid = state
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: "victim_pk".into(),
                    display_name: None,
                },
                &genesis.digest,
            )
            .unwrap();
        state
            .cast_vote(
                &pid,
                Vote {
                    voter_digest: genesis.digest.clone(),
                    choice: VoteChoice::Accept,
                    signature: vec![0; 64],
                    timestamp: chrono::Utc::now(),
                },
            )
            .unwrap();

        let victim_digest = MemberIdentity::compute_digest("victim_pk");

        // Expel
        let pid2 = state
            .submit_proposal(
                ProposalType::ExpelMember {
                    member_digest: victim_digest.clone(),
                },
                &genesis.digest,
            )
            .unwrap();

        // Both vote to expel
        state
            .cast_vote(
                &pid2,
                Vote {
                    voter_digest: genesis.digest.clone(),
                    choice: VoteChoice::Accept,
                    signature: vec![0; 64],
                    timestamp: chrono::Utc::now(),
                },
            )
            .unwrap();
        state
            .cast_vote(
                &pid2,
                Vote {
                    voter_digest: victim_digest.clone(),
                    choice: VoteChoice::Accept,
                    signature: vec![0; 64],
                    timestamp: chrono::Utc::now(),
                },
            )
            .unwrap();

        assert_eq!(state.active_member_count(), 1);
        assert!(!state.is_active_member(&victim_digest));
    }

    #[test]
    fn test_expel_bumps_epoch() {
        let (mut state, genesis) = genesis_state();
        assert_eq!(state.epoch, 0);

        let pid = state
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: "bob_pk".into(),
                    display_name: Some("Bob".into()),
                },
                &genesis.digest,
            )
            .unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        assert_eq!(state.epoch, 1);
        assert_eq!(state.active_member_count(), 2);

        let bob_digest = MemberIdentity::compute_digest("bob_pk");
        let expel_pid = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: bob_digest.clone() },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: bob_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();

        assert_eq!(state.epoch, 2);
        assert_eq!(state.active_member_count(), 1);
        assert!(!state.is_active_member(&bob_digest));
    }

    #[test]
    fn test_cannot_expel_self() {
        let (mut state, genesis) = genesis_state();

        let result = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: genesis.digest.clone() },
            &genesis.digest,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            GovernanceError::CannotExpelSelf => {}
            other => panic!("Expected CannotExpelSelf, got: {:?}", other),
        }
    }

    #[test]
    fn test_cannot_expel_nonactive_member() {
        let (mut state, genesis) = genesis_state();
        let fake_digest = "nonexistent_digest".to_string();

        let result = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: fake_digest },
            &genesis.digest,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            GovernanceError::NotActiveMember => {}
            other => panic!("Expected NotActiveMember, got: {:?}", other),
        }
    }

    #[test]
    fn test_cannot_expel_already_expelled_member() {
        let (mut state, genesis) = genesis_state();

        let pid = state.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: "target_pk".into(),
                display_name: None,
            },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();

        let target = MemberIdentity::compute_digest("target_pk");

        let expel_pid = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: target.clone() },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: target.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        assert!(!state.is_active_member(&target));

        // Trying to expel again should fail
        let result = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: target },
            &genesis.digest,
        );
        assert!(matches!(result, Err(GovernanceError::NotActiveMember)));
    }

    #[test]
    fn test_expelled_member_cannot_submit_proposals() {
        let (mut state, genesis) = genesis_state();

        let pid = state.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: "bob_pk".into(),
                display_name: Some("Bob".into()),
            },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        let bob_digest = MemberIdentity::compute_digest("bob_pk");
        assert!(state.is_active_member(&bob_digest));

        // Expel Bob
        let expel_pid = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: bob_digest.clone() },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: bob_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();

        // Bob cannot submit proposals
        let result = state.submit_proposal(
            ProposalType::AddFile {
                path: "rogue.md".into(),
                content: None,
                content_hash: "h".into(),
            },
            &bob_digest,
        );
        assert!(matches!(result, Err(GovernanceError::NotActiveMember)));
    }

    #[test]
    fn test_expelled_member_cannot_vote() {
        let (mut state, genesis) = genesis_state();

        let bob_digest = MemberIdentity::compute_digest("bob_pk");
        let carol_digest = MemberIdentity::compute_digest("carol_pk");

        // Add Bob (1 member -> 1 vote needed)
        let pid = state.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: "bob_pk".into(),
                display_name: None,
            },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        assert_eq!(state.active_member_count(), 2);

        // Add Carol (2 members -> 2 votes needed)
        let pid = state.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: "carol_pk".into(),
                display_name: None,
            },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: bob_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        assert_eq!(state.active_member_count(), 3);

        // Expel Bob
        let expel_pid = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: bob_digest.clone() },
            &genesis.digest,
        ).unwrap();
        for digest in [&genesis.digest, &carol_digest, &bob_digest] {
            let result = state.cast_vote(&expel_pid, Vote {
                voter_digest: digest.clone(),
                choice: VoteChoice::Accept,
                signature: vec![0; 64],
                timestamp: chrono::Utc::now(),
            });
            if matches!(result, Ok(ProposalStatus::Accepted)) { break; }
        }
        assert!(!state.is_active_member(&bob_digest));
        assert_eq!(state.active_member_count(), 2);

        // Create a new proposal and verify Bob cannot vote
        let pid = state.submit_proposal(
            ProposalType::AddFile {
                path: "doc.md".into(),
                content: None,
                content_hash: "h".into(),
            },
            &genesis.digest,
        ).unwrap();

        let result = state.cast_vote(&pid, Vote {
            voter_digest: bob_digest,
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        });
        assert!(matches!(result, Err(GovernanceError::NotActiveMember)));
    }

    #[test]
    fn test_expelled_member_shows_in_expelled_list() {
        let (mut state, genesis) = genesis_state();

        let pid = state.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: "bob_pk".into(),
                display_name: Some("Bob".into()),
            },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        let bob_digest = MemberIdentity::compute_digest("bob_pk");

        let expel_pid = state.submit_proposal(
            ProposalType::ExpelMember { member_digest: bob_digest.clone() },
            &genesis.digest,
        ).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: genesis.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        state.cast_vote(&expel_pid, Vote {
            voter_digest: bob_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();

        let expelled = state.expelled_members();
        assert_eq!(expelled.len(), 1);
        assert_eq!(expelled[0].identity.digest, bob_digest);
        assert!(expelled[0].expelled_at.is_some());
    }

    #[test]
    fn test_epoch_increments_on_every_accepted_proposal() {
        let (mut state, genesis) = genesis_state();
        assert_eq!(state.epoch, 0);

        // Each accepted proposal bumps epoch by 1
        for i in 0..5 {
            let pid = state.submit_proposal(
                ProposalType::AddFile {
                    path: format!("file{}.md", i),
                    content: None,
                    content_hash: format!("h{}", i),
                },
                &genesis.digest,
            ).unwrap();
            state.cast_vote(&pid, Vote {
                voter_digest: genesis.digest.clone(),
                choice: VoteChoice::Accept,
                signature: vec![0; 64],
                timestamp: chrono::Utc::now(),
            }).unwrap();
            assert_eq!(state.epoch, (i + 1) as u64);
        }
    }

    #[test]
    fn test_epoch_does_not_increment_on_rejected_proposal() {
        let (mut state, genesis) = genesis_state();

        // Add two more members so rejection is possible
        for pk in &["m2", "m3"] {
            let pid = state.submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: pk.to_string(),
                    display_name: None,
                },
                &genesis.digest,
            ).unwrap();
            state.cast_vote(&pid, Vote {
                voter_digest: genesis.digest.clone(),
                choice: VoteChoice::Accept,
                signature: vec![0; 64],
                timestamp: chrono::Utc::now(),
            }).unwrap();
        }
        let m2 = MemberIdentity::compute_digest("m2");
        let m3 = MemberIdentity::compute_digest("m3");
        let epoch_before = state.epoch;

        let pid = state.submit_proposal(
            ProposalType::AddFile {
                path: "nope.md".into(),
                content: None,
                content_hash: "h".into(),
            },
            &genesis.digest,
        ).unwrap();

        // All three reject
        for d in &[&genesis.digest, &m2, &m3] {
            let status = state.cast_vote(&pid, Vote {
                voter_digest: d.to_string(),
                choice: VoteChoice::Reject,
                signature: vec![0; 64],
                timestamp: chrono::Utc::now(),
            }).unwrap();
            if status == ProposalStatus::Rejected { break; }
        }

        assert_eq!(state.epoch, epoch_before);
    }
}
