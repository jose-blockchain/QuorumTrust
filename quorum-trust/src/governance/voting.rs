use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalType {
    AddMember {
        public_key_hex: String,
        display_name: Option<String>,
    },
    ExpelMember {
        member_digest: String,
    },
    AddFile {
        path: String,
        content_hash: String,
        content: Option<String>,
    },
    EditFile {
        path: String,
        diff: String,
        content_hash: String,
    },
    RemoveFile {
        path: String,
    },
    MarkFinal {
        path: String,
    },
    ChangeMemberName {
        member_digest: String,
        new_name: String,
    },
    ChangeMemberKey {
        member_digest: String,
        new_public_key_hex: String,
    },
    ChangeFileName {
        path: String,
        new_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VoteChoice {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter_digest: String,
    pub choice: VoteChoice,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub proposal_type: ProposalType,
    pub proposer_digest: String,
    pub votes: HashMap<String, Vote>,
    pub status: ProposalStatus,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

impl Proposal {
    pub fn new(proposal_type: ProposalType, proposer_digest: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            proposal_type,
            proposer_digest: proposer_digest.to_string(),
            votes: HashMap::new(),
            status: ProposalStatus::Pending,
            created_at: Utc::now(),
            resolved_at: None,
        }
    }

    /// Create a proposal with a specific id (used when applying proposals received from gossip).
    pub fn with_id(
        id: String,
        proposal_type: ProposalType,
        proposer_digest: &str,
    ) -> Self {
        Self {
            id,
            proposal_type,
            proposer_digest: proposer_digest.to_string(),
            votes: HashMap::new(),
            status: ProposalStatus::Pending,
            created_at: Utc::now(),
            resolved_at: None,
        }
    }

    pub fn add_vote(&mut self, vote: Vote) -> bool {
        if self.status != ProposalStatus::Pending {
            return false;
        }
        if self.votes.contains_key(&vote.voter_digest) {
            return false;
        }
        self.votes.insert(vote.voter_digest.clone(), vote);
        true
    }

    pub fn accept_count(&self) -> usize {
        self.votes
            .values()
            .filter(|v| v.choice == VoteChoice::Accept)
            .count()
    }

    pub fn reject_count(&self) -> usize {
        self.votes
            .values()
            .filter(|v| v.choice == VoteChoice::Reject)
            .count()
    }

    pub fn total_votes(&self) -> usize {
        self.votes.len()
    }

    /// Check if the proposal has reached >2/3 acceptance from `total_members` active members.
    /// Returns true if accepted threshold met.
    pub fn check_accepted(&self, total_members: usize) -> bool {
        if total_members == 0 {
            return false;
        }
        let required = (total_members * 2) / 3 + 1;
        self.accept_count() >= required
    }

    /// Check if the proposal is rejected (2/3 or more negative).
    pub fn check_rejected(&self, total_members: usize) -> bool {
        if total_members == 0 {
            return false;
        }
        let reject_threshold = (total_members * 2 + 2) / 3;
        self.reject_count() >= reject_threshold
    }

    pub fn resolve(&mut self, total_members: usize) -> ProposalStatus {
        if self.status != ProposalStatus::Pending {
            return self.status.clone();
        }
        if self.check_accepted(total_members) {
            self.status = ProposalStatus::Accepted;
            self.resolved_at = Some(Utc::now());
        } else if self.check_rejected(total_members) {
            self.status = ProposalStatus::Rejected;
            self.resolved_at = Some(Utc::now());
        }
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vote(voter: &str, choice: VoteChoice) -> Vote {
        Vote {
            voter_digest: voter.to_string(),
            choice,
            signature: vec![0u8; 64],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_single_member_accepts() {
        let mut p = Proposal::new(
            ProposalType::AddMember {
                public_key_hex: "abc".into(),
                display_name: None,
            },
            "genesis",
        );
        p.add_vote(make_vote("genesis", VoteChoice::Accept));
        assert!(p.check_accepted(1));
    }

    #[test]
    fn test_two_of_two_required() {
        let mut p = Proposal::new(
            ProposalType::AddMember {
                public_key_hex: "abc".into(),
                display_name: None,
            },
            "a",
        );
        p.add_vote(make_vote("a", VoteChoice::Accept));
        assert!(!p.check_accepted(2));
        p.add_vote(make_vote("b", VoteChoice::Accept));
        assert!(p.check_accepted(2));
    }

    #[test]
    fn test_three_members_need_three_accepts() {
        let mut p = Proposal::new(
            ProposalType::AddMember {
                public_key_hex: "abc".into(),
                display_name: None,
            },
            "a",
        );
        p.add_vote(make_vote("a", VoteChoice::Accept));
        p.add_vote(make_vote("b", VoteChoice::Accept));
        assert!(!p.check_accepted(3));
        p.add_vote(make_vote("c", VoteChoice::Accept));
        assert!(p.check_accepted(3));
    }

    #[test]
    fn test_rejection_threshold() {
        let mut p = Proposal::new(
            ProposalType::AddFile {
                path: "doc.md".into(),
                content_hash: "hash".into(),
                content: None,
            },
            "a",
        );
        p.add_vote(make_vote("a", VoteChoice::Reject));
        p.add_vote(make_vote("b", VoteChoice::Reject));
        assert!(p.check_rejected(3));
    }

    #[test]
    fn test_no_duplicate_votes() {
        let mut p = Proposal::new(
            ProposalType::RemoveFile {
                path: "doc.md".into(),
            },
            "a",
        );
        assert!(p.add_vote(make_vote("a", VoteChoice::Accept)));
        assert!(!p.add_vote(make_vote("a", VoteChoice::Reject)));
        assert_eq!(p.total_votes(), 1);
    }
}
