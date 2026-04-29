use crate::governance::voting::{ProposalType, VoteChoice};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessageType {
    /// Request to join the network
    JoinRequest {
        public_key_hex: String,
        display_name: Option<String>,
    },
    /// Proposal for governance action (add/remove member, add/edit/remove file, etc.)
    Proposal {
        proposal_id: String,
        proposal_type: ProposalType,
    },
    /// Vote on a pending proposal
    Vote {
        proposal_id: String,
        choice: VoteChoice,
    },
    /// Announce accepted proposal result to all peers
    ProposalResult {
        proposal_id: String,
        accepted: bool,
    },
    /// Sync request for current state
    SyncRequest,
    /// Sync response with full governance state
    SyncResponse {
        state_json: String,
    },
    /// Heartbeat with member status
    Heartbeat {
        member_digest: String,
        active_members: usize,
        pending_proposals: usize,
    },
    /// Distribute encrypted FROST threshold key shares after MarkFinal
    ThresholdKeyDistribution {
        session_id: String,
        document_path: String,
        document_hash: String,
        group_public_key: Vec<u8>,
        dealer_x25519_public_hex: String,
        shares: Vec<KeyShareEnvelope>,
        threshold: u16,
        total: u16,
    },
    /// Start signing round 1: signers broadcast commitments
    SigningSessionStart {
        session_id: String,
        document_path: String,
        document_hash: String,
    },
    /// FROST Round 1: signer broadcasts nonce commitment
    SigningCommitment {
        session_id: String,
        commitment: Vec<u8>,
        share_id: u16,
    },
    /// FROST Round 2: signer broadcasts partial signature
    SigningShare {
        session_id: String,
        share: Vec<u8>,
        share_id: u16,
    },
    /// Assembled FROST threshold signature
    ThresholdSignatureResult {
        session_id: String,
        document_path: String,
        signature: Vec<u8>,
        group_public_key: Vec<u8>,
        threshold: u16,
        total: u16,
    },
    /// Peer exchange: nodes share their known peer addresses
    PeerExchange {
        known_peers: Vec<PeerInfo>,
    },
}

impl GossipMessageType {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::JoinRequest { .. } => "JoinRequest",
            Self::Proposal { .. } => "Proposal",
            Self::Vote { .. } => "Vote",
            Self::ProposalResult { .. } => "ProposalResult",
            Self::SyncRequest => "SyncRequest",
            Self::SyncResponse { .. } => "SyncResponse",
            Self::Heartbeat { .. } => "Heartbeat",
            Self::ThresholdKeyDistribution { .. } => "ThresholdKeyDistribution",
            Self::SigningSessionStart { .. } => "SigningSessionStart",
            Self::SigningCommitment { .. } => "SigningCommitment",
            Self::SigningShare { .. } => "SigningShare",
            Self::ThresholdSignatureResult { .. } => "ThresholdSignatureResult",
            Self::PeerExchange { .. } => "PeerExchange",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareEnvelope {
    pub recipient_digest: String,
    pub share_id: u16,
    pub encrypted_share: Vec<u8>,
}

/// Information about a known peer node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// IP address or hostname
    pub address: String,
    /// P2P port
    pub port: u16,
    /// Display name (optional)
    pub name: Option<String>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub id: String,
    pub sender_digest: String,
    pub message_type: GossipMessageType,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub network_name: String,
}

impl GossipMessage {
    pub fn new(
        sender_digest: &str,
        message_type: GossipMessageType,
        network_name: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender_digest: sender_digest.to_string(),
            message_type,
            signature: Vec::new(),
            timestamp: Utc::now(),
            network_name: network_name.to_string(),
        }
    }

    pub fn payload_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(self.sender_digest.as_bytes());
        data.extend_from_slice(self.network_name.as_bytes());
        let type_json = serde_json::to_vec(&self.message_type).unwrap_or_default();
        data.extend_from_slice(&type_json);
        data.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        data
    }

    pub fn sign(&mut self, frost_manager: &crate::crypto::frost::FrostManager) {
        let payload = self.payload_for_signing();
        self.signature = frost_manager.sign(&payload);
    }

    pub fn verify_signature(
        &self,
        frost_manager: &crate::crypto::frost::FrostManager,
        sender_public_key: &[u8],
    ) -> bool {
        let payload = self.payload_for_signing();
        frost_manager.verify(sender_public_key, &payload, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::frost::FrostManager;

    #[test]
    fn test_sign_and_verify_message() {
        let mgr = FrostManager::new();
        let mut msg = GossipMessage::new(
            &mgr.member_digest(),
            GossipMessageType::Heartbeat {
                member_digest: mgr.member_digest(),
                active_members: 1,
                pending_proposals: 0,
            },
            "test-net",
        );
        msg.sign(&mgr);
        assert!(msg.verify_signature(&mgr, &mgr.public_key_bytes()));
    }
}
