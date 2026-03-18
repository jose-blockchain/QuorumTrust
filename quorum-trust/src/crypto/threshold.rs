//! FROST t-of-n threshold signing session management.
//! Coordinates key distribution, commitment collection, partial signing, and assembly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    AwaitingKeyShares,
    Committing,
    Signing,
    Complete,
}

#[derive(Debug, Clone)]
pub struct SigningSession {
    pub session_id: String,
    pub document_path: String,
    pub document_hash: String,
    pub threshold: u16,
    pub total: u16,
    pub status: SessionStatus,
    pub group_public_key: Vec<u8>,
    pub key_share: Option<Vec<u8>>,
    pub my_share_id: Option<u16>,
    pub my_nonce: Option<Vec<u8>>,
    pub my_commitment: Option<Vec<u8>>,
    /// commitment bytes keyed by share_id
    pub commitments: HashMap<u16, Vec<u8>>,
    /// partial signature bytes keyed by share_id
    pub shares: HashMap<u16, Vec<u8>>,
    /// group commitment bytes (computed when enough commitments arrive)
    pub group_commitment: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

impl SigningSession {
    pub fn new(
        session_id: String,
        document_path: String,
        document_hash: String,
        threshold: u16,
        total: u16,
        group_public_key: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            document_path,
            document_hash,
            threshold,
            total,
            status: SessionStatus::AwaitingKeyShares,
            group_public_key,
            key_share: None,
            my_share_id: None,
            my_nonce: None,
            my_commitment: None,
            commitments: HashMap::new(),
            shares: HashMap::new(),
            group_commitment: None,
            signature: None,
        }
    }

    pub fn set_key_share(&mut self, share_bytes: Vec<u8>, share_id: u16) {
        self.key_share = Some(share_bytes);
        self.my_share_id = Some(share_id);
        self.status = SessionStatus::Committing;
    }

    /// Generate our commitment (Round 1). Returns commitment bytes to broadcast.
    pub fn generate_commitment(&mut self) -> anyhow::Result<Vec<u8>> {
        let key_share = self
            .key_share
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no key share"))?;
        let (comm_bytes, nonce_bytes) =
            crate::crypto::frost::FrostManager::frost_commit(key_share)?;
        self.my_nonce = Some(nonce_bytes);
        self.my_commitment = Some(comm_bytes.clone());
        if let Some(id) = self.my_share_id {
            self.commitments.insert(id, comm_bytes.clone());
        }
        Ok(comm_bytes)
    }

    /// Add a peer's commitment. Returns true if we now have enough to sign.
    pub fn add_commitment(&mut self, share_id: u16, commitment_bytes: Vec<u8>) -> bool {
        self.commitments.insert(share_id, commitment_bytes);
        self.commitments.len() >= self.threshold as usize
    }

    /// Returns true if we have enough commitments and haven't signed yet.
    pub fn ready_to_sign(&self) -> bool {
        self.commitments.len() >= self.threshold as usize
            && self.status == SessionStatus::Committing
            && self.my_nonce.is_some()
            && self.key_share.is_some()
    }

    /// Produce our partial signature (Round 2). Returns (share_bytes, group_commitment_bytes).
    pub fn produce_partial_signature(
        &mut self,
        message: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let key_share = self
            .key_share
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no key share"))?;
        let nonce = self
            .my_nonce
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no nonce"))?;

        let sorted_ids = self.sorted_commitment_ids();
        let comm_bytes: Vec<Vec<u8>> = sorted_ids
            .iter()
            .map(|id| self.commitments[id].clone())
            .collect();

        let (share_bytes, gc_bytes) = crate::crypto::frost::FrostManager::frost_partial_sign(
            nonce,
            &comm_bytes,
            message,
            key_share,
        )?;

        self.group_commitment = Some(gc_bytes.clone());
        if let Some(id) = self.my_share_id {
            self.shares.insert(id, share_bytes.clone());
        }
        self.status = SessionStatus::Signing;
        self.my_nonce = None; // consumed
        Ok((share_bytes, gc_bytes))
    }

    /// Add a peer's partial signature. Returns true if we now have enough to assemble.
    pub fn add_share(&mut self, share_id: u16, share_bytes: Vec<u8>) -> bool {
        self.shares.insert(share_id, share_bytes);
        self.shares.len() >= self.threshold as usize
    }

    /// Returns true if we have enough shares and haven't assembled yet.
    pub fn ready_to_assemble(&self) -> bool {
        self.shares.len() >= self.threshold as usize
            && self.signature.is_none()
            && self.group_commitment.is_some()
    }

    /// Assemble the final FROST threshold signature.
    pub fn assemble_signature(&mut self) -> anyhow::Result<Vec<u8>> {
        let key_share = self
            .key_share
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no key share"))?;
        let gc = self
            .group_commitment
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no group commitment"))?;

        let sorted_ids = self.sorted_share_ids();
        let share_bytes: Vec<Vec<u8>> = sorted_ids
            .iter()
            .map(|id| self.shares[id].clone())
            .collect();

        let sig = crate::crypto::frost::FrostManager::frost_assemble(gc, key_share, &share_bytes)?;
        self.signature = Some(sig.clone());
        self.status = SessionStatus::Complete;
        Ok(sig)
    }

    fn sorted_commitment_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self.commitments.keys().copied().collect();
        ids.sort();
        ids.truncate(self.threshold as usize);
        ids
    }

    fn sorted_share_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self.shares.keys().copied().collect();
        ids.sort();
        ids.truncate(self.threshold as usize);
        ids
    }
}

/// Manages all active signing sessions for this node.
#[derive(Debug, Default)]
pub struct ThresholdState {
    pub sessions: HashMap<String, SigningSession>,
}

impl ThresholdState {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn get_session(&self, session_id: &str) -> Option<&SigningSession> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut SigningSession> {
        self.sessions.get_mut(session_id)
    }

    pub fn create_session(
        &mut self,
        session_id: String,
        document_path: String,
        document_hash: String,
        threshold: u16,
        total: u16,
        group_public_key: Vec<u8>,
    ) -> &mut SigningSession {
        self.sessions.entry(session_id.clone()).or_insert_with(|| {
            SigningSession::new(
                session_id,
                document_path,
                document_hash,
                threshold,
                total,
                group_public_key,
            )
        })
    }

    /// Find the completed signature for a document path.
    pub fn completed_signature(&self, document_path: &str) -> Option<&SigningSession> {
        self.sessions
            .values()
            .find(|s| s.document_path == document_path && s.status == SessionStatus::Complete)
    }
}
