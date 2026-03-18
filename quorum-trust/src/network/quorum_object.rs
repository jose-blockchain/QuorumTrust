//! QuorumTrust ApplicationObject for chaincraft gossip.
//! Processes incoming GossipMessage from SharedMessage.data and updates governance/documents.

use crate::config::NodeConfig;
use crate::crypto::frost::FrostManager;
use crate::crypto::threshold::ThresholdState;
use crate::document::DocumentManager;
use crate::governance::membership::GovernanceState;
use crate::governance::persistence;
use crate::governance::voting::{ProposalStatus, ProposalType, Vote};
use crate::network::messages::{GossipMessage, GossipMessageType};
use async_trait::async_trait;
use chaincraft::shared::{SharedMessage, SharedObjectId};
use chaincraft::shared_object::ApplicationObject;
use chaincraft::Result as ChaincraftResult;
use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedSender, RwLock};

/// ApplicationObject that processes QuorumTrust gossip messages received via chaincraft UDP.
pub struct QuorumTrustObject {
    id: SharedObjectId,
    config: NodeConfig,
    frost: Arc<RwLock<FrostManager>>,
    governance: Arc<RwLock<GovernanceState>>,
    documents: Arc<RwLock<DocumentManager>>,
    seen_messages: Arc<RwLock<HashSet<String>>>,
    threshold_state: Arc<RwLock<ThresholdState>>,
    /// Channel to request broadcasts (e.g. SyncResponse) from the network.
    broadcast_tx: UnboundedSender<GossipMessage>,
}

impl std::fmt::Debug for QuorumTrustObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuorumTrustObject")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl QuorumTrustObject {
    pub fn new(
        config: NodeConfig,
        frost: Arc<RwLock<FrostManager>>,
        governance: Arc<RwLock<GovernanceState>>,
        documents: Arc<RwLock<DocumentManager>>,
        seen_messages: Arc<RwLock<HashSet<String>>>,
        threshold_state: Arc<RwLock<ThresholdState>>,
        broadcast_tx: UnboundedSender<GossipMessage>,
    ) -> Self {
        Self {
            id: SharedObjectId::new(),
            config,
            frost,
            governance,
            documents,
            seen_messages,
            threshold_state,
            broadcast_tx,
        }
    }
}

#[async_trait]
impl ApplicationObject for QuorumTrustObject {
    fn id(&self) -> &SharedObjectId {
        &self.id
    }

    fn type_name(&self) -> &'static str {
        "QuorumTrustObject"
    }

    async fn is_valid(&self, message: &SharedMessage) -> ChaincraftResult<bool> {
        Ok(crate::network::compress::is_valid_message(&message.data))
    }

    async fn add_message(&mut self, message: SharedMessage) -> ChaincraftResult<()> {
        let was_compressed = message.data.get("z").is_some();
        let msg: GossipMessage = crate::network::compress::decompress_message(&message.data)
            .map_err(|e| chaincraft::ChaincraftError::from(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;

        tracing::info!("Received {} from {}{} (id={})",
            msg.message_type.type_name(),
            &msg.sender_digest[..12],
            if was_compressed { " [compressed]" } else { "" },
            &msg.id[..8],
        );

        {
            let mut seen = self.seen_messages.write().await;
            if seen.contains(&msg.id) {
                return Ok(());
            }
            seen.insert(msg.id.clone());
        }

        if msg.network_name != self.config.network_name {
            return Ok(());
        }

        let gov = self.governance.read().await;
        let is_member = gov.is_active_member(&msg.sender_digest);
        drop(gov);

        match &msg.message_type {
            GossipMessageType::JoinRequest { .. } => {
                tracing::info!("Join request from {}", msg.sender_digest);
            }

            GossipMessageType::Proposal {
                proposal_id,
                proposal_type,
            } => {
                if !is_member {
                    tracing::warn!("Proposal from non-member: {}", msg.sender_digest);
                    return Ok(());
                }
                let mut gov = self.governance.write().await;
                gov.insert_proposal_from_peer(
                    proposal_id,
                    proposal_type.clone(),
                    &msg.sender_digest,
                );
                tracing::info!("Proposal applied: {} from {}", proposal_id, msg.sender_digest);
            }

            GossipMessageType::Vote {
                proposal_id,
                choice,
            } => {
                if !is_member {
                    return Ok(());
                }
                let vote = Vote {
                    voter_digest: msg.sender_digest.clone(),
                    choice: choice.clone(),
                    signature: msg.signature.clone(),
                    timestamp: msg.timestamp,
                };
                let mut gov = self.governance.write().await;
                match gov.cast_vote(proposal_id, vote) {
                    Ok(ProposalStatus::Accepted) => {
                        let proposal = gov.proposals.get(proposal_id).cloned();
                        drop(gov);
                        if let Some(p) = proposal {
                            if let Err(e) =
                                on_proposal_accepted(
                                    &self.config,
                                    &self.frost,
                                    &self.governance,
                                    &self.documents,
                                    &self.threshold_state,
                                    &self.broadcast_tx,
                                    &p,
                                )
                                .await
                            {
                                tracing::warn!("on_proposal_accepted error: {e}");
                            }
                            if let Err(e) = persistence::save_governance(&self.config.data_dir, &*self.governance.read().await) {
                                tracing::warn!("Failed to persist governance: {e}");
                            }
                        }
                    }
                    _ => {}
                }
            }

            GossipMessageType::SyncRequest => {
                // Ensure our x25519 key is in governance before responding
                {
                    let frost = self.frost.read().await;
                    let my_d = frost.member_digest();
                    let x25519 = frost.x25519_public_hex();
                    drop(frost);
                    let mut g = self.governance.write().await;
                    if let Some(m) = g.members.get_mut(&my_d) {
                        if m.identity.x25519_public_key_hex.as_deref() != Some(&x25519) {
                            m.identity.x25519_public_key_hex = Some(x25519);
                        }
                    }
                }
                let gov = self.governance.read().await;
                let mut state_to_send = (*gov).clone();
                // Ensure we include AddFile content for accepted paths that peers may be missing.
                // After a restart we have accepted_file_paths but proposals are not persisted;
                // read files from disk and add synthetic proposals so adopters can apply them.
                let docs = self.documents.read().await;
                for path in &state_to_send.accepted_file_paths {
                    let has_content = state_to_send.proposals.values().any(|p| {
                        matches!(&p.proposal_type, ProposalType::AddFile { path: pp, content: Some(_), .. } if pp == path)
                    });
                    if !has_content {
                        if let Ok(content) = docs.read_file(path) {
                            let proposal_type = ProposalType::AddFile {
                                path: path.to_string(),
                                content_hash: String::new(),
                                content: Some(content),
                            };
                            let synthetic_id = format!("sync-file-{}", path.replace('/', "-"));
                            let proposal = crate::governance::voting::Proposal::with_id(
                                synthetic_id,
                                proposal_type,
                                "sync",
                            );
                            state_to_send.proposals.insert(proposal.id.clone(), proposal);
                        }
                    }
                }
                drop(docs);
                drop(gov);

                let state_json = serde_json::to_string(&state_to_send).unwrap_or_default();
                let frost = self.frost.read().await;
                let digest = frost.member_digest();
                let mut response = GossipMessage::new(
                    &digest,
                    GossipMessageType::SyncResponse { state_json },
                    &self.config.network_name,
                );
                response.sign(&frost);
                drop(frost);

                let _ = self.broadcast_tx.send(response);
            }

            GossipMessageType::SyncResponse { state_json } => {
                if let Ok(remote) = serde_json::from_str::<GovernanceState>(state_json) {
                    let mut gov = self.governance.write().await;
                    let frost = self.frost.read().await;
                    let my_digest = frost.member_digest();
                    drop(frost);

                    let i_am_active_locally = gov.is_active_member(&my_digest);
                    let i_am_active_in_remote = remote.is_active_member(&my_digest);

                    // Always merge x25519 keys from remote into local, even without full adoption
                    let mut keys_merged = 0u32;
                    for (digest, remote_member) in &remote.members {
                        if let Some(ref remote_key) = remote_member.identity.x25519_public_key_hex {
                            if let Some(local_member) = gov.members.get_mut(digest) {
                                if local_member.identity.x25519_public_key_hex.is_none() {
                                    local_member.identity.x25519_public_key_hex = Some(remote_key.clone());
                                    keys_merged += 1;
                                }
                            }
                        }
                    }

                    // Always ensure our own x25519 key is set (may have been cleared by prior adoption)
                    {
                        let frost = self.frost.read().await;
                        let x25519_hex = frost.x25519_public_hex();
                        if let Some(member) = gov.members.get_mut(&my_digest) {
                            if member.identity.x25519_public_key_hex.as_deref() != Some(&x25519_hex) {
                                member.identity.x25519_public_key_hex = Some(x25519_hex);
                                keys_merged += 1;
                            }
                        }
                    }

                    if keys_merged > 0 {
                        tracing::info!("Merged {} x25519 key(s) from SyncResponse", keys_merged);
                    }

                    // Accept the state if we were legitimately expelled
                    let i_am_expelled_in_remote = remote.members.get(&my_digest)
                        .map(|m| m.status == crate::crypto::identity::MemberStatus::Expelled)
                        .unwrap_or(false);

                    // Never adopt a state that would demote us from active,
                    // UNLESS we were explicitly expelled by governance vote.
                    if i_am_active_locally && !i_am_active_in_remote && !i_am_expelled_in_remote {
                        tracing::debug!("Rejecting SyncResponse: would remove us from active set");
                        drop(gov);
                    } else {
                    let adopt = remote.epoch > gov.epoch
                        || remote.proposals.len() > gov.proposals.len()
                        || remote.active_member_count() > gov.active_member_count();
                    if adopt {
                        let root = self.documents.read().await.root().to_path_buf();
                        let mut files_to_apply: Vec<(String, String, String)> = Vec::new();
                        for path in &remote.accepted_file_paths {
                            let full = root.join(path);
                            if !full.exists() {
                                for p in remote.proposals.values() {
                                    if let ProposalType::AddFile {
                                        path: ref ppath,
                                        content: Some(ref c),
                                        ..
                                    } = p.proposal_type
                                    {
                                        if ppath == path {
                                            files_to_apply.push((
                                                path.clone(),
                                                c.clone(),
                                                p.proposer_digest.clone(),
                                            ));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        // Collect all known x25519 keys before overwriting
                        let local_x25519_keys: std::collections::HashMap<String, String> = gov.members.iter()
                            .filter_map(|(d, m)| {
                                m.identity.x25519_public_key_hex.clone().map(|k| (d.clone(), k))
                            })
                            .collect();
                        *gov = remote;
                        // Re-apply any x25519 keys the remote didn't have
                        for (digest, key) in &local_x25519_keys {
                            if let Some(member) = gov.members.get_mut(digest) {
                                if member.identity.x25519_public_key_hex.is_none() {
                                    member.identity.x25519_public_key_hex = Some(key.clone());
                                }
                            }
                        }
                        tracing::info!(
                            "Governance state synced: epoch={}, {} active members, {} accepted files, {} proposals",
                            gov.epoch,
                            gov.active_member_count(),
                            gov.accepted_file_paths.len(),
                            gov.proposals.len(),
                        );
                        if let Err(e) = persistence::save_governance(&self.config.data_dir, &*gov) {
                            tracing::warn!("Failed to persist governance after sync: {e}");
                        }
                        // Collect accepted MarkFinal proposals that might need FROST
                        let mut mark_final_paths: Vec<String> = Vec::new();
                        for p in gov.proposals.values() {
                            if p.status == ProposalStatus::Accepted {
                                if let ProposalType::MarkFinal { path } = &p.proposal_type {
                                    mark_final_paths.push(path.clone());
                                }
                            }
                        }
                        drop(gov);

                        for (path, content, proposer) in files_to_apply {
                            let mut docs = self.documents.write().await;
                            if let Err(e) = docs.add_file(&path, &content, &proposer) {
                                tracing::warn!("AddFile from sync failed for {path}: {e}");
                            } else {
                                tracing::info!("File applied from sync: {path}");
                            }
                        }

                        // Trigger FROST for any MarkFinal proposals accepted via sync
                        for path in mark_final_paths {
                            let needs_frost = {
                                let mut docs = self.documents.write().await;
                                let _ = docs.mark_final(&path);
                                let has_sig = docs.list_files()
                                    .unwrap_or_default()
                                    .iter()
                                    .any(|f| f.path == path && f.threshold_signature_hex.is_some());
                                !has_sig
                            };
                            if needs_frost {
                                tracing::info!("FROST: MarkFinal for {} learned via sync, triggering ceremony", path);
                                let doc_hash = {
                                    let mut docs = self.documents.write().await;
                                    docs.content_hash(&path).unwrap_or_default()
                                };
                                trigger_frost_from_sync(
                                    &self.config,
                                    &self.frost,
                                    &self.governance,
                                    &self.documents,
                                    &self.threshold_state,
                                    &self.broadcast_tx,
                                    &path,
                                    &doc_hash,
                                ).await;
                            }
                        }
                    }
                    } // end else (safe to consider adoption)
                } else {
                    tracing::warn!("Failed to decode governance sync response");
                }
            }

            GossipMessageType::ThresholdKeyDistribution {
                session_id,
                document_path,
                document_hash,
                group_public_key,
                dealer_x25519_public_hex,
                shares,
                threshold,
                total,
            } => {
                let frost = self.frost.read().await;
                let my_digest = frost.member_digest();
                let my_x25519_secret = frost.x25519_secret();
                drop(frost);

                tracing::info!("FROST: ThresholdKeyDistribution for {} ({}-of-{}), {} envelopes, session {}",
                    document_path, threshold, total, shares.len(), &session_id[..8]);
                let my_envelope = shares.iter().find(|e| e.recipient_digest == my_digest);
                if let Some(envelope) = my_envelope {
                    let context = format!("frost-share-{}", session_id);
                    match crate::crypto::encrypted_channel::decrypt_from_sender(
                        &my_x25519_secret,
                        dealer_x25519_public_hex,
                        &envelope.encrypted_share,
                        context.as_bytes(),
                    ) {
                        Ok(share_bytes) => {
                            let mut ts = self.threshold_state.write().await;
                            let session = ts.create_session(
                                session_id.clone(),
                                document_path.clone(),
                                document_hash.clone(),
                                *threshold,
                                *total,
                                group_public_key.clone(),
                            );
                            session.set_key_share(share_bytes, envelope.share_id);

                            match session.generate_commitment() {
                                Ok(comm_bytes) => {
                                    let share_id = envelope.share_id;
                                    drop(ts);
                                    tracing::info!("FROST: key share received, commitment generated for session {}", &session_id[..8]);

                                    let frost = self.frost.read().await;
                                    let mut comm_msg = GossipMessage::new(
                                        &frost.member_digest(),
                                        GossipMessageType::SigningCommitment {
                                            session_id: session_id.clone(),
                                            commitment: comm_bytes,
                                            share_id,
                                        },
                                        &self.config.network_name,
                                    );
                                    comm_msg.sign(&frost);
                                    drop(frost);
                                    let _ = self.broadcast_tx.send(comm_msg);
                                }
                                Err(e) => {
                                    tracing::warn!("FROST: commitment generation failed: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("FROST: failed to decrypt key share: {e}");
                        }
                    }
                } else {
                    tracing::warn!("FROST: no envelope for us ({}) in session {} — dealer may be missing our x25519 key",
                        &my_digest[..12], &session_id[..8]);
                }
            }

            GossipMessageType::SigningSessionStart { .. } => {
                // Sessions are started by ThresholdKeyDistribution; this is informational.
            }

            GossipMessageType::SigningCommitment {
                session_id,
                commitment,
                share_id,
            } => {
                let mut ts = self.threshold_state.write().await;
                if let Some(session) = ts.get_session_mut(session_id) {
                    session.add_commitment(*share_id, commitment.clone());
                    tracing::info!("FROST: commitment from share_id={} for session {} ({}/{} needed)",
                        share_id, &session_id[..8], session.commitments.len(), session.threshold);

                    if session.ready_to_sign() {
                        let doc_hash = session.document_hash.clone();
                        match session.produce_partial_signature(doc_hash.as_bytes()) {
                            Ok((share_bytes, _gc_bytes)) => {
                                let my_share_id = session.my_share_id.unwrap();
                                let sid = session_id.clone();
                                drop(ts);

                                tracing::info!("FROST: partial signature produced for session {}", &sid[..8]);
                                let frost = self.frost.read().await;
                                let mut share_msg = GossipMessage::new(
                                    &frost.member_digest(),
                                    GossipMessageType::SigningShare {
                                        session_id: sid,
                                        share: share_bytes,
                                        share_id: my_share_id,
                                    },
                                    &self.config.network_name,
                                );
                                share_msg.sign(&frost);
                                drop(frost);
                                let _ = self.broadcast_tx.send(share_msg);
                            }
                            Err(e) => {
                                tracing::warn!("FROST: partial_sign failed: {e}");
                            }
                        }
                    }
                } else {
                    tracing::warn!("FROST: no session for commitment (session_id={})", &session_id[..8]);
                }
            }

            GossipMessageType::SigningShare {
                session_id,
                share,
                share_id,
            } => {
                let assembly_result = {
                    let mut ts = self.threshold_state.write().await;
                    if let Some(session) = ts.get_session_mut(session_id) {
                        session.add_share(*share_id, share.clone());
                        tracing::info!("FROST: share from share_id={} for session {} ({}/{})",
                            share_id, &session_id[..8], session.shares.len(), session.threshold);

                        if session.ready_to_assemble() {
                            match session.assemble_signature() {
                                Ok(sig_bytes) => Some((
                                    sig_bytes,
                                    session.document_path.clone(),
                                    session.document_hash.clone(),
                                    session.group_public_key.clone(),
                                    session.threshold,
                                    session.total,
                                    session_id.clone(),
                                )),
                                Err(e) => {
                                    tracing::warn!("FROST: assembly failed: {e}");
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if let Some((sig_bytes, doc_path, doc_hash, gpk, threshold, total, sid)) = assembly_result {
                    let verified = FrostManager::verify_group_signature(
                        &gpk,
                        doc_hash.as_bytes(),
                        &sig_bytes,
                    );
                    tracing::info!("FROST: signature assembled for {} (verified={})", doc_path, verified);

                    let mut docs = self.documents.write().await;
                    docs.set_threshold_signature(&doc_path, sig_bytes.clone(), gpk.clone(), threshold, total);
                    drop(docs);

                    let frost = self.frost.read().await;
                    let mut result_msg = GossipMessage::new(
                        &frost.member_digest(),
                        GossipMessageType::ThresholdSignatureResult {
                            session_id: sid,
                            document_path: doc_path,
                            signature: sig_bytes,
                            group_public_key: gpk,
                            threshold,
                            total,
                        },
                        &self.config.network_name,
                    );
                    result_msg.sign(&frost);
                    drop(frost);
                    let _ = self.broadcast_tx.send(result_msg);
                }
            }

            GossipMessageType::ThresholdSignatureResult {
                document_path,
                signature,
                group_public_key,
                threshold,
                total,
                ..
            } => {
                let mut docs = self.documents.write().await;
                docs.set_threshold_signature(
                    document_path,
                    signature.clone(),
                    group_public_key.clone(),
                    *threshold,
                    *total,
                );
                tracing::info!("FROST: threshold signature stored for {}", document_path);
            }

            GossipMessageType::Heartbeat { .. } | GossipMessageType::ProposalResult { .. } => {}
        }

        Ok(())
    }

    fn is_merkleized(&self) -> bool {
        false
    }

    async fn get_latest_digest(&self) -> ChaincraftResult<String> {
        let gov = self.governance.read().await;
        Ok(gov.active_member_count().to_string())
    }

    async fn has_digest(&self, _digest: &str) -> ChaincraftResult<bool> {
        Ok(false)
    }

    async fn is_valid_digest(&self, _digest: &str) -> ChaincraftResult<bool> {
        Ok(true)
    }

    async fn add_digest(&mut self, _digest: String) -> ChaincraftResult<bool> {
        Ok(true)
    }

    async fn gossip_messages(&self, _digest: Option<&str>) -> ChaincraftResult<Vec<SharedMessage>> {
        Ok(Vec::new())
    }

    async fn get_messages_since_digest(&self, _digest: &str) -> ChaincraftResult<Vec<SharedMessage>> {
        Ok(Vec::new())
    }

    async fn get_state(&self) -> ChaincraftResult<serde_json::Value> {
        let gov = self.governance.read().await;
        Ok(serde_json::json!({
            "active_members": gov.active_member_count(),
            "network_name": self.config.network_name
        }))
    }

    async fn reset(&mut self) -> ChaincraftResult<()> {
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn ApplicationObject> {
        Box::new(QuorumTrustObject {
            id: self.id.clone(),
            config: self.config.clone(),
            frost: self.frost.clone(),
            governance: self.governance.clone(),
            documents: self.documents.clone(),
            seen_messages: self.seen_messages.clone(),
            threshold_state: self.threshold_state.clone(),
            broadcast_tx: self.broadcast_tx.clone(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

async fn broadcast_governance_sync(
    config: &NodeConfig,
    frost: &Arc<RwLock<FrostManager>>,
    governance: &Arc<RwLock<GovernanceState>>,
    broadcast_tx: &UnboundedSender<GossipMessage>,
) -> anyhow::Result<()> {
    // Ensure our own x25519 key is present before broadcasting
    {
        let frost_guard = frost.read().await;
        let my_digest = frost_guard.member_digest();
        let x25519_hex = frost_guard.x25519_public_hex();
        drop(frost_guard);
        let mut gov = governance.write().await;
        if let Some(member) = gov.members.get_mut(&my_digest) {
            if member.identity.x25519_public_key_hex.as_deref() != Some(&x25519_hex) {
                member.identity.x25519_public_key_hex = Some(x25519_hex);
            }
        }
    }
    let gov = governance.read().await;
    let state_json = serde_json::to_string(&*gov)?;
    drop(gov);

    let frost_guard = frost.read().await;
    let digest = frost_guard.member_digest();
    let mut msg = GossipMessage::new(
        &digest,
        GossipMessageType::SyncResponse { state_json },
        &config.network_name,
    );
    msg.sign(&frost_guard);
    drop(frost_guard);
    let _ = broadcast_tx.send(msg);
    Ok(())
}

/// Trigger FROST signing ceremony when MarkFinal is discovered via SyncResponse adoption.
/// Mirrors the FROST trigger in gossip.rs::trigger_frost_signing but for the quorum_object context.
async fn trigger_frost_from_sync(
    config: &NodeConfig,
    frost: &Arc<RwLock<FrostManager>>,
    governance: &Arc<RwLock<GovernanceState>>,
    documents: &Arc<RwLock<DocumentManager>>,
    threshold_state: &Arc<RwLock<crate::crypto::threshold::ThresholdState>>,
    broadcast_tx: &UnboundedSender<GossipMessage>,
    path: &str,
    doc_hash: &str,
) {
    let gov = governance.read().await;
    let mut digests: Vec<String> = gov.active_members().iter()
        .map(|m| m.identity.digest.clone())
        .collect();
    digests.sort();

    let frost_guard = frost.read().await;
    let my_digest = frost_guard.member_digest();

    let n = digests.len();
    if n == 0 || digests.first().map(|d| d.as_str()) != Some(&my_digest) {
        return; // not the dealer
    }

    let t = if n == 1 { 1 } else { (n * 2) / 3 + 1 };
    tracing::info!("FROST (via sync): I am the dealer. Generating {}-of-{} keys for {}", t, n, path);

    let (group_pk_bytes, shares) = match FrostManager::generate_group_keys(t, n) {
        Ok(v) => v,
        Err(e) => { tracing::warn!("FROST keygen failed: {e}"); return; }
    };

    let session_id = uuid::Uuid::new_v4().to_string();

    // 1-of-1
    if n == 1 {
        let (share_id, share_bytes) = &shares[0];
        let mut session = crate::crypto::threshold::SigningSession::new(
            session_id.clone(), path.to_string(), doc_hash.to_string(), 1, 1, group_pk_bytes.clone(),
        );
        session.set_key_share(share_bytes.clone(), *share_id);
        if session.generate_commitment().is_err() { return; }
        if session.produce_partial_signature(doc_hash.as_bytes()).is_err() { return; }
        let sig = match session.assemble_signature() {
            Ok(s) => s,
            Err(_) => return,
        };
        let verified = FrostManager::verify_group_signature(&group_pk_bytes, doc_hash.as_bytes(), &sig);
        tracing::info!("FROST (via sync): 1-of-1 signature for {} (verified={})", path, verified);
        let mut docs = documents.write().await;
        docs.set_threshold_signature(path, sig.clone(), group_pk_bytes.clone(), 1, 1);
        drop(docs);
        let mut result_msg = GossipMessage::new(
            &my_digest,
            GossipMessageType::ThresholdSignatureResult {
                session_id, document_path: path.to_string(),
                signature: sig, group_public_key: group_pk_bytes,
                threshold: 1, total: 1,
            },
            &config.network_name,
        );
        result_msg.sign(&frost_guard);
        drop(frost_guard);
        drop(gov);
        let _ = broadcast_tx.send(result_msg);
        return;
    }

    // Multi-member
    let dealer_x25519_secret = frost_guard.x25519_secret();
    let dealer_x25519_public_hex = frost_guard.x25519_public_hex();
    let context = format!("frost-share-{}", session_id);

    for digest in &digests {
        let has_key = gov.members.get(digest)
            .and_then(|m| m.identity.x25519_public_key_hex.as_ref())
            .map(|k| !k.is_empty())
            .unwrap_or(false);
        tracing::info!("FROST (via sync): member {} x25519_key={}", &digest[..12], if has_key { "present" } else { "MISSING" });
    }

    let mut envelopes = Vec::new();
    let mut my_share_bytes: Option<Vec<u8>> = None;
    let mut my_share_id: Option<u16> = None;

    for (i, digest) in digests.iter().enumerate() {
        let (share_id, share_bytes) = &shares[i];
        if digest == &my_digest {
            my_share_bytes = Some(share_bytes.clone());
            my_share_id = Some(*share_id);
        }
        let recipient_x25519_hex = gov.members.get(digest)
            .and_then(|m| m.identity.x25519_public_key_hex.as_ref())
            .cloned()
            .unwrap_or_default();
        if recipient_x25519_hex.is_empty() {
            tracing::warn!("FROST (via sync): member {} missing x25519 key, skipping", &digest[..12]);
            continue;
        }
        match crate::crypto::encrypted_channel::encrypt_for_recipient(
            &dealer_x25519_secret, &recipient_x25519_hex, share_bytes, context.as_bytes(),
        ) {
            Ok(encrypted) => {
                envelopes.push(crate::network::messages::KeyShareEnvelope {
                    recipient_digest: digest.clone(), share_id: *share_id, encrypted_share: encrypted,
                });
            }
            Err(e) => { tracing::warn!("FROST (via sync): encrypt for {} failed: {e}", &digest[..12]); }
        }
    }
    drop(gov);

    let mut dist_msg = GossipMessage::new(
        &my_digest,
        GossipMessageType::ThresholdKeyDistribution {
            session_id: session_id.clone(), document_path: path.to_string(),
            document_hash: doc_hash.to_string(), group_public_key: group_pk_bytes.clone(),
            dealer_x25519_public_hex, shares: envelopes,
            threshold: t as u16, total: n as u16,
        },
        &config.network_name,
    );
    dist_msg.sign(&frost_guard);
    let _ = broadcast_tx.send(dist_msg);
    tracing::info!("FROST (via sync): key distribution broadcast for session {}", &session_id[..8]);

    // Dealer self-processes its own share
    if let (Some(share_bytes), Some(share_id)) = (my_share_bytes, my_share_id) {
        let mut ts = threshold_state.write().await;
        let session = ts.create_session(
            session_id.clone(), path.to_string(), doc_hash.to_string(),
            t as u16, n as u16, group_pk_bytes,
        );
        session.set_key_share(share_bytes, share_id);
        match session.generate_commitment() {
            Ok(comm_bytes) => {
                drop(ts);
                tracing::info!("FROST (via sync): dealer self-committed for session {}", &session_id[..8]);
                let mut comm_msg = GossipMessage::new(
                    &frost_guard.member_digest(),
                    GossipMessageType::SigningCommitment {
                        session_id, commitment: comm_bytes, share_id,
                    },
                    &config.network_name,
                );
                comm_msg.sign(&frost_guard);
                drop(frost_guard);
                let _ = broadcast_tx.send(comm_msg);
            }
            Err(e) => { tracing::warn!("FROST (via sync): dealer commitment failed: {e}"); }
        }
    }
}

async fn on_proposal_accepted(
    config: &NodeConfig,
    frost: &Arc<RwLock<FrostManager>>,
    governance: &Arc<RwLock<GovernanceState>>,
    documents: &Arc<RwLock<DocumentManager>>,
    threshold_state: &Arc<RwLock<crate::crypto::threshold::ThresholdState>>,
    broadcast_tx: &UnboundedSender<GossipMessage>,
    proposal: &crate::governance::voting::Proposal,
) -> anyhow::Result<()> {
    let proposal_type = &proposal.proposal_type;
    match proposal_type {
        ProposalType::AddMember { .. } | ProposalType::ExpelMember { .. } => {
            broadcast_governance_sync(config, frost, governance, broadcast_tx).await?;
        }
        ProposalType::AddFile { path, content, .. } => {
            if let Some(content) = content {
                let mut docs = documents.write().await;
                let full_path = docs.root().join(path);
                if !full_path.exists() {
                    match docs.add_file(path, content, &proposal.proposer_digest) {
                        Ok(_) => tracing::info!("File applied to disk: {path}"),
                        Err(e) => tracing::warn!("AddFile apply failed: {e}"),
                    }
                }
            } else {
                tracing::info!("AddFile accepted (legacy, no content): {path}");
            }
            let _ = broadcast_governance_sync(config, frost, governance, broadcast_tx).await;
        }
        ProposalType::EditFile { path, diff, .. } => {
            let file_diff = crate::document::diff::FileDiff {
                path: path.clone(),
                unified_diff: diff.clone(),
                additions: 0,
                deletions: 0,
            };
            let mut docs = documents.write().await;
            let _ = docs.apply_edit(path, &file_diff, "network");
            let _ = broadcast_governance_sync(config, frost, governance, broadcast_tx).await;
        }
        ProposalType::RemoveFile { path } => {
            let mut docs = documents.write().await;
            let _ = docs.remove_file(path);
            let _ = broadcast_governance_sync(config, frost, governance, broadcast_tx).await;
        }
        ProposalType::MarkFinal { path } => {
            let mut docs = documents.write().await;
            let _ = docs.mark_final(path);
            let doc_hash = docs.content_hash(path).unwrap_or_default();
            drop(docs);
            let _ = broadcast_governance_sync(config, frost, governance, broadcast_tx).await;

            // Genesis node (lowest digest) acts as trusted dealer for FROST signing
            let gov = governance.read().await;
            let active: Vec<_> = {
                let mut digests: Vec<String> = gov.active_members().iter()
                    .map(|m| m.identity.digest.clone())
                    .collect();
                digests.sort();
                digests
            };
            let frost_guard = frost.read().await;
            let my_digest = frost_guard.member_digest();

            let n = active.len();
            if n == 0 || active.first().map(|d| d.as_str()) != Some(&my_digest) {
                return Ok(());
            }

            let t = if n == 1 { 1 } else { (n * 2) / 3 + 1 };
            tracing::info!("FROST: I am the dealer. Generating {}-of-{} keys for {}", t, n, path);

            let (group_pk_bytes, shares) = FrostManager::generate_group_keys(t, n)
                .map_err(|e| { tracing::warn!("FROST keygen failed: {e}"); e })?;

            let session_id = uuid::Uuid::new_v4().to_string();

            // --- Special case: single member (1-of-1) — sign entirely locally ---
            if n == 1 {
                let (share_id, share_bytes) = &shares[0];
                let mut session = crate::crypto::threshold::SigningSession::new(
                    session_id.clone(),
                    path.clone(),
                    doc_hash.clone(),
                    1,
                    1,
                    group_pk_bytes.clone(),
                );
                session.set_key_share(share_bytes.clone(), *share_id);
                let _comm = session.generate_commitment()?;
                let (_share, _gc) = session.produce_partial_signature(doc_hash.as_bytes())?;
                let sig = session.assemble_signature()?;

                let verified = FrostManager::verify_group_signature(
                    &group_pk_bytes, doc_hash.as_bytes(), &sig,
                );
                tracing::info!("FROST: 1-of-1 signature for {} (verified={})", path, verified);

                let mut docs = documents.write().await;
                docs.set_threshold_signature(path, sig.clone(), group_pk_bytes.clone(), 1, 1);
                drop(docs);

                let mut result_msg = GossipMessage::new(
                    &my_digest,
                    GossipMessageType::ThresholdSignatureResult {
                        session_id,
                        document_path: path.clone(),
                        signature: sig,
                        group_public_key: group_pk_bytes,
                        threshold: 1,
                        total: 1,
                    },
                    &config.network_name,
                );
                result_msg.sign(&frost_guard);
                drop(frost_guard);
                drop(gov);
                let _ = broadcast_tx.send(result_msg);
                return Ok(());
            }

            // --- Multi-member: encrypt and distribute key shares ---
            let dealer_x25519_secret = frost_guard.x25519_secret();
            let dealer_x25519_public_hex = frost_guard.x25519_public_hex();
            let context = format!("frost-share-{}", session_id);

            let mut envelopes = Vec::new();
            let mut my_share_bytes: Option<Vec<u8>> = None;
            let mut my_share_id: Option<u16> = None;

            for (i, digest) in active.iter().enumerate() {
                let (share_id, share_bytes) = &shares[i];

                // Dealer keeps its own share directly (no encrypt/decrypt roundtrip)
                if digest == &my_digest {
                    my_share_bytes = Some(share_bytes.clone());
                    my_share_id = Some(*share_id);
                }

                let recipient_x25519_hex = gov.members.get(digest)
                    .and_then(|m| m.identity.x25519_public_key_hex.as_ref())
                    .cloned()
                    .unwrap_or_default();

                if recipient_x25519_hex.is_empty() {
                    tracing::warn!("FROST: member {} missing x25519 key, skipping", &digest[..12]);
                    continue;
                }

                match crate::crypto::encrypted_channel::encrypt_for_recipient(
                    &dealer_x25519_secret,
                    &recipient_x25519_hex,
                    share_bytes,
                    context.as_bytes(),
                ) {
                    Ok(encrypted) => {
                        envelopes.push(crate::network::messages::KeyShareEnvelope {
                            recipient_digest: digest.clone(),
                            share_id: *share_id,
                            encrypted_share: encrypted,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("FROST: encrypt share for {} failed: {e}", &digest[..12]);
                    }
                }
            }
            drop(gov);

            // Broadcast key distribution to peers
            let mut dist_msg = GossipMessage::new(
                &my_digest,
                GossipMessageType::ThresholdKeyDistribution {
                    session_id: session_id.clone(),
                    document_path: path.clone(),
                    document_hash: doc_hash.clone(),
                    group_public_key: group_pk_bytes.clone(),
                    dealer_x25519_public_hex,
                    shares: envelopes,
                    threshold: t as u16,
                    total: n as u16,
                },
                &config.network_name,
            );
            dist_msg.sign(&frost_guard);
            drop(frost_guard);
            let _ = broadcast_tx.send(dist_msg);
            tracing::info!("FROST: key distribution broadcast for session {}", &session_id[..8]);

            // Dealer processes its own share locally (won't receive its own broadcast)
            if let (Some(share_bytes), Some(share_id)) = (my_share_bytes, my_share_id) {
                let mut ts = threshold_state.write().await;
                let session = ts.create_session(
                    session_id.clone(),
                    path.clone(),
                    doc_hash.clone(),
                    t as u16,
                    n as u16,
                    group_pk_bytes.clone(),
                );
                session.set_key_share(share_bytes, share_id);
                match session.generate_commitment() {
                    Ok(comm_bytes) => {
                        drop(ts);
                        tracing::info!("FROST: dealer self-committed for session {}", &session_id[..8]);
                        let frost_guard = frost.read().await;
                        let mut comm_msg = GossipMessage::new(
                            &frost_guard.member_digest(),
                            GossipMessageType::SigningCommitment {
                                session_id: session_id.clone(),
                                commitment: comm_bytes,
                                share_id,
                            },
                            &config.network_name,
                        );
                        comm_msg.sign(&frost_guard);
                        drop(frost_guard);
                        let _ = broadcast_tx.send(comm_msg);
                    }
                    Err(e) => {
                        tracing::warn!("FROST: dealer commitment generation failed: {e}");
                    }
                }
            }
        }
        ProposalType::ChangeFileName { path, new_name } => {
            let new_path = std::path::Path::new(path)
                .parent()
                .map(|p| p.join(new_name))
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| new_name.clone());
            let mut docs = documents.write().await;
            if let Err(e) = docs.rename_file(path, &new_path) {
                tracing::warn!("ChangeFileName apply failed: {e}");
            }
            drop(docs);
            let _ = broadcast_governance_sync(config, frost, governance, broadcast_tx).await;
        }
        _ => {}
    }
    Ok(())
}
