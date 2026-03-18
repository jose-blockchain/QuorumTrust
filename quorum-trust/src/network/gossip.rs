use crate::config::NodeConfig;
use crate::crypto::frost::FrostManager;
use crate::crypto::identity::MemberIdentity;
use crate::crypto::threshold::ThresholdState;
use crate::document::DocumentManager;
use crate::governance::membership::GovernanceState;
use crate::governance::persistence;
use crate::governance::voting::{ProposalStatus, ProposalType, Vote, VoteChoice};
use crate::network::messages::{GossipMessage, GossipMessageType};
use crate::network::quorum_object::QuorumTrustObject;
use chaincraft::{ChaincraftNode, storage::MemoryStorage};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

pub struct QuorumNetwork {
    pub config: NodeConfig,
    pub frost: Arc<RwLock<FrostManager>>,
    pub governance: Arc<RwLock<GovernanceState>>,
    pub documents: Arc<RwLock<DocumentManager>>,
    pub threshold_state: Arc<RwLock<ThresholdState>>,
    chaincraft_node: Arc<Mutex<Option<ChaincraftNode>>>,
    seen_messages: Arc<RwLock<HashSet<String>>>,
}

impl QuorumNetwork {
    pub async fn new(config: NodeConfig) -> anyhow::Result<(Self, mpsc::UnboundedReceiver<GossipMessage>)> {
        let frost = if config.secret_key_file.exists() {
            let key_hex = std::fs::read_to_string(&config.secret_key_file)?;
            let key_bytes = hex::decode(key_hex.trim())?;
            FrostManager::from_secret(&key_bytes)?
        } else {
            anyhow::bail!(
                "Secret key file not found: {}. Run 'quorum-trust init' first.",
                config.secret_key_file.display()
            );
        };
        let mut governance = match persistence::load_governance(&config.data_dir, &config.network_name) {
            Ok(Some(gov)) => {
                tracing::info!(
                    "Loaded persisted governance: {} members, {} accepted files",
                    gov.active_member_count(),
                    gov.accepted_file_paths.len()
                );
                gov
            }
            Ok(None) | Err(_) => {
                if let Some(genesis) = &config.genesis {
                    let member_identity =
                        MemberIdentity::new(&genesis.public_key_hex, Some(genesis.member_name.clone()));
                    GovernanceState::new_genesis(&config.network_name, member_identity)
                } else {
                    GovernanceState::new_empty(&config.network_name)
                }
            }
        };
        let documents = DocumentManager::new(config.documents_dir.clone());
        documents.ensure_root()?;

        // Set x25519 public key on genesis member identity if present
        let x25519_hex = frost.x25519_public_hex();
        if let Some(genesis) = &config.genesis {
            let digest = MemberIdentity::compute_digest(&genesis.public_key_hex);
            if let Some(record) = governance.members.get_mut(&digest) {
                record.identity.x25519_public_key_hex = Some(x25519_hex.clone());
            }
        }

        let frost = Arc::new(RwLock::new(frost));
        let governance = Arc::new(RwLock::new(governance));
        let documents = Arc::new(RwLock::new(documents));
        let seen_messages = Arc::new(RwLock::new(HashSet::new()));
        let threshold_state = Arc::new(RwLock::new(ThresholdState::new()));

        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel();

        let quorum_obj = QuorumTrustObject::new(
            config.clone(),
            frost.clone(),
            governance.clone(),
            documents.clone(),
            seen_messages.clone(),
            threshold_state.clone(),
            broadcast_tx,
        );

        #[allow(unused_mut)]
        let mut chaincraft_node = ChaincraftNode::builder()
            .with_storage(Arc::new(MemoryStorage::new()))
            .port(config.node_port)
            .host("127.0.0.1")
            .max_peers(50)
            .local_discovery(true)
            .persist_peers(false)
            .build()
            .map_err(|e| anyhow::anyhow!("Chaincraft build failed: {e}"))?;

        chaincraft_node
            .add_shared_object(Box::new(quorum_obj))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to add QuorumTrustObject: {e}"))?;

        Ok((
            Self {
                config,
                frost,
                governance,
                documents,
                threshold_state,
                chaincraft_node: Arc::new(Mutex::new(Some(chaincraft_node))),
                seen_messages,
            },
            broadcast_rx,
        ))
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let mut node_guard = self.chaincraft_node.lock().await;
        if let Some(ref mut node) = *node_guard {
            node.start().await?;
        }
        drop(node_guard);

        for peer in &self.config.bootstrap_peers {
            let mut node_guard = self.chaincraft_node.lock().await;
            if let Some(ref mut node) = *node_guard {
                node.connect_to_peer(peer).await?;
            }
        }

        tracing::info!(
            "QuorumTrust node started on port {} (RPC: {}, Public: {})",
            self.config.node_port,
            self.config.rpc_port,
            self.config.public_port
        );

        self.ensure_x25519_key().await;

        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        let mut msg = GossipMessage::new(
            &digest,
            GossipMessageType::SyncRequest,
            &self.config.network_name,
        );
        msg.sign(&frost);
        drop(frost);
        self.broadcast_message(&msg).await?;

        Ok(())
    }

    /// Ensure our x25519 public key is set on our member record in governance.
    pub async fn ensure_x25519_key(&self) {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        let x25519_hex = frost.x25519_public_hex();
        drop(frost);
        let mut gov = self.governance.write().await;
        let mut changed = false;
        if let Some(record) = gov.members.get_mut(&digest) {
            if record.identity.x25519_public_key_hex.as_deref() != Some(&x25519_hex) {
                record.identity.x25519_public_key_hex = Some(x25519_hex);
                changed = true;
                tracing::info!("Set x25519 public key on member record");
            }
        }
        if changed {
            let state_json = serde_json::to_string(&*gov).unwrap_or_default();
            drop(gov);
            let frost = self.frost.read().await;
            let mut msg = GossipMessage::new(
                &frost.member_digest(),
                GossipMessageType::SyncResponse { state_json },
                &self.config.network_name,
            );
            msg.sign(&frost);
            drop(frost);
            let _ = self.broadcast_message(&msg).await;
        }
    }

    /// Broadcast a SyncRequest so peers respond with their governance state.
    /// Call this when the node may be behind (e.g. after startup or on demand).
    pub async fn request_governance_sync(&self) -> anyhow::Result<()> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        let mut msg = GossipMessage::new(
            &digest,
            GossipMessageType::SyncRequest,
            &self.config.network_name,
        );
        msg.sign(&frost);
        drop(frost);
        self.broadcast_message(&msg).await?;
        tracing::info!("Governance sync requested");
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        let mut node_guard = self.chaincraft_node.lock().await;
        if let Some(ref mut node) = *node_guard {
            node.close().await?;
        }
        tracing::info!("QuorumTrust node stopped");
        Ok(())
    }

    pub async fn broadcast_message(&self, msg: &GossipMessage) -> anyhow::Result<()> {
        let json = crate::network::compress::compress_message(msg)?;
        let mut node_guard = self.chaincraft_node.lock().await;
        if let Some(ref mut node) = *node_guard {
            node.create_shared_message_with_data(json).await?;
        }
        Ok(())
    }

    /// Broadcast a new proposal to the network so peers receive it before votes.
    pub async fn broadcast_proposal(
        &self,
        proposal_id: &str,
        proposal_type: &ProposalType,
    ) -> anyhow::Result<()> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        let mut msg = GossipMessage::new(
            &digest,
            GossipMessageType::Proposal {
                proposal_id: proposal_id.to_string(),
                proposal_type: proposal_type.clone(),
            },
            &self.config.network_name,
        );
        msg.sign(&frost);
        drop(frost);
        self.broadcast_message(&msg).await?;
        tracing::info!("Proposal broadcast: {} ({:?})", proposal_id, proposal_type);
        Ok(())
    }

    /// Process incoming message (used by simulated/test nodes; real nodes use QuorumTrustObject)
    pub async fn handle_incoming_message(&self, msg: GossipMessage) -> anyhow::Result<()> {
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
            }
            GossipMessageType::Vote { proposal_id, choice } => {
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
                            self.on_proposal_accepted(&p).await?;
                        }
                    }
                    _ => {}
                }
            }
            GossipMessageType::SyncRequest => {
                let gov = self.governance.read().await;
                let state_json = serde_json::to_string(&*gov)?;
                let frost = self.frost.read().await;
                let digest = frost.member_digest();
                let mut response = GossipMessage::new(
                    &digest,
                    GossipMessageType::SyncResponse { state_json },
                    &self.config.network_name,
                );
                response.sign(&frost);
                drop(frost);
                self.broadcast_message(&response).await?;
            }
            GossipMessageType::SyncResponse { state_json } => {
                if let Ok(remote) = serde_json::from_str::<GovernanceState>(state_json) {
                    let mut gov = self.governance.write().await;
                    if remote.active_member_count() > gov.active_member_count() {
                        *gov = remote;
                        tracing::info!(
                            "Governance state synced: {} active members",
                            gov.active_member_count()
                        );
                    }
                } else {
                    tracing::warn!("Failed to decode governance sync response");
                }
            }
            GossipMessageType::Heartbeat { .. } | GossipMessageType::ProposalResult { .. } => {}
            GossipMessageType::ThresholdKeyDistribution { .. }
            | GossipMessageType::SigningSessionStart { .. }
            | GossipMessageType::SigningCommitment { .. }
            | GossipMessageType::SigningShare { .. }
            | GossipMessageType::ThresholdSignatureResult { .. } => {
                // Handled in QuorumTrustObject::add_message (quorum_object.rs)
            }
        }

        Ok(())
    }

    async fn on_proposal_accepted(&self, proposal: &crate::governance::voting::Proposal) -> anyhow::Result<()> {
        let proposal_type = &proposal.proposal_type;

        // 1. Apply document operations
        match proposal_type {
            ProposalType::AddFile { path, content, .. } => {
                if let Some(content) = content {
                    let mut docs = self.documents.write().await;
                    let full_path = docs.root().join(path);
                    if !full_path.exists() {
                        match docs.add_file(path, content, &proposal.proposer_digest) {
                            Ok(_) => tracing::info!("File applied to disk: {path}"),
                            Err(e) => tracing::warn!("AddFile apply failed: {e}"),
                        }
                    }
                } else {
                    tracing::warn!("AddFile accepted but no content (legacy proposal): {path}");
                }
            }
            ProposalType::EditFile { path, diff, .. } => {
                let file_diff = crate::document::diff::FileDiff {
                    path: path.clone(),
                    unified_diff: diff.clone(),
                    additions: 0,
                    deletions: 0,
                };
                let mut docs = self.documents.write().await;
                let _ = docs.apply_edit(path, &file_diff, "network");
            }
            ProposalType::RemoveFile { path } => {
                let mut docs = self.documents.write().await;
                let _ = docs.remove_file(path);
            }
            ProposalType::MarkFinal { path } => {
                let mut docs = self.documents.write().await;
                let _ = docs.mark_final(path);
                let doc_hash = docs.content_hash(path).unwrap_or_default();
                drop(docs);

                // FROST signing ceremony after finalization
                self.trigger_frost_signing(path, &doc_hash).await;
            }
            ProposalType::ChangeFileName { path, new_name } => {
                let new_path = std::path::Path::new(path)
                    .parent()
                    .map(|p| p.join(new_name))
                    .and_then(|p| p.to_str().map(String::from))
                    .unwrap_or_else(|| new_name.clone());
                let mut docs = self.documents.write().await;
                if let Err(e) = docs.rename_file(path, &new_path) {
                    tracing::warn!("ChangeFileName apply failed: {e}");
                }
            }
            _ => {}
        }

        // 2. Broadcast sync for proposals that change governance (accepted_file_paths)
        match proposal_type {
            ProposalType::AddMember { .. }
            | ProposalType::ExpelMember { .. }
            | ProposalType::AddFile { .. }
            | ProposalType::RemoveFile { .. }
            | ProposalType::MarkFinal { .. }
            | ProposalType::ChangeFileName { .. } => {
                self.ensure_x25519_key().await;
                let gov = self.governance.read().await;
                let state_json = serde_json::to_string(&*gov)?;
                drop(gov);

                let frost = self.frost.read().await;
                let digest = frost.member_digest();
                let mut msg = GossipMessage::new(
                    &digest,
                    GossipMessageType::SyncResponse { state_json },
                    &self.config.network_name,
                );
                msg.sign(&frost);
                drop(frost);
                self.broadcast_message(&msg).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn trigger_frost_signing(&self, path: &str, doc_hash: &str) {
        let gov = self.governance.read().await;
        let mut digests: Vec<String> = gov.active_members().iter()
            .map(|m| m.identity.digest.clone())
            .collect();
        digests.sort();

        let frost_guard = self.frost.read().await;
        let my_digest = frost_guard.member_digest();

        let n = digests.len();
        if n == 0 || digests.first().map(|d| d.as_str()) != Some(&my_digest) {
            return; // not the genesis node / dealer
        }

        let t = if n == 1 { 1 } else { (n * 2) / 3 + 1 };
        tracing::info!("FROST: I am the dealer. Generating {}-of-{} keys for {}", t, n, path);

        let (group_pk_bytes, shares) = match FrostManager::generate_group_keys(t, n) {
            Ok(v) => v,
            Err(e) => { tracing::warn!("FROST keygen failed: {e}"); return; }
        };

        let session_id = uuid::Uuid::new_v4().to_string();

        // --- 1-of-1: sign entirely locally ---
        if n == 1 {
            let (share_id, share_bytes) = &shares[0];
            let mut session = crate::crypto::threshold::SigningSession::new(
                session_id.clone(), path.to_string(), doc_hash.to_string(), 1, 1, group_pk_bytes.clone(),
            );
            session.set_key_share(share_bytes.clone(), *share_id);
            if let Err(e) = session.generate_commitment() {
                tracing::warn!("FROST 1-of-1 commit failed: {e}"); return;
            }
            match session.produce_partial_signature(doc_hash.as_bytes()) {
                Ok(_) => {}
                Err(e) => { tracing::warn!("FROST 1-of-1 partial sign failed: {e}"); return; }
            }
            let sig = match session.assemble_signature() {
                Ok(s) => s,
                Err(e) => { tracing::warn!("FROST 1-of-1 assemble failed: {e}"); return; }
            };

            let verified = FrostManager::verify_group_signature(&group_pk_bytes, doc_hash.as_bytes(), &sig);
            tracing::info!("FROST: 1-of-1 signature for {} (verified={})", path, verified);

            let mut docs = self.documents.write().await;
            docs.set_threshold_signature(path, sig.clone(), group_pk_bytes.clone(), 1, 1);
            drop(docs);

            let mut result_msg = GossipMessage::new(
                &my_digest,
                GossipMessageType::ThresholdSignatureResult {
                    session_id, document_path: path.to_string(),
                    signature: sig, group_public_key: group_pk_bytes,
                    threshold: 1, total: 1,
                },
                &self.config.network_name,
            );
            result_msg.sign(&frost_guard);
            drop(frost_guard);
            drop(gov);
            if let Err(e) = self.broadcast_message(&result_msg).await {
                tracing::warn!("FROST: broadcast 1-of-1 result failed: {e}");
            }
            return;
        }

        // --- Multi-member: encrypt + distribute key shares ---
        let dealer_x25519_secret = frost_guard.x25519_secret();
        let dealer_x25519_public_hex = frost_guard.x25519_public_hex();
        let context = format!("frost-share-{}", session_id);

        let mut envelopes = Vec::new();
        let mut my_share_bytes: Option<Vec<u8>> = None;
        let mut my_share_id: Option<u16> = None;

        // Log x25519 key availability for all members
        for digest in &digests {
            let has_key = gov.members.get(digest)
                .and_then(|m| m.identity.x25519_public_key_hex.as_ref())
                .map(|k| !k.is_empty())
                .unwrap_or(false);
            tracing::info!("FROST: member {} x25519_key={}", &digest[..12], if has_key { "present" } else { "MISSING" });
        }

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
                tracing::warn!("FROST: member {} missing x25519 key, skipping", &digest[..12]);
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
                Err(e) => { tracing::warn!("FROST: encrypt share for {} failed: {e}", &digest[..12]); }
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
            &self.config.network_name,
        );
        dist_msg.sign(&frost_guard);
        drop(frost_guard);
        if let Err(e) = self.broadcast_message(&dist_msg).await {
            tracing::warn!("FROST: broadcast key distribution failed: {e}");
        }
        tracing::info!("FROST: key distribution broadcast for session {}", &session_id[..8]);

        // Dealer processes its own share locally
        if let (Some(share_bytes), Some(share_id)) = (my_share_bytes, my_share_id) {
            let mut ts = self.threshold_state.write().await;
            let session = ts.create_session(
                session_id.clone(), path.to_string(), doc_hash.to_string(),
                t as u16, n as u16, group_pk_bytes,
            );
            session.set_key_share(share_bytes, share_id);
            match session.generate_commitment() {
                Ok(comm_bytes) => {
                    drop(ts);
                    tracing::info!("FROST: dealer self-committed for session {}", &session_id[..8]);
                    let frost_guard = self.frost.read().await;
                    let mut comm_msg = GossipMessage::new(
                        &frost_guard.member_digest(),
                        GossipMessageType::SigningCommitment {
                            session_id, commitment: comm_bytes, share_id,
                        },
                        &self.config.network_name,
                    );
                    comm_msg.sign(&frost_guard);
                    drop(frost_guard);
                    if let Err(e) = self.broadcast_message(&comm_msg).await {
                        tracing::warn!("FROST: broadcast dealer commitment failed: {e}");
                    }
                }
                Err(e) => { tracing::warn!("FROST: dealer commitment failed: {e}"); }
            }
        }
    }

    pub async fn propose_add_file(&self, path: &str, content: &str) -> anyhow::Result<String> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        let content_hash = hex::encode(sha2::Sha256::digest(content.as_bytes()));

        let mut gov = self.governance.write().await;
        if !gov.check_rate_limit(&digest, self.config.rate_limit.max_requests_per_day) {
            anyhow::bail!("Rate limit exceeded");
        }
        gov.increment_rate_counter(&digest);

        let proposal_type = ProposalType::AddFile {
            path: path.to_string(),
            content_hash,
            content: Some(content.to_string()),
        };
        let proposal_id = gov.submit_proposal(proposal_type.clone(), &digest)?;
        drop(gov);

        if let Err(e) = self.broadcast_proposal(&proposal_id, &proposal_type).await {
            tracing::warn!("Broadcast AddFile proposal failed: {e}");
        }
        let _ = self.vote_on_proposal(&proposal_id, VoteChoice::Accept).await;

        Ok(proposal_id)
    }

    pub async fn propose_finalize(&self, path: &str) -> anyhow::Result<String> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        drop(frost);

        let mut gov = self.governance.write().await;
        if !gov.check_rate_limit(&digest, self.config.rate_limit.max_requests_per_day) {
            anyhow::bail!("Rate limit exceeded");
        }
        gov.increment_rate_counter(&digest);

        let proposal_type = ProposalType::MarkFinal {
            path: path.to_string(),
        };
        let proposal_id = gov.submit_proposal(proposal_type.clone(), &digest)?;
        drop(gov);

        if let Err(e) = self.broadcast_proposal(&proposal_id, &proposal_type).await {
            tracing::warn!("Broadcast MarkFinal proposal failed: {e}");
        }
        let _ = self.vote_on_proposal(&proposal_id, VoteChoice::Accept).await;

        Ok(proposal_id)
    }

    pub async fn propose_change_name(&self, path: &str, new_name: &str) -> anyhow::Result<String> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        drop(frost);

        let mut gov = self.governance.write().await;
        if !gov.is_network_file(path) {
            anyhow::bail!("File not on network: {path}");
        }
        if !gov.check_rate_limit(&digest, self.config.rate_limit.max_requests_per_day) {
            anyhow::bail!("Rate limit exceeded");
        }
        gov.increment_rate_counter(&digest);

        let proposal_type = ProposalType::ChangeFileName {
            path: path.to_string(),
            new_name: new_name.to_string(),
        };
        let proposal_id = gov.submit_proposal(proposal_type.clone(), &digest)?;
        drop(gov);

        if let Err(e) = self.broadcast_proposal(&proposal_id, &proposal_type).await {
            tracing::warn!("Broadcast ChangeFileName proposal failed: {e}");
        }
        let _ = self.vote_on_proposal(&proposal_id, VoteChoice::Accept).await;

        Ok(proposal_id)
    }

    pub async fn propose_edit_file(
        &self,
        path: &str,
        diff: &str,
        content_hash: &str,
    ) -> anyhow::Result<String> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();
        drop(frost);

        let mut gov = self.governance.write().await;
        if !gov.check_rate_limit(&digest, self.config.rate_limit.max_requests_per_day) {
            anyhow::bail!("Rate limit exceeded");
        }
        gov.increment_rate_counter(&digest);

        let proposal_type = ProposalType::EditFile {
            path: path.to_string(),
            diff: diff.to_string(),
            content_hash: content_hash.to_string(),
        };
        let proposal_id = gov.submit_proposal(proposal_type.clone(), &digest)?;
        drop(gov);

        if let Err(e) = self.broadcast_proposal(&proposal_id, &proposal_type).await {
            tracing::warn!("Broadcast EditFile proposal failed: {e}");
        }
        let _ = self.vote_on_proposal(&proposal_id, VoteChoice::Accept).await;

        Ok(proposal_id)
    }

    pub async fn vote_on_proposal(
        &self,
        proposal_id: &str,
        choice: VoteChoice,
    ) -> anyhow::Result<ProposalStatus> {
        let frost = self.frost.read().await;
        let digest = frost.member_digest();

        let vote = Vote {
            voter_digest: digest.clone(),
            choice: choice.clone(),
            signature: frost.sign(proposal_id.as_bytes()),
            timestamp: chrono::Utc::now(),
        };

        let mut gov = self.governance.write().await;
        let status = gov.cast_vote(proposal_id, vote)?;

        if status == ProposalStatus::Accepted {
            let proposal = gov.proposals.get(proposal_id).cloned();
            drop(gov);
            if let Some(p) = proposal {
                self.on_proposal_accepted(&p).await?;
            }
        } else {
            drop(gov);
        }

        let frost2 = self.frost.read().await;
        let mut msg = GossipMessage::new(
            &digest,
            GossipMessageType::Vote {
                proposal_id: proposal_id.to_string(),
                choice,
            },
            &self.config.network_name,
        );
        msg.sign(&frost2);
        drop(frost);
        drop(frost2);
        self.broadcast_message(&msg).await?;

        Ok(status)
    }
}

use sha2::Digest;
