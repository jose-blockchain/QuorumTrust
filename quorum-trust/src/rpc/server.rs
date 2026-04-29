use crate::governance::voting::VoteChoice;
use crate::network::QuorumNetwork;
use sha2::Digest;
use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
    details: Option<String>,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

type SharedNetwork = Arc<RwLock<QuorumNetwork>>;

pub struct RpcServer {
    network: SharedNetwork,
    api_key: String,
    bind_localhost_only: bool,
    port: u16,
}

impl RpcServer {
    pub fn new(network: SharedNetwork, api_key: String, port: u16, localhost_only: bool) -> Self {
        Self {
            network,
            api_key,
            bind_localhost_only: localhost_only,
            port,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let api_key = self.api_key.clone();
        let network = self.network.clone();

        let app = Router::new()
            .route("/api/status", get(get_status))
            .route("/api/members", get(get_members))
            .route("/api/proposals", get(get_proposals))
            .route("/api/proposals/:id/vote", post(vote_on_proposal))
            .route("/api/files", get(list_files))
            .route("/api/files/read", get(read_file))
            .route("/api/files/add", post(add_file_local))
            .route("/api/files/propose-add", post(propose_add_file))
            .route("/api/files/edit", post(edit_file))
            .route("/api/files/fork", post(fork_file))
            .route("/api/files/finalize", post(finalize_file))
            .route("/api/files/rename-local", post(rename_file_local))
            .route("/api/files/propose-rename", post(propose_change_name))
            .route("/api/governance/propose-member", post(propose_member))
            .route("/api/governance/propose-expel", post(propose_expel))
            .route("/api/governance/sync", post(trigger_governance_sync))
            .route("/api/identity", get(get_identity))
            .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
            .layer(TraceLayer::new_for_http())
            .with_state(AppState {
                network,
                api_key,
            });

        let host = if self.bind_localhost_only {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        };
        let addr: SocketAddr = format!("{host}:{}", self.port).parse()?;
        tracing::info!("RPC server listening on {addr}");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    network: SharedNetwork,
    api_key: String,
}

fn check_api_key(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key != state.api_key {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

#[derive(Serialize)]
struct StatusResponse {
    node_name: Option<String>,
    network_name: String,
    active_members: usize,
    pending_proposals: usize,
    proposals_awaiting_my_vote: usize,
    is_active_member: bool,
    node_digest: String,
    node_public_key: String,
}

async fn get_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let gov = net.governance.read().await;
    let frost = net.frost.read().await;

    let digest = frost.member_digest();
    let is_active = gov.is_active_member(&digest);
    Ok(Json(StatusResponse {
        node_name: net.config.node_name.clone(),
        network_name: gov.network_name.clone(),
        active_members: gov.active_member_count(),
        pending_proposals: gov.pending_proposals().len(),
        proposals_awaiting_my_vote: if is_active { gov.proposals_awaiting_vote(&digest) } else { 0 },
        is_active_member: is_active,
        node_digest: digest,
        node_public_key: frost.public_key_hex(),
    }))
}

async fn get_members(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let gov = net.governance.read().await;

    let members: Vec<_> = gov.members.values().cloned().collect();
    Ok(Json(members))
}

async fn get_proposals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let gov = net.governance.read().await;

    let mut proposals: Vec<_> = gov.proposals.values().cloned().collect();
    proposals.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(Json(proposals))
}

#[derive(Deserialize)]
struct VoteRequest {
    choice: String,
}

async fn vote_on_proposal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<VoteRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let choice = match body.choice.as_str() {
        "accept" => VoteChoice::Accept,
        "reject" => VoteChoice::Reject,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let net = state.network.read().await;
    match net.vote_on_proposal(&id, choice).await {
        Ok(status) => Ok(Json(serde_json::json!({ "status": format!("{:?}", status) }))),
        Err(e) => {
            tracing::error!("Vote error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_files(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let mut docs = net.documents.write().await;
    let mut files = match docs.list_files() {
        Ok(f) => f,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let gov = net.governance.read().await;
    for f in &mut files {
        f.is_network = gov.is_network_file(&f.path);
    }
    Ok(Json(files))
}

#[derive(Deserialize)]
struct ReadFileQuery {
    path: String,
}

async fn read_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReadFileQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let docs = net.documents.read().await;
    match docs.read_file(&q.path) {
        Ok(content) => Ok(Json(serde_json::json!({ "path": q.path, "content": content }))),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct AddFileRequest {
    path: String,
    content: String,
}

/// Add file locally only (no proposal). Use propose-add to submit to network.
async fn add_file_local(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AddFileRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let frost = net.frost.read().await;
    let digest = frost.member_digest();
    drop(frost);
    let mut docs = net.documents.write().await;
    match docs.add_file(&body.path, &body.content, &digest) {
        Ok(_) => Ok(Json(serde_json::json!({ "path": body.path }))),
        Err(e) => {
            tracing::error!("Add file local error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ProposeAddFileRequest {
    path: String,
}

/// Propose an existing local file to the network (arrow button). Reads content from disk.
async fn propose_add_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProposeAddFileRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let docs = net.documents.read().await;
    let content = docs.read_file(&body.path).map_err(|e| {
        tracing::error!("Propose add: read failed {e}");
        StatusCode::NOT_FOUND
    })?;
    drop(docs);
    match net.propose_add_file(&body.path, &content).await {
        Ok(proposal_id) => Ok(Json(serde_json::json!({ "proposal_id": proposal_id }))),
        Err(e) => {
            tracing::error!("Propose add file error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct EditFileRequest {
    path: String,
    new_content: String,
}

async fn edit_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EditFileRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let gov = net.governance.read().await;
    if !gov.is_network_file(&body.path) {
        return Err(StatusCode::BAD_REQUEST);
    }
    drop(gov);
    let docs = net.documents.read().await;
    let diff = match docs.compute_diff(&body.path, &body.new_content) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Edit error: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    drop(docs);
    match net
        .propose_edit_file(
            &body.path,
            &diff.unified_diff,
            &hex::encode(sha2::Sha256::digest(body.new_content.as_bytes())),
        )
        .await
    {
        Ok(proposal_id) => Ok(Json(serde_json::json!({
            "proposal_id": proposal_id,
            "path": body.path,
            "diff": diff.unified_diff,
            "additions": diff.additions,
            "deletions": diff.deletions,
        }))),
        Err(e) => {
            tracing::error!("Edit proposal error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ForkRequest {
    path: String,
    new_name: Option<String>,
    share: bool,
}

async fn fork_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ForkRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let frost = net.frost.read().await;
    let digest = frost.member_digest();
    drop(frost);

    let mut docs = net.documents.write().await;
    match docs.fork_file(&body.path, body.new_name.as_deref(), &digest) {
        Ok(new_path) => Ok(Json(serde_json::json!({
            "forked_path": new_path,
            "shared": body.share,
        }))),
        Err(e) => {
            tracing::error!("Fork error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct FinalizeRequest {
    path: String,
}

async fn finalize_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FinalizeRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let gov = net.governance.read().await;
    if !gov.is_network_file(&body.path) {
        return Err(StatusCode::BAD_REQUEST);
    }
    drop(gov);
    match net.propose_finalize(&body.path).await {
        Ok(pid) => Ok(Json(serde_json::json!({ "proposal_id": pid }))),
        Err(e) => {
            tracing::error!("Finalize error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ProposeMemberRequest {
    public_key_hex: String,
    display_name: Option<String>,
}

async fn propose_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProposeMemberRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let frost = net.frost.read().await;
    let digest = frost.member_digest();
    drop(frost);

    let mut gov = net.governance.write().await;
    let proposal_type = crate::governance::voting::ProposalType::AddMember {
        public_key_hex: body.public_key_hex.trim().to_string(),
        display_name: body.display_name,
    };
    match gov.submit_proposal(proposal_type.clone(), &digest) {
        Ok(pid) => {
            drop(gov);
            if let Err(e) = net.broadcast_proposal(&pid, &proposal_type).await {
                tracing::warn!("Broadcast member proposal failed: {e}");
            }
            if let Err(e) = net.vote_on_proposal(&pid, VoteChoice::Accept).await {
                tracing::error!("Auto-vote on member proposal failed: {e}");
            }
            Ok(Json(serde_json::json!({ "proposal_id": pid })))
        }
        Err(e) => {
            tracing::error!("Propose member error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ProposeExpelRequest {
    member_digest: String,
}

async fn propose_expel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProposeExpelRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let frost = net.frost.read().await;
    let digest = frost.member_digest();
    drop(frost);

    let mut gov = net.governance.write().await;
    let proposal_type = crate::governance::voting::ProposalType::ExpelMember {
        member_digest: body.member_digest,
    };
    match gov.submit_proposal(proposal_type.clone(), &digest) {
        Ok(pid) => {
            drop(gov);
            if let Err(e) = net.broadcast_proposal(&pid, &proposal_type).await {
                tracing::warn!("Broadcast expel proposal failed: {e}");
            }
            if let Err(e) = net.vote_on_proposal(&pid, VoteChoice::Accept).await {
                tracing::error!("Auto-vote on expel proposal failed: {e}");
            }
            Ok(Json(serde_json::json!({ "proposal_id": pid })))
        }
        Err(e) => {
            tracing::error!("Propose expel error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn trigger_governance_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    if let Err(e) = net.request_governance_sync().await {
        tracing::error!("Governance sync request failed: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Deserialize)]
struct RenameLocalRequest {
    path: String,
    new_name: String,
}

/// Rename a local-only file. Fails if file is on the network.
async fn rename_file_local(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RenameLocalRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let gov = net.governance.read().await;
    if gov.is_network_file(&body.path) {
        return Err(StatusCode::BAD_REQUEST);
    }
    drop(gov);
    let new_path = std::path::Path::new(&body.path)
        .parent()
        .map(|p| p.join(&body.new_name))
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| body.new_name.clone());
    let mut docs = net.documents.write().await;
    match docs.rename_file(&body.path, &new_path) {
        Ok(_) => Ok(Json(serde_json::json!({ "path": new_path }))),
        Err(e) => {
            tracing::error!("Rename local error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ProposeRenameRequest {
    path: String,
    new_name: String,
}

/// Propose a name change for a network file. Requires vote.
async fn propose_change_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProposeRenameRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    match net.propose_change_name(&body.path, &body.new_name).await {
        Ok(proposal_id) => Ok(Json(serde_json::json!({ "proposal_id": proposal_id }))),
        Err(e) => {
            tracing::error!("Propose rename error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_api_key(&state, &headers)?;
    let net = state.network.read().await;
    let frost = net.frost.read().await;
    Ok(Json(serde_json::json!({
        "digest": frost.member_digest(),
        "public_key": frost.public_key_hex(),
    })))
}
