//! In-process RPC integration tests.
//! Starts QuorumNetwork + RPC server and hits endpoints with reqwest.

use chaincraft::clear_local_registry;
use quorum_trust::config::{GenesisConfig, NodeConfig};
use quorum_trust::governance::persistence;
use quorum_trust::network::QuorumNetwork;
use quorum_trust::rpc::RpcServer;
use reqwest::blocking::Client;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

const API_KEY: &str = "rpc-test-key-12345";

fn make_test_config(temp: &TempDir, base_port: u16) -> NodeConfig {
    let base = temp.path();
    let node_dir = base.join("node");
    let data_dir = node_dir.join("data");
    let docs_dir = base.join("docs");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&docs_dir).unwrap();

    let frost = quorum_trust::crypto::frost::FrostManager::new();
    let secret_hex = hex::encode(frost.secret_key_bytes());
    std::fs::write(data_dir.join("secret.key"), &secret_hex).unwrap();
    std::fs::write(data_dir.join("public.key"), frost.public_key_hex()).unwrap();
    std::fs::write(data_dir.join("digest"), frost.member_digest()).unwrap();

    // Reset persisted governance so node starts with clean state
    persistence::clear_governance(&data_dir);

    NodeConfig {
        node_name: Some("RpcTestNode".into()),
        network_name: "rpc-test-net".into(),
        node_port: base_port,
        rpc_port: base_port + 9,
        public_port: base_port + 2,
        rpc_api_key: API_KEY.to_string(),
        rpc_bind_localhost_only: true,
        documents_dir: docs_dir.clone(),
        data_dir: data_dir.clone(),
        secret_key_file: data_dir.join("secret.key"),
        genesis: Some(GenesisConfig {
            member_name: "RpcTestNode".into(),
            public_key_hex: frost.public_key_hex(),
        }),
        bootstrap_peers: vec![],
        ..NodeConfig::default()
    }
}

#[test]
fn test_rpc_status_members_identity() {
    clear_local_registry();
    let temp = TempDir::new().unwrap();
    let base_port = 19990u16;
    let config = make_test_config(&temp, base_port);
    let rpc_port = base_port + 9;

    let rt = Runtime::new().unwrap();
    let (network, mut broadcast_rx) = rt.block_on(async {
        let (net, rx) = QuorumNetwork::new(config.clone()).await.unwrap();
        net.start().await.unwrap();
        (net, rx)
    });

    let network = Arc::new(RwLock::new(network));
    let state = network.clone();
    rt.spawn(async move {
        while let Some(msg) = broadcast_rx.recv().await {
            let guard = state.read().await;
            let _ = guard.broadcast_message(&msg).await;
        }
    });

    let rpc = RpcServer::new(network.clone(), API_KEY.to_string(), rpc_port, true);
    rt.spawn(async move {
        let _ = rpc.run().await;
    });

    thread::sleep(Duration::from_millis(500));

    let client = Client::new();
    let base = format!("http://127.0.0.1:{rpc_port}");

    let status: serde_json::Value = client
        .get(format!("{base}/api/status"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(status["node_name"], "RpcTestNode");
    assert_eq!(status["network_name"], "rpc-test-net");
    assert_eq!(status["active_members"], 1);

    let members: Vec<serde_json::Value> = client
        .get(format!("{base}/api/members"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["identity"]["display_name"], "RpcTestNode");

    let identity: serde_json::Value = client
        .get(format!("{base}/api/identity"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert!(identity["digest"].is_string());
    assert!(identity["public_key"].is_string());

    let _files: Vec<serde_json::Value> = client
        .get(format!("{base}/api/files"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();
}

#[test]
fn test_rpc_propose_member_and_add_file() {
    clear_local_registry();
    let temp = TempDir::new().unwrap();
    let base_port = 19970u16;
    let config = make_test_config(&temp, base_port);
    let rpc_port = base_port + 9;

    let rt = Runtime::new().unwrap();
    let (network, mut broadcast_rx) = rt.block_on(async {
        let (net, rx) = QuorumNetwork::new(config.clone()).await.unwrap();
        net.start().await.unwrap();
        (net, rx)
    });

    let network = Arc::new(RwLock::new(network));
    let state = network.clone();
    rt.spawn(async move {
        while let Some(msg) = broadcast_rx.recv().await {
            let guard = state.read().await;
            let _ = guard.broadcast_message(&msg).await;
        }
    });

    let rpc = RpcServer::new(network.clone(), API_KEY.to_string(), rpc_port, true);
    rt.spawn(async move {
        let _ = rpc.run().await;
    });

    thread::sleep(Duration::from_millis(500));

    let client = Client::new();
    let base = format!("http://127.0.0.1:{rpc_port}");

    let bob_frost = quorum_trust::crypto::frost::FrostManager::new();

    let propose_member: serde_json::Value = client
        .post(format!("{base}/api/governance/propose-member"))
        .header("x-api-key", API_KEY)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "public_key_hex": bob_frost.public_key_hex(),
            "display_name": "Bob"
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert!(propose_member.get("proposal_id").unwrap().as_str().is_some());

    let add_file: serde_json::Value = client
        .post(format!("{base}/api/files/add"))
        .header("x-api-key", API_KEY)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "path": "readme.md",
            "content": "# Hello\n"
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(add_file.get("path").and_then(|p| p.as_str()), Some("readme.md"));

    let files: Vec<serde_json::Value> = client
        .get(format!("{base}/api/files"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();

    let paths: Vec<&str> = files
        .iter()
        .filter_map(|f| f.get("path").and_then(|p| p.as_str()))
        .collect();
    assert!(paths.contains(&"readme.md"));
}

#[test]
fn test_rpc_rejects_missing_api_key() {
    clear_local_registry();
    let temp = TempDir::new().unwrap();
    let base_port = 19980u16;
    let config = make_test_config(&temp, base_port);
    let rpc_port = base_port + 9;

    let rt = Runtime::new().unwrap();
    let (network, mut broadcast_rx) = rt.block_on(async {
        let (net, rx) = QuorumNetwork::new(config.clone()).await.unwrap();
        net.start().await.unwrap();
        (net, rx)
    });

    let network = Arc::new(RwLock::new(network));
    let state = network.clone();
    rt.spawn(async move {
        while let Some(msg) = broadcast_rx.recv().await {
            let guard = state.read().await;
            let _ = guard.broadcast_message(&msg).await;
        }
    });

    let rpc = RpcServer::new(network, API_KEY.to_string(), rpc_port, true);
    rt.spawn(async move {
        let _ = rpc.run().await;
    });

    thread::sleep(Duration::from_millis(400));

    let client = Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{rpc_port}/api/status"))
        .send()
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[test]
fn test_rpc_propose_expel_lifecycle() {
    clear_local_registry();
    let temp = TempDir::new().unwrap();
    let base_port = 19960u16;
    let config = make_test_config(&temp, base_port);
    let rpc_port = base_port + 9;

    let rt = Runtime::new().unwrap();
    let (network, mut broadcast_rx) = rt.block_on(async {
        let (net, rx) = QuorumNetwork::new(config.clone()).await.unwrap();
        net.start().await.unwrap();
        (net, rx)
    });

    let network = Arc::new(RwLock::new(network));
    let state = network.clone();
    rt.spawn(async move {
        while let Some(msg) = broadcast_rx.recv().await {
            let guard = state.read().await;
            let _ = guard.broadcast_message(&msg).await;
        }
    });

    let rpc = RpcServer::new(network.clone(), API_KEY.to_string(), rpc_port, true);
    rt.spawn(async move {
        let _ = rpc.run().await;
    });

    thread::sleep(Duration::from_millis(500));

    let client = Client::new();
    let base = format!("http://127.0.0.1:{rpc_port}");

    // First add a member so we have someone to expel
    let bob_frost = quorum_trust::crypto::frost::FrostManager::new();
    let bob_digest = quorum_trust::crypto::identity::MemberIdentity::compute_digest(&bob_frost.public_key_hex());

    let _propose: serde_json::Value = client
        .post(format!("{base}/api/governance/propose-member"))
        .header("x-api-key", API_KEY)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "public_key_hex": bob_frost.public_key_hex(),
            "display_name": "Bob"
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();

    // With 1 active member, the proposal auto-accepts.
    // Verify Bob is now a member.
    thread::sleep(Duration::from_millis(200));
    let members: Vec<serde_json::Value> = client
        .get(format!("{base}/api/members"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(members.len(), 2);

    // Propose expelling Bob
    let expel_resp: serde_json::Value = client
        .post(format!("{base}/api/governance/propose-expel"))
        .header("x-api-key", API_KEY)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "member_digest": bob_digest
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(expel_resp.get("proposal_id").is_some());

    // With 2 active members, genesis auto-votes Accept.
    // Bob also needs to vote for >2/3, but the RPC only auto-votes from proposer.
    // Check proposals to find the pending expel proposal.
    thread::sleep(Duration::from_millis(200));
    let proposals: Vec<serde_json::Value> = client
        .get(format!("{base}/api/proposals"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();

    let expel_proposals: Vec<&serde_json::Value> = proposals.iter()
        .filter(|p| {
            p.get("proposal_type")
                .and_then(|pt| pt.get("ExpelMember"))
                .is_some()
        })
        .collect();
    assert!(!expel_proposals.is_empty());

    // Attempt to expel self should fail
    let identity: serde_json::Value = client
        .get(format!("{base}/api/identity"))
        .header("x-api-key", API_KEY)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let my_digest = identity["digest"].as_str().unwrap();

    let self_expel_resp = client
        .post(format!("{base}/api/governance/propose-expel"))
        .header("x-api-key", API_KEY)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "member_digest": my_digest
        }))
        .send()
        .unwrap();
    assert_eq!(self_expel_resp.status().as_u16(), 500);
}

#[test]
fn test_rpc_expel_nonexistent_member_fails() {
    clear_local_registry();
    let temp = TempDir::new().unwrap();
    let base_port = 19950u16;
    let config = make_test_config(&temp, base_port);
    let rpc_port = base_port + 9;

    let rt = Runtime::new().unwrap();
    let (network, mut broadcast_rx) = rt.block_on(async {
        let (net, rx) = QuorumNetwork::new(config.clone()).await.unwrap();
        net.start().await.unwrap();
        (net, rx)
    });

    let network = Arc::new(RwLock::new(network));
    let state = network.clone();
    rt.spawn(async move {
        while let Some(msg) = broadcast_rx.recv().await {
            let guard = state.read().await;
            let _ = guard.broadcast_message(&msg).await;
        }
    });

    let rpc = RpcServer::new(network, API_KEY.to_string(), rpc_port, true);
    rt.spawn(async move {
        let _ = rpc.run().await;
    });

    thread::sleep(Duration::from_millis(500));

    let client = Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{rpc_port}/api/governance/propose-expel"))
        .header("x-api-key", API_KEY)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "member_digest": "nonexistent_digest_value"
        }))
        .send()
        .unwrap();

    assert_eq!(resp.status().as_u16(), 500);
}
