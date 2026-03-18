use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use quorum_trust::governance::persistence;
use reqwest::blocking::Client;
use serde_json::Value;
use tempfile::TempDir;

fn node_binary_available() -> bool {
    Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn gui_dir() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/../quorum-trust-gui")
}

struct TestNode {
    child: Child,
    rpc_port: u16,
    api_key: String,
    public_key: String,
    _temp: TempDir,
}

struct TestGui {
    child: Child,
    port: u16,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for TestGui {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn init_and_start_node(
    bin: &str,
    name: &str,
    display_name: &str,
    genesis: bool,
    node_port: u16,
    rpc_port: u16,
    public_port: u16,
    bootstrap: Option<&str>,
) -> TestNode {
    let temp = TempDir::new().unwrap();
    let base = temp.path();
    let node_dir = base.join("node");
    let config_path = node_dir.join("quorum-trust.toml");
    let docs_dir = base.join("docs");

    std::fs::create_dir_all(&node_dir).unwrap();

    let config_str = config_path.to_string_lossy().to_string();
    let docs_str = docs_dir.to_string_lossy().to_string();

    // --config is a global arg and must come before the subcommand
    let mut args: Vec<String> = vec![
        "--config".into(),
        config_str.clone(),
        "init".into(),
        "--name".into(),
        name.into(),
        "--display-name".into(),
        display_name.into(),
        "--documents-dir".into(),
        docs_str,
        "--node-port".into(),
        node_port.to_string(),
        "--rpc-port".into(),
        rpc_port.to_string(),
        "--public-port".into(),
        public_port.to_string(),
    ];
    if genesis {
        args.push("--genesis".into());
    }
    if let Some(peer) = bootstrap {
        args.push("--bootstrap".into());
        args.push(peer.into());
    }

    let output = Command::new(bin)
        .args(&args)
        .output()
        .expect("failed to run quorum-trust init");
    assert!(
        output.status.success(),
        "quorum-trust init failed for {display_name}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let public_key = std::fs::read_to_string(node_dir.join("data").join("public.key"))
        .expect("public.key not found after init")
        .trim()
        .to_string();

    // Read api key from the generated config
    let config_content = std::fs::read_to_string(&config_path).expect("config not found");
    let config_val: toml::Value = config_content.parse().expect("invalid toml config");
    let api_key = config_val["rpc_api_key"]
        .as_str()
        .expect("rpc_api_key missing")
        .to_string();

    // Reset persisted governance so node starts with clean state
    let data_dir = node_dir.join("data");
    persistence::clear_governance(&data_dir);

    let child = Command::new(bin)
        .args(["--config", &config_str, "start"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn quorum-trust start");

    let client = Client::new();
    let rpc_base = format!("http://127.0.0.1:{rpc_port}");
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(resp) = client
            .get(format!("{rpc_base}/api/status"))
            .header("x-api-key", &api_key)
            .send()
        {
            if resp.status().is_success() {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    assert!(ready, "RPC for {display_name} did not become ready within 15s");

    TestNode {
        child,
        rpc_port,
        api_key,
        public_key,
        _temp: temp,
    }
}

fn start_gui(rpc_port: u16, api_key: &str, gui_port: u16) -> TestGui {
    let child = Command::new("node")
        .arg("server.js")
        .current_dir(gui_dir())
        .env("RPC_HOST", "http://127.0.0.1")
        .env("RPC_PORT", rpc_port.to_string())
        .env("GUI_PORT", gui_port.to_string())
        .env("API_KEY", api_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn GUI server");

    let client = Client::new();
    let base = format!("http://127.0.0.1:{gui_port}");
    let mut ready = false;
    for _ in 0..80 {
        if let Ok(resp) = client.get(format!("{base}/api/status")).send() {
            if resp.status().is_success() {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    assert!(ready, "GUI on port {gui_port} did not become ready within 12s");

    TestGui {
        child,
        port: gui_port,
    }
}

fn api_get(client: &Client, base: &str, path: &str) -> Value {
    let resp = client.get(format!("{base}{path}")).send().unwrap();
    assert!(
        resp.status().is_success(),
        "GET {path} failed: {}",
        resp.status()
    );
    resp.json().unwrap()
}

fn api_post(client: &Client, base: &str, path: &str, body: &Value) -> Value {
    let resp = client
        .post(format!("{base}{path}"))
        .json(body)
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "POST {path} failed: {}",
        resp.status()
    );
    resp.json().unwrap()
}

/// Full-stack test: 2 real quorum-trust nodes + 2 real GUI servers.
/// Exercises status, propose member, gossip-sync verification (Bob sees Alice+Bob),
/// add file, edit file, list files, fork, read.
#[test]
fn test_full_stack_two_nodes_two_guis() {
    if !node_binary_available() {
        eprintln!("SKIP: `node` binary not found on PATH.");
        return;
    }

    let bin = env!("CARGO_BIN_EXE_quorum-trust");
    let client = Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
        .unwrap();

    // ── Boot Alice (genesis) ─────────────────────────────────
    println!("[full-stack] Starting Alice node (genesis)...");
    let alice = init_and_start_node(bin, "fstack", "Alice", true, 9600, 9601, 9602, None);
    println!("[full-stack] Starting Alice GUI...");
    let gui_alice = start_gui(alice.rpc_port, &alice.api_key, 4201);
    let ga = format!("http://127.0.0.1:{}", gui_alice.port);

    // ── Boot Bob ─────────────────────────────────────────────
    println!("[full-stack] Starting Bob node...");
    let bob = init_and_start_node(
        bin,
        "fstack",
        "Bob",
        false,
        9610,
        9611,
        9612,
        Some("127.0.0.1:9600"),
    );
    println!("[full-stack] Starting Bob GUI...");
    let gui_bob = start_gui(bob.rpc_port, &bob.api_key, 4202);
    let gb = format!("http://127.0.0.1:{}", gui_bob.port);

    // ═══════════════════════════════════════════════════════════
    // 1) Status via Alice's GUI
    // ═══════════════════════════════════════════════════════════
    let status = api_get(&client, &ga, "/api/status");
    assert_eq!(status["node_name"], "Alice");
    assert_eq!(status["network_name"], "fstack");
    assert_eq!(status["active_members"], 1);
    println!("[full-stack] 1/11 Alice status OK");

    // ═══════════════════════════════════════════════════════════
    // 2) Propose Bob as member via Alice's GUI
    // ═══════════════════════════════════════════════════════════
    let propose = api_post(
        &client,
        &ga,
        "/api/governance/propose-member",
        &serde_json::json!({
            "public_key_hex": bob.public_key,
            "display_name": "Bob",
        }),
    );
    assert!(propose["proposal_id"].is_string());
    println!(
        "[full-stack] 2/11 Member proposal for Bob: {}",
        propose["proposal_id"]
    );

    // Alice auto-votes; with 1 active member that's enough to accept.
    thread::sleep(Duration::from_millis(500));

    let status2 = api_get(&client, &ga, "/api/status");
    assert_eq!(
        status2["active_members"], 2,
        "Alice should see 2 members after Bob accepted"
    );
    println!("[full-stack] 3/11 Alice sees 2 active members");

    // ═══════════════════════════════════════════════════════════
    // 3) Members list via Alice GUI
    // ═══════════════════════════════════════════════════════════
    let members = api_get(&client, &ga, "/api/members");
    let names: Vec<&str> = members
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["identity"]["display_name"].as_str())
        .collect();
    assert!(names.contains(&"Alice"), "Alice missing from members");
    assert!(names.contains(&"Bob"), "Bob missing from members");
    println!("[full-stack] 4/11 Members list via Alice OK: {:?}", names);

    // ═══════════════════════════════════════════════════════════
    // 3b) Bob sees both Alice and Bob after gossip sync
    // ═══════════════════════════════════════════════════════════
    let mut bob_synced = false;
    for attempt in 1..=40 {
        let bob_st = api_get(&client, &gb, "/api/status");
        let bob_members = bob_st["active_members"].as_u64().unwrap_or(0);
        if bob_members >= 2 {
            bob_synced = true;
            println!(
                "[full-stack] 5/11 Bob synced ({} active members) after {} attempts",
                bob_members, attempt
            );
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    assert!(bob_synced, "Bob did not sync membership within 10s");

    let bob_members_list = api_get(&client, &gb, "/api/members");
    let bob_names: Vec<&str> = bob_members_list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["identity"]["display_name"].as_str())
        .collect();
    assert!(
        bob_names.contains(&"Alice"),
        "Bob should see Alice in members, got: {:?}",
        bob_names
    );
    assert!(
        bob_names.contains(&"Bob"),
        "Bob should see himself in members, got: {:?}",
        bob_names
    );
    println!(
        "[full-stack] 6/11 Bob member list OK: {:?}",
        bob_names
    );

    // ═══════════════════════════════════════════════════════════
    // 4) Add a file via Alice GUI (local first, then propose to network)
    // ═══════════════════════════════════════════════════════════
    let _add_local = api_post(
        &client,
        &ga,
        "/api/files/add",
        &serde_json::json!({
            "path": "docs/charter.md",
            "content": "# Charter\n\nVersion 1.\n",
        }),
    );
    let add = api_post(
        &client,
        &ga,
        "/api/files/propose-add",
        &serde_json::json!({ "path": "docs/charter.md" }),
    );
    assert!(add["proposal_id"].is_string());
    let add_proposal_id = add["proposal_id"].as_str().unwrap();
    println!("[full-stack] 7/11 AddFile proposal: {}", add_proposal_id);

    // Bob must vote Accept for AddFile to be accepted (2 members need 2 votes)
    api_post(
        &client,
        &gb,
        &format!("/api/proposals/{}/vote", add_proposal_id),
        &serde_json::json!({ "choice": "accept" }),
    );
    thread::sleep(Duration::from_millis(3500)); // allow vote + SyncResponse to propagate

    // ═══════════════════════════════════════════════════════════
    // 5) List files via Alice GUI
    // ═══════════════════════════════════════════════════════════
    let files = api_get(&client, &ga, "/api/files");
    let paths: Vec<&str> = files
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["path"].as_str())
        .collect();
    assert!(
        paths.iter().any(|p| p.contains("charter.md")),
        "charter.md missing: {:?}",
        paths
    );
    println!("[full-stack] 8/11 File listing OK: {:?}", paths);

    // ═══════════════════════════════════════════════════════════
    // 6) Edit file via Alice GUI (diff)
    // ═══════════════════════════════════════════════════════════
    let edit = api_post(
        &client,
        &ga,
        "/api/files/edit",
        &serde_json::json!({
            "path": "docs/charter.md",
            "new_content": "# Charter\n\nVersion 2 - updated.\n",
        }),
    );
    assert!(edit["diff"].is_string());
    assert!(edit["additions"].as_u64().unwrap() >= 1);
    assert!(edit["deletions"].as_u64().unwrap() >= 1);
    println!(
        "[full-stack] 9/11 Edit diff OK: +{} -{}",
        edit["additions"], edit["deletions"]
    );

    // ═══════════════════════════════════════════════════════════
    // 7) Read file via Alice GUI
    // ═══════════════════════════════════════════════════════════
    let read = api_get(&client, &ga, "/api/files/read?path=docs/charter.md");
    assert_eq!(read["content"], "# Charter\n\nVersion 1.\n");
    println!("[full-stack] 10/11 Read file OK");

    // ═══════════════════════════════════════════════════════════
    // 8) Fork file via Alice GUI
    // ═══════════════════════════════════════════════════════════
    let fork = api_post(
        &client,
        &ga,
        "/api/files/fork",
        &serde_json::json!({
            "path": "docs/charter.md",
            "new_name": "charter-v2.md",
            "share": false,
        }),
    );
    assert!(fork["forked_path"].is_string());
    println!("[full-stack] 11/11 Fork OK: {}", fork["forked_path"]);

    // ═══════════════════════════════════════════════════════════
    // Extra: Bob identity + proposals
    // ═══════════════════════════════════════════════════════════
    let bob_id = api_get(&client, &gb, "/api/identity");
    assert!(bob_id["digest"].is_string());
    assert!(bob_id["public_key"].is_string());
    println!("[full-stack] Bob identity: digest={}", bob_id["digest"]);

    let proposals = api_get(&client, &ga, "/api/proposals");
    let n = proposals.as_array().unwrap().len();
    assert!(n >= 2, "Expected >= 2 proposals, got {n}");
    println!("[full-stack] Proposals: {n}");

    println!("\n[full-stack] ALL TESTS PASSED.");

    drop(gui_bob);
    drop(gui_alice);
    drop(bob);
    drop(alice);
}

/// Full-stack test: 3 nodes + 3 GUIs; membership sync; file added via Alice.
#[test]
fn test_full_stack_three_nodes_and_guis() {
    if !node_binary_available() {
        eprintln!("SKIP: `node` binary not found on PATH.");
        return;
    }

    let bin = env!("CARGO_BIN_EXE_quorum-trust");
    let client = Client::new();

    println!("[full-stack-3] Starting Alice node...");
    let alice = init_and_start_node(bin, "fstack3", "Alice", true, 9700, 9701, 9702, None);
    let gui_alice = start_gui(alice.rpc_port, &alice.api_key, 4301);

    println!("[full-stack-3] Starting Bob node...");
    let bob = init_and_start_node(bin, "fstack3", "Bob", false, 9710, 9711, 9712, Some("127.0.0.1:9700"));
    let gui_bob = start_gui(bob.rpc_port, &bob.api_key, 4302);

    println!("[full-stack-3] Starting Carol node...");
    let carol = init_and_start_node(bin, "fstack3", "Carol", false, 9720, 9721, 9722, Some("127.0.0.1:9700"));
    let gui_carol = start_gui(carol.rpc_port, &carol.api_key, 4303);

    let ga = format!("http://127.0.0.1:{}", gui_alice.port);
    let gb = format!("http://127.0.0.1:{}", gui_bob.port);
    let gc = format!("http://127.0.0.1:{}", gui_carol.port);

    // Propose Bob via Alice (1 member = quorum)
    let _ = api_post(&client, &ga, "/api/governance/propose-member",
        &serde_json::json!({"public_key_hex": bob.public_key, "display_name": "Bob"}));
    thread::sleep(Duration::from_millis(1000));

    let st = api_get(&client, &ga, "/api/status");
    assert!(st["active_members"].as_u64().unwrap_or(0) >= 2, "Alice should see 2+ members");

    // Alice adds a file (local first, then propose to network)
    let _ = api_post(&client, &ga, "/api/files/add",
        &serde_json::json!({"path": "shared/note.md", "content": "# Shared Note\n\nSync test."}));
    let add = api_post(&client, &ga, "/api/files/propose-add",
        &serde_json::json!({"path": "shared/note.md"}));
    assert!(add["proposal_id"].is_string());
    thread::sleep(Duration::from_millis(2000));

    // Alice should see the file (proposer)
    let files_a = api_get(&client, &ga, "/api/files");
    let alice_has = files_a.as_array().unwrap().iter()
        .any(|f| f["path"].as_str().map(|s| s.contains("note.md")).unwrap_or(false));
    assert!(alice_has, "Alice should see shared/note.md");

    // All three GUIs must respond to status
    let _ = api_get(&client, &ga, "/api/status");
    let _ = api_get(&client, &gb, "/api/status");
    let _ = api_get(&client, &gc, "/api/status");

    let id_b = api_get(&client, &gb, "/api/identity");
    let id_c = api_get(&client, &gc, "/api/identity");
    assert!(id_b["digest"].is_string());
    assert!(id_c["digest"].is_string());

    println!("[full-stack-3] Three-node + 3 GUI test passed.");

    drop(gui_carol);
    drop(gui_bob);
    drop(gui_alice);
    drop(carol);
    drop(bob);
    drop(alice);
}
