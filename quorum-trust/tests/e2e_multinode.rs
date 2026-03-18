use quorum_trust::crypto::frost::FrostManager;
use quorum_trust::crypto::identity::MemberIdentity;
use quorum_trust::document::manager::DocumentManager;
use quorum_trust::governance::membership::GovernanceState;
use quorum_trust::governance::voting::{ProposalType, ProposalStatus, Vote, VoteChoice};

use tempfile::TempDir;

/// Simulates a multi-node QuorumTrust network locally.
/// Since actual networking requires running processes, this test
/// simulates the protocol by sharing GovernanceState between nodes.
#[allow(dead_code)]
struct SimulatedNode {
    id: usize,
    frost: FrostManager,
    identity: MemberIdentity,
    documents: DocumentManager,
    docs_dir: TempDir,
}

impl SimulatedNode {
    fn new(id: usize) -> Self {
        let frost = FrostManager::new();
        let identity = MemberIdentity::new(
            &frost.public_key_hex(),
            Some(format!("Node{}", id)),
        );
        let docs_dir = TempDir::new().unwrap();
        let documents = DocumentManager::new(docs_dir.path().to_path_buf());
        documents.ensure_root().unwrap();

        Self { id, frost, identity, documents, docs_dir }
    }
}

#[test]
fn test_e2e_five_node_network() {
    // Create 5 nodes
    let nodes: Vec<SimulatedNode> = (0..5).map(SimulatedNode::new).collect();

    // Genesis node creates the network
    let mut governance = GovernanceState::new_genesis(
        "e2e-test-network",
        nodes[0].identity.clone(),
    );

    assert_eq!(governance.active_member_count(), 1);

    // Node 0 adds nodes 1 through 4
    for i in 1..5 {
        let pid = governance
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: nodes[i].frost.public_key_hex(),
                    display_name: Some(format!("Node{}", i)),
                },
                &nodes[0].identity.digest,
            )
            .unwrap();

        // All current active members vote accept (stop once accepted)
        for j in 0..i {
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            match governance.cast_vote(&pid, vote) {
                Ok(ProposalStatus::Accepted) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    assert_eq!(governance.active_member_count(), 5);
    println!("[e2e] Network has {} active members", governance.active_member_count());

    // Node 0 proposes adding a Markdown file
    let add_pid = governance
        .submit_proposal(
            ProposalType::AddFile {
                path: "contracts/partnership.md".into(),
                content_hash: "abc123".into(),
                content: None,
            },
            &nodes[0].identity.digest,
        )
        .unwrap();

    // >2/3 of 5 = 4 needed
    for i in 0..5 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(add_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        match governance.cast_vote(&add_pid, vote) {
            Ok(ProposalStatus::Accepted) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let file_proposal = governance.proposals.get(&add_pid).unwrap();
    assert_eq!(file_proposal.status, ProposalStatus::Accepted);
    println!("[e2e] File proposal ACCEPTED with {} votes", file_proposal.accept_count());

    // Simulate each node adding the file locally
    for node in &nodes {
        let mut docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        docs.add_file(
            "contracts/partnership.md",
            "# Partnership Agreement\n\nTerms and conditions apply.\n",
            &node.identity.digest,
        )
        .unwrap();
    }

    // Node 1 proposes an edit
    let edit_diff = "--- a/contracts/partnership.md\n+++ b/contracts/partnership.md\n@@ -1,3 +1,3 @@\n # Partnership Agreement\n \n-Terms and conditions apply.\n+Updated terms and conditions.\n";
    let edit_pid = governance
        .submit_proposal(
            ProposalType::EditFile {
                path: "contracts/partnership.md".into(),
                diff: edit_diff.into(),
                content_hash: "def456".into(),
            },
            &nodes[1].identity.digest,
        )
        .unwrap();

    // All 5 nodes vote accept
    for i in 0..5 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(edit_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        let _ = governance.cast_vote(&edit_pid, vote);
    }

    let edit_proposal = governance.proposals.get(&edit_pid).unwrap();
    assert_eq!(edit_proposal.status, ProposalStatus::Accepted);
    println!("[e2e] Edit proposal ACCEPTED");

    // Node 2 proposes adding a JavaScript file
    let js_pid = governance
        .submit_proposal(
            ProposalType::AddFile {
                path: "src/utils.js".into(),
                content_hash: "js_hash".into(),
                content: None,
            },
            &nodes[2].identity.digest,
        )
        .unwrap();

    for i in 0..5 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        match governance.cast_vote(&js_pid, vote) {
            Ok(ProposalStatus::Accepted) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    assert_eq!(
        governance.proposals.get(&js_pid).unwrap().status,
        ProposalStatus::Accepted
    );
    println!("[e2e] JS file proposal ACCEPTED");

    // Node 3 proposes marking the agreement as final
    let final_pid = governance
        .submit_proposal(
            ProposalType::MarkFinal {
                path: "contracts/partnership.md".into(),
            },
            &nodes[3].identity.digest,
        )
        .unwrap();

    for i in 0..5 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        match governance.cast_vote(&final_pid, vote) {
            Ok(ProposalStatus::Accepted) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    assert_eq!(
        governance.proposals.get(&final_pid).unwrap().status,
        ProposalStatus::Accepted
    );
    println!("[e2e] Finalize proposal ACCEPTED");

    // Verify all proposals are resolved
    let pending = governance.pending_proposals();
    assert!(pending.is_empty(), "No proposals should be pending");

    // Final stats
    println!("[e2e] Total proposals: {}", governance.proposals.len());
    println!("[e2e] Active members: {}", governance.active_member_count());
    println!("[e2e] All e2e tests passed.");
}

/// Seven-node network with expel, rejection, and RemoveFile proposal.
#[test]
fn test_e2e_seven_node_expel_and_rejection() {
    let nodes: Vec<SimulatedNode> = (0..7).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("seven-node", nodes[0].identity.clone());

    // Add nodes 1–6
    for i in 1..7 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("Node{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();

        for j in 0..i {
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(&pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }
    assert_eq!(governance.active_member_count(), 7);

    // Add a file first
    let add_pid = governance.submit_proposal(
        ProposalType::AddFile {
            path: "docs/temp.md".into(),
            content_hash: "h1".into(),
            content: None,
        },
        &nodes[0].identity.digest,
    ).unwrap();
    for i in 0..7 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(add_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(governance.cast_vote(&add_pid, vote), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }

    // Propose expelling node 6; need >2/3 of 7 = 5 accepts
    let node6_digest = nodes[6].identity.digest.clone();
    let expel_pid = governance.submit_proposal(
        ProposalType::ExpelMember { member_digest: node6_digest.clone() },
        &nodes[0].identity.digest,
    ).unwrap();

    for i in 0..6 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(expel_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(governance.cast_vote(&expel_pid, vote), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }
    assert_eq!(governance.active_member_count(), 6);
    assert!(!governance.is_active_member(&node6_digest));

    // Propose RemoveFile; reject needs 2/3 of 6 = 4 rejects
    let remove_pid = governance.submit_proposal(
        ProposalType::RemoveFile { path: "docs/temp.md".into() },
        &nodes[1].identity.digest,
    ).unwrap();

    for i in 0..6 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Reject,
            signature: nodes[i].frost.sign(remove_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        let status = governance.cast_vote(&remove_pid, vote).unwrap();
        if status == ProposalStatus::Rejected {
            break;
        }
    }
    assert_eq!(governance.proposals.get(&remove_pid).unwrap().status, ProposalStatus::Rejected);
    println!("[e2e] Seven-node expel + rejection test passed.");
}

/// Concurrent proposals from different nodes; all must resolve independently.
#[test]
fn test_e2e_concurrent_proposals_from_multiple_nodes() {
    let nodes: Vec<SimulatedNode> = (0..4).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("concurrent", nodes[0].identity.clone());

    for i in 1..4 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("N{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();
        for j in 0..i {
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            let _ = governance.cast_vote(&pid, vote);
        }
    }
    assert_eq!(governance.active_member_count(), 4);

    // Node 0: AddFile, Node 1: AddFile, Node 2: AddFile (different paths)
    let p0 = governance.submit_proposal(
        ProposalType::AddFile {
            path: "a.md".into(),
            content_hash: "h0".into(),
            content: None,
        },
        &nodes[0].identity.digest,
    ).unwrap();
    let p1 = governance.submit_proposal(
        ProposalType::AddFile {
            path: "b.md".into(),
            content_hash: "h1".into(),
            content: None,
        },
        &nodes[1].identity.digest,
    ).unwrap();
    let p2 = governance.submit_proposal(
        ProposalType::AddFile {
            path: "c.md".into(),
            content_hash: "h2".into(),
            content: None,
        },
        &nodes[2].identity.digest,
    ).unwrap();

    let proposals = [&p0, &p1, &p2];
    for pid in proposals {
        for i in 0..4 {
            let vote = Vote {
                voter_digest: nodes[i].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[i].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }

    assert_eq!(governance.proposals.get(&p0).unwrap().status, ProposalStatus::Accepted);
    assert_eq!(governance.proposals.get(&p1).unwrap().status, ProposalStatus::Accepted);
    assert_eq!(governance.proposals.get(&p2).unwrap().status, ProposalStatus::Accepted);
    println!("[e2e] Concurrent proposals test passed.");
}

/// All nodes sign votes; cross-verify between nodes using FROST.
#[test]
fn test_e2e_all_signatures_frost_cross_verify() {
    let mut nodes: Vec<SimulatedNode> = (0..4).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("frost-sig", nodes[0].identity.clone());

    for i in 1..4 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("Node{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();

        for j in 0..i {
            let sig = nodes[j].frost.sign(pid.as_bytes());
            assert!(nodes[j].frost.verify(
                &nodes[j].frost.public_key_bytes(),
                pid.as_bytes(),
                &sig,
            ));
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: sig,
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(&pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }

    // Node 0 registers all members (incl. self) to verify their signatures
    let pubkeys: Vec<Vec<u8>> = (0..4).map(|i| nodes[i].frost.public_key_bytes()).collect();
    for i in 0..4 {
        nodes[0].frost.register_member(&format!("node{}", i), &pubkeys[i]).ok();
    }

    let add_pid = governance.submit_proposal(
        ProposalType::AddFile {
            path: "signed.md".into(),
            content_hash: "h".into(),
            content: None,
        },
        &nodes[0].identity.digest,
    ).unwrap();

    for i in 0..4 {
        let sig = nodes[i].frost.sign(add_pid.as_bytes());
        assert!(nodes[0].frost.verify_member_signature(
            &format!("node{}", i),
            add_pid.as_bytes(),
            &sig,
        ));
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: sig,
            timestamp: chrono::Utc::now(),
        };
        if matches!(governance.cast_vote(&add_pid, vote), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }

    assert_eq!(governance.active_member_count(), 4);
    assert_eq!(governance.proposals.get(&add_pid).unwrap().status, ProposalStatus::Accepted);
    println!("[e2e] FROST cross-verify test passed.");
}

#[test]
fn test_e2e_document_replication_across_nodes() {
    let nodes: Vec<SimulatedNode> = (0..4).map(SimulatedNode::new).collect();

    let md_files = vec![
        ("docs/readme.md", "# QuorumTrust\n\nDecentralized editing.\n"),
        ("docs/spec.md", "# Spec\n\n## Protocol\n\nDetails.\n"),
        ("src/app.js", "function main() {\n  console.log('QuorumTrust');\n}\n"),
    ];

    // Each node independently creates the same files (simulating replication)
    for node in &nodes {
        let mut docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        for (path, content) in &md_files {
            docs.add_file(path, content, &node.identity.digest).unwrap();
        }
    }

    // Verify all nodes have the same content
    for node in &nodes {
        let docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        for (path, content) in &md_files {
            assert_eq!(docs.read_file(path).unwrap(), *content);
        }
    }

    // Apply the same edit on all nodes
    for node in &nodes {
        let mut docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        let diff = docs.compute_diff("docs/readme.md", "# QuorumTrust\n\nDecentralized editing platform.\n").unwrap();
        docs.apply_edit("docs/readme.md", &diff, "network").unwrap();
    }

    // Verify consistency
    for node in &nodes {
        let docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        assert_eq!(
            docs.read_file("docs/readme.md").unwrap(),
            "# QuorumTrust\n\nDecentralized editing platform.\n"
        );
    }

    println!("[e2e] Document replication test passed across {} nodes.", nodes.len());
}

#[test]
fn test_e2e_governance_with_signature_verification() {
    let nodes: Vec<SimulatedNode> = (0..3).map(SimulatedNode::new).collect();

    let mut governance = GovernanceState::new_genesis("sig-test", nodes[0].identity.clone());

    // Add node 1
    let pid = governance.submit_proposal(
        ProposalType::AddMember {
            public_key_hex: nodes[1].frost.public_key_hex(),
            display_name: Some("Node1".into()),
        },
        &nodes[0].identity.digest,
    ).unwrap();

    // Node 0 signs the vote
    let vote_msg = format!("vote:{}:accept", pid);
    let sig = nodes[0].frost.sign(vote_msg.as_bytes());

    // Verify signature before accepting vote
    assert!(nodes[0].frost.verify(&nodes[0].frost.public_key_bytes(), vote_msg.as_bytes(), &sig));

    governance.cast_vote(&pid, Vote {
        voter_digest: nodes[0].identity.digest.clone(),
        choice: VoteChoice::Accept,
        signature: sig,
        timestamp: chrono::Utc::now(),
    }).unwrap();

    assert_eq!(governance.active_member_count(), 2);

    // Add node 2 with both existing members voting
    let pid2 = governance.submit_proposal(
        ProposalType::AddMember {
            public_key_hex: nodes[2].frost.public_key_hex(),
            display_name: Some("Node2".into()),
        },
        &nodes[0].identity.digest,
    ).unwrap();

    for i in 0..2 {
        let msg = format!("vote:{}:accept", pid2);
        let sig = nodes[i].frost.sign(msg.as_bytes());
        assert!(nodes[i].frost.verify(&nodes[i].frost.public_key_bytes(), msg.as_bytes(), &sig));

        governance.cast_vote(&pid2, Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: sig,
            timestamp: chrono::Utc::now(),
        }).unwrap();
    }

    assert_eq!(governance.active_member_count(), 3);
    println!("[e2e] Signature verification test passed with {} members.", governance.active_member_count());
}

/// End-to-end test of a full document lifecycle driven by decentralized governance
/// decisions across multiple members.
#[test]
fn test_e2e_multi_member_document_lifecycle_with_governance() {
    // Three simulated nodes with their own keys and document roots.
    let nodes: Vec<SimulatedNode> = (0..3).map(SimulatedNode::new).collect();

    // Genesis governance state with Node0 as the first active member.
    let mut governance =
        GovernanceState::new_genesis("doc-lifecycle", nodes[0].identity.clone());
    assert_eq!(governance.active_member_count(), 1);

    // Add Node1 and Node2 as members via governance proposals.
    for i in 1..3 {
        let pid = governance
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: nodes[i].frost.public_key_hex(),
                    display_name: Some(format!("Node{}", i)),
                },
                &nodes[0].identity.digest,
            )
            .unwrap();

        // All currently active members vote Accept until the proposal is accepted.
        // This simulates decentralized agreement on membership.
        let active_snapshot: Vec<String> = governance
            .active_members()
            .iter()
            .map(|m| m.identity.digest.clone())
            .collect();

        for digest in active_snapshot {
            let vote = Vote {
                voter_digest: digest,
                choice: VoteChoice::Accept,
                signature: vec![0; 64],
                timestamp: chrono::Utc::now(),
            };
            match governance.cast_vote(&pid, vote) {
                Ok(ProposalStatus::Accepted) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    assert_eq!(governance.active_member_count(), 3);

    // 1) Node0 proposes adding a shared Markdown document.
    let add_pid = governance
        .submit_proposal(
            ProposalType::AddFile {
                path: "docs/charter.md".into(),
                content_hash: "hash_v1".into(),
                content: None,
            },
            &nodes[0].identity.digest,
        )
        .unwrap();

    // All three members vote Accept; with 3 active members, 3 accepts are required.
    for i in 0..3 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        let status = governance.cast_vote(&add_pid, vote).unwrap();
        if status == ProposalStatus::Accepted {
            break;
        }
    }

    let add_prop = governance.proposals.get(&add_pid).unwrap();
    assert_eq!(add_prop.status, ProposalStatus::Accepted);

    // Apply the AddFile decision to the documents of all nodes.
    for node in &nodes {
        let mut docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        docs.add_file(
            "docs/charter.md",
            "# Charter\n\nVersion 1.\n",
            &node.identity.digest,
        )
        .unwrap();
    }

    // 2) Node1 proposes an edit to the charter.
    let edit_diff = "--- a/docs/charter.md\n+++ b/docs/charter.md\n@@ -1,3 +1,3 @@\n # Charter\n \n-Version 1.\n+Version 2.\n";
    let edit_pid = governance
        .submit_proposal(
            ProposalType::EditFile {
                path: "docs/charter.md".into(),
                diff: edit_diff.into(),
                content_hash: "hash_v2".into(),
            },
            &nodes[1].identity.digest,
        )
        .unwrap();

    for i in 0..3 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        let status = governance.cast_vote(&edit_pid, vote).unwrap();
        if status == ProposalStatus::Accepted {
            break;
        }
    }

    let edit_prop = governance.proposals.get(&edit_pid).unwrap();
    assert_eq!(edit_prop.status, ProposalStatus::Accepted);

    // Apply the edit diff to each node's document.
    for node in &nodes {
        let mut docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        let file_diff =
            docs.compute_diff("docs/charter.md", "# Charter\n\nVersion 2.\n").unwrap();
        docs.apply_edit("docs/charter.md", &file_diff, "network")
            .unwrap();
    }

    // All nodes should now see Version 2.
    for node in &nodes {
        let docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        assert_eq!(
            docs.read_file("docs/charter.md").unwrap(),
            "# Charter\n\nVersion 2.\n"
        );
    }

    // 3) Node2 proposes marking the charter as final.
    let final_pid = governance
        .submit_proposal(
            ProposalType::MarkFinal {
                path: "docs/charter.md".into(),
            },
            &nodes[2].identity.digest,
        )
        .unwrap();

    for i in 0..3 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        let status = governance.cast_vote(&final_pid, vote).unwrap();
        if status == ProposalStatus::Accepted {
            break;
        }
    }

    let final_prop = governance.proposals.get(&final_pid).unwrap();
    assert_eq!(final_prop.status, ProposalStatus::Accepted);

    // Apply finalization and verify that further in-place edits are rejected,
    // forcing collaborators to fork instead.
    for node in &nodes {
        let mut docs = DocumentManager::new(node.docs_dir.path().to_path_buf());
        docs.mark_final("docs/charter.md").unwrap();

        let attempted_diff = docs
            .compute_diff("docs/charter.md", "# Charter\n\nPost-final edit.\n")
            .unwrap();
        assert!(docs
            .apply_edit("docs/charter.md", &attempted_diff, "network")
            .is_err());

        // But a fork is still allowed. When passing only the new file name,
        // DocumentManager::fork_file preserves the original directory prefix.
        let forked = docs
            .fork_file("docs/charter.md", Some("charter-v3.md"), "network")
            .unwrap();
        assert_eq!(forked, "docs/charter-v3.md");
    }
}

/// Expel lowers active count and bumps epoch; sync adoption uses epoch.
#[test]
fn test_e2e_expel_epoch_based_sync_adoption() {
    let nodes: Vec<SimulatedNode> = (0..4).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("expel-epoch", nodes[0].identity.clone());
    assert_eq!(governance.epoch, 0);

    // Add nodes 1–3
    for i in 1..4 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("Node{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();
        for j in 0..=i.min(governance.active_member_count()) {
            if j >= nodes.len() { break; }
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(&pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }
    assert_eq!(governance.active_member_count(), 4);
    let epoch_after_adds = governance.epoch;
    assert_eq!(epoch_after_adds, 3);

    // Bob's stale copy of state before expel
    let bob_stale = governance.clone();

    // Expel node 3 (need >2/3 of 4 = 3 accepts)
    let node3_digest = nodes[3].identity.digest.clone();
    let expel_pid = governance.submit_proposal(
        ProposalType::ExpelMember { member_digest: node3_digest.clone() },
        &nodes[0].identity.digest,
    ).unwrap();
    for i in 0..4 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(expel_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(governance.cast_vote(&expel_pid, vote), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }
    assert_eq!(governance.active_member_count(), 3);
    assert!(!governance.is_active_member(&node3_digest));
    assert_eq!(governance.epoch, epoch_after_adds + 1);

    // Simulate sync: Bob's stale state should adopt via epoch comparison
    let alice_post_expel = governance.clone();
    assert!(alice_post_expel.epoch > bob_stale.epoch);
    // Old heuristic would fail: active_member_count went DOWN
    assert!(alice_post_expel.active_member_count() < bob_stale.active_member_count());
    // Epoch-based adoption works
    assert!(alice_post_expel.epoch > bob_stale.epoch);
}

/// Expelled node syncs the expel state (self-demotion accepted for expelled status).
#[test]
fn test_e2e_expelled_node_accepts_own_expulsion_via_sync() {
    let nodes: Vec<SimulatedNode> = (0..3).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("expel-sync", nodes[0].identity.clone());

    for i in 1..3 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("Node{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();
        for j in 0..3 {
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(&pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }
    assert_eq!(governance.active_member_count(), 3);

    // Node2's local copy before expel
    let mut node2_state = governance.clone();
    let node2_digest = nodes[2].identity.digest.clone();
    assert!(node2_state.is_active_member(&node2_digest));

    // Expel node2 on the "network" state
    let expel_pid = governance.submit_proposal(
        ProposalType::ExpelMember { member_digest: node2_digest.clone() },
        &nodes[0].identity.digest,
    ).unwrap();
    for i in 0..3 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(expel_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(governance.cast_vote(&expel_pid, vote), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }
    assert!(!governance.is_active_member(&node2_digest));

    // Simulate node2 receiving the sync: it should accept even though
    // it demotes itself, because its status is Expelled (not just missing).
    let remote = governance.clone();
    let i_am_active_locally = node2_state.is_active_member(&node2_digest);
    let i_am_active_in_remote = remote.is_active_member(&node2_digest);
    let i_am_expelled_in_remote = remote.members.get(&node2_digest)
        .map(|m| m.status == quorum_trust::crypto::identity::MemberStatus::Expelled)
        .unwrap_or(false);

    assert!(i_am_active_locally);
    assert!(!i_am_active_in_remote);
    assert!(i_am_expelled_in_remote);

    // The sync adoption guard allows this because expelled is a legitimate demotion
    let should_reject = i_am_active_locally && !i_am_active_in_remote && !i_am_expelled_in_remote;
    assert!(!should_reject);

    // Adopt the remote state (epoch is higher)
    assert!(remote.epoch > node2_state.epoch);
    node2_state = remote;
    assert!(!node2_state.is_active_member(&node2_digest));
    assert_eq!(node2_state.expelled_members().len(), 1);
}

/// Expel followed by re-adding the same member works.
#[test]
fn test_e2e_expel_then_readd_member() {
    let nodes: Vec<SimulatedNode> = (0..3).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("expel-readd", nodes[0].identity.clone());

    // Add node1
    let pid = governance.submit_proposal(
        ProposalType::AddMember {
            public_key_hex: nodes[1].frost.public_key_hex(),
            display_name: Some("Node1".into()),
        },
        &nodes[0].identity.digest,
    ).unwrap();
    governance.cast_vote(&pid, Vote {
        voter_digest: nodes[0].identity.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    assert_eq!(governance.active_member_count(), 2);

    let node1_digest = nodes[1].identity.digest.clone();

    // Expel node1
    let expel_pid = governance.submit_proposal(
        ProposalType::ExpelMember { member_digest: node1_digest.clone() },
        &nodes[0].identity.digest,
    ).unwrap();
    governance.cast_vote(&expel_pid, Vote {
        voter_digest: nodes[0].identity.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    governance.cast_vote(&expel_pid, Vote {
        voter_digest: node1_digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    assert_eq!(governance.active_member_count(), 1);
    assert!(!governance.is_active_member(&node1_digest));

    // Re-add node1 with the same key
    let readd_pid = governance.submit_proposal(
        ProposalType::AddMember {
            public_key_hex: nodes[1].frost.public_key_hex(),
            display_name: Some("Node1-Readmitted".into()),
        },
        &nodes[0].identity.digest,
    ).unwrap();
    governance.cast_vote(&readd_pid, Vote {
        voter_digest: nodes[0].identity.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    assert_eq!(governance.active_member_count(), 2);
    assert!(governance.is_active_member(&node1_digest));
}

/// Expel proposal can be rejected by the network.
#[test]
fn test_e2e_expel_proposal_rejected() {
    let nodes: Vec<SimulatedNode> = (0..5).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("expel-reject", nodes[0].identity.clone());

    for i in 1..5 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("Node{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();
        for j in 0..5 {
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(&pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }
    assert_eq!(governance.active_member_count(), 5);

    let node4_digest = nodes[4].identity.digest.clone();
    let epoch_before = governance.epoch;

    // Propose expelling node4, but majority rejects
    let expel_pid = governance.submit_proposal(
        ProposalType::ExpelMember { member_digest: node4_digest.clone() },
        &nodes[0].identity.digest,
    ).unwrap();

    // 4 out of 5 reject -> >2/3 rejects
    for i in 0..5 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Reject,
            signature: nodes[i].frost.sign(expel_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        let status = governance.cast_vote(&expel_pid, vote).unwrap();
        if status == ProposalStatus::Rejected { break; }
    }

    // Expel was rejected; node4 still active, epoch unchanged
    assert!(governance.is_active_member(&node4_digest));
    assert_eq!(governance.active_member_count(), 5);
    assert_eq!(governance.epoch, epoch_before);
}

/// After expulsion, the expelled member's votes on existing pending proposals
/// are no longer counted (they fail if cast after expulsion).
#[test]
fn test_e2e_expelled_member_pending_proposals() {
    let nodes: Vec<SimulatedNode> = (0..3).map(SimulatedNode::new).collect();

    let mut governance =
        GovernanceState::new_genesis("expel-pending", nodes[0].identity.clone());

    // Add all 3 nodes
    for i in 1..3 {
        let pid = governance.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: nodes[i].frost.public_key_hex(),
                display_name: Some(format!("Node{}", i)),
            },
            &nodes[0].identity.digest,
        ).unwrap();
        for j in 0..3 {
            let vote = Vote {
                voter_digest: nodes[j].identity.digest.clone(),
                choice: VoteChoice::Accept,
                signature: nodes[j].frost.sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(governance.cast_vote(&pid, vote), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }
    assert_eq!(governance.active_member_count(), 3);

    // Node0 proposes a file
    let file_pid = governance.submit_proposal(
        ProposalType::AddFile {
            path: "important.md".into(),
            content: None,
            content_hash: "h".into(),
        },
        &nodes[0].identity.digest,
    ).unwrap();

    // Expel node2 before they can vote on the file proposal
    let node2_digest = nodes[2].identity.digest.clone();
    let expel_pid = governance.submit_proposal(
        ProposalType::ExpelMember { member_digest: node2_digest.clone() },
        &nodes[0].identity.digest,
    ).unwrap();
    for i in 0..3 {
        let vote = Vote {
            voter_digest: nodes[i].identity.digest.clone(),
            choice: VoteChoice::Accept,
            signature: nodes[i].frost.sign(expel_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(governance.cast_vote(&expel_pid, vote), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }
    assert!(!governance.is_active_member(&node2_digest));

    // Node2 tries to vote on the file proposal after being expelled
    let result = governance.cast_vote(&file_pid, Vote {
        voter_digest: node2_digest,
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    });
    assert!(result.is_err());
}
