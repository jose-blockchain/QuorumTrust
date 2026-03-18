use quorum_trust::config::NodeConfig;
use quorum_trust::crypto::frost::FrostManager;
use quorum_trust::crypto::identity::MemberIdentity;
use quorum_trust::document::diff::FileDiff;
use quorum_trust::document::manager::DocumentManager;

use quorum_trust::governance::membership::GovernanceState;
use quorum_trust::governance::voting::{ProposalType, ProposalStatus, Vote, VoteChoice};

use tempfile::TempDir;

// --- Crypto Integration Tests ---

#[test]
fn test_frost_manager_full_lifecycle() {
    let alice = FrostManager::new();
    let bob = FrostManager::new();

    assert_ne!(alice.public_key_hex(), bob.public_key_hex());
    assert_ne!(alice.member_digest(), bob.member_digest());

    let msg = b"document content hash";
    let sig_a = alice.sign(msg);
    let sig_b = bob.sign(msg);

    assert!(alice.verify(&alice.public_key_bytes(), msg, &sig_a));
    assert!(bob.verify(&bob.public_key_bytes(), msg, &sig_b));
    assert!(!alice.verify(&bob.public_key_bytes(), msg, &sig_a));
}

#[test]
fn test_cross_verification() {
    let alice = FrostManager::new();
    let mut bob = FrostManager::new();

    bob.register_member("alice", &alice.public_key_bytes()).unwrap();

    let msg = b"cross-verify test";
    let sig = alice.sign(msg);
    assert!(bob.verify_member_signature("alice", msg, &sig));
    assert!(!bob.verify_member_signature("alice", b"wrong", &sig));
}

// --- Governance Integration Tests ---

#[test]
fn test_full_governance_lifecycle_five_members() {
    let members: Vec<_> = (0..5)
        .map(|_| FrostManager::new())
        .collect();

    let genesis_id = MemberIdentity::new(
        &members[0].public_key_hex(),
        Some("Genesis".into()),
    );
    let mut state = GovernanceState::new_genesis("test-net", genesis_id.clone());

    // Add members 2 through 5
    for i in 1..5 {
        let pid = state
            .submit_proposal(
                ProposalType::AddMember {
                    public_key_hex: members[i].public_key_hex(),
                    display_name: Some(format!("Member{}", i + 1)),
                },
                &genesis_id.digest,
            )
            .unwrap();

        // All active members vote accept (stop once accepted)
        for j in 0..i {
            let voter_digest = MemberIdentity::compute_digest(&members[j].public_key_hex());
            let vote = Vote {
                voter_digest,
                choice: VoteChoice::Accept,
                signature: members[j].sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            match state.cast_vote(&pid, vote) {
                Ok(ProposalStatus::Accepted) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    assert_eq!(state.active_member_count(), 5);

    // Expel member 5
    let m5_digest = MemberIdentity::compute_digest(&members[4].public_key_hex());
    let expel_pid = state
        .submit_proposal(
            ProposalType::ExpelMember {
                member_digest: m5_digest.clone(),
            },
            &genesis_id.digest,
        )
        .unwrap();

    for i in 0..5 {
        let voter_digest = MemberIdentity::compute_digest(&members[i].public_key_hex());
        let vote = Vote {
            voter_digest,
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        match state.cast_vote(&expel_pid, vote) {
            Ok(ProposalStatus::Accepted) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    assert_eq!(state.active_member_count(), 4);
    assert!(!state.is_active_member(&m5_digest));
}

#[test]
fn test_proposal_rejection() {
    let m1 = FrostManager::new();
    let m2 = FrostManager::new();
    let m3 = FrostManager::new();

    let id1 = MemberIdentity::new(&m1.public_key_hex(), Some("M1".into()));
    let mut state = GovernanceState::new_genesis("test", id1.clone());

    // Add m2
    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: m2.public_key_hex(), display_name: None },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    // Add m3
    let id2 = MemberIdentity::compute_digest(&m2.public_key_hex());
    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: m3.public_key_hex(), display_name: None },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(), choice: VoteChoice::Accept,
        signature: vec![0; 64], timestamp: chrono::Utc::now(),
    }).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id2.clone(), choice: VoteChoice::Accept,
        signature: vec![0; 64], timestamp: chrono::Utc::now(),
    }).unwrap();

    assert_eq!(state.active_member_count(), 3);

    // Propose adding a 4th member, but 2 out of 3 reject
    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: "new_pk".into(), display_name: None },
        &id1.digest,
    ).unwrap();

    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(), choice: VoteChoice::Reject,
        signature: vec![0; 64], timestamp: chrono::Utc::now(),
    }).unwrap();
    let status = state.cast_vote(&pid, Vote {
        voter_digest: id2, choice: VoteChoice::Reject,
        signature: vec![0; 64], timestamp: chrono::Utc::now(),
    }).unwrap();

    assert_eq!(status, ProposalStatus::Rejected);
}

// --- Document Integration Tests ---

#[test]
fn test_document_full_lifecycle() {
    let dir = TempDir::new().unwrap();
    let mut mgr = DocumentManager::new(dir.path().to_path_buf());

    // Add files
    mgr.add_file("README.md", "# Project\n\nDescription here.\n", "alice").unwrap();
    mgr.add_file("src/main.js", "console.log('hello');\n", "alice").unwrap();
    mgr.add_file("contracts/agreement.md", "# Agreement\n\nTerms...\n", "bob").unwrap();

    // Verify reads
    assert_eq!(mgr.read_file("README.md").unwrap(), "# Project\n\nDescription here.\n");
    assert_eq!(mgr.read_file("src/main.js").unwrap(), "console.log('hello');\n");

    // Edit via diff
    let diff = mgr.compute_diff("README.md", "# Project\n\nUpdated description.\n").unwrap();
    assert_eq!(diff.additions, 1);
    assert_eq!(diff.deletions, 1);
    let ver = mgr.apply_edit("README.md", &diff, "bob").unwrap();
    assert_eq!(ver, 2);
    assert_eq!(mgr.read_file("README.md").unwrap(), "# Project\n\nUpdated description.\n");

    // Fork
    let forked = mgr.fork_file("README.md", Some("README-v2.md"), "charlie").unwrap();
    assert_eq!(forked, "README-v2.md");
    assert_eq!(mgr.read_file("README-v2.md").unwrap(), "# Project\n\nUpdated description.\n");

    // Finalize
    mgr.mark_final("contracts/agreement.md").unwrap();
    let diff2 = FileDiff::compute("contracts/agreement.md", "# Agreement\n\nTerms...\n", "Changed\n");
    assert!(mgr.apply_edit("contracts/agreement.md", &diff2, "alice").is_err());

    // Auto-fork with timestamp suffix
    let auto_forked = mgr.fork_file("src/main.js", None, "alice").unwrap();
    assert!(auto_forked.contains("-fork-"));
    assert!(auto_forked.ends_with(".js"));

    // List files
    let files = mgr.list_files().unwrap();
    assert!(files.len() >= 4);
}

#[test]
fn test_diff_save_and_versioning() {
    let dir = TempDir::new().unwrap();
    let mut mgr = DocumentManager::new(dir.path().to_path_buf());

    mgr.add_file("doc.md", "line1\nline2\nline3\n", "alice").unwrap();

    // Multiple edits
    for i in 0..5 {
        let new_content = format!("line1\nedit{}\nline3\n", i);
        let diff = mgr.compute_diff("doc.md", &new_content).unwrap();
        let ver = mgr.apply_edit("doc.md", &diff, "bob").unwrap();
        assert_eq!(ver, (i + 2) as u64);
    }

    assert_eq!(mgr.read_file("doc.md").unwrap(), "line1\nedit4\nline3\n");
}

// --- Rate Limiting Tests ---

#[test]
fn test_rate_limiting() {
    let id = MemberIdentity::new("pk1", Some("Test".into()));
    let mut state = GovernanceState::new_genesis("test", id.clone());

    assert!(state.check_rate_limit(&id.digest, 3));

    state.increment_rate_counter(&id.digest);
    state.increment_rate_counter(&id.digest);
    assert!(state.check_rate_limit(&id.digest, 3));

    state.increment_rate_counter(&id.digest);
    assert!(!state.check_rate_limit(&id.digest, 3));
}

// --- Governance Snapshot / Threshold Tests ---

#[test]
fn test_governance_snapshot_adoption_from_genesis() {
    // Alice creates a network and adds Bob as a member.
    let alice_frost = FrostManager::new();
    let bob_frost = FrostManager::new();

    let alice_identity =
        MemberIdentity::new(&alice_frost.public_key_hex(), Some("Alice".into()));
    let mut alice_state = GovernanceState::new_genesis("snapshot-net", alice_identity.clone());

    let add_bob_pid = alice_state
        .submit_proposal(
            ProposalType::AddMember {
                public_key_hex: bob_frost.public_key_hex(),
                display_name: Some("Bob".into()),
            },
            &alice_identity.digest,
        )
        .unwrap();

    // Alice votes accept; with 1 active member this is enough to accept.
    let bob_digest = MemberIdentity::compute_digest(&bob_frost.public_key_hex());
    let vote = Vote {
        voter_digest: alice_identity.digest.clone(),
        choice: VoteChoice::Accept,
        signature: alice_frost.sign(add_bob_pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    };
    let status = alice_state.cast_vote(&add_bob_pid, vote).unwrap();
    assert_eq!(status, ProposalStatus::Accepted);
    assert_eq!(alice_state.active_member_count(), 2);
    assert!(alice_state.is_active_member(&bob_digest));

    // Bob starts as an empty node and receives Alice's serialized snapshot.
    let mut bob_state = GovernanceState::new_empty("snapshot-net");
    assert_eq!(bob_state.active_member_count(), 0);

    let snapshot_json = serde_json::to_string(&alice_state).unwrap();
    let remote: GovernanceState = serde_json::from_str(&snapshot_json).unwrap();

    // Apply the same adoption rule used by the gossip sync logic:
    if remote.active_member_count() > bob_state.active_member_count() {
        bob_state = remote;
    }

    // Bob should now see both Alice and himself as active members.
    assert_eq!(bob_state.active_member_count(), 2);
    assert!(bob_state
        .members
        .values()
        .any(|m| m.identity.display_name.as_deref() == Some("Alice")));
    assert!(bob_state
        .members
        .values()
        .any(|m| m.identity.display_name.as_deref() == Some("Bob")));
}

#[test]
fn test_proposer_auto_vote_threshold_behavior() {
    // Three members: Alice (genesis), Bob, Carol.
    let alice = FrostManager::new();
    let bob = FrostManager::new();
    let carol = FrostManager::new();

    let alice_id =
        MemberIdentity::new(&alice.public_key_hex(), Some("Alice".into()));
    let mut state = GovernanceState::new_genesis("auto-vote-net", alice_id.clone());

    // Add Bob: only Alice votes; with 1 active member this is sufficient.
    let add_bob_pid = state
        .submit_proposal(
            ProposalType::AddMember {
                public_key_hex: bob.public_key_hex(),
                display_name: Some("Bob".into()),
            },
            &alice_id.digest,
        )
        .unwrap();
    let vote_alice_on_bob = Vote {
        voter_digest: alice_id.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    };
    let status = state.cast_vote(&add_bob_pid, vote_alice_on_bob).unwrap();
    assert_eq!(status, ProposalStatus::Accepted);

    // Add Carol: Alice and Bob vote.
    let add_carol_pid = state
        .submit_proposal(
            ProposalType::AddMember {
                public_key_hex: carol.public_key_hex(),
                display_name: Some("Carol".into()),
            },
            &alice_id.digest,
        )
        .unwrap();
    let bob_digest = MemberIdentity::compute_digest(&bob.public_key_hex());

    for voter_digest in [alice_id.digest.clone(), bob_digest.clone()] {
        let vote = Vote {
            voter_digest,
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        };
        match state.cast_vote(&add_carol_pid, vote) {
            Ok(ProposalStatus::Accepted) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    assert_eq!(state.active_member_count(), 3);

    // Now Alice proposes adding a file; we simulate auto-vote by casting her Accept immediately.
    let add_file_pid = state
        .submit_proposal(
            ProposalType::AddFile {
                path: "contracts/partnership.md".into(),
                content_hash: "hash123".into(),
                content: None,
            },
            &alice_id.digest,
        )
        .unwrap();

    // Auto-vote: Alice votes Accept at proposal creation time.
    let auto_vote = Vote {
        voter_digest: alice_id.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    };
    let _ = state.cast_vote(&add_file_pid, auto_vote).unwrap();

    // With 3 active members, >2/3 acceptance means 3 votes are required.
    {
        let proposal = state.proposals.get(&add_file_pid).unwrap();
        assert_eq!(proposal.accept_count(), 1);
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    // Bob and Carol vote Accept; after Bob's vote it should still be Pending,
    // after Carol's vote it must move to Accepted.
    let bob_digest = MemberIdentity::compute_digest(&bob.public_key_hex());
    let carol_digest = MemberIdentity::compute_digest(&carol.public_key_hex());

    let vote_bob = Vote {
        voter_digest: bob_digest,
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    };
    let status_after_bob = state.cast_vote(&add_file_pid, vote_bob).unwrap();
    assert_eq!(status_after_bob, ProposalStatus::Pending);

    let vote_carol = Vote {
        voter_digest: carol_digest,
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    };
    let status_after_carol = state.cast_vote(&add_file_pid, vote_carol).unwrap();
    assert_eq!(status_after_carol, ProposalStatus::Accepted);

    let proposal = state.proposals.get(&add_file_pid).unwrap();
    // At least two distinct accepts (Alice + Bob) must be present,
    // and the proposal must be marked as Accepted.
    assert!(proposal.accept_count() >= 2);
    assert_eq!(proposal.status, ProposalStatus::Accepted);
}

// --- RemoveFile proposal integration ---

#[test]
fn test_remove_file_proposal_lifecycle() {
    let members: Vec<_> = (0..3).map(|_| FrostManager::new()).collect();
    let genesis = MemberIdentity::new(&members[0].public_key_hex(), Some("G".into()));
    let mut state = GovernanceState::new_genesis("rm-test", genesis.clone());

    for i in 1..3 {
        let pid = state.submit_proposal(
            ProposalType::AddMember {
                public_key_hex: members[i].public_key_hex(),
                display_name: Some(format!("M{i}")),
            },
            &genesis.digest,
        ).unwrap();
        for j in 0..i {
            let v = Vote {
                voter_digest: MemberIdentity::compute_digest(&members[j].public_key_hex()),
                choice: VoteChoice::Accept,
                signature: members[j].sign(pid.as_bytes()),
                timestamp: chrono::Utc::now(),
            };
            if matches!(state.cast_vote(&pid, v), Ok(ProposalStatus::Accepted)) {
                break;
            }
        }
    }
    assert_eq!(state.active_member_count(), 3);

    let add_pid = state.submit_proposal(
        ProposalType::AddFile { path: "tmp.md".into(), content_hash: "h".into(), content: None },
        &genesis.digest,
    ).unwrap();
    for i in 0..3 {
        let v = Vote {
            voter_digest: MemberIdentity::compute_digest(&members[i].public_key_hex()),
            choice: VoteChoice::Accept,
            signature: members[i].sign(add_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(state.cast_vote(&add_pid, v), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }

    let remove_pid = state.submit_proposal(
        ProposalType::RemoveFile { path: "tmp.md".into() },
        &genesis.digest,
    ).unwrap();
    for i in 0..3 {
        let v = Vote {
            voter_digest: MemberIdentity::compute_digest(&members[i].public_key_hex()),
            choice: VoteChoice::Accept,
            signature: members[i].sign(remove_pid.as_bytes()),
            timestamp: chrono::Utc::now(),
        };
        if matches!(state.cast_vote(&remove_pid, v), Ok(ProposalStatus::Accepted)) {
            break;
        }
    }
    assert_eq!(state.proposals.get(&remove_pid).unwrap().status, ProposalStatus::Accepted);
}

// --- FROST secret persistence integration ---

#[test]
fn test_frost_persistence_roundtrip() {
    let original = FrostManager::new();
    let secret = original.secret_key_bytes();
    let pub_hex = original.public_key_hex();
    let msg = b"persistence test";

    let restored = FrostManager::from_secret(&secret).unwrap();
    assert_eq!(restored.public_key_hex(), pub_hex);

    let sig = restored.sign(msg);
    assert!(original.verify(&original.public_key_bytes(), msg, &sig));
}

// --- Sequential edits ---

#[test]
fn test_sequential_edits_apply() {
    let dir = TempDir::new().unwrap();
    let mut mgr = DocumentManager::new(dir.path().to_path_buf());
    mgr.ensure_root().unwrap();

    mgr.add_file("doc.md", "A\nB\nC\n", "alice").unwrap();

    let diff1 = mgr.compute_diff("doc.md", "A\nB1\nC\n").unwrap();
    mgr.apply_edit("doc.md", &diff1, "bob").unwrap();
    assert_eq!(mgr.read_file("doc.md").unwrap(), "A\nB1\nC\n");

    // Second diff computed against current state (sequential edits)
    let diff2 = mgr.compute_diff("doc.md", "A\nB1\nC2\n").unwrap();
    mgr.apply_edit("doc.md", &diff2, "carol").unwrap();
    assert_eq!(mgr.read_file("doc.md").unwrap(), "A\nB1\nC2\n");
}

// --- Config Tests ---

#[test]
fn test_config_save_load() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("test-config.toml");

    let config = NodeConfig::default();
    config.save_to_file(&config_path).unwrap();

    let loaded = NodeConfig::load_from_file(&config_path).unwrap();
    assert_eq!(loaded.network_name, config.network_name);
    assert_eq!(loaded.node_port, config.node_port);
    assert_eq!(loaded.rpc_port, config.rpc_port);
}

// --- Expel Integration Tests ---

#[test]
fn test_expel_full_lifecycle_three_members() {
    let m1 = FrostManager::new();
    let m2 = FrostManager::new();
    let m3 = FrostManager::new();

    let id1 = MemberIdentity::new(&m1.public_key_hex(), Some("Alice".into()));
    let id2_digest = MemberIdentity::compute_digest(&m2.public_key_hex());
    let id3_digest = MemberIdentity::compute_digest(&m3.public_key_hex());

    let mut state = GovernanceState::new_genesis("expel-int", id1.clone());

    // Add m2 and m3
    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: m2.public_key_hex(), display_name: Some("Bob".into()) },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: m1.sign(pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    }).unwrap();

    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: m3.public_key_hex(), display_name: Some("Carol".into()) },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: m1.sign(pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    }).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id2_digest.clone(),
        choice: VoteChoice::Accept,
        signature: m2.sign(pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    }).unwrap();

    assert_eq!(state.active_member_count(), 3);
    assert_eq!(state.epoch, 2);

    // Expel Bob — needs 3 votes (>2/3 of 3 = 3)
    let expel_pid = state.submit_proposal(
        ProposalType::ExpelMember { member_digest: id2_digest.clone() },
        &id1.digest,
    ).unwrap();

    // Alice votes
    let status = state.cast_vote(&expel_pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: m1.sign(expel_pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    }).unwrap();
    assert_eq!(status, ProposalStatus::Pending);

    // Carol votes
    let status = state.cast_vote(&expel_pid, Vote {
        voter_digest: id3_digest.clone(),
        choice: VoteChoice::Accept,
        signature: m3.sign(expel_pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    }).unwrap();
    assert_eq!(status, ProposalStatus::Pending);

    // Bob votes (needs all 3 for >2/3)
    let status = state.cast_vote(&expel_pid, Vote {
        voter_digest: id2_digest.clone(),
        choice: VoteChoice::Accept,
        signature: m2.sign(expel_pid.as_bytes()),
        timestamp: chrono::Utc::now(),
    }).unwrap();
    assert_eq!(status, ProposalStatus::Accepted);

    assert_eq!(state.active_member_count(), 2);
    assert!(!state.is_active_member(&id2_digest));
    assert!(state.is_active_member(&id1.digest));
    assert!(state.is_active_member(&id3_digest));
    assert_eq!(state.epoch, 3);
    assert_eq!(state.expelled_members().len(), 1);
}

#[test]
fn test_expel_snapshot_persistence_roundtrip() {
    use quorum_trust::governance::persistence::{save_governance, load_governance};

    let m1 = FrostManager::new();
    let m2 = FrostManager::new();
    let id1 = MemberIdentity::new(&m1.public_key_hex(), Some("Alice".into()));
    let id2_digest = MemberIdentity::compute_digest(&m2.public_key_hex());

    let mut state = GovernanceState::new_genesis("persist-expel", id1.clone());

    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: m2.public_key_hex(), display_name: Some("Bob".into()) },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    // Expel Bob
    let expel_pid = state.submit_proposal(
        ProposalType::ExpelMember { member_digest: id2_digest.clone() },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&expel_pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    state.cast_vote(&expel_pid, Vote {
        voter_digest: id2_digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    assert_eq!(state.epoch, 2);
    assert!(!state.is_active_member(&id2_digest));

    // Persist and reload
    let dir = TempDir::new().unwrap();
    save_governance(dir.path(), &state).unwrap();
    let loaded = load_governance(dir.path(), "persist-expel").unwrap().unwrap();

    assert_eq!(loaded.epoch, 2);
    assert_eq!(loaded.active_member_count(), 1);
    assert!(!loaded.is_active_member(&id2_digest));
    assert!(loaded.is_active_member(&id1.digest));
    // Expelled member record is preserved
    let bob_record = loaded.members.get(&id2_digest).unwrap();
    assert_eq!(bob_record.status, quorum_trust::crypto::identity::MemberStatus::Expelled);
    assert!(bob_record.expelled_at.is_some());
}

#[test]
fn test_expel_epoch_sync_adoption_simulated() {
    let alice_frost = FrostManager::new();
    let bob_frost = FrostManager::new();
    let carol_frost = FrostManager::new();

    let alice_id = MemberIdentity::new(&alice_frost.public_key_hex(), Some("Alice".into()));
    let bob_digest = MemberIdentity::compute_digest(&bob_frost.public_key_hex());
    let carol_digest = MemberIdentity::compute_digest(&carol_frost.public_key_hex());

    let mut alice_state = GovernanceState::new_genesis("sync-expel", alice_id.clone());

    // Add Bob
    let pid = alice_state.submit_proposal(
        ProposalType::AddMember { public_key_hex: bob_frost.public_key_hex(), display_name: Some("Bob".into()) },
        &alice_id.digest,
    ).unwrap();
    alice_state.cast_vote(&pid, Vote {
        voter_digest: alice_id.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    // Add Carol
    let pid = alice_state.submit_proposal(
        ProposalType::AddMember { public_key_hex: carol_frost.public_key_hex(), display_name: Some("Carol".into()) },
        &alice_id.digest,
    ).unwrap();
    alice_state.cast_vote(&pid, Vote {
        voter_digest: alice_id.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    alice_state.cast_vote(&pid, Vote {
        voter_digest: bob_digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    assert_eq!(alice_state.active_member_count(), 3);

    // Carol has a stale copy
    let mut carol_state = alice_state.clone();
    assert_eq!(carol_state.epoch, alice_state.epoch);

    // Alice expels Carol on her state
    let expel_pid = alice_state.submit_proposal(
        ProposalType::ExpelMember { member_digest: carol_digest.clone() },
        &alice_id.digest,
    ).unwrap();
    for d in [&alice_id.digest, &bob_digest, &carol_digest] {
        let result = alice_state.cast_vote(&expel_pid, Vote {
            voter_digest: d.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        });
        if matches!(result, Ok(ProposalStatus::Accepted)) { break; }
    }
    assert!(!alice_state.is_active_member(&carol_digest));

    // Simulate Carol receiving Alice's state via sync
    let remote = alice_state.clone();
    let i_am_active_locally = carol_state.is_active_member(&carol_digest);
    let i_am_active_in_remote = remote.is_active_member(&carol_digest);
    let i_am_expelled_in_remote = remote.members.get(&carol_digest)
        .map(|m| m.status == quorum_trust::crypto::identity::MemberStatus::Expelled)
        .unwrap_or(false);

    // Guard allows because expelled
    let should_reject = i_am_active_locally && !i_am_active_in_remote && !i_am_expelled_in_remote;
    assert!(!should_reject);

    // Epoch is strictly higher, so adoption proceeds
    assert!(remote.epoch > carol_state.epoch);
    carol_state = remote;
    assert!(!carol_state.is_active_member(&carol_digest));

    // Bob also syncs via epoch
    let mut bob_state = GovernanceState::new_genesis("sync-expel", alice_id.clone());
    bob_state.epoch = 0; // stale
    let remote2 = alice_state.clone();
    assert!(remote2.epoch > bob_state.epoch);
    bob_state = remote2;
    assert_eq!(bob_state.active_member_count(), 2);
    assert!(!bob_state.is_active_member(&carol_digest));
}

#[test]
fn test_expel_does_not_affect_accepted_files() {
    let m1 = FrostManager::new();
    let m2 = FrostManager::new();
    let id1 = MemberIdentity::new(&m1.public_key_hex(), Some("Alice".into()));
    let id2_digest = MemberIdentity::compute_digest(&m2.public_key_hex());

    let mut state = GovernanceState::new_genesis("expel-files", id1.clone());

    // Add m2
    let pid = state.submit_proposal(
        ProposalType::AddMember { public_key_hex: m2.public_key_hex(), display_name: None },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    // Add files
    for name in &["doc1.md", "doc2.md"] {
        let pid = state.submit_proposal(
            ProposalType::AddFile {
                path: name.to_string(),
                content: None,
                content_hash: format!("h_{}", name),
            },
            &id1.digest,
        ).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: id1.digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
        state.cast_vote(&pid, Vote {
            voter_digest: id2_digest.clone(),
            choice: VoteChoice::Accept,
            signature: vec![0; 64],
            timestamp: chrono::Utc::now(),
        }).unwrap();
    }
    assert_eq!(state.accepted_file_paths.len(), 2);

    // Expel m2
    let expel_pid = state.submit_proposal(
        ProposalType::ExpelMember { member_digest: id2_digest.clone() },
        &id1.digest,
    ).unwrap();
    state.cast_vote(&expel_pid, Vote {
        voter_digest: id1.digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();
    state.cast_vote(&expel_pid, Vote {
        voter_digest: id2_digest.clone(),
        choice: VoteChoice::Accept,
        signature: vec![0; 64],
        timestamp: chrono::Utc::now(),
    }).unwrap();

    // Files are preserved after expel
    assert_eq!(state.accepted_file_paths.len(), 2);
    assert!(state.is_network_file("doc1.md"));
    assert!(state.is_network_file("doc2.md"));
}
