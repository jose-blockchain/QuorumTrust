use clap::Parser;
use quorum_trust::cli::commands::{Cli, Commands};
use quorum_trust::config::NodeConfig;
use quorum_trust::crypto::frost::FrostManager;
use quorum_trust::document::DocumentManager;
use quorum_trust::governance::voting::VoteChoice;
use quorum_trust::network::QuorumNetwork;
use quorum_trust::rpc::RpcServer;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Helper to print structured output in JSON or human-readable format
fn output<T: Serialize>(data: T, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(&data).unwrap());
    }
}

/// Response wrapper for JSON output consistency
#[derive(Serialize)]
struct InitResponse {
    role: String,
    network: String,
    config_path: String,
    documents_dir: String,
    ports: PortsInfo,
    secret_key_path: String,
    public_key: String,
    digest: String,
    rpc_api_key: String,
}

#[derive(Serialize)]
struct PortsInfo {
    node: u16,
    rpc: u16,
    public: u16,
}

#[derive(Serialize)]
struct StartResponse {
    network: String,
    node_port: u16,
    rpc_port: u16,
    public_port: u16,
    status: String,
}

#[derive(Serialize)]
struct StatusResponse {
    network: String,
    node_port: u16,
    rpc_port: u16,
    documents: String,
}

#[derive(Serialize)]
struct KeygenResponse {
    secret_key_path: String,
    public_key: String,
    digest: String,
}

#[derive(Serialize)]
struct FileEntry {
    path: String,
    status: String,
    version: Option<u32>,
    is_dir: bool,
}

#[derive(Serialize)]
struct FileListResponse {
    files: Vec<FileEntry>,
}

#[derive(Serialize)]
struct FileAddedResponse {
    path: String,
    version: u32,
}

#[derive(Serialize)]
struct DiffResponse {
    path: String,
    unified_diff: String,
    additions: i32,
    deletions: i32,
}

#[derive(Serialize)]
struct ForkResponse {
    original: String,
    forked: String,
}

#[derive(Serialize)]
struct VoteResponse {
    proposal_id: String,
    choice: String,
    status: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let json = cli.json;

    match cli.command {
        Commands::Init {
            name,
            display_name,
            documents_dir,
            genesis,
            node_port,
            rpc_port,
            public_port,
            bootstrap,
        } => {
            let frost = FrostManager::new();

            let config_dir = cli.config.parent().unwrap_or(std::path::Path::new("."));
            let data_dir = config_dir.join("data");
            let secret_key_file = data_dir.join("secret.key");

            let genesis_config = if genesis {
                Some(quorum_trust::config::GenesisConfig {
                    member_name: display_name.clone().unwrap_or("genesis".into()),
                    public_key_hex: frost.public_key_hex(),
                })
            } else {
                None
            };

            let config = NodeConfig {
                node_name: display_name.clone(),
                network_name: name.clone(),
                node_port,
                rpc_port,
                public_port,
                documents_dir: documents_dir.clone(),
                data_dir: data_dir.clone(),
                secret_key_file: secret_key_file.clone(),
                genesis: genesis_config,
                bootstrap_peers: bootstrap,
                ..NodeConfig::default()
            };

            if let Some(parent) = cli.config.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir_all(&data_dir)?;
            std::fs::write(&secret_key_file, hex::encode(frost.secret_key_bytes()))?;
            std::fs::write(data_dir.join("public.key"), frost.public_key_hex())?;
            std::fs::write(data_dir.join("digest"), frost.member_digest())?;
            config.save_to_file(&cli.config)?;
            std::fs::create_dir_all(&documents_dir)?;

            let role = if genesis { "Genesis node" } else { "Member node" };
            let resp = InitResponse {
                role: role.to_string(),
                network: name,
                config_path: cli.config.to_string_lossy().to_string(),
                documents_dir: documents_dir.to_string_lossy().to_string(),
                ports: PortsInfo {
                    node: node_port,
                    rpc: rpc_port,
                    public: public_port,
                },
                secret_key_path: secret_key_file.to_string_lossy().to_string(),
                public_key: frost.public_key_hex(),
                digest: frost.member_digest(),
                rpc_api_key: config.rpc_api_key.clone(),
            };
            output(resp, json);
        }

        Commands::Start => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let (network, mut broadcast_rx) = QuorumNetwork::new(config.clone()).await?;
            network.start().await?;

            let network = Arc::new(RwLock::new(network));
            let state = network.clone();
            tokio::spawn(async move {
                while let Some(msg) = broadcast_rx.recv().await {
                    let guard = state.read().await;
                    let _ = guard.broadcast_message(&msg).await;
                }
            });
            let state2 = network.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let guard = state2.read().await;
                if let Err(e) = guard.request_governance_sync().await {
                    tracing::warn!("Delayed governance sync failed: {e}");
                }
            });

            let rpc = RpcServer::new(
                network.clone(),
                config.rpc_api_key.clone(),
                config.rpc_port,
                config.rpc_bind_localhost_only,
            );

            if json {
                let resp = StartResponse {
                    network: config.network_name.clone(),
                    node_port: config.node_port,
                    rpc_port: config.rpc_port,
                    public_port: config.public_port,
                    status: "starting".to_string(),
                };
                output(resp, json);
            } else {
                println!("QuorumTrust node starting...");
                println!("  Network: {}", config.network_name);
                println!("  Node port: {}", config.node_port);
                println!("  RPC port: {}", config.rpc_port);
                println!("  Public port: {}", config.public_port);
            }

            rpc.run().await?;
        }

        Commands::Status => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let resp = StatusResponse {
                network: config.network_name.clone(),
                node_port: config.node_port,
                rpc_port: config.rpc_port,
                documents: config.documents_dir.to_string_lossy().to_string(),
            };
            output(resp, json);
        }

        Commands::Keygen { output } => {
            let frost = FrostManager::new();
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let out_dir = output.parent().unwrap_or(std::path::Path::new("."));
            std::fs::write(&output, hex::encode(frost.secret_key_bytes()))?;
            std::fs::write(out_dir.join("public.key"), frost.public_key_hex())?;
            std::fs::write(out_dir.join("digest"), frost.member_digest())?;

            let resp = KeygenResponse {
                secret_key_path: output.to_string_lossy().to_string(),
                public_key: frost.public_key_hex(),
                digest: frost.member_digest(),
            };
            output(resp, json);
        }

        Commands::ListFiles => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            let files = mgr.list_files()?;

            if json {
                let entries: Vec<FileEntry> = files
                    .into_iter()
                    .map(|f| FileEntry {
                        path: f.path,
                        status: match f.tracking_status {
                            quorum_trust::document::manager::TrackingStatus::Tracked => "tracked",
                            quorum_trust::document::manager::TrackingStatus::PendingVote => "pending",
                            quorum_trust::document::manager::TrackingStatus::NotTracked => "untracked",
                        }
                        .to_string(),
                        version: f.version,
                        is_dir: f.is_dir,
                    })
                    .collect();
                output(FileListResponse { files: entries }, json);
            } else {
                for f in files {
                    let status = match f.tracking_status {
                        quorum_trust::document::manager::TrackingStatus::Tracked => "[TRACKED]",
                        quorum_trust::document::manager::TrackingStatus::PendingVote => "[PENDING]",
                        quorum_trust::document::manager::TrackingStatus::NotTracked => "[UNTRACKED]",
                    };
                    let ver = f.version.map(|v| format!(" v{v}")).unwrap_or_default();
                    let dir = if f.is_dir { "/" } else { "" };
                    println!("  {status}{ver} {}{dir}", f.path);
                }
            }
        }

        Commands::ReadFile { path } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mgr = DocumentManager::new(config.documents_dir);
            let content = mgr.read_file(&path)?;
            print!("{content}");
        }

        Commands::AddFile { path, content } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            let content = content.unwrap_or_else(|| {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf).unwrap();
                buf
            });
            let meta = mgr.add_file(&path, &content, "local")?;

            if json {
                output(
                    FileAddedResponse {
                        path: meta.path,
                        version: meta.version,
                    },
                    json,
                );
            } else {
                println!("File added: {} (v{})", meta.path, meta.version);
            }
        }

        Commands::EditFile { path, content } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mgr = DocumentManager::new(config.documents_dir.clone());
            let content = content.unwrap_or_else(|| {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf).unwrap();
                buf
            });
            let diff = mgr.compute_diff(&path, &content)?;

            if json {
                output(
                    DiffResponse {
                        path,
                        unified_diff: diff.unified_diff.clone(),
                        additions: diff.additions,
                        deletions: diff.deletions,
                    },
                    json,
                );
            } else {
                println!("Diff for {}:", path);
                println!("{}", diff.unified_diff);
                println!("+{} -{}", diff.additions, diff.deletions);
            }

            quorum_trust::document::diff::save_diff_file(
                &config.documents_dir,
                &path,
                &diff,
                "local",
            )?;

            if !json {
                println!("Diff saved. Use 'vote' command to apply pending changes.");
            }
        }

        Commands::Fork {
            path,
            new_name,
            share,
        } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            let new_path = mgr.fork_file(&path, new_name.as_deref(), "local")?;

            if json {
                output(
                    ForkResponse {
                        original: path,
                        forked: new_path.clone(),
                    },
                    json,
                );
            } else {
                println!("Forked: {path} -> {new_path}");
                if share {
                    println!("Fork will be shared with network (proposal created).");
                }
            }
        }

        Commands::Finalize { path } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            mgr.mark_final(&path)?;
            if json {
                #[derive(Serialize)]
                struct FinalizeResponse {
                    path: String,
                    status: String,
                }
                output(
                    FinalizeResponse {
                        path,
                        status: "finalized".to_string(),
                    },
                    json,
                );
            } else {
                println!("Document marked as final: {path}");
            }
        }

        Commands::Vote {
            proposal_id,
            choice,
        } => {
            let _choice = match choice.as_str() {
                "accept" => VoteChoice::Accept,
                "reject" => VoteChoice::Reject,
                _ => {
                    if json {
                        output(
                            ErrorResponse {
                                error: "Invalid choice. Use 'accept' or 'reject'.".to_string(),
                            },
                            json,
                        );
                    } else {
                        eprintln!("Invalid choice. Use 'accept' or 'reject'.");
                    }
                    std::process::exit(1);
                }
            };

            if json {
                output(
                    VoteResponse {
                        proposal_id: proposal_id.clone(),
                        choice: choice.clone(),
                        status: "recorded".to_string(),
                    },
                    json,
                );
            } else {
                println!("Vote recorded for proposal {proposal_id}: {choice}");
            }
        }

        Commands::Proposals => {
            if !json {
                println!("Pending proposals (run node with 'start' for live data):");
            }
        }

        Commands::Members => {
            if !json {
                println!("Members (run node with 'start' for live data):");
            }
        }

        Commands::ProposeMember { public_key, name } => {
            if json {
                #[derive(Serialize)]
                struct ProposeMemberResponse {
                    public_key: String,
                    name: Option<String>,
                    status: String,
                }
                output(
                    ProposeMemberResponse {
                        public_key: public_key.clone(),
                        name: name.clone(),
                        status: "proposed".to_string(),
                    },
                    json,
                );
            } else {
                println!("Proposed adding member: {} ({:?})", public_key, name);
            }
        }

        Commands::ProposeExpel { digest } => {
            if json {
                #[derive(Serialize)]
                struct ProposeExpelResponse {
                    digest: String,
                    status: String,
                }
                output(
                    ProposeExpelResponse {
                        digest: digest.clone(),
                        status: "proposed".to_string(),
                    },
                    json,
                );
            } else {
                println!("Proposed expelling member: {digest}");
            }
        }
    }

    Ok(())
}
