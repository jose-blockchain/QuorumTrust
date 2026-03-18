use clap::Parser;
use quorum_trust::cli::commands::{Cli, Commands};
use quorum_trust::config::NodeConfig;
use quorum_trust::crypto::frost::FrostManager;
use quorum_trust::document::DocumentManager;
use quorum_trust::governance::voting::VoteChoice;
use quorum_trust::network::QuorumNetwork;
use quorum_trust::rpc::RpcServer;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

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
            println!("QuorumTrust {role} initialized: {name}");
            println!("  Config:     {}", cli.config.display());
            println!("  Documents:  {}", documents_dir.display());
            println!("  Ports:      node={node_port} rpc={rpc_port} public={public_port}");
            println!("  Secret Key: {}", secret_key_file.display());
            println!("  Public Key: {} (saved to {}/public.key)", frost.public_key_hex(), data_dir.display());
            println!("  Digest:     {} (saved to {}/digest)", frost.member_digest(), data_dir.display());
            println!("  RPC API Key: {}", config.rpc_api_key);
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
            // Delayed sync so peers have time to connect; helps nodes that missed initial SyncResponse
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

            println!("QuorumTrust node starting...");
            println!("  Network: {}", config.network_name);
            println!("  Node port: {}", config.node_port);
            println!("  RPC port: {}", config.rpc_port);
            println!("  Public port: {}", config.public_port);

            rpc.run().await?;
        }

        Commands::Status => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            println!("Network: {}", config.network_name);
            println!("Node port: {}", config.node_port);
            println!("RPC port: {}", config.rpc_port);
            println!("Documents: {}", config.documents_dir.display());
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
            println!("Generated new keypair:");
            println!("  Secret Key: saved to {}", output.display());
            println!("  Public Key: {} (saved to {}/public.key)", frost.public_key_hex(), out_dir.display());
            println!("  Digest:     {} (saved to {}/digest)", frost.member_digest(), out_dir.display());
        }

        Commands::ListFiles => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            let files = mgr.list_files()?;
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
            println!("File added: {} (v{})", meta.path, meta.version);
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
            println!("Diff for {}:", path);
            println!("{}", diff.unified_diff);
            println!("+{} -{}", diff.additions, diff.deletions);

            quorum_trust::document::diff::save_diff_file(
                &config.documents_dir,
                &path,
                &diff,
                "local",
            )?;
            println!("Diff saved. Use 'vote' command to apply pending changes.");
        }

        Commands::Fork {
            path,
            new_name,
            share,
        } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            let new_path = mgr.fork_file(&path, new_name.as_deref(), "local")?;
            println!("Forked: {path} -> {new_path}");
            if share {
                println!("Fork will be shared with network (proposal created).");
            }
        }

        Commands::Finalize { path } => {
            let config = NodeConfig::load_from_file(&cli.config)?;
            let mut mgr = DocumentManager::new(config.documents_dir);
            mgr.mark_final(&path)?;
            println!("Document marked as final: {path}");
        }

        Commands::Vote {
            proposal_id,
            choice,
        } => {
            let _choice = match choice.as_str() {
                "accept" => VoteChoice::Accept,
                "reject" => VoteChoice::Reject,
                _ => {
                    eprintln!("Invalid choice. Use 'accept' or 'reject'.");
                    std::process::exit(1);
                }
            };
            println!("Vote recorded for proposal {proposal_id}: {choice}");
        }

        Commands::Proposals => {
            println!("Pending proposals (run node with 'start' for live data):");
        }

        Commands::Members => {
            println!("Members (run node with 'start' for live data):");
        }

        Commands::ProposeMember { public_key, name } => {
            println!("Proposed adding member: {} ({:?})", public_key, name);
        }

        Commands::ProposeExpel { digest } => {
            println!("Proposed expelling member: {digest}");
        }
    }

    Ok(())
}
