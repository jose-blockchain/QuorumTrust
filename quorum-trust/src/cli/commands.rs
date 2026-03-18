use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "quorum-trust")]
#[command(about = "QuorumTrust - Decentralized Collaborative Document Signing")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to the configuration file
    #[arg(short, long, global = true, default_value = "quorum-trust.toml")]
    pub config: PathBuf,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a QuorumTrust node
    Init {
        /// Network name
        #[arg(short, long)]
        name: String,

        /// Your display name
        #[arg(short = 'D', long)]
        display_name: Option<String>,

        /// Documents directory
        #[arg(short = 'd', long, default_value = "./documents")]
        documents_dir: PathBuf,

        /// Initialize as genesis (first) member of the network
        #[arg(long, default_value = "false")]
        genesis: bool,

        /// Node P2P port
        #[arg(long, default_value = "9400")]
        node_port: u16,

        /// RPC API port
        #[arg(long, default_value = "9401")]
        rpc_port: u16,

        /// Public-facing port
        #[arg(long, default_value = "9402")]
        public_port: u16,

        /// Bootstrap peer addresses (comma-separated, e.g. 127.0.0.1:9400)
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,
    },

    /// Start the QuorumTrust node
    Start,

    /// Show node status and identity
    Status,

    /// Add a file to the shared document system
    AddFile {
        /// Path to the file (relative to documents dir)
        #[arg(short, long)]
        path: String,

        /// File content (reads from stdin if not provided)
        #[arg(short, long)]
        content: Option<String>,
    },

    /// Edit a shared file (creates a diff proposal)
    EditFile {
        /// Path to the file
        #[arg(short, long)]
        path: String,

        /// New content (reads from stdin if not provided)
        #[arg(short, long)]
        content: Option<String>,
    },

    /// List all files in the documents directory
    ListFiles,

    /// Read a file's content
    ReadFile {
        /// Path to the file
        path: String,
    },

    /// Fork a document (create a local copy)
    Fork {
        /// Source file path
        #[arg(short, long)]
        path: String,

        /// New name for the fork
        #[arg(short, long)]
        new_name: Option<String>,

        /// Share the fork with the network
        #[arg(short, long, default_value = "false")]
        share: bool,
    },

    /// Mark a document as final
    Finalize {
        /// File path
        path: String,
    },

    /// Vote on a pending proposal
    Vote {
        /// Proposal ID
        #[arg(short, long)]
        proposal_id: String,

        /// Vote choice: accept or reject
        #[arg(short, long)]
        choice: String,
    },

    /// List pending proposals
    Proposals,

    /// List network members
    Members,

    /// Propose adding a new member
    ProposeMember {
        /// Public key hex of the new member
        #[arg(short, long)]
        public_key: String,

        /// Display name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Propose expelling a member
    ProposeExpel {
        /// Member digest to expel
        #[arg(short, long)]
        digest: String,
    },

    /// Generate a new keypair and save to file
    Keygen {
        /// Output file for the secret key (default: ./secret.key)
        #[arg(short, long, default_value = "./secret.key")]
        output: PathBuf,
    },
}
