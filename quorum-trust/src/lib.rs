//! QuorumTrust - A decentralized document collaboration platform using threshold cryptography.
//!
//! This library provides the core modules for secure multi-party document editing,
//! cryptographic operations using FROST (Flexible Round-Optimized Schnorr Threshold),
//! and decentralized network coordination.
//!
//! # Features
//!
//! - **Threshold Cryptography**: Uses FROST for distributed key generation and signing
//! - **Decentralized Network**: Built on Chaincraft for P2P communication
//! - **Document Management**: Collaborative editing with conflict resolution
//! - **RPC Interface**: Axum-based server for API access
//!
//! # Example
//!
//! ```rust
//! use quorum_trust::NodeConfig;
//! // Create and configure a node
//! let config = NodeConfig::default();
//! ```

pub mod config;
pub mod crypto;
pub mod governance;
pub mod document;
pub mod network;
pub mod rpc;
pub mod cli;

pub use config::NodeConfig;
pub use crypto::identity::MemberIdentity;
pub use governance::GovernanceState;
pub use document::DocumentManager;
pub use network::QuorumNetwork;
