<p align="center">
  <img src="img/QuorumTrust-logo.png" alt="QuorumTrust Logo" width="720">
</p>

<h1 align="center">QuorumTrust</h1>

<p align="center">
  <strong>Decentralized Collaborative Document Editing & Threshold Signing</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.82%2B-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/node.js-18%2B-green?style=flat-square&logo=node.js" alt="Node.js">
  <img src="https://img.shields.io/badge/crypto-FROST--Ed25519-1E88E5?style=flat-square&logo=letsencrypt" alt="FROST">
  <img src="https://img.shields.io/badge/network-Chaincraft-blue?style=flat-square&logo=ethereum" alt="Chaincraft">
  <img src="https://img.shields.io/badge/license-Apache--2.0-lightgrey?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-134%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

---

[![Video Title](https://img.youtube.com/vi/4Q7_9oyiipQ/0.jpg)](https://www.youtube.com/watch?v=4Q7_9oyiipQ)

## Overview

QuorumTrust is a Rust-based decentralized node system for secure collaborative editing and signing of Markdown documents across distributed networks. It uses **FROST Threshold Cryptography** from [Crypto@Bern Thetacrypt project](https://github.com/cryptobern/thetacrypt) (Ed25519-SHA512) and [**Chaincraft**](https://github.com/jose-blockchain/chaincraft-rust) for peer-to-peer coordination without central authority.

- **Threshold Signatures** — No single node can unilaterally sign documents
- **Governance by Consensus** — Member additions/removals require >2/3 majority
- **Diff-based Editing** — Document changes tracked via unified diffs with versioning
- **Document Lifecycle** — Draft → Voted → Final, with deadlines and forking
- **Rate Limiting** — Configurable daily limits to prevent spam

## Architecture

```
QuorumTrust/
├── quorum-trust/          # Rust crate (library + node binary)
│   ├── src/
│   │   ├── crypto/       # FROST Ed25519 signatures & identity
│   │   ├── governance/   # Membership, voting, >2/3 consensus
│   │   ├── document/     # Add/edit/diff/version/finalize/fork
│   │   ├── network/      # Chaincraft integration, gossip
│   │   ├── rpc/          # Axum RPC server (API key auth)
│   │   └── cli/          # CLI commands
│   └── tests/            # Integration + e2e (multi-node)
├── quorum-trust-gui/      # Node.js web interface
│   ├── server.js         # Express + Helmet (XSS protection)
│   └── public/           # SPA frontend
└── documents/            # Shared documents root
```

## Quick Start

### Build the Node

```bash
cd QuorumTrust
cargo build --release
```

### Initialize a Network

```bash
./target/release/quorum-trust init --name "my-network" --display-name "Alice"
```

This creates `quorum-trust.toml` with your configuration including the RPC API key.

### Start the Node

```bash
./target/release/quorum-trust start
```

The node exposes three ports:
- **Node port** (9400) — Chaincraft P2P communication
- **RPC port** (9401) — Private API for GUI (localhost-only, API key required)
- **Public port** (9402) — Public-facing network port

### Multi-Node Local Demo

See **[TUTORIAL.md](TUTORIAL.md)** for a full step-by-step recipe to run 4 local nodes with 4 Web GUIs and walk through the governance and editing workflow live.

### CLI Commands

```bash
# File operations
quorum-trust add-file --path docs/contract.md --content "# Contract"
quorum-trust edit-file --path docs/contract.md --content "# Updated Contract"
quorum-trust list-files
quorum-trust read-file docs/contract.md
quorum-trust fork --path docs/contract.md --new-name contract-v2.md
quorum-trust finalize docs/contract.md

# Governance
quorum-trust propose-member --public-key <hex> --name "Bob"
quorum-trust propose-expel --digest <member-digest>
quorum-trust vote --proposal-id <id> --choice accept
quorum-trust proposals
quorum-trust members

# Utility
quorum-trust keygen
quorum-trust status
```

### Web GUI

```bash
cd quorum-trust-gui
npm install
API_KEY=<your-rpc-api-key> npm start
```

Open `http://127.0.0.1:3000` — the GUI connects to the local node's RPC.

## Governance Protocol

1. **Genesis** — A single founding member creates the network
2. **Membership** — New members propose joining; existing members vote (>2/3 required)
3. **Documents** — File add/edit/remove/finalize proposals require >2/3 majority
4. **Voting** — Each active member has one vote per proposal
5. **Expulsion** — Any member can propose expelling another; >2/3 votes needed
6. **Identity** — Members identified by SHA-512 digest of their Ed25519 public key

## Cryptography

- **Scheme**: FROST-Ed25519-SHA512-v1
- **Signing**: Ed25519 signatures for message authentication
- **Hashing**: SHA-512 for identity digests, SHA-256 for content hashing
- **Library**: Built on `thetacrypt-jose` threshold cryptography primitives

## Configuration

`quorum-trust.toml`:

```toml
network_name = "my-network"
node_port = 9400
rpc_port = 9401
public_port = 9402
rpc_api_key = "generated-uuid"
rpc_bind_localhost_only = true
documents_dir = "./documents"
data_dir = "./data"
expose_public_port = true

[crypto_scheme]
type = "Frost"

[rate_limit]
max_new_files_per_day = 50
max_file_updates_per_day = 200
max_requests_per_day = 500

[genesis]
member_name = "Alice"
public_key_hex = "..."

bootstrap_peers = ["192.168.1.10:9400"]
```

## Security

- **RPC**: API key authentication, localhost-only binding by default
- **GUI**: Helmet.js CSP headers, input sanitization, rate limiting
- **Network**: Message signatures verified before processing; non-member messages rejected
- **Documents**: Content-addressable hashing for integrity verification

## Testing

```bash
# Run all tests (29 unit + 8 integration + 3 e2e)
cd QuorumTrust
cargo test

# Verbose output
cargo test -- --nocapture
```

The e2e tests simulate 4-5 node networks with full governance workflows including member onboarding, document creation, editing, and finalization.

## Dependencies

- **Chaincraft Rust** — Decentralized node framework, P2P networking
- **thetacrypt-jose** — FROST threshold cryptography (Ed25519)
- **Axum** — Async HTTP/RPC server
- **Ed25519-dalek** — Signature primitives
- **Similar/Diffy** — Diff computation and patching

## License

Apache License 2.0 — see [LICENSE](LICENSE).
