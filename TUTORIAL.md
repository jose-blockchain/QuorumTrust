# QuorumTrust Local Tutorial — 4 Nodes

This tutorial walks you through running a 4-node QuorumTrust network on a single machine, each with its own Web GUI, so you can observe the decentralized governance and document editing process live.

---

## Prerequisites

- Rust 1.82+ (`rustc --version`)
- Node.js 18+ (`node --version`)
- 5 terminal windows (or tabs)

## 1. Build the Binary

```bash
cd QuorumTrust
cargo build --release
```

The binary is at `target/release/quorum-trust`.

## 2. Install GUI Dependencies

```bash
cd quorum-trust-gui
npm install
cd ..
```

## 3. Initialize All 4 Nodes

Each `init` command generates a keypair, saves keys to disk, creates the config with the specified ports, and sets bootstrap peers. Only the first node uses `--genesis` to mark itself as the network founder.

**Node 1 — Alice (Genesis):**

```bash
./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Alice" \
  --genesis \
  --node-port 9400 --rpc-port 9401 --public-port 9402 \
  --documents-dir ./local-demo/node1/documents \
  --config ./local-demo/node1/quorum-trust.toml
```

**Node 2 — Bob:**

```bash
./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Bob" \
  --node-port 9410 --rpc-port 9411 --public-port 9412 \
  --bootstrap 127.0.0.1:9400 \
  --documents-dir ./local-demo/node2/documents \
  --config ./local-demo/node2/quorum-trust.toml
```

**Node 3 — Carol:**

```bash
./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Carol" \
  --node-port 9420 --rpc-port 9421 --public-port 9422 \
  --bootstrap 127.0.0.1:9400 \
  --documents-dir ./local-demo/node3/documents \
  --config ./local-demo/node3/quorum-trust.toml
```

**Node 4 — Dave:**

```bash
./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Dave" \
  --node-port 9430 --rpc-port 9431 --public-port 9432 \
  --bootstrap 127.0.0.1:9400 \
  --documents-dir ./local-demo/node4/documents \
  --config ./local-demo/node4/quorum-trust.toml
```

Each command automatically saves three key files under `<node>/data/`:

| File          | Contents                              |
|---------------|---------------------------------------|
| `secret.key`  | FROST private key (hex)               |
| `public.key`  | FROST public key (hex)                |
| `digest`      | SHA-512 identity digest (hex)        |

The RPC API key is stored inside `quorum-trust.toml` (field `rpc_api_key`).

Whenever you need a node's public key, digest, or API key, read them from disk:

```bash
cat local-demo/node2/data/public.key    # Bob's public key
cat local-demo/node2/data/digest        # Bob's digest
grep rpc_api_key local-demo/node2/quorum-trust.toml  # Bob's API key
```

No copy-pasting from terminal output. No manual config editing required.

## 4. Start All 4 Nodes (4 Terminal Windows)

**Terminal 1 — Node 1 (Alice, Genesis):**

```bash
cd QuorumTrust
./target/release/quorum-trust start --config ./local-demo/node1/quorum-trust.toml
```

**Terminal 2 — Node 2 (Bob):**

```bash
cd QuorumTrust
./target/release/quorum-trust start --config ./local-demo/node2/quorum-trust.toml
```

**Terminal 3 — Node 3 (Carol):**

```bash
cd QuorumTrust
./target/release/quorum-trust start --config ./local-demo/node3/quorum-trust.toml
```

**Terminal 4 — Node 4 (Dave):**

```bash
cd QuorumTrust
./target/release/quorum-trust start --config ./local-demo/node4/quorum-trust.toml
```

Each node loads its secret key from `data/secret.key` and starts with the same identity it was initialized with.

## 5. Start 4 Web GUIs (4 More Terminal Tabs)

Each GUI connects to its respective node's RPC port. The API key is extracted from the config automatically:

**GUI 1 (Alice) — http://127.0.0.1:3001**

```bash
cd QuorumTrust/quorum-trust-gui
API_KEY=$(grep rpc_api_key ../local-demo/node1/quorum-trust.toml | cut -d'"' -f2) \
  RPC_PORT=9401 GUI_PORT=3001 node server.js
```

**GUI 2 (Bob) — http://127.0.0.1:3002**

```bash
cd QuorumTrust/quorum-trust-gui
API_KEY=$(grep rpc_api_key ../local-demo/node2/quorum-trust.toml | cut -d'"' -f2) \
  RPC_PORT=9411 GUI_PORT=3002 node server.js
```

**GUI 3 (Carol) — http://127.0.0.1:3003**

```bash
cd QuorumTrust/quorum-trust-gui
API_KEY=$(grep rpc_api_key ../local-demo/node3/quorum-trust.toml | cut -d'"' -f2) \
  RPC_PORT=9421 GUI_PORT=3003 node server.js
```

**GUI 4 (Dave) — http://127.0.0.1:3004**

```bash
cd QuorumTrust/quorum-trust-gui
API_KEY=$(grep rpc_api_key ../local-demo/node4/quorum-trust.toml | cut -d'"' -f2) \
  RPC_PORT=9431 GUI_PORT=3004 node server.js
```

Open all four URLs in your browser.

## 6. Demo Walkthrough

### Step A — Add Members

On Alice's GUI (port 3001):

1. Go to **Members** and click **+ Propose Member**
2. Paste Bob's public key — get it with `cat local-demo/node2/data/public.key`
3. Enter "Bob" as display name, then click **Propose**
4. The proposer's vote (Accept) is automatic. Since Alice is the only member, her vote meets >2/3 — Bob is accepted immediately.

Repeat for Carol (`cat local-demo/node3/data/public.key`) and Dave (`cat local-demo/node4/data/public.key`). For subsequent members, the proposer auto-votes Accept; the other members must vote in their GUIs to reach the >2/3 threshold.

### Step B — Add a Shared Document

On Bob's GUI (port 3002):

1. Go to **Documents** and click **+ New File**
2. Path: `contracts/partnership.md`
3. Content:

```markdown
# Partnership Agreement

## Parties
- Alice (Genesis)
- Bob
- Carol
- Dave

## Terms
All parties agree to collaborate on this project.

## Signatures
Pending threshold signatures from all parties.
```

4. Click **Add File** — a proposal is created
5. Switch to each GUI and vote **Accept** on the proposal

### Step C — Edit the Document

On Carol's GUI (port 3003):

1. Click on `contracts/partnership.md` in the sidebar
2. Edit the content — change the Terms section
3. Click **Save & Propose**
4. The diff is shown — other members can review it
5. Switch to other GUIs to vote on the edit proposal

### Step D — Fork a Document

On Dave's GUI (port 3004):

1. Open `contracts/partnership.md`
2. Click **Fork**
3. Enter a new name like `partnership-v2.md` or leave empty for auto-naming
4. The fork appears in the file tree

### Step E — Finalize

On Alice's GUI (port 3001):

1. Open `contracts/partnership.md`
2. Click **Finalize**
3. A finalization proposal is created
4. All members vote to accept
5. Once finalized, the document can no longer be edited (forks still allowed)

### Step F — Expel a Member

On any member's GUI:

1. Go to **Members**
2. Note the digest of a member to expel
3. Use the RPC (GUI may have an expel button, or use curl):

```bash
curl -X POST http://127.0.0.1:9401/api/governance/propose-expel \
  -H "x-api-key: $(grep rpc_api_key local-demo/node1/quorum-trust.toml | cut -d'\"' -f2)" \
  -H "Content-Type: application/json" \
  -d "{\"member_digest\": \"$(cat local-demo/node4/data/digest)\"}"
```

4. Members vote in their GUIs — requires >2/3 majority

## Quick Reference: Port Map

| Node  | Name  | Node Port | RPC Port | Public Port | GUI URL               |
|-------|-------|-----------|----------|-------------|-----------------------|
| 1     | Alice | 9400      | 9401     | 9402        | http://127.0.0.1:3001 |
| 2     | Bob   | 9410      | 9411     | 9412        | http://127.0.0.1:3002 |
| 3     | Carol | 9420      | 9421     | 9422        | http://127.0.0.1:3003 |
| 4     | Dave  | 9430      | 9431     | 9432        | http://127.0.0.1:3004 |

## File Layout After Init

```
local-demo/
├── node1/
│   ├── quorum-trust.toml       # Config (ports, API key, paths, genesis)
│   ├── data/
│   │   ├── secret.key         # FROST private key (hex)
│   │   ├── public.key         # FROST public key (hex)
│   │   └── digest             # SHA-512 identity digest (hex)
│   └── documents/             # Shared documents root
├── node2/
│   ├── quorum-trust.toml       # Config (ports, API key, paths, NO genesis)
│   ├── data/
│   │   ├── secret.key
│   │   ├── public.key
│   │   └── digest
│   └── documents/
├── node3/ ...
└── node4/ ...
```

## One-Liner Startup Script

Save as `local-demo/start-all.sh`:

```bash
#!/usr/bin/env bash
set -e

QUORUM=./target/release/quorum-trust
GUI_DIR=./quorum-trust-gui

NODE1_KEY=$(grep rpc_api_key local-demo/node1/quorum-trust.toml | cut -d'"' -f2)
NODE2_KEY=$(grep rpc_api_key local-demo/node2/quorum-trust.toml | cut -d'"' -f2)
NODE3_KEY=$(grep rpc_api_key local-demo/node3/quorum-trust.toml | cut -d'"' -f2)
NODE4_KEY=$(grep rpc_api_key local-demo/node4/quorum-trust.toml | cut -d'"' -f2)

echo "Starting 4 QuorumTrust nodes..."

$QUORUM start --config ./local-demo/node1/quorum-trust.toml &
$QUORUM start --config ./local-demo/node2/quorum-trust.toml &
$QUORUM start --config ./local-demo/node3/quorum-trust.toml &
$QUORUM start --config ./local-demo/node4/quorum-trust.toml &

sleep 2
echo "Starting 4 Web GUIs..."

(cd $GUI_DIR && API_KEY="$NODE1_KEY" RPC_PORT=9401 GUI_PORT=3001 node server.js) &
(cd $GUI_DIR && API_KEY="$NODE2_KEY" RPC_PORT=9411 GUI_PORT=3002 node server.js) &
(cd $GUI_DIR && API_KEY="$NODE3_KEY" RPC_PORT=9421 GUI_PORT=3003 node server.js) &
(cd $GUI_DIR && API_KEY="$NODE4_KEY" RPC_PORT=9431 GUI_PORT=3004 node server.js) &

echo ""
echo "All running. Open in browser:"
echo "  Alice: http://127.0.0.1:3001"
echo "  Bob:   http://127.0.0.1:3002"
echo "  Carol: http://127.0.0.1:3003"
echo "  Dave:  http://127.0.0.1:3004"
echo ""
echo "Press Ctrl+C to stop all."

wait
```

Make it executable:

```bash
chmod +x local-demo/start-all.sh
```

## Cleanup

```bash
rm -rf local-demo/
```
