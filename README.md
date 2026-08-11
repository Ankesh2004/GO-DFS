# GO-DFS: Zero-Dependency Peer-to-Peer Distributed File System

**GO-DFS** (Golang File System) is a high-performance, peer-to-peer (P2P) distributed file system engineered entirely from scratch in Go. It operates with zero dependencies on external P2P frameworks (like IPFS or `libp2p`), implementing every transport, routing, storage, cryptographic, and consensus layer from first principles.

Recently, I've poured a ton of work into stabilizing the network and adding some killer new features. The local loopback P2P is now rock-solid, and we've got a shiny new Next.js dashboard that hooks directly into the node APIs. Plus, I integrated an RL (Reinforcement Learning) sidecar to optimize chunk placements!

---

## 🔥 Key Features

- **Zero-Dependency Core**: Built directly on top of standard Go network primitives (`net`, `crypto`, `golang.org/x/crypto`), giving complete control over every wire byte.
- **Next.js Web Dashboard (New!)**: A modern, fully-integrated Next.js 16 dashboard for visual node monitoring, peer tracking, and file transfer management. It's wired directly to the local HTTP API!
- **RL Sidecar Integration (New!)**: We now run a Reinforcement Learning sidecar that observes network health and intelligently optimizes chunk replication and placement.
- **Kademlia DHT Routing**: Custom, robust implementation of Kademlia with 256-bit XOR distance metrics, $K=20$ routing tables, and proactive peer discovery loops. 
- **Local Loopback P2P Stabilization**: Massive improvements to the local loopback testing mesh—no more dropped connections or zombie nodes during local cluster simulations. 
- **End-to-End Encryption**: Data is encrypted before network transport using ChaCha20-Poly1305 AEAD with 24-byte incremental nonces and per-user key management.
- **Content-Addressed Storage (CAS)**: Files and chunks are hashed using SHA-256 and stored in an optimized 4-level nested directory structure.
- **Fixed-Size Chunking Engine**: Large files are split into 8MB chunks using a high-throughput buffer pool (`sync.Pool`), allowing parallel transport and resilient, fault-tolerant transfers.
- **NAT Traversal & Multi-Hop Relaying**: Remote peers behind strict NATs communicate seamlessly through public bootstrap relay nodes.
- **Automated Health & Self-Healing Replication**: Active heartbeat monitoring and periodic background audits detect offline peers and re-replicate chunks.

<!-- finally got the RL sidecar and the web UI talking perfectly. Took a few sleepless nights but it was worth it! -->

---

## 🏗️ Architecture Overview

```text
                      +----------------------------------+
                      |         dfs CLI / Web UI         |
                      +----------------------------------+
                                        | (HTTP / REST)
                                        v
                      +----------------------------------+
                      |    Local Control API (:9000)     |
                      |       (X-Local-Auth Token)       |
                      +----------------------------------+
                                        |
                                        v
                      +----------------------------------+
                      |        FileServer Engine         |
                      +----------------------------------+
                        /       |                |       \
                       /        |                |        \
                      v         v                v         v
+---------------+  +--------+  +---------------+  +-------------------+
|  Storage &    |  |   RL   |  |  Kademlia     |  |  Secure P2P       |
|  CAS Engine   |  | Sidecar|  |  DHT Engine   |  |  Transport        |
+---------------+  +--------+  +---------------+  +-------------------+
| - 8MB Chunker |  | - Opt. |  | - XOR Metric  |  | - TCP Listener    |
| - CID Index   |  | - Place|  | - RoutingTab  |  | - X25519 Handshake|
| - Ledger      |  | - Rep. |  | - Peer Discov |  | - ChaCha20 AEAD   |
+---------------+  +--------+  +---------------+  +-------------------+
        |                                                  |
        v                                                  v
Local File System                                   P2P Mesh Network
```

---

## 📂 Project Structure

```text
GO-DFS/
├── cmd/
│   └── dfs/                   # Cobra CLI application entry points
├── internal/
│   ├── server/                # Core P2P file server implementation (API, Replication, etc.)
│   └── storage/               # Low-level Content-Addressed Storage (CAS)
├── pkg/
│   ├── crypto/                # Symmetric encryption primitives
│   ├── dht/                   # Distributed Hash Table routing
│   └── p2p/                   # Custom wire protocol & transport layer
├── sidecar/                   # RL Sidecar for chunk placement optimization
├── web/                       # Next.js 16 Web Dashboard (Fully wired to API!)
├── go.mod                     # Go module definitions
└── go.sum                     # Dependency checksums
```

<!-- Note to self: need to add more tests for the sidecar soon. It's working well but I don't want regressions. -->

---

## 🚀 Quick Start Guide

### Prerequisites
- **Go**: Version 1.25+ installed.
- **Node.js & npm**: Node 18+ (for the dashboard).

### 1. Build the Executable
```bash
# Building the main CLI (finally compiles cleanly!)
go build -o dfs.exe ./cmd/dfs
```

### 2. Multi-Node Cluster Setup (Local Test)
The local loopback is now extremely stable for testing. Spin up a local cluster:

**Node 1 (Bootstrap):**
```powershell
./dfs.exe node start --port :7000 --api-port :9000 --advertise 127.0.0.1:7000
```

**Node 2:**
```powershell
./dfs.exe node start --port :7001 --api-port :9001 --bootstrap 127.0.0.1:7000 --advertise 127.0.0.1:7001
```

**Node 3:**
```powershell
./dfs.exe node start --port :7002 --api-port :9002 --bootstrap 127.0.0.1:7000 --advertise 127.0.0.1:7002
```

### 3. Using the Web Dashboard
I've fully integrated the dashboard with the local API. No more mocking!
```bash
cd web
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) to see your nodes, peer topology, and manage files beautifully.

---

## 🛡️ Security & Threat Model

1. **End-to-End Zero-Trust Storage**: Files are encrypted at rest using XChaCha20-Poly1305. 
2. **Transport Security (AEAD)**: All TCP communication requires X25519 key agreement and HKDF key expansion.
3. **Local API Sandboxing**: Bound to `127.0.0.1` and secured with an `api_token` (`0600` perms).

<!-- I spent way too much time tweaking the HKDF salts, but security first! -->

---

## 🔮 Future Work

While a lot has been accomplished (especially the UI API wiring and RL sidecar!), there's still more to do:
- **Iterative Kademlia Lookup**: Multi-hop `FIND_NODE` convergence.
- **Erasure Coding (Reed-Solomon)**: Splitting chunks into parity pieces.
- **Connection Multiplexing**: Moving to Yamux or QUIC.
- **Storage Quotas**: Enforcing disk bounds with LRU eviction.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
