# GO-DFS: Zero-Dependency Peer-to-Peer Distributed File System

**GO-DFS** (Golang File System) is a high-performance, peer-to-peer (P2P) distributed file system engineered entirely from scratch in Go. It operates with zero dependencies on external P2P frameworks (such as IPFS or `libp2p`), implementing every transport, routing, storage, cryptographic, and consensus layer from first principles.

GO-DFS provides end-to-end encrypted Content-Addressed Storage (CAS), Kademlia DHT peer discovery, 8MB streaming chunking, background replication health auditing, multi-hop NAT traversal relaying, a localhost REST control API, a rich CLI, and a Next.js web dashboard.

---

## Key Features

- **Zero-Dependency Core**: Built directly on top of standard Go network primitives (`net`, `crypto`, `golang.org/x/crypto`), giving complete control over every wire byte.
- **End-to-End Encryption**: Data is encrypted before network transport using ChaCha20-Poly1305 AEAD with 24-byte incremental nonces and per-user key management.
- **Content-Addressed Storage (CAS)**: Files and chunks are hashed using SHA-256 and stored in an optimized 4-level nested directory structure (`hash[0:8]/hash[8:16]/hash[16:24]/hash[24:32]`).
- **Single Ownership & Privacy**: Avoids cross-user deduplication side channels. Identical plaintexts encrypted under different user keys yield unique CIDs, eliminating data-existence leaks.
- **Fixed-Size Chunking Engine**: Large files are split into 8MB chunks using a high-throughput buffer pool (`sync.Pool`), allowing parallel transport and resilient, fault-tolerant transfers.
- **Kademlia DHT Routing**: Custom implementation of Kademlia with 256-bit XOR distance metrics, $K=20$ routing tables, and proactive peer discovery loops.
- **Transport Security**: Transport connections undergo an ephemeral X25519 ECDH handshake and derive independent directional keys via HKDF for ChaCha20-Poly1305 wire framing.
- **NAT Traversal & Multi-Hop Relaying**: Remote peers behind strict NATs communicate seamlessly through public bootstrap relay nodes using encapsulated `MessageRelay` envelopes.
- **Automated Health & Self-Healing Replication**: Active heartbeat monitoring and periodic background audits detect offline peers and re-replicate under-replicated chunks across the mesh.
- **Local Control API & CLI**: A localhost HTTP REST control API secured by `X-Local-Auth` tokens powers the `dfs` CLI binary and interactive REPL mode.
- **Web Interface**: Modern Next.js 16 dashboard for visual node monitoring, peer tracking, and file transfer management.

---

## Architecture Overview

```
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
                        /              |               \
                       /               |                \
                      v                v                 v
          +---------------+    +---------------+   +-------------------+
          |  Storage &    |    |  Kademlia     |   |  Secure P2P       |
          |  CAS Engine   |    |  DHT Engine   |   |  Transport        |
          +---------------+    +---------------+   +-------------------+
          | - 8MB Chunker |    | - XOR Metric  |   | - TCP Listener    |
          | - CID Index   |    | - RoutingTab  |   | - X25519 Handshake|
          | - Ledger      |    | - Peer Discov |   | - ChaCha20-Poly1305|
          | - Tombstones  |    | - K-Buckets   |   | - Relay Protocol  |
          +---------------+    +---------------+   +-------------------+
                  |                                          |
                  v                                          v
          Local File System                        P2P Mesh Network
     (cas_<port>/hash/.../hash)               (Raw TCP Frames over Wire)
```

---

## Project Structure

```
GO-DFS/
├── cmd/
│   └── dfs/                   # Cobra CLI application entry points
│       ├── main.go            # Root command definition & persistent flags
│       ├── node.go            # 'node start' daemon runner & flag parsing
│       ├── put.go             # 'dfs put' upload command
│       ├── get.go             # 'dfs get' download command
│       ├── ls.go              # 'dfs ls' catalog listing command
│       ├── rm.go              # 'dfs rm' file deletion command
│       ├── status.go          # 'dfs status' cluster health & audit command
│       ├── peers.go           # 'dfs peers' peer discovery command
│       ├── id.go              # 'dfs id' identity inspection command
│       ├── demo.go            # Interactive demo helper
│       ├── cli.go             # REPL & HTTP client wrappers
│       └── helpers.go          # Auth token loading & formatting utilities
├── internal/
│   ├── server/                # Core P2P file server implementation
│   │   ├── server.go          # FileServer lifecycle, RPC router & handshake
│   │   ├── api.go             # Localhost REST control API handlers
│   │   ├── chunked_ops.go     # Parallel 8MB chunk store/fetch orchestration
│   │   ├── delete_ops.go      # Tombstone propagation & file removal logic
│   │   ├── replication.go     # Peer health monitoring & replication auditor
│   │   ├── placement.go       # Storage tier profiling & placement logic
│   │   └── metrics.go         # Node operation counters & event trackers
│   └── storage/               # Low-level Content-Addressed Storage (CAS)
│       ├── store.go           # CAS path generation (4-tier hash tree) & file I/O
│       ├── chunker.go         # 8MB chunking & sync.Pool buffer allocation
│       ├── cid_index.go       # Local CID -> File Manifest index persistence
│       ├── chunk_ledger.go    # Disk chunk manifest & ledger management
│       └── tombstone.go       # Soft-delete tombstone tracker
├── pkg/
│   ├── crypto/                # Symmetric encryption primitives
│   │   └── crypto.go          # ChaCha20-Poly1305 chunk encryption & keygen
│   ├── dht/                   # Distributed Hash Table routing
│   │   ├── id.go              # 256-bit Node/Content ID & XOR distance math
│   │   ├── kademlia.go        # Kademlia engine & shortlist sorting
│   │   ├── routing_table.go   # K-Bucket routing table & eviction management
│   │   └── discovery.go       # Bootstrap address resolution & auto-detection
│   └── p2p/                   # Custom wire protocol & transport layer
│       ├── transport.go       # Transport and Peer interfaces
│       ├── tcp.go             # TCP transport implementation & incoming listeners
│       ├── handshake.go       # Default handshake hooks
│       ├── secure.go          # X25519 ECDH key exchange & AEAD framing wrapper
│       ├── encoding.go        # GOB encoding/decoding transport pipelines
│       └── message.go         # RPC payload definitions & relay stream headers
├── web/                       # Next.js 16 Web Dashboard
│   ├── app/                   # Next.js App Router pages & layout
│   └── components/            # UI components & interactive landing pages
├── go.mod                     # Go module definitions
└── go.sum                     # Dependency checksums
```

---

## Core Packages & Components

### 1. `pkg/crypto`
Handles client-side data protection.
- **Key Generation**: Generates 32-byte cryptographically secure symmetric keys stored locally in `myKey.key`.
- **Encryption Engine**: Encrypts data streams using `chacha20poly1305.NewX()` (XChaCha20-Poly1305) with 24-byte nonces. Each 32KB frame over the wire contains `[4-byte length][ciphertext + 16-byte Poly1305 tag]`.

### 2. `pkg/dht`
Implements the Kademlia Distributed Hash Table.
- **256-bit Node IDs**: Identifiers created via SHA-256 (`dht.ID`). XOR distance between two keys is computed via `big.Int`.
- **Routing Table**: Organized into 256 K-buckets ($K=20$). Evaluates node liveness before bucket replacement to prevent eclipse attacks.
- **Discovery**: Periodically queries connected nodes using `MessageFindNode` payloads to discover new peers.

### 3. `pkg/p2p`
Manages node networking and secure framing.
- **X25519 Key Exchange**: Ephemeral X25519 keypairs exchanged during connection initialization.
- **HKDF Key Derivation**: Derives separate 32-byte read and write keys per direction (`go-dfs-secure-transport` salt), ensuring immunity against replay attacks.
- **Framed TCP Transport**: Enforces maximum frame boundaries (16KB plaintext max per frame) over raw TCP connections.

### 4. `internal/storage`
Controls local disk persistence.
- **CAS Path Structure**: Maps a key to `RootDir/hash[0:8]/hash[8:16]/hash[16:24]/hash[24:32]/hash`.
- **Chunker (`chunker.go`)**: Splits files into 8MB blocks, computing SHA-256 hashes for each chunk. Uses `sync.Pool` to reuse 8MB memory allocations under high traffic.
- **Indexers**: `cid_index.go` tracks local CIDs and their manifests; `chunk_ledger.go` records all stored chunk hashes.

### 5. `internal/server`
Orchestrates high-level system logic.
- **RPC Router**: Dispatches incoming message payloads (`MessageStoreChunk`, `MessageGetChunk`, `MessageDeleteFile`, `MessageRelay`, `MessagePeerExchange`, etc.).
- **Replication Auditor**: Periodically queries chunk holders with `MessageBatchChunkQuery` and auto-replicates chunks whose replica count falls below the target replication factor ($R$).
- **Peer Health Monitor**: Tracks heartbeats (`Ping`/`Pong`), calculates uptime ratios and round-trip time (RTT) metrics.

---

## REST Control API Specification

The control API is bound strictly to `127.0.0.1` (localhost only) and authenticated via the `X-Local-Auth` header.

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/put` | `POST` | Upload a file (`multipart/form-data`). Returns JSON with CID, size, and chunk count. |
| `/api/get/<CID>` | `GET` | Retrieve and decrypt a file by CID. Streams raw octet-stream bytes back. |
| `/api/ls` | `GET` | List all files tracked in the node's CID index. |
| `/api/rm/<CID>` | `DELETE` | Tombstone a file locally and broadcast deletion across the network. |
| `/api/peers` | `GET` | View active P2P peer connections. |
| `/api/status` | `GET` | Inspect node health, peer ping status, and replication audit metrics. |
| `/api/id` | `GET` | Retrieve local node ID, advertise address, data directory, and key state. |
| `/api/metrics` | `GET` | Output system operational metrics as JSON. |

---

## Quick Start Guide

### Prerequisites
- **Go**: Version 1.25+ installed.
- **Node.js & npm** (Optional, for running the `web/` dashboard): Node 18+.

### 1. Build the Executable
From the project root:
```bash
go build -o dfs.exe ./cmd/dfs
```
*(On Linux/macOS, use `go build -o dfs ./cmd/dfs`)*

---

### 2. Multi-Node Cluster Setup (Local Test)

#### Step 1: Start Bootstrap / Relay Node (Node 1)
Start the primary node listening on P2P port `:7000` with API port `:9000`:
```powershell
./dfs.exe node start --port :7000 --api-port :9000 --advertise 127.0.0.1:7000
```

#### Step 2: Start Secondary Node A (Node 2)
In a second terminal, launch Node 2 listening on `:7001` and bootstrapping via `:7000`:
```powershell
./dfs.exe node start --port :7001 --api-port :9001 --bootstrap 127.0.0.1:7000 --advertise 127.0.0.1:7001
```

#### Step 3: Start Secondary Node B (Node 3)
In a third terminal, launch Node 3 listening on `:7002` and bootstrapping via `:7000`:
```powershell
./dfs.exe node start --port :7002 --api-port :9002 --bootstrap 127.0.0.1:7000 --advertise 127.0.0.1:7002
```

---

### 3. File Operations via CLI

#### Upload a File (`dfs put`)
Upload a file to Node A via API port `:9001`:
```powershell
./dfs.exe put ./sample.pdf --api localhost:9001
```
*Output:*
```text
Uploading 'sample.pdf' (15420114 bytes)...
✓ Stored!
  CID    : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Name   : sample.pdf
  Size   : 14.7 MB
  Chunks : 2

  Use this CID to retrieve the file from any node with your key.
```

#### Retrieve a File (`dfs get`)
Retrieve the file from Node B via API port `:9002` using the CID:
```powershell
./dfs.exe get e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -o downloaded.pdf --api localhost:9002
```

#### List Stored Files (`dfs ls`)
```powershell
./dfs.exe ls --api localhost:9001
```

#### Check Cluster Status (`dfs status`)
```powershell
./dfs.exe status --api localhost:9001
```

#### Delete a File (`dfs rm`)
```powershell
./dfs.exe rm e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 --api localhost:9001
```

---

### 4. Running Interactive REPL Mode
To start a node with an interactive shell:
```powershell
./dfs.exe node start --port :7001 --bootstrap 127.0.0.1:7000 -i
```
Inside the interactive prompt:
```text
dfs> store ./myfile.txt
dfs> get <CID> -o output.txt
dfs> status
dfs> peers
dfs> quit
```

---

### 5. Running the Web Dashboard

Navigate to the `web` directory and launch the Next.js development server:
```bash
cd web
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser to interact with the visual interface.

---

## Security & Threat Model

1. **End-to-End Zero-Trust Storage**: Files are encrypted at rest on local CAS stores using XChaCha20-Poly1305. Nodes holding replicas cannot inspect plaintexts without the creator's 32-byte secret key.
2. **Transport Security (AEAD)**: All node-to-node TCP communication requires X25519 key agreement and HKDF key expansion, protecting wire traffic from eavesdropping and MITM tampering.
3. **Local API Sandboxing**: The REST API forces binding to loopback (`127.0.0.1`) and validates requests against an `api_token` generated on disk (`0600` permissions), protecting against unauthorized local processes.
4. **Side-Channel Protection**: Cross-user deduplication is deliberately disabled. Plaintext hashes are salted with per-user keys and nonces, preventing file enumeration or existence queries.

---

## Future Work

While GO-DFS is a robust P2P distributed file system, there are several advanced production features planned for future iterations:

### Networking & Routing
- **Iterative Kademlia Lookup**: Implementing $\alpha=3$ concurrent `FIND_NODE` multi-hop convergence to target keys.
- **Connection Multiplexing**: Moving to Yamux or QUIC streams over a single socket to avoid head-of-line blocking.
- **Peer Persistence**: Saving the routing table to `peers.json` across restarts so nodes don't forget the entire mesh.
- **Bootstrap Retry with Backoff**: Exponential backoff loop for bootstrap dialing to improve resilience against temporary downtime.
- **Relay Rate Limiting**: Bandwidth caps and authentication tokens on public relay nodes.

### Security Hardening
- **Signed Identity Handshake**: Adding Ed25519 static keypairs per node to sign X25519 DH ephemeral keys, eliminating the risk of MITM attacks.
- **KDF for Subkeys**: Deriving separate subkeys for metadata vs. payload encryption (e.g., using HKDF or Argon2id).
- **Envelope Encryption**: Securing the master key via KMS (Vault / AWS KMS) so raw keys never touch the disk.

### Storage & Data Integrity
- **Erasure Coding (Reed-Solomon)**: Splitting chunks into 8 data + 4 parity pieces to reduce storage overhead from 300% (3x replication) to 150%.
- **Bit-Rot Scrubbing**: Background SHA-256 verification to detect and repair corrupted on-disk chunks over time.
- **Storage Quotas & Eviction**: Enforcing disk capacity bounds using LRU chunk eviction.
- **Content-Defined Chunking (FastCDC)**: Variable-size chunks to handle file edits without triggering full re-chunking of the entire file.
- **Chunk Compression (Zstd/Snappy)**: Compressing data before encryption to reduce storage and bandwidth footprint.
- **Resumable Transfers**: Allowing partial chunk transfer resumption on failure.

### Web Dashboard
- **API Integration**: Wiring the Next.js frontend directly to the local HTTP API to enable a fully functional file browser, peer topology map, and node health monitor via the browser.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
