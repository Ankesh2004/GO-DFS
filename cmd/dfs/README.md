# `cmd/dfs` — GO-DFS Command-Line Interface & Node Daemon

`cmd/dfs` is the main entrypoint and command-line application for **GO-DFS** — a peer-to-peer distributed file system written in Go. Built using the [Cobra](https://github.com/spf13/cobra) CLI framework, `cmd/dfs` operates both as a long-running P2P node daemon (hosting an authenticated HTTP control API) and as a thin client tool for file operations and cluster management.

---

## 🏗️ Architecture & Design

```
+-------------------------------------------------------------------------+
|                              dfs CLI / REPL                             |
|    (dfs put, dfs get, dfs ls, dfs rm, dfs id, dfs peers, dfs status)    |
+-------------------------------------------------------------------------+
                                    |
                           HTTP Control API
                        (Header: X-Local-Auth)
                                    v
+-------------------------------------------------------------------------+
|                        dfs node start (Daemon)                          |
|  +---------------------+  +---------------------+  +-----------------+  |
|  |   Control API Server|  |   P2P Transport     |  |   Kademlia DHT  |  |
|  |     (Port :9000)    |  |     (Port :7000)    |  |   (Peer/Key)    |  |
|  +---------------------+  +---------------------+  +-----------------+  |
|  +-------------------------------------------------------------------+  |
|  |                    FileServer (CAS / Encrypted Storage)           |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
```

### Key Architectural Highlights
* **Client-Daemon Split**: Running `dfs node start` initializes the P2P node daemon and an HTTP control API (default `:9000`). Subcommands (`put`, `get`, `ls`, `rm`, `id`, `peers`, `status`) execute as lightweight HTTP clients querying the control API.
* **Token Authentication (`X-Local-Auth`)**: Client commands automatically discover and load security tokens from local node directories (`cas_*/api_token`), securing control API endpoints.
* **Zero-Copy Streaming I/O**: File uploads (`dfs put`) and downloads (`dfs get`) stream data through `io.Pipe` and temporary download files, avoiding high memory overhead on multi-gigabyte files.
* **Dual Execution Modes**: Supports headless daemon mode for production/background operation and interactive REPL mode (`-i` / `dfs demo`) for testing and manual mesh interaction.

---

## ⚙️ Global Flags

All subcommands inherit global persistent flags defined in [`main.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/main.go):

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--api` | `string` | `localhost:9000` | Target HTTP control API address |
| `--api-token` | `string` | `""` | `X-Local-Auth` token (auto-loaded from `cas_*/api_token` if omitted) |

---

## 📜 Command Reference

### 1. Node Daemon Commands (`dfs node`)

Managed in [`node.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/node.go).

#### `dfs node start`
Starts the P2P node daemon, listening transport, and HTTP control API.

```bash
dfs node start [flags]
```

**Flags:**
* `--port string`: P2P TCP listen port (default `":7000"`).
* `--bootstrap string`: Comma-separated list of bootstrap node addresses (e.g. `127.0.0.1:7000`).
* `--advertise string`: Public address advertised to P2P mesh peers (auto-detected if blank).
* `--data string`: Directory for content-addressed storage (default `./cas_<port>`).
* `--id string`: Manual node identity override (auto-generated key if blank).
* `--relay`: Enable relay-only mode (participates in routing/forwarding without local CAS storage).
* `--api-port string`: HTTP control API port (default `":9000"`).
* `-i`, `--interactive`: Launch the interactive terminal REPL alongside the daemon.
* **Hardware & RL Placement Flags:**
  * `--tier string`: Storage hardware tier (`nvme`, `ssd`, `hdd`; default `"ssd"`).
  * `--latency float`: Simulated I/O latency in milliseconds (default `5.0`).
  * `--cost float`: Simulated storage cost in USD/GB/hour (default `0.01`).
  * `--bandwidth float`: Network bandwidth in Mbps (default `100.0`).
  * `--rl-enabled`: Enable Reinforcement Learning-based chunk placement optimization.
  * `--rl-sidecar string`: URL of the Python RL placement sidecar (default `"http://127.0.0.1:5100"`).

---

### 2. Client File Operations

#### `dfs put <filepath>`
Implemented in [`put.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/put.go).  
Encrypts, chunks, and uploads a file to the P2P network. Returns a Content Identifier (CID).

```bash
dfs put ./documents/report.pdf
```

**Output:**
```
Uploading 'report.pdf' (1048576 bytes)...
✓ Stored!
  CID    : 4a8f9b2c...
  Name   : report.pdf
  Size   : 1.0 MB
  Chunks : 4
```

#### `dfs get <CID>`
Implemented in [`get.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/get.go).  
Retrieves file chunks from the mesh network, decrypts them, and saves the file locally.

```bash
dfs get <CID> [flags]
```

**Flags:**
* `-o`, `--output string`: Custom destination filepath (default `./myFiles/<original_name>`).

**Example:**
```bash
dfs get 4a8f9b2c... -o ./downloads/restored.pdf
```

#### `dfs ls`
Implemented in [`ls.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/ls.go).  
Lists all files stored by the target node.

```bash
dfs ls [flags]
```

**Flags:**
* `--json`: Output file entries as raw JSON for scripting and automation.

#### `dfs rm <CID>`
Implemented in [`rm.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/rm.go).  
Deletes a file by tombstoning local metadata/chunks and broadcasting deletion tombstone signals to network peers.

```bash
dfs rm 4a8f9b2c...
```

---

### 3. Cluster & Network Diagnostics

#### `dfs id`
Implemented in [`id_cmd.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/id_cmd.go).  
Displays node identity, listen/advertise addresses, storage location, and security status.

```bash
dfs id
```

#### `dfs peers`
Implemented in [`peers_cmd.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/peers_cmd.go).  
Lists all currently connected P2P network peers.

```bash
dfs peers
```

#### `dfs status`
Implemented in [`status_cmd.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/status_cmd.go).  
Displays network peer health (missed pings, last active timestamps) and chunk replication audit metrics.

```bash
dfs status
```

---

### 4. Interactive Local Demo (`dfs demo`)

Implemented in [`demo.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/demo.go).  
Spins up a local two-node cluster (`:7000` and `:7001`), connects them via bootstrap discovery, and opens an interactive REPL session on node 1.

```bash
dfs demo
```

---

## 💻 Interactive REPL Mode

When running `dfs node start -i` or `dfs demo`, an interactive prompt (`dfs> `) is opened (handled by [`cli.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/cli.go)).

Available REPL commands:

| Command | Usage | Description |
| :--- | :--- | :--- |
| `store` | `store <filename>` | Encrypt, chunk, and store file in mesh |
| `get` | `get <CID> [filename]` | Retrieve and decrypt file by CID |
| `delete` | `delete <CID>` | Tombstone and broadcast file deletion |
| `list` | `list` | Show files stored on local node |
| `peers` | `peers` | List active connected peers |
| `status` | `status` | Show peer health and replication audit results |
| `id` | `id` | Display node ID and endpoint addresses |
| `exit` | `exit` | Gracefully shut down node and exit |

---

## 📁 Source File Breakdown

| File | Description |
| :--- | :--- |
| [`main.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/main.go) | Entrypoint, defines Cobra `rootCmd` and persistent flags (`--api`, `--api-token`). |
| [`node.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/node.go) | `dfs node start` implementation; initializes P2P transport, CAS server, RL sidecar integration, and HTTP control API. |
| [`cli.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/cli.go) | REPL command parser (`commandLoop`) and in-process file retrieval/decryption helper (`RetrieveAndDecrypt`). |
| [`helpers.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/helpers.go) | HTTP client setup, `X-Local-Auth` token resolution from `cas_*/api_token`, error handlers, and key loader. |
| [`put.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/put.go) | `dfs put` command logic; streams multipart form uploads to the control API. |
| [`get.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/get.go) | `dfs get` command logic; streams downloads with temporary `.tmp` write safety to prevent partial file corruption. |
| [`ls.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/ls.go) | `dfs ls` command logic; formats file metadata list or outputs JSON. |
| [`rm.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/rm.go) | `dfs rm` command logic; requests deletion/tombstoning via control API. |
| [`id_cmd.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/id_cmd.go) | `dfs id` command logic; queries node identity and network status. |
| [`peers_cmd.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/peers_cmd.go) | `dfs peers` command logic; lists connected mesh nodes. |
| [`status_cmd.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/status_cmd.go) | `dfs status` command logic; outputs peer health and chunk replication audit summary. |
| [`demo.go`](file:///c:/UNIVERSE/Projects/GO-DFS/cmd/dfs/demo.go) | `dfs demo` command logic; bootstraps a local 2-node cluster in memory for testing. |

---

## 🚀 Quickstart Guide

### 1. Build the Binary
```bash
go build -o dfs ./cmd/dfs
```

### 2. Start a Primary Bootstrap Node
```bash
./dfs node start --port :7000 --api-port :9000
```

### 3. Start a Secondary Node (in another terminal)
```bash
./dfs node start --port :7001 --api-port :9001 --bootstrap 127.0.0.1:7000
```

### 4. Upload and Retrieve Files
```bash
# Upload a file via Node 1
./dfs put sample.txt --api localhost:9000

# List stored files
./dfs ls --api localhost:9000

# Download the file from Node 2 (retrieving chunks across the P2P mesh)
./dfs get <CID> --api localhost:9001 -o downloaded_sample.txt
```
