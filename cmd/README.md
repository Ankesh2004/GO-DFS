# GO-DFS CLI Reference

Welcome to the **GO-DFS** command-line interface! I built this peer-to-peer distributed file system completely from scratch in Go. That means no IPFS, no libp2p — every single byte of this network is ours! 🚀

The CLI provides all the tools you need to spin up a node, interact with the mesh, and store or retrieve your files securely.

---

## 🛠️ Getting Started

Before you can store or retrieve files, you need to have a node running. All client commands (`put`, `get`, `ls`, etc.) talk to the local node's control API.

```bash
# Start a local node on port 7000
dfs node start --port :7000

# In another terminal, store a file!
dfs put myfile.txt
```

---

## 📜 Command Overview

### Node Management
* **`dfs node start`**
  Spins up the P2P node daemon and the HTTP control API. It stays alive in the foreground, handling mesh traffic and accepting CLI commands.
  
  **Key Flags:**
  * `--port` (default: `:7000`): P2P listen port.
  * `--bootstrap`: Comma-separated addresses of bootstrap nodes to join an existing network.
  * `--advertise`: Address to advertise to peers.
  * `--data`: Root directory for CAS storage (defaults to `./cas_<port>`).
  * `--id`: Override node identity string.
  * `--api-port` (default: `:9000`): HTTP control API port.
  * `-i, --interactive`: Start the interactive REPL alongside the node.
  * **Relay Mode:** `--relay`, `--relay-token`, `--relay-bw-limit`.
  * **RL Placement:** `--tier` (nvme, ssd, hdd), `--latency`, `--cost`, `--bandwidth`, `--rl-sidecar`, `--rl-enabled`.

  *Example:*
  ```bash
  # Starting a node and connecting it to a bootstrap peer
  dfs node start --port :7001 --bootstrap 127.0.0.1:7000
  ```

### File Operations
* **`dfs put <filepath>`**
  Uploads a file to the DFS network. It encrypts, chunks, and stores the file in the mesh, returning a Content ID (CID) you'll need for retrieval.
  *Example:* `dfs put ./photos/vacation.jpg`

* **`dfs get <CID>`**
  Retrieves a file by its CID, decrypts it, and saves it locally.
  **Flags:**
  * `-o, --output`: Override the save destination. (Defaults to `./myFiles/<original_name>`)
  *Example:* `dfs get a1b2c3d4e5f6... -o ./downloads/vacation.jpg`

* **`dfs ls`**
  Lists all files currently stored by your local node.

* **`dfs rm <CID>`**
  Deletes a file from the network. This broadcasts tombstones to the network, and peers will clean up their copies during garbage collection.

### Network Monitoring
* **`dfs peers`**
  Lists all currently connected peers in the mesh network.

* **`dfs status`**
  Shows peer health (like missed pings) and the latest replication audit results (healthy, under-replicated, over-replicated chunks).

---

## 💻 Interactive Shell (REPL)

If you prefer an interactive experience over typing `dfs` repeatedly, you can launch the node with the `-i` (interactive) flag!

```bash
dfs node start --port :7000 -i
```

This drops you into a sweet `dfs>` prompt where you can run commands directly against the active node:
* `store <filename>` (equivalent to `dfs put`)
* `get <CID> [filename]` (equivalent to `dfs get`)
* `list` (equivalent to `dfs ls`)
* `delete <CID>` (equivalent to `dfs rm`)
* `peers`
* `status`
* `id`
* `exit`

---

## ⚙️ Global Configuration Flags

All client commands inherit global flags to talk to the node API:
* `--api` (default: `localhost:9000`): Address of the node's control API.
* `--api-token`: `X-Local-Auth` token for the control API (auto-loaded from local cas_* dirs if not set).

<!-- 
Man, building this CLI was a blast. Getting Cobra to play nicely with our custom P2P mesh and keeping the interactive shell smooth took some tweaking, but it feels super solid now! 
-->
