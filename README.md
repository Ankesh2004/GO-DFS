# GO-DFS

It's a peer-to-peer distributed file system, built entirely from scratch in Go — (Golang File System OR GOD File System :-)  no IPFS, libp2p, or DFS libraries. Think "minimal IPFS" where you understand every byte.

### NOTE THAT : WE HAVE LOGICALLY SINGLE OWNERSHIP FOR EACH CHUNK
because....
chunkKey = SHA256(encrypt(userKey, randomNonce, plaintext))
---> same userKey + chunk + plainText is very very rare.

---> so we don't need to worry about cross-user dedup, and deletion of chunk by other user.

## Quick Start: 3-Node Relay Test

To test the system across NAT (real-world trial), follow this 3-node setup.

### 1. Start the Relay (EC2 Cloud)
Run this on a public server to act as the bootstrap and NAT traversal bridge.
```bash
./dfs node start --port :7000 --relay --advertise <PUBLIC_IP>:7000
```

### 2. Start Local Node A (Sender)
Run this on your workstation. It will bootstrap via the cloud relay.
```powershell
./dfs.exe node start --port :7001 --bootstrap <PUBLIC_IP>:7000 --api-port :9001 -i
```

### 3. Start Local Node B (Receiver)
Run this in another terminal window (simulating a second peer).
```powershell
./dfs.exe node start --port :7002 --bootstrap <PUBLIC_IP>:7000 --api-port :9002 -i
```

---

### 4. Test the Mesh
Once all nodes are healthy (check with `status`), try a cross-node transfer:

**On Node A (Terminal 1):**
```bash
dfs> store my_file.txt
# Copy the CID returned (e.g., b64730...)
```

**On Node B (Terminal 2):**
```bash
# Node B will find Node A through the Relay and pull the file
dfs> get <CID_FROM_NODE_A> -o downloaded.txt
```
> [!TIP]
> Use the `--api-port` flag when using the thin CLI (e.g., `dfs ls --api-port :9001`) if you aren't using the interactive `-i` mode.


