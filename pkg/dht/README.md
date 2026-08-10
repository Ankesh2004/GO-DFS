# `pkg/dht` - Kademlia DHT Routing Table & Peer Discovery

`pkg/dht` implements a 256-bit **Kademlia Distributed Hash Table (DHT)** routing table and network address discovery package for `GO-DFS`. It enables decentralized node lookup, XOR metric distance calculations, $K$-bucket routing maintenance with speculative eviction, and dynamic public/local IP address resolution.

---

## 🏗 Architecture & Core Concepts

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Kademlia                                   │
│  High-level coordinator wrapping RoutingTable & lookup sorting         │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            RoutingTable                                 │
│  256 K-Buckets (K=20 per bucket) indexed by Common Prefix Length (CPL)  │
│  Thread-safe access (sync.RWMutex) & pluggable PingFunc liveness check  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
             ┌───────────────────────┴───────────────────────┐
             ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│        ID Space         │                     │   Address Discovery     │
│ 256-bit (32-byte) keys  │                     │ STUN-like Public IP     │
│ XOR Distance & CPL      │                     │ Local IP fallback       │
└─────────────────────────┘                     └─────────────────────────┘
```

### 1. 256-bit Node & Key Identifier (`ID`)
Nodes and keys reside in a 256-bit address space. Identifiers are generated using **SHA-256** hashes of strings (such as node addresses or file content hashes).

### 2. XOR Metric Distance
Distance between two 256-bit identifiers $A$ and $B$ is calculated using the bitwise XOR operation:

$$\text{Distance}(A, B) = A \oplus B$$

- **Unidirectional & Symmetric**: $\text{Distance}(A, B) = \text{Distance}(B, A)$.
- **Self-Distance**: $\text{Distance}(A, A) = 0$.

### 3. $K$-Bucket Routing Table ($K = 20$)
The routing table contains **256 buckets** ($32 \text{ bytes} \times 8 \text{ bits/byte}$), corresponding to the Common Prefix Length (CPL) between the local node's ID and peer node IDs:
- **Bucket Index**: Determined by `CommonPrefixLen(localID, peerID)`.
- **Bucket Capacity**: Up to $K = 20$ nodes per bucket.

### 4. Speculative Eviction Policy
When adding a node to a full bucket ($K = 20$), `RoutingTable` strictly adheres to the Kademlia specification:
1. **Probe Oldest Entry**: The oldest node (head of the bucket) is pinged using `PingNode(addr)`.
2. **Preference for Long-Lived Nodes**:
   - If the head node responds (is alive), it is moved to the tail (most recently seen) and the newcomer is **dropped**. Kademlia intentionally favors long-lived nodes because they are statistically more likely to stay online.
   - If the head node fails to respond (is dead), it is evicted from the bucket and the newcomer is appended to the tail.
3. **Lock Efficiency**: RWMutex locks are released during the `PingNode` network call to prevent blocking concurrent table operations.

---

## 🛠 Package Components & API Reference

### `id.go` — Identifier Operations

| Type / Function | Description |
| :--- | :--- |
| `ID` | `[32]byte` array representing a 256-bit DHT key or node identifier. |
| `NewID(data string) ID` | Generates a 256-bit `ID` by computing the SHA-256 hash of `data`. |
| `NewIDFromBytes(b []byte) ID` | Constructs an `ID` directly from a byte slice. |
| `IDFromHex(s string) (ID, error)` | Parses a 64-character hex string into an `ID`. |
| `(id ID) String() string` | Returns the hex-encoded string representation of an `ID`. |
| `Distance(a, b ID) *big.Int` | Computes the XOR distance between two `ID`s as a `*big.Int`. |
| `Less(a, b, target ID) bool` | Returns `true` if node `a` is closer to `target` than node `b`. |
| `CommonPrefixLen(a, b ID) int` | Counts leading zero bits of `a XOR b` (0–256). |

---

### `routing_table.go` — K-Bucket Storage & Maintenance

| Structure / Type | Description |
| :--- | :--- |
| `NodeInfo` | Struct holding peer details (`ID ID`, `Addr string`). |
| `PingFunc` | Function signature `func(addr string) bool` used for probing peer liveness. |
| `RoutingTable` | Thread-safe storage managing 256 K-buckets ($K=20$). |

#### `RoutingTable` Methods:
- [`NewRoutingTable(localID ID) *RoutingTable`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/dht/routing_table.go#L28-L32): Initializes a routing table for the given local node ID.
- [`AddNode(node NodeInfo)`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/dht/routing_table.go#L42-L116): Inserts or updates a peer node in the appropriate bucket, enforcing eviction rules when full.
- [`RemoveNode(id ID)`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/dht/routing_table.go#L120-L140): Removes a node by ID (useful when updating temporary transport addresses).
- [`GetClosestNodes(target ID, count int) []NodeInfo`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/dht/routing_table.go#L143-L160): Returns up to `count` closest nodes to `target` sorted by XOR distance.
- [`GetAllNodes() []NodeInfo`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/dht/routing_table.go#L162-L171): Returns a slice of all active nodes stored in the routing table.

---

### `kademlia.go` — High-Level DHT Coordinator

| Component | Description |
| :--- | :--- |
| `Kademlia` | Coordinator wrapping a `*RoutingTable`. |
| `NewKademlia(localID ID) *Kademlia` | Creates a `Kademlia` instance. |
| `(k *Kademlia) Update(id ID, addr string)` | Short-hand method to add/update a node in the routing table. |
| `(k *Kademlia) NearestNodes(target ID, count int) []NodeInfo` | Fetches nearest `count` nodes to `target`. |
| `ShortList` | Struct containing `Nodes []NodeInfo` and `Target ID`. Call `Sort()` to sort nodes by distance to `Target`. |

---

### `discovery.go` — IP Address Resolution

| Function | Description |
| :--- | :--- |
| `DiscoverPublicIP() (string, error)` | Queries public IP endpoints (`ipify.org`, `ifconfig.me`, `icanhazip.com`) with a 5-second timeout. |
| `GetLocalIP() (string, error)` | Uses UDP outbound route checking (`8.8.8.8:80`) to inspect OS routing tables for the active local IP. |
| `ResolveAdvertiseAddr(listenPort, advertiseAddr string) (string, error)` | Resolves the host:port address advertised to peers according to priority: explicit override > public IP > local IP. |

---

## 💻 Code Examples

### 1. Working with Identifiers & XOR Distance

```go
package main

import (
	"fmt"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
)

func main() {
	node1 := dht.NewID("192.168.1.10:7000")
	node2 := dht.NewID("192.168.1.11:7000")
	target := dht.NewID("my-file-key")

	fmt.Printf("Node 1 ID: %s\n", node1)
	fmt.Printf("Node 2 ID: %s\n", node2)

	// Compare closeness to target
	if dht.Less(node1, node2, target) {
		fmt.Println("Node 1 is closer to target than Node 2")
	} else {
		fmt.Println("Node 2 is closer to target than Node 1")
	}
}
```

### 2. Initializing Routing Table with Network Ping Eviction

```go
package main

import (
	"net"
	"time"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
)

func main() {
	localID := dht.NewID("local-node-address:7000")
	rt := dht.NewRoutingTable(localID)

	// Inject custom PingNode callback (wired to server/transport layer)
	rt.PingNode = func(addr string) bool {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}

	// Add peer
	rt.AddNode(dht.NodeInfo{
		ID:   dht.NewID("peer-1:7000"),
		Addr: "192.168.1.15:7000",
	})
}
```

### 3. Sorting ShortLists for Node Lookups

```go
package main

import (
	"fmt"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
)

func main() {
	target := dht.NewID("target-hash")
	shortlist := dht.ShortList{
		Target: target,
		Nodes: []dht.NodeInfo{
			{ID: dht.NewID("peerA"), Addr: ":7001"},
			{ID: dht.NewID("peerB"), Addr: ":7002"},
			{ID: dht.NewID("peerC"), Addr: ":7003"},
		},
	}

	// Sort nodes ascending by XOR distance to target
	shortlist.Sort()

	for _, node := range shortlist.Nodes {
		fmt.Printf("Node: %s Addr: %s\n", node.ID.String()[:8], node.Addr)
	}
}
```

---

## 🔗 Integration with `GO-DFS`

In `GO-DFS`, the DHT routing components interact directly with the transport and P2P server layers:
1. **Peer Discovery**: Nodes resolve their advertise address via [`ResolveAdvertiseAddr`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/dht/discovery.go#L61-L85) upon startup.
2. **Liveness Wire-up**: The server injects network ping handlers into `RoutingTable.PingNode` to keep $K$-buckets free of offline peers.
3. **Lookup & Routing**: When uploading or downloading file chunks, nodes use `GetClosestNodes` or `NearestNodes` to discover responsible peers across the P2P network.
