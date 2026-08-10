package dht

import (
	"sort"
	"sync"
)

const K = 20 // Bucket size

type NodeInfo struct {
	ID   ID
	Addr string
}

// PingFunc checks whether a node is still alive.
// the DHT layer doesn't know how to do networking, so the server
// layer injects this callback after creating the routing table.
// returns true if the node responded, false if it's dead.
type PingFunc func(addr string) bool

type RoutingTable struct {
	localID  ID
	buckets  [IDLength * 8][]NodeInfo
	mu       sync.RWMutex
	PingNode PingFunc // injected by the server layer, nil = skip eviction (old behavior)
}

func NewRoutingTable(localID ID) *RoutingTable {
	return &RoutingTable{
		localID: localID,
	}
}

// AddNode adds a node to the appropriate K-bucket.
// if the bucket is full, we follow the Kademlia spec:
//   - ping the OLDEST node (head of bucket)
//   - if it responds → move it to tail (long-lived nodes are precious), drop newcomer
//   - if it's dead → evict it, add newcomer at the tail
//
// this prevents the routing table from stagnating with dead entries
// that block active new peers from getting in.
func (rt *RoutingTable) AddNode(node NodeInfo) {
	if node.ID == rt.localID {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	bucketIdx := CommonPrefixLen(rt.localID, node.ID)
	if bucketIdx >= len(rt.buckets) {
		bucketIdx = len(rt.buckets) - 1
	}

	bucket := rt.buckets[bucketIdx]

	// if node already exists, move to end (most recently seen)
	for i, n := range bucket {
		if n.ID == node.ID {
			rt.buckets[bucketIdx] = append(bucket[:i], bucket[i+1:]...)
			rt.buckets[bucketIdx] = append(rt.buckets[bucketIdx], node)
			return
		}
	}

	// bucket has room, just append
	if len(bucket) < K {
		rt.buckets[bucketIdx] = append(bucket, node)
		return
	}

	// bucket is full — Kademlia eviction time.
	// if we don't have a ping function, fall back to dropping the newcomer
	// (old behavior, keeps things working for tests that don't wire up networking)
	if rt.PingNode == nil {
		return
	}

	// ping the oldest entry (head of bucket).
	// we have to drop the lock while pinging to avoid blocking
	// all other routing table operations during network I/O.
	oldest := bucket[0]
	rt.mu.Unlock()
	alive := rt.PingNode(oldest.Addr)
	rt.mu.Lock()

	// re-fetch the bucket since another goroutine may have modified it
	bucket = rt.buckets[bucketIdx]
	if len(bucket) == 0 {
		// bucket got cleared while we were pinging (peer eviction, etc.)
		rt.buckets[bucketIdx] = append(bucket, node)
		return
	}

	if alive {
		// oldest is still kicking — move it to the tail and drop the newcomer.
		// Kademlia intentionally prefers long-lived nodes because they're
		// statistically more likely to stay online.
		if bucket[0].ID == oldest.ID {
			rt.buckets[bucketIdx] = append(bucket[1:], oldest)
		}
		// newcomer gets dropped — that's the spec
		return
	}

	// oldest is dead — kick it out and add the newcomer at the tail
	if bucket[0].ID == oldest.ID {
		rt.buckets[bucketIdx] = append(bucket[1:], node)
	} else {
		// someone else already removed the oldest while we were pinging,
		// check if there's room now
		if len(bucket) < K {
			rt.buckets[bucketIdx] = append(bucket, node)
		}
	}
}

// RemoveNode removes a node from the routing table by ID.
// Used to clean up temp entries when we learn the real advertise address.
func (rt *RoutingTable) RemoveNode(id ID) {
	if id == rt.localID {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	bucketIdx := CommonPrefixLen(rt.localID, id)
	if bucketIdx >= len(rt.buckets) {
		bucketIdx = len(rt.buckets) - 1
	}

	bucket := rt.buckets[bucketIdx]
	for i, n := range bucket {
		if n.ID == id {
			rt.buckets[bucketIdx] = append(bucket[:i], bucket[i+1:]...)
			return
		}
	}
}

// GetClosestNodes returns the K closest nodes to the target ID
func (rt *RoutingTable) GetClosestNodes(target ID, count int) []NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var allNodes []NodeInfo
	for _, bucket := range rt.buckets {
		allNodes = append(allNodes, bucket...)
	}

	sort.Slice(allNodes, func(i, j int) bool {
		return Less(allNodes[i].ID, allNodes[j].ID, target)
	})

	if len(allNodes) > count {
		return allNodes[:count]
	}
	return allNodes
}

func (rt *RoutingTable) GetAllNodes() []NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var allNodes []NodeInfo
	for _, bucket := range rt.buckets {
		allNodes = append(allNodes, bucket...)
	}
	return allNodes
}
