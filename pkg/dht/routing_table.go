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

type RoutingTable struct {
	localID ID
	buckets [IDLength * 8][]NodeInfo
	mu      sync.RWMutex
}

func NewRoutingTable(localID ID) *RoutingTable {
	return &RoutingTable{
		localID: localID,
	}
}

// AddNode adds a new node to the routing table
func (rt *RoutingTable) AddNode(node NodeInfo) {
	if node.ID == rt.localID {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	bucketIdx := CommonPrefixLen(rt.localID, node.ID)
	// Edge case: if IDs are identical but this was checked above
	if bucketIdx >= len(rt.buckets) {
		bucketIdx = len(rt.buckets) - 1
	}

	bucket := rt.buckets[bucketIdx]

	// If node already exists, move to end (most recently seen)
	for i, n := range bucket {
		if n.ID == node.ID {
			rt.buckets[bucketIdx] = append(bucket[:i], bucket[i+1:]...)
			rt.buckets[bucketIdx] = append(rt.buckets[bucketIdx], node)
			return
		}
	}

	// If bucket is not full, add it
	if len(bucket) < K {
		rt.buckets[bucketIdx] = append(bucket, node)
	} else {
		// In a full Kademlia implementation, we would ping the oldest node
		// For now, we'll just not add (simple version)
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
