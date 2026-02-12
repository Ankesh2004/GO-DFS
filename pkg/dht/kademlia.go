package dht

import (
	"fmt"
	"sort"
)

// Kademlia handles the high-level logic for DHT operations.
// It integrates the RoutingTable with the ability to perform lookups.
type Kademlia struct {
	RoutingTable *RoutingTable
}

func NewKademlia(localID ID) *Kademlia {
	return &Kademlia{
		RoutingTable: NewRoutingTable(localID),
	}
}

// Update adds or updates a node in the routing table.
func (k *Kademlia) Update(id ID, addr string) {
	k.RoutingTable.AddNode(NodeInfo{
		ID:   id,
		Addr: addr,
	})
}

// NearestNodes returns the closest nodes to a target ID from the local routing table.
func (k *Kademlia) NearestNodes(target ID, count int) []NodeInfo {
	return k.RoutingTable.GetClosestNodes(target, count)
}

// Node represents a point in the DHT keyspace.
type Node struct {
	ID   ID
	Addr string
}

func (n Node) String() string {
	return fmt.Sprintf("Node{ID: %s, Addr: %s}", n.ID.String()[:8], n.Addr)
}

// ShortList is a list of nodes sorted by distance to a target.
type ShortList struct {
	Nodes  []NodeInfo
	Target ID
}

func (s *ShortList) Sort() {
	sort.Slice(s.Nodes, func(i, j int) bool {
		return Less(s.Nodes[i].ID, s.Nodes[j].ID, s.Target)
	})
}
