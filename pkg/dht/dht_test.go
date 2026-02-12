package dht

import (
	"math/big"
	"testing"
)

func TestXORDistance(t *testing.T) {
	id1 := NewID("node1")
	id2 := NewID("node2")

	dist := Distance(id1, id2)

	// Distance to self should be 0
	distSelf := Distance(id1, id1)
	if distSelf.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Expected distance to self to be 0, got %v", distSelf)
	}

	// XOR distance should be symmetric: dist(a,b) == dist(b,a)
	dist2 := Distance(id2, id1)
	if dist.Cmp(dist2) != 0 {
		t.Error("XOR distance should be symmetric")
	}
}

func TestRoutingTableBuckets(t *testing.T) {
	localID := NewID("local")
	rt := NewRoutingTable(localID)

	// Create a node that is very close (many common prefix bits)
	// For simplicity in test, we'll just add some random nodes
	nodes := []NodeInfo{
		{ID: NewID("node1"), Addr: ":7001"},
		{ID: NewID("node2"), Addr: ":7002"},
		{ID: NewID("node3"), Addr: ":7003"},
	}

	for _, n := range nodes {
		rt.AddNode(n)
	}

	closest := rt.GetClosestNodes(NewID("target"), 2)
	if len(closest) != 2 {
		t.Errorf("Expected 2 closest nodes, got %d", len(closest))
	}
}

func TestCommonPrefixLen(t *testing.T) {
	id1 := ID{0b11110000}
	id2 := ID{0b11110000}
	if CommonPrefixLen(id1, id2) != 256 {
		t.Errorf("Expected 256 for identical IDs, got %d", CommonPrefixLen(id1, id2))
	}

	id3 := ID{0b00000000}
	if CommonPrefixLen(id1, id3) != 0 {
		t.Errorf("Expected 0 for completely different IDs, got %d", CommonPrefixLen(id1, id3))
	}

	// 0b11110000 and 0b11100000 share 3 bits
	id4 := ID{0b11100000}
	if CommonPrefixLen(id1, id4) != 3 {
		t.Errorf("Expected 3, got %d", CommonPrefixLen(id1, id4))
	}
}
