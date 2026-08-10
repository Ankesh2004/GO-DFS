package server

import (
	"sync"

	"github.com/Ankesh2004/GO-DFS/pkg/dht"
)

// NetworkLookup performs an iterative Kademlia lookup to find the K closest nodes to the targetID
// by concurrently querying up to Alpha (3) nodes at a time across the network.
func (s *FileServer) NetworkLookup(targetID dht.ID) []dht.NodeInfo {
	alpha := 3

	// 1. Initialize shortlist with our locally known closest nodes
	localClosest := s.DHT.NearestNodes(targetID, dht.K)
	if len(localClosest) == 0 {
		return nil
	}

	shortList := &dht.ShortList{
		Nodes:  localClosest,
		Target: targetID,
	}
	shortList.Sort()

	queried := make(map[string]bool)
	queried[s.AdvertiseAddr] = true // Don't query ourselves

	for {
		// 2. Find up to Alpha unqueried nodes from the top K of the shortlist
		var toQuery []dht.NodeInfo
		for i := 0; i < len(shortList.Nodes) && i < dht.K; i++ {
			node := shortList.Nodes[i]
			if !queried[node.Addr] {
				toQuery = append(toQuery, node)
				if len(toQuery) >= alpha {
					break
				}
			}
		}

		// If no unqueried nodes in the top K, we are done
		if len(toQuery) == 0 {
			break
		}

		// Mark them as queried
		for _, n := range toQuery {
			queried[n.Addr] = true
		}

		closestBeforeRound := shortList.Nodes[0].ID

		// 3. Launch concurrent FIND_NODE queries
		var wg sync.WaitGroup
		var mu sync.Mutex
		var newPeers []PeerInfo

		for _, node := range toQuery {
			wg.Add(1)
			go func(addr string) {
				defer wg.Done()
				peers, err := s.sendFindNode(addr, targetID)
				if err == nil && len(peers) > 0 {
					mu.Lock()
					newPeers = append(newPeers, peers...)
					mu.Unlock()
				}
			}(node.Addr)
		}

		wg.Wait()

		// 4. Merge newly discovered peers into the shortlist
		if len(newPeers) > 0 {
			existingMap := make(map[string]bool)
			for _, n := range shortList.Nodes {
				existingMap[n.Addr] = true
			}

			for _, p := range newPeers {
				if !existingMap[p.Addr] && p.Addr != s.AdvertiseAddr {
					shortList.Nodes = append(shortList.Nodes, dht.NodeInfo{
						ID:   dht.ID(p.ID),
						Addr: p.Addr,
					})
					existingMap[p.Addr] = true
				}
			}

			// Resort
			shortList.Sort()
			
			// If we grew beyond K, truncate to keep only the best K
			if len(shortList.Nodes) > dht.K {
				shortList.Nodes = shortList.Nodes[:dht.K]
			}
		}

		// 5. Check if we made progress
		closestAfterRound := shortList.Nodes[0].ID
		if closestBeforeRound == closestAfterRound {
			// No progress made this round (we didn't find anyone closer).
			// In standard Kademlia, we'd query ALL remaining unqueried nodes in the top K.
			// But for simplicity, we assume convergence.
			break
		}
	}

	// Return up to K nodes
	if len(shortList.Nodes) > dht.K {
		return shortList.Nodes[:dht.K]
	}
	return shortList.Nodes
}
