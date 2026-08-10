package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Ankesh2004/GO-DFS/pkg/dht"
)

type SavedPeer struct {
	ID   [32]byte `json:"id"`
	Addr string   `json:"addr"`
}

// loadPeers reads peers.json from disk and populates the routing table.
func (s *FileServer) loadPeers() {
	path := filepath.Join(s.RootDir, "peers.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("[%s] Warning: failed to read peers.json: %v\n", s.Transport.Addr(), err)
		}
		return
	}

	var saved []SavedPeer
	if err := json.Unmarshal(data, &saved); err != nil {
		fmt.Printf("[%s] Warning: failed to parse peers.json: %v\n", s.Transport.Addr(), err)
		return
	}

	for _, p := range saved {
		id := dht.ID(p.ID)
		if id != s.ID {
			s.DHT.Update(id, p.Addr)
		}
	}
	fmt.Printf("[%s] Loaded %d peers from peers.json\n", s.Transport.Addr(), len(saved))
}

// savePeers writes the current routing table to peers.json atomically.
func (s *FileServer) savePeers() {
	nodes := s.DHT.RoutingTable.GetAllNodes()
	var saved []SavedPeer
	for _, n := range nodes {
		saved = append(saved, SavedPeer{
			ID:   [32]byte(n.ID),
			Addr: n.Addr,
		})
	}

	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		fmt.Printf("[%s] Error marshaling peers: %v\n", s.Transport.Addr(), err)
		return
	}

	path := filepath.Join(s.RootDir, "peers.json")
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		fmt.Printf("[%s] Error writing peers to tmp file: %v\n", s.Transport.Addr(), err)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		fmt.Printf("[%s] Error renaming peers.json: %v\n", s.Transport.Addr(), err)
	}
}

// persistLoop periodically saves the routing table to disk.
func (s *FileServer) persistLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.savePeers()
		case <-s.quitChannel:
			return
		}
	}
}
