package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CIDEntry holds metadata about a file we stored on the network.
// This is purely local bookkeeping — other nodes don't see this.
type CIDEntry struct {
	CID          string `json:"cid"`
	OriginalName string `json:"original_name"`
	Size         int64  `json:"size"` // encrypted size (sum of chunks)
	ChunkCount   int    `json:"chunk_count"`
	StoredAt     string `json:"stored_at"` // RFC3339 timestamp
}

// CIDIndex is a simple file-backed index that maps CIDs to metadata.
// It lives in the node's data directory so each node has its own index.
type CIDIndex struct {
	path    string
	mu      sync.Mutex
	entries map[string]CIDEntry // keyed by CID for O(1) lookup
}

// NewCIDIndex loads (or creates) the index file at <rootDir>/cid_index.json.
func NewCIDIndex(rootDir string) *CIDIndex {
	idx := &CIDIndex{
		path:    filepath.Join(rootDir, "cid_index.json"),
		entries: make(map[string]CIDEntry),
	}
	idx.load() // if file doesn't exist yet, we just start empty
	return idx
}

// Add records a new CID in the index and persists to disk.
func (idx *CIDIndex) Add(entry CIDEntry) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	entry.StoredAt = time.Now().Format(time.RFC3339)
	idx.entries[entry.CID] = entry
	return idx.save()
}

// List returns all entries in the index, sorted by nothing (map order).
// the caller can sort if they want.
func (idx *CIDIndex) List() []CIDEntry {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	result := make([]CIDEntry, 0, len(idx.entries))
	for _, e := range idx.entries {
		result = append(result, e)
	}
	return result
}

// load reads the index from disk. if the file doesn't exist, it's a no-op.
func (idx *CIDIndex) load() {
	data, err := os.ReadFile(idx.path)
	if err != nil {
		return // file doesn't exist yet, start fresh
	}

	var entries []CIDEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return // corrupted file, start fresh (we'll overwrite on next Add)
	}
	for _, e := range entries {
		idx.entries[e.CID] = e
	}
}

// save writes the full index to disk as a JSON array.
func (idx *CIDIndex) save() error {
	entries := make([]CIDEntry, 0, len(idx.entries))
	for _, e := range idx.entries {
		entries = append(entries, e)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(idx.path, data, 0644)
}
