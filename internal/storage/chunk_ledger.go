package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ChunkLedger tracks every chunk key stored on this node's disk.
// unlike CIDIndex (which only knows about files WE uploaded),
// this tracks ALL chunks — including replicas received from other nodes.
// this is what the replication audit iterates so that EVERY node
// can detect under-replication and re-replicate, not just the uploader.
type ChunkLedger struct {
	path string
	mu   sync.RWMutex
	keys map[string]struct{}
}

// NewChunkLedger loads (or creates) the ledger at <rootDir>/chunk_ledger.json.
func NewChunkLedger(rootDir string) *ChunkLedger {
	cl := &ChunkLedger{
		path: filepath.Join(rootDir, "chunk_ledger.json"),
		keys: make(map[string]struct{}),
	}
	cl.load()
	return cl
}

// Add registers a chunk key in the ledger. idempotent — adding a key
// that already exists is a no-op (but still persists, just in case
// a previous save was interrupted).
func (cl *ChunkLedger) Add(key string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	cl.keys[key] = struct{}{}
	if err := cl.save(); err != nil {
		fmt.Printf("[ChunkLedger] warning: failed to persist after Add(%s): %v\n", key[:min(16, len(key))], err)
	}
}

// Remove deletes a chunk key from the ledger. no-op if the key isn't tracked.
func (cl *ChunkLedger) Remove(key string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if _, exists := cl.keys[key]; !exists {
		return
	}
	delete(cl.keys, key)
	if err := cl.save(); err != nil {
		fmt.Printf("[ChunkLedger] warning: failed to persist after Remove(%s): %v\n", key[:min(16, len(key))], err)
	}
}

// Has checks if a chunk key is tracked in the ledger.
func (cl *ChunkLedger) Has(key string) bool {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	_, exists := cl.keys[key]
	return exists
}

// All returns a snapshot of every chunk key in the ledger.
func (cl *ChunkLedger) All() []string {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	result := make([]string, 0, len(cl.keys))
	for k := range cl.keys {
		result = append(result, k)
	}
	return result
}

// Count returns how many chunk keys are tracked.
func (cl *ChunkLedger) Count() int {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return len(cl.keys)
}

// load reads the ledger from disk. if the file doesn't exist, we start empty.
// if it's corrupted, we log a warning and start empty — the ledger will
// get repopulated as chunks arrive or are audited by the network.
func (cl *ChunkLedger) load() {
	data, err := os.ReadFile(cl.path)
	if err != nil {
		return // file doesn't exist yet, start fresh
	}

	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		// unlike CIDIndex which silently starts empty on corruption,
		// at least yell about it so someone notices
		fmt.Printf("[ChunkLedger] WARNING: %s is corrupted, starting empty: %v\n", cl.path, err)
		return
	}
	for _, k := range keys {
		cl.keys[k] = struct{}{}
	}
}

// save writes the ledger to disk atomically: write to .tmp, then rename.
// this prevents the corruption-on-crash bug that cid_index.json has,
// where a partial write leaves a broken file that gets silently wiped on reboot.
func (cl *ChunkLedger) save() error {
	keys := make([]string, 0, len(cl.keys))
	for k := range cl.keys {
		keys = append(keys, k)
	}

	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	// write to a temp file first, then atomic rename
	tmpPath := cl.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, cl.path)
}
