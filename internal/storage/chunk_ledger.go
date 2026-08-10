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
// It returns the ledger and a boolean indicating if it was missing or corrupted (needs rebuild).
func NewChunkLedger(rootDir string) (*ChunkLedger, bool) {
	cl := &ChunkLedger{
		path: filepath.Join(rootDir, "chunk_ledger.json"),
		keys: make(map[string]struct{}),
	}
	needsRebuild := cl.load()
	return cl, needsRebuild
}

// Add registers a chunk key in the ledger. idempotent — adding a key
// that already exists is a no-op. Returns an error if persistence fails,
// rolling back the in-memory state so it doesn't get out of sync with disk.
func (cl *ChunkLedger) Add(key string) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if _, exists := cl.keys[key]; exists {
		return nil
	}

	cl.keys[key] = struct{}{}
	if err := cl.save(); err != nil {
		delete(cl.keys, key) // rollback
		return fmt.Errorf("failed to persist ledger after Add: %w", err)
	}
	return nil
}

// AddBatch adds multiple chunk keys under a single lock and single disk write.
// Ideal for file uploads with many chunks.
func (cl *ChunkLedger) AddBatch(keys []string) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	added := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, exists := cl.keys[k]; !exists {
			cl.keys[k] = struct{}{}
			added = append(added, k)
		}
	}

	if len(added) == 0 {
		return nil
	}

	if err := cl.save(); err != nil {
		// rollback
		for _, k := range added {
			delete(cl.keys, k)
		}
		return fmt.Errorf("failed to persist ledger after AddBatch: %w", err)
	}
	return nil
}

// Remove deletes a chunk key from the ledger. no-op if the key isn't tracked.
// Rolls back if persistence fails.
func (cl *ChunkLedger) Remove(key string) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if _, exists := cl.keys[key]; !exists {
		return nil
	}
	
	delete(cl.keys, key)
	if err := cl.save(); err != nil {
		cl.keys[key] = struct{}{} // rollback
		return fmt.Errorf("failed to persist ledger after Remove: %w", err)
	}
	return nil
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

// load reads the ledger from disk.
// Returns true if the file was missing or corrupted (so caller knows to rebuild it).
func (cl *ChunkLedger) load() bool {
	data, err := os.ReadFile(cl.path)
	if err != nil {
		if os.IsNotExist(err) {
			return true // missing, needs rebuild for existing nodes
		}
		fmt.Printf("[ChunkLedger] WARNING: failed to read %s: %v\n", cl.path, err)
		return true // treat error as needing rebuild
	}

	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		fmt.Printf("[ChunkLedger] WARNING: %s is corrupted, needs rebuild: %v\n", cl.path, err)
		return true
	}
	for _, k := range keys {
		cl.keys[k] = struct{}{}
	}
	return false
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
