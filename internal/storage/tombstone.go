package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Tombstone marks a chunk as permanently deleted.
// We keep this around indefinitely as a delete journal to ensure
// offline peers can always sync and learn about the deletion when they reconnect.
type Tombstone struct {
	ChunkKey  string    `json:"chunk_key"`
	DeletedAt time.Time `json:"deleted_at"`
}

// TombstoneStore is a file-backed, thread-safe registry of deleted chunks.
// Lives at <rootDir>/tombstones.json on each node.
type TombstoneStore struct {
	path    string
	mu      sync.RWMutex
	entries map[string]Tombstone // keyed by ChunkKey for O(1) lookup
}

// NewTombstoneStore loads (or creates) the tombstone file at <rootDir>/tombstones.json.
func NewTombstoneStore(rootDir string) *TombstoneStore {
	ts := &TombstoneStore{
		path:    filepath.Join(rootDir, "tombstones.json"),
		entries: make(map[string]Tombstone),
	}
	ts.load() // no-op if file doesn't exist yet
	return ts
}

// Kill adds a tombstone for chunkKey and persists to disk immediately.
func (ts *TombstoneStore) Kill(chunkKey string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.entries[chunkKey] = Tombstone{
		ChunkKey:  chunkKey,
		DeletedAt: time.Now(),
	}
	return ts.save()
}

// IsDead checks if chunkKey has been tombstoned.
func (ts *TombstoneStore) IsDead(chunkKey string) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	_, ok := ts.entries[chunkKey]
	return ok
}

// All returns a snapshot of all current tombstones (for sync messages to new peers).
func (ts *TombstoneStore) All() []Tombstone {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make([]Tombstone, 0, len(ts.entries))
	for _, t := range ts.entries {
		result = append(result, t)
	}
	return result
}


// ApplyBatch adds multiple tombstones at once (used during TombstoneSync).
// skips any that are already in our store.
func (ts *TombstoneStore) ApplyBatch(tombstones []Tombstone) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	changed := false
	for _, t := range tombstones {
		if _, exists := ts.entries[t.ChunkKey]; !exists {
			ts.entries[t.ChunkKey] = t
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return ts.save()
}

// -------- Persistence --------

func (ts *TombstoneStore) load() {
	data, err := os.ReadFile(ts.path)
	if err != nil {
		return // file doesn't exist yet, that's fine
	}

	var list []Tombstone
	if err := json.Unmarshal(data, &list); err != nil {
		return // corrupted file — start fresh, will be overwritten on next Kill
	}
	for _, t := range list {
		ts.entries[t.ChunkKey] = t
	}
}

func (ts *TombstoneStore) save() error {
	list := make([]Tombstone, 0, len(ts.entries))
	for _, t := range ts.entries {
		list = append(list, t)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	// make sure rootDir exists (first ever save)
	if err := os.MkdirAll(filepath.Dir(ts.path), 0755); err != nil {
		return err
	}
	return os.WriteFile(ts.path, data, 0644)
}
