package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// how long a tombstone sticks around after the bytes are deleted.
// 24h is plenty of time for offline peers to come back and learn about the deletion.
// after that, the tombstone record is purged — safe because a re-store of the same
// file always produces fresh chunk keys (new random nonce each time).
const TombstoneGracePeriod = 24 * time.Hour

// Tombstone marks a chunk as permanently deleted.
// We keep this around for the grace period to block any stale
// offline peer from re-pushing old data back into our store.
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

// IsDead checks if chunkKey has been tombstoned and the grace period is still active.
// Once the grace period expires the tombstone is considered gone — re-stores are fine.
func (ts *TombstoneStore) IsDead(chunkKey string) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	t, ok := ts.entries[chunkKey]
	if !ok {
		return false
	}
	// still within grace period — treat as dead
	return time.Since(t.DeletedAt) < TombstoneGracePeriod
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

// Purge removes a tombstone record entirely. Only call this after the grace period
// has expired and the chunk bytes are confirmed gone.
func (ts *TombstoneStore) Purge(chunkKey string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	delete(ts.entries, chunkKey)
	return ts.save()
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
