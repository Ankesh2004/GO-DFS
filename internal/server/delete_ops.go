package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/storage"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
)

// truncateKey safely shortens a key string for log output.
// avoids a panic when a key is somehow shorter than maxLen.
func truncateKey(key string, maxLen int) string {
	if len(key) <= maxLen {
		return key
	}
	return key[:maxLen]
}

// DeleteFile deletes a file from the network by:
//  1. Loading the manifest to get all chunk keys
//  2. Tombstoning every chunk + the manifest locally
//  3. Deleting the bytes from local CAS
//  4. Broadcasting MessageDeleteFile to all known peers
//  5. Cleaning up CIDIndex
func (s *FileServer) DeleteFile(cid string) error {
	manifestKey := cid + ".manifest"

	// need the manifest to know which chunks to kill
	manifest, err := s.loadManifest(manifestKey)
	if err != nil {
		return fmt.Errorf("delete: can't load manifest for %s: %w", cid, err)
	}

	// build the tombstone list: manifest + every chunk
	keys := make([]string, 0, len(manifest.ChunkKeys)+1)
	keys = append(keys, manifestKey)
	keys = append(keys, manifest.ChunkKeys...)

	tombstones := make([]storage.Tombstone, 0, len(keys))
	for _, key := range keys {
		// Kill MUST succeed before we delete bytes or tell the network.
		// If the tombstone isn't persisted, we could lose track of the deletion
		// and the file could resurface after a restart — abort the whole operation.
		if err := s.Tombstones.Kill(key); err != nil {
			return fmt.Errorf("delete: failed to tombstone %s: %w", truncateKey(key, 16), err)
		}
		tombstones = append(tombstones, storage.Tombstone{
			ChunkKey:  key,
			DeletedAt: time.Now(),
		})
		// delete the bytes immediately from local CAS
		// if this fails, the GC loop will clean them up later — tombstone is already set
		if s.Store.Has(key) {
			if err := s.Store.DeleteStream(key); err != nil {
				fmt.Printf("[%s] Warning: failed to delete local bytes for %s: %v\n", s.Transport.Addr(), truncateKey(key, 16), err)
			}
		}
	}

	// remove from local index
	s.CIDIndex.Remove(cid)

	fmt.Printf("[%s] Deleted file %s locally (%d chunks + manifest)\n",
		s.Transport.Addr(), truncateKey(cid, 16), len(manifest.ChunkKeys))

	// broadcast the tombstones to the network
	// we send to DHT-nearest nodes AND all direct peers for maximum reach
	msg := &Message{
		Payload: MessageDeleteFile{
			CID:        cid,
			Tombstones: tombstones,
		},
	}
	s.broadcastDeleteToNetwork(cid, msg)

	return nil
}

// broadcastDeleteToNetwork sends the delete message to DHT-nearest nodes
// plus any direct peers not covered by the DHT lookup.
func (s *FileServer) broadcastDeleteToNetwork(cid string, msg *Message) {
	targeted := make(map[string]bool)

	// DHT-nearest nodes (most likely to have a replica)
	targetID := dht.NewID(cid)
	closest := s.DHT.NearestNodes(targetID, dht.K)
	for _, node := range closest {
		if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
			continue
		}
		targeted[node.Addr] = true
		if err := s.sendToAddr(node.Addr, msg); err != nil {
			fmt.Printf("[%s] Delete broadcast failed for %s: %v\n", s.Transport.Addr(), node.Addr, err)
		}
	}

	// also hit all direct peers not already covered above
	s.peersLock.Lock()
	var remaining []string
	for addr := range s.peers {
		if !targeted[addr] {
			remaining = append(remaining, addr)
		}
	}
	s.peersLock.Unlock()

	for _, addr := range remaining {
		if err := s.sendToAddr(addr, msg); err != nil {
			fmt.Printf("[%s] Delete broadcast (fallback) failed for %s: %v\n", s.Transport.Addr(), addr, err)
		}
	}
}

// -------- handleDeleteFile (received from a peer) --------

// handleDeleteFile applies incoming tombstones locally and deletes the chunk bytes.
// We don't re-broadcast here — that would flood the network.
// Offline peers catch up via MessageTombstoneSync when they reconnect.
func (s *FileServer) handleDeleteFile(_ string, msg MessageDeleteFile) error {
	// note: relay nodes (s.RelayOnly = true) shouldn't be storing data anyway,
	// but we still apply tombstones so they don't accidentally serve anything
	// if something slipped through.

	// track the first Kill error — we still process the rest of the tombstones
	// as best-effort cleanup, but we'll return the error at the end so the
	// caller knows something went wrong instead of silently getting nil.
	var firstKillErr error

	for _, t := range msg.Tombstones {
		// apply tombstone first — if this fails, don't delete the bytes
		// (a un-tombstoned chunk that still has bytes is safer than a
		// un-tombstoned chunk with deleted bytes and no record of why)
		if err := s.Tombstones.Kill(t.ChunkKey); err != nil {
			fmt.Printf("[%s] Warning: tombstone failed for %s: %v\n", s.Transport.Addr(), truncateKey(t.ChunkKey, 16), err)
			if firstKillErr == nil {
				firstKillErr = err
			}
			continue // don't delete bytes without a persisted tombstone
		}
		// delete local bytes
		if s.Store.Has(t.ChunkKey) {
			if err := s.Store.DeleteStream(t.ChunkKey); err != nil {
				fmt.Printf("[%s] Warning: failed to delete bytes for %s: %v\n", s.Transport.Addr(), truncateKey(t.ChunkKey, 16), err)
			} else {
				fmt.Printf("[%s] Deleted chunk %s (tombstoned by peer)\n", s.Transport.Addr(), truncateKey(t.ChunkKey, 16))
			}
		}
	}

	// best-effort: remove from CIDIndex regardless of Kill failures
	// (the index is cosmetic — an incomplete entry is less harmful than leaving it)
	s.CIDIndex.Remove(msg.CID)

	if firstKillErr != nil {
		return fmt.Errorf("handleDeleteFile %s: some tombstones failed to persist: %w",
			truncateKey(msg.CID, 16), firstKillErr)
	}

	fmt.Printf("[%s] Applied %d tombstones for file %s\n",
		s.Transport.Addr(), len(msg.Tombstones), truncateKey(msg.CID, 16))
	return nil
}

// -------- handleTombstoneSync (received from a newly connected peer) --------

// handleTombstoneSync applies a batch of tombstones from a peer.
// This is how nodes that were offline catch up on deletions they missed.
func (s *FileServer) handleTombstoneSync(_ string, msg MessageTombstoneSync) error {
	if len(msg.Tombstones) == 0 {
		return nil
	}

	// apply the batch — TombstoneStore.ApplyBatch only adds ones we don't have yet
	if err := s.Tombstones.ApplyBatch(msg.Tombstones); err != nil {
		return fmt.Errorf("tombstone sync: %w", err)
	}

	// delete any local bytes we have for newly tombstoned chunks
	for _, t := range msg.Tombstones {
		// If this is a manifest tombstone, also clean up the CID index
		if strings.HasSuffix(t.ChunkKey, ".manifest") {
			cid := strings.TrimSuffix(t.ChunkKey, ".manifest")
			s.CIDIndex.Remove(cid)
		}

		if !s.Store.Has(t.ChunkKey) {
			continue
		}
		if err := s.Store.DeleteStream(t.ChunkKey); err != nil {
			fmt.Printf("[%s] Warning: failed to delete bytes for synced tombstone %s: %v\n",
				s.Transport.Addr(), truncateKey(t.ChunkKey, 16), err)
		}
	}

	fmt.Printf("[%s] TombstoneSync: applied %d tombstones from peer\n",
		s.Transport.Addr(), len(msg.Tombstones))
	return nil
}

// -------- GC Loop --------

// gcLoop runs every 10 minutes.
// For each tombstone:
//   - deletes the chunk bytes from CAS (in case any slipped through or disk write failed earlier)
//     (The tombstone record itself stays indefinitely as a delete journal for offline peers)
func (s *FileServer) gcLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.runGC()
		case <-s.quitChannel:
			return
		}
	}
}

func (s *FileServer) runGC() {
	tombstones := s.Tombstones.All()
	if len(tombstones) == 0 {
		return
	}

	fmt.Printf("[%s] GC: checking %d tombstones\n", s.Transport.Addr(), len(tombstones))
	cleaned := 0

	for _, t := range tombstones {
		// make sure bytes are gone
		if s.Store.Has(t.ChunkKey) {
			if err := s.Store.DeleteStream(t.ChunkKey); err != nil {
				fmt.Printf("[%s] GC: failed to delete %s: %v\n", s.Transport.Addr(), truncateKey(t.ChunkKey, 16), err)
				continue
			}
			cleaned++
		}
	}

	if cleaned > 0 {
		fmt.Printf("[%s] GC: removed local bytes for %d tombstoned chunks\n", s.Transport.Addr(), cleaned)
	}
}
