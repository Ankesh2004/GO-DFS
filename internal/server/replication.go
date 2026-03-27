package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

// how many copies of each chunk we want alive in the network.
// separate from the DHT K constant — K is about routing table buckets,
// R is about data durability. keeping it small to save bandwidth.
const ReplicaTarget = 3

// heartbeat timing — 15s interval, 3 misses = dead.
// aggressive enough to catch crashes quickly, chill enough
// to not spam the network with pings on every breath.
const (
	HeartbeatInterval = 15 * time.Second
	FailureThreshold  = 3
)

// how often we scan our local manifests and check if chunks are healthy.
// 60s is a decent balance — fast enough to catch issues, slow enough
// to not turn the network into a constant audit firehose.
const (
	AuditInterval = 60 * time.Second
	AuditTimeout  = 3 * time.Second // max wait for peer batch responses
)

// PeerHealth tracks whether a peer is alive or ghosting us.
// missedPings goes up each heartbeat if they don't pong back,
// resets to 0 when they do.
type PeerHealth struct {
	LastSeen    time.Time
	MissedPings int
}

// holderSet is a set of advertise addresses that reported holding a chunk.
// using map[string]struct{} instead of a slice so dedup is automatic.
type holderSet map[string]struct{}

// batchAudit collects batch responses from peers during one audit round.
// each peer sends back which chunks they hold + their address, so we know
// exactly WHO has each chunk — not just a count.
type batchAudit struct {
	mu      sync.Mutex
	holders map[string]holderSet // chunkKey -> set of holder addresses
	done    chan struct{}        // closed when the collection window ends
}

// -------- Heartbeat / Failure Detection --------

// heartbeatLoop pings every connected peer on a timer.
// if a peer misses too many pongs in a row, we kick them out
// and immediately trigger a replication audit to patch any holes.
func (s *FileServer) heartbeatLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.runHeartbeat()
		case <-s.quitChannel:
			return
		}
	}
}

func (s *FileServer) runHeartbeat() {
	s.peersLock.Lock()
	peerList := make([]struct {
		addr string
		peer p2p.Peer
	}, 0, len(s.peers))
	for addr, p := range s.peers {
		peerList = append(peerList, struct {
			addr string
			peer p2p.Peer
		}{addr, p})
	}
	s.peersLock.Unlock()

	if len(peerList) == 0 {
		return
	}

	// ping everyone
	pingMsg := &Message{Payload: MessagePing{}}
	for _, entry := range peerList {
		if err := s.sendToPeer(entry.peer, pingMsg); err != nil {
			fmt.Printf("[%s] Heartbeat: failed to ping %s: %v\n", s.Transport.Addr(), entry.addr, err)
		}
	}

	// give peers a moment to respond, but respect shutdown signals.
	select {
	case <-time.After(2 * time.Second):
	case <-s.quitChannel:
		return
	}

	// check who responded and who didn't
	var deadPeers []string
	s.healthLock.Lock()
	for _, entry := range peerList {
		health, exists := s.peerHealth[entry.addr]
		if !exists {
			// first time seeing this peer in heartbeat — initialize
			s.peerHealth[entry.addr] = &PeerHealth{
				LastSeen:    time.Now(),
				MissedPings: 0,
			}
			continue
		}

		// if they responded, handlePong already reset missedPings.
		// if they didn't, bump the counter.
		if time.Since(health.LastSeen) > HeartbeatInterval {
			health.MissedPings++
			if health.MissedPings >= FailureThreshold {
				deadPeers = append(deadPeers, entry.addr)
			} else {
				fmt.Printf("[%s] Heartbeat: peer %s missed %d/%d pings\n",
					s.Transport.Addr(), entry.addr, health.MissedPings, FailureThreshold)
			}
		}
	}
	s.healthLock.Unlock()

	// evict dead peers and trigger re-replication
	for _, addr := range deadPeers {
		s.evictDeadPeer(addr)
	}
	if len(deadPeers) > 0 {
		// a node went down — don't wait for the next audit cycle,
		// check chunk health RIGHT NOW so we can re-replicate fast
		go s.runReplicationAudit()
	}
}

// markPeerAlive is called by handlePong to reset a peer's health status.
// this is how we know a peer is still alive — they responded to our ping.
func (s *FileServer) markPeerAlive(addr string) {
	s.healthLock.Lock()
	defer s.healthLock.Unlock()

	health, exists := s.peerHealth[addr]
	if !exists {
		s.peerHealth[addr] = &PeerHealth{
			LastSeen:    time.Now(),
			MissedPings: 0,
		}
		return
	}

	health.LastSeen = time.Now()
	health.MissedPings = 0
}

// evictDeadPeer removes a peer from every tracking structure.
// this is the "funeral" — once we call this, the peer is gone from
// our worldview until they reconnect and do PeerExchange again.
func (s *FileServer) evictDeadPeer(addr string) {
	fmt.Printf("[%s] EVICTING dead peer: %s (missed %d heartbeats)\n",
		s.Transport.Addr(), addr, FailureThreshold)

	s.peersLock.Lock()
	// close the TCP connection so the read-loop goroutine exits cleanly
	if peer, ok := s.peers[addr]; ok {
		peer.Close()
	}
	delete(s.peers, addr)
	delete(s.verifiedAddrs, addr)
	delete(s.relayPeers, addr)
	for raw, advertised := range s.addrMap {
		if advertised == addr {
			delete(s.addrMap, raw)
		}
	}
	s.peersLock.Unlock()

	// find the peer's actual DHT ID by looking up their address in the routing table.
	// can't just do dht.NewID(addr) because that hashes the address string,
	// but the routing table stores the real ID from PeerExchange.
	allNodes := s.DHT.RoutingTable.GetAllNodes()
	for _, n := range allNodes {
		if n.Addr == addr {
			s.DHT.RoutingTable.RemoveNode(n.ID)
			break
		}
	}

	// clean up health tracking
	s.healthLock.Lock()
	delete(s.peerHealth, addr)
	s.healthLock.Unlock()
}

// -------- Replication Audit Loop --------

// replicationLoop runs every AuditInterval and checks if our locally
// known chunks have enough replicas across the network.
func (s *FileServer) replicationLoop() {
	ticker := time.NewTicker(AuditInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.runReplicationAudit()
		case <-s.quitChannel:
			return
		}
	}
}

// runReplicationAudit does a TWO-PHASE audit to minimize lock contention:
//
// Phase 1 (fast, under auditLock): collect all chunk keys and query peers.
//
//	sends ONE batched message per peer instead of one per chunk.
//	waits for responses with a single timeout instead of N timeouts.
//
// Phase 2 (no auditLock): act on the results — push under-replicated chunks,
//
//	tell over-replicated nodes to drop. network I/O happens here,
//	completely outside any lock.
func (s *FileServer) runReplicationAudit() {
	if s.RelayOnly {
		return
	}

	// prevent concurrent audit runs — but uses TryLock so we don't
	// block indefinitely if another audit is already running.
	// if we can't get the lock, just skip this round.
	if !s.auditLock.TryLock() {
		return
	}
	defer s.auditLock.Unlock()

	entries := s.CIDIndex.List()
	if len(entries) == 0 {
		return
	}

	// ---- Phase 1: collect all chunk keys from our manifests ----
	// also build an ownership set so we don't have to re-read manifests
	// later in handleOverReplication / handleDropChunk for each chunk.
	var allChunks []string
	ownedChunks := make(map[string]bool)
	for _, entry := range entries {
		manifestKey := entry.CID + ".manifest"
		manifest, err := s.loadManifest(manifestKey)
		if err != nil {
			continue
		}
		for _, chunkKey := range manifest.ChunkKeys {
			if !s.Tombstones.IsDead(chunkKey) {
				allChunks = append(allChunks, chunkKey)
				ownedChunks[chunkKey] = true
			}
		}
	}

	if len(allChunks) == 0 {
		return
	}

	fmt.Printf("[%s] Replication audit: checking %d chunks across %d files\n",
		s.Transport.Addr(), len(allChunks), len(entries))

	// ---- Phase 1b: send ONE batch query per peer, collect ALL responses ----
	// now returns a map of chunkKey -> set of holder addresses, not just counts.
	holderMap := s.batchAuditChunks(allChunks)

	// ---- Phase 2: act on the results (no locks held) ----
	underReplicated := 0
	overReplicated := 0
	healthy := 0

	type chunkAction struct {
		key     string
		holders holderSet
	}
	var underActions, overActions []chunkAction

	for _, chunkKey := range allChunks {
		holders := holderMap[chunkKey]
		count := len(holders)
		switch {
		case count < ReplicaTarget:
			underReplicated++
			underActions = append(underActions, chunkAction{chunkKey, holders})
		case count > ReplicaTarget:
			overReplicated++
			overActions = append(overActions, chunkAction{chunkKey, holders})
		default:
			healthy++
		}
	}

	if underReplicated > 0 || overReplicated > 0 {
		fmt.Printf("[%s] Audit done: %d healthy, %d under-replicated, %d over-replicated\n",
			s.Transport.Addr(), healthy, underReplicated, overReplicated)
	}

	// stash results for the CLI status command
	s.healthLock.Lock()
	s.lastAuditHealthy = healthy
	s.lastAuditUnder = underReplicated
	s.lastAuditOver = overReplicated
	s.lastAuditTime = time.Now()
	s.healthLock.Unlock()

	// now do the actual re-replication / cleanup.
	// this is the slow part (network I/O), and it's completely outside any lock.
	for _, a := range underActions {
		s.handleUnderReplication(a.key, a.holders)
	}
	for _, a := range overActions {
		s.handleOverReplication(a.key, a.holders, ownedChunks)
	}
}

// batchAuditChunks sends ONE query per peer with ALL chunk keys,
// collects responses, and returns a map of chunkKey -> set of holder addrs.
// this replaces the old per-chunk auditChunkReplicas that was O(n × 3s).
// now it's just ONE 3s timeout for the entire batch.
func (s *FileServer) batchAuditChunks(chunkKeys []string) map[string]holderSet {
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	auditID := hex.EncodeToString(idBytes)

	audit := &batchAudit{
		holders: make(map[string]holderSet, len(chunkKeys)),
		done:    make(chan struct{}),
	}
	s.pendingAudits.Store(auditID, audit)
	defer s.pendingAudits.Delete(auditID)

	// count ourselves — check which chunks we have locally
	for _, ck := range chunkKeys {
		if s.Store.Has(ck) {
			if audit.holders[ck] == nil {
				audit.holders[ck] = make(holderSet)
			}
			audit.holders[ck][s.AdvertiseAddr] = struct{}{}
		}
	}

	// send ONE batch query to each connected peer
	askMsg := &Message{
		Payload: MessageBatchChunkQuery{
			ChunkKeys: chunkKeys,
			AuditID:   auditID,
			ReplyAddr: s.AdvertiseAddr,
		},
	}

	s.peersLock.Lock()
	var targets []string
	for addr := range s.peers {
		if !s.relayPeers[addr] {
			targets = append(targets, addr)
		}
	}
	s.peersLock.Unlock()

	for _, addr := range targets {
		s.sendToAddr(addr, askMsg)
	}

	// single timeout for ALL responses — not per-chunk anymore!
	select {
	case <-time.After(AuditTimeout):
	case <-s.quitChannel:
	}
	close(audit.done)

	// snapshot the results
	audit.mu.Lock()
	result := make(map[string]holderSet, len(audit.holders))
	for k, set := range audit.holders {
		cp := make(holderSet, len(set))
		for addr := range set {
			cp[addr] = struct{}{}
		}
		result[k] = cp
	}
	audit.mu.Unlock()

	return result
}

// -------- Under-Replication Handling --------

// handleUnderReplication pushes a chunk to more nodes to reach ReplicaTarget.
// now uses the actual holder set to skip nodes that already have the chunk
// instead of blindly picking DHT-closest and hoping for the best.
func (s *FileServer) handleUnderReplication(chunkKey string, holders holderSet) {
	if !s.Store.Has(chunkKey) {
		// we don't have the chunk ourselves — can't push what we don't have.
		// another node that has it will handle the re-replication.
		return
	}

	needed := ReplicaTarget - len(holders)
	if needed <= 0 {
		return
	}

	fmt.Printf("[%s] Chunk %s under-replicated (%d/%d), need %d more copies\n",
		s.Transport.Addr(), truncateKey(chunkKey, 16), len(holders), ReplicaTarget, needed)

	targetID := dht.NewID(chunkKey)
	candidates := s.DHT.NearestNodes(targetID, dht.K)

	pushed := 0
	for _, node := range candidates {
		if pushed >= needed {
			break
		}
		if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
			continue
		}
		// skip nodes that already have the chunk — we know from the audit
		if _, alreadyHas := holders[node.Addr]; alreadyHas {
			continue
		}
		s.peersLock.Lock()
		isRelay := s.relayPeers[node.Addr]
		s.peersLock.Unlock()
		if isRelay {
			continue
		}

		fmt.Printf("[%s] Re-replicating chunk %s to %s\n",
			s.Transport.Addr(), truncateKey(chunkKey, 16), node.Addr)

		if err := s.pushChunkToAddr(node.Addr, chunkKey); err != nil {
			fmt.Printf("[%s] Failed to re-replicate chunk %s to %s: %v\n",
				s.Transport.Addr(), truncateKey(chunkKey, 16), node.Addr, err)
			continue
		}
		pushed++
	}

	if pushed > 0 {
		fmt.Printf("[%s] Re-replicated chunk %s to %d new nodes\n",
			s.Transport.Addr(), truncateKey(chunkKey, 16), pushed)
	}
}

// handleOverReplication tells the furthest actual holders to drop the chunk.
// now targets ONLY nodes that reported having the chunk, sorted by DHT distance.
// no more guessing — we send DropChunk only to confirmed holders.
func (s *FileServer) handleOverReplication(chunkKey string, holders holderSet, ownedChunks map[string]bool) {
	excess := len(holders) - ReplicaTarget
	if excess <= 0 {
		return
	}

	fmt.Printf("[%s] Chunk %s over-replicated (%d/%d), telling %d nodes to drop\n",
		s.Transport.Addr(), truncateKey(chunkKey, 16), len(holders), ReplicaTarget, excess)

	chunkTargetID := dht.NewID(chunkKey)
	myDist := dht.Distance(s.ID, chunkTargetID)

	dropMsg := &Message{
		Payload: MessageDropChunk{ChunkKey: chunkKey},
	}

	dropped := 0

	// check if we ourselves should drop — only if we're far from the chunk
	// AND enough closer holders exist AND we don't own the file.
	closerHolderCount := 0
	for addr := range holders {
		if addr == s.AdvertiseAddr {
			continue
		}
		// look up this holder's DHT ID from the routing table
		allNodes := s.DHT.RoutingTable.GetAllNodes()
		for _, n := range allNodes {
			if n.Addr == addr {
				if dht.Distance(n.ID, chunkTargetID).Cmp(myDist) < 0 {
					closerHolderCount++
				}
				break
			}
		}
	}

	if closerHolderCount >= ReplicaTarget && s.Store.Has(chunkKey) && dropped < excess {
		if !ownedChunks[chunkKey] {
			fmt.Printf("[%s] Dropping our own copy of chunk %s (we're far from it, %d closer holders exist)\n",
				s.Transport.Addr(), truncateKey(chunkKey, 16), closerHolderCount)
			if err := s.Store.DeleteStream(chunkKey); err != nil {
				fmt.Printf("[%s] Failed to drop our chunk %s: %v\n",
					s.Transport.Addr(), truncateKey(chunkKey, 16), err)
			} else {
				dropped++
			}
		} else {
			fmt.Printf("[%s] Skipping self-drop of chunk %s — it belongs to our file\n",
				s.Transport.Addr(), truncateKey(chunkKey, 16))
		}
	}

	// tell other confirmed holders to drop — pick the furthest ones first.
	// only send to addrs that are in the holder set, not just any routing table entry.
	if dropped < excess {
		for addr := range holders {
			if dropped >= excess {
				break
			}
			if addr == s.AdvertiseAddr || addr == s.Transport.Addr() {
				continue
			}
			// confirm they're further from the chunk than us
			allNodes := s.DHT.RoutingTable.GetAllNodes()
			for _, n := range allNodes {
				if n.Addr == addr {
					nodeDist := dht.Distance(n.ID, chunkTargetID)
					if nodeDist.Cmp(myDist) > 0 {
						if err := s.sendToAddr(addr, dropMsg); err == nil {
							dropped++
						}
					}
					break
				}
			}
		}
	}
}

// isOwnedChunk checks if a chunk belongs to any file in our CIDIndex.
// extracted so handleDropChunk can use it.
func (s *FileServer) isOwnedChunk(chunkKey string) bool {
	entries := s.CIDIndex.List()
	for _, e := range entries {
		manifestKey := e.CID + ".manifest"
		manifest, err := s.loadManifest(manifestKey)
		if err != nil {
			continue
		}
		for _, ck := range manifest.ChunkKeys {
			if ck == chunkKey {
				return true
			}
		}
	}
	return false
}

// -------- Message Handlers --------

// handleBatchChunkQuery responds to a batched "which of these chunks do you have?" query.
// checks all requested chunks in one pass and sends back one response.
func (s *FileServer) handleBatchChunkQuery(from string, msg MessageBatchChunkQuery) error {
	if s.RelayOnly {
		return nil
	}

	// check which of the requested chunks we actually have
	var held []string
	for _, ck := range msg.ChunkKeys {
		if s.Store.Has(ck) && !s.Tombstones.IsDead(ck) {
			held = append(held, ck)
		}
	}

	// only reply if we actually have something — no point sending an empty response
	if len(held) == 0 {
		return nil
	}

	response := &Message{
		Payload: MessageBatchChunkResponse{
			AuditID:    msg.AuditID,
			HeldChunks: held,
			HolderAddr: s.AdvertiseAddr,
		},
	}

	return s.sendToAddr(msg.ReplyAddr, response)
}

// handleBatchChunkResponse merges a peer's batch response into our audit state.
// now records the actual holder address per chunk instead of just incrementing a counter.
func (s *FileServer) handleBatchChunkResponse(_ string, msg MessageBatchChunkResponse) error {
	val, ok := s.pendingAudits.Load(msg.AuditID)
	if !ok {
		return nil // audit already finished or we didn't start one
	}

	audit := val.(*batchAudit)

	// check if the collection window is still open
	select {
	case <-audit.done:
		return nil // too late
	default:
	}

	audit.mu.Lock()
	for _, ck := range msg.HeldChunks {
		if audit.holders[ck] == nil {
			audit.holders[ck] = make(holderSet)
		}
		audit.holders[ck][msg.HolderAddr] = struct{}{}
	}
	audit.mu.Unlock()

	return nil
}

// handleDropChunk processes a request from another node telling us to drop a chunk.
func (s *FileServer) handleDropChunk(_ string, msg MessageDropChunk) error {
	if s.RelayOnly {
		return nil
	}
	if s.Tombstones.IsDead(msg.ChunkKey) || !s.Store.Has(msg.ChunkKey) {
		return nil
	}

	// never drop chunks from files we uploaded
	if s.isOwnedChunk(msg.ChunkKey) {
		fmt.Printf("[%s] Refusing to drop chunk %s — it belongs to our file\n",
			s.Transport.Addr(), truncateKey(msg.ChunkKey, 16))
		return nil
	}

	if err := s.Store.DeleteStream(msg.ChunkKey); err != nil {
		return fmt.Errorf("failed to drop chunk %s: %w", truncateKey(msg.ChunkKey, 16), err)
	}

	fmt.Printf("[%s] Dropped chunk %s (over-replicated, freed up space)\n",
		s.Transport.Addr(), truncateKey(msg.ChunkKey, 16))
	return nil
}

// -------- Status APIs --------

// GetReplicationStatus returns the latest audit results for the CLI.
func (s *FileServer) GetReplicationStatus() (healthy, under, over int, lastAudit time.Time) {
	s.healthLock.Lock()
	defer s.healthLock.Unlock()
	return s.lastAuditHealthy, s.lastAuditUnder, s.lastAuditOver, s.lastAuditTime
}

// GetPeerHealthMap returns a snapshot of peer health for the CLI.
func (s *FileServer) GetPeerHealthMap() map[string]PeerHealth {
	s.healthLock.Lock()
	defer s.healthLock.Unlock()

	result := make(map[string]PeerHealth, len(s.peerHealth))
	for addr, h := range s.peerHealth {
		result[addr] = *h
	}
	return result
}
