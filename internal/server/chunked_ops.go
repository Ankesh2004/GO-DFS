package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/storage"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

// verifyChunkHash checks that the SHA-256 of data matches the expected key.
// This is the core of zero-trust: we never trust a peer's claim about
// what chunk they're sending us. If the hash doesn't match, they lied.
func verifyChunkHash(expectedKey string, data []byte) error {
	actual := sha256.Sum256(data)
	actualHex := hex.EncodeToString(actual[:])
	if actualHex != expectedKey {
		return fmt.Errorf("chunk integrity failed: expected %s, got %s", expectedKey[:16], actualHex[:16])
	}
	return nil
}

// relayBufPool is used during relay stream piping so we're not
// allocating 32KB buffers on every relay request. Critical for
// bootstrap nodes that handle tons of relay traffic.
var relayBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024) // 32KB pipe buffer
		return &buf
	},
}

// -------- Relay Stream Handling --------

// handleRelayStream is called when we receive a relay stream RPC (0x3).
// The decoder already parsed the header (RelayStreamMeta), so we know
// who sent it, who it's for, and how many bytes are coming.
//
// If WE are the target: read the data and store the chunk locally.
// If we're NOT the target: pipe the data to the actual target peer.
func (s *FileServer) handleRelayStream(from string, rpc p2p.RPC) error {
	meta := rpc.RelayMeta

	// find the peer connection that sent us this data — we need to read from it
	s.peersLock.Lock()
	sourcePeer, sourceOk := s.peers[from]
	s.peersLock.Unlock()

	if !sourceOk {
		return fmt.Errorf("relay stream from unknown peer %s", from)
	}

	// Are WE the intended target?
	if meta.TargetAddr == s.AdvertiseAddr || meta.TargetAddr == s.Transport.Addr() {
		fmt.Printf("[%s] Receiving relay stream: %s (%d bytes) from %s\n",
			s.Transport.Addr(), meta.Key, meta.TotalSize, meta.OriginAddr)

		if s.RelayOnly {
			// we're a relay node, not supposed to store anything — drain and discard
			_, _ = io.CopyN(io.Discard, sourcePeer, meta.TotalSize)
			sourcePeer.CloseStream()
			return nil
		}

		// read the streamed bytes into memory so we can verify the hash
		// before committing to disk. this prevents a malicious peer from
		// poisoning our store with garbage under a valid chunk key.
		data := make([]byte, meta.TotalSize)
		_, err := io.ReadFull(sourcePeer, data)
		sourcePeer.CloseStream()
		if err != nil {
			return fmt.Errorf("failed to read relay stream data for %s: %w", meta.Key, err)
		}

		if err := verifyChunkHash(meta.Key, data); err != nil {
			return fmt.Errorf("[%s] REJECTING relay chunk from %s: %w", s.Transport.Addr(), meta.OriginAddr, err)
		}

		n, err := s.Store.WriteStream(meta.Key, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("failed to store relay stream data for %s: %w", meta.Key, err)
		}
		fmt.Printf("[%s] Stored relay stream chunk %s: %d bytes (verified)\n", s.Transport.Addr(), meta.Key, n)
		s.notifyChunkArrived(meta.Key)
		return nil
	}

	// We're NOT the target — pipe it through to whoever is
	s.peersLock.Lock()
	targetPeer, targetOk := s.peers[meta.TargetAddr]
	s.peersLock.Unlock()

	if !targetOk {
		// can't forward, drain the data so we don't corrupt the connection
		_, _ = io.CopyN(io.Discard, sourcePeer, meta.TotalSize)
		sourcePeer.CloseStream()
		return fmt.Errorf("[%s] can't relay stream to %s: not in peer list", s.Transport.Addr(), meta.TargetAddr)
	}

	fmt.Printf("[%s] Piping relay stream %s → %s (%d bytes)\n",
		s.Transport.Addr(), meta.OriginAddr, meta.TargetAddr, meta.TotalSize)

	// write the type marker + header to the target so they know what's coming
	if _, err := targetPeer.Write([]byte{p2p.IncomingRelayStream}); err != nil {
		_, _ = io.CopyN(io.Discard, sourcePeer, meta.TotalSize)
		sourcePeer.CloseStream()
		return fmt.Errorf("failed to write relay stream type marker to %s: %w", meta.TargetAddr, err)
	}
	if err := writeRelayStreamHeader(targetPeer, meta); err != nil {
		_, _ = io.CopyN(io.Discard, sourcePeer, meta.TotalSize)
		sourcePeer.CloseStream()
		return fmt.Errorf("failed to write relay stream header to %s: %w", meta.TargetAddr, err)
	}

	// now just pipe raw bytes: source → target, using a pooled buffer
	bufPtr := relayBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(targetPeer, io.LimitReader(sourcePeer, meta.TotalSize), *bufPtr)
	relayBufPool.Put(bufPtr)

	if err != nil {
		// drain any unread bytes so the connection stays in sync
		remaining := meta.TotalSize - n
		if remaining > 0 {
			_, _ = io.CopyN(io.Discard, sourcePeer, remaining)
		}
		sourcePeer.CloseStream()
		return fmt.Errorf("relay pipe error after %d bytes: %w", n, err)
	}

	sourcePeer.CloseStream()

	fmt.Printf("[%s] Relay stream piped %d bytes for chunk %s\n", s.Transport.Addr(), n, meta.Key)
	return nil
}

// sendRelayStream initiates a streaming relay transfer.
// Wire format: [0x3] [4-byte header len] [gob-encoded RelayStreamMeta] [raw bytes...]
// The relay node reads the header, then pipes the raw bytes to the target.
func (s *FileServer) sendRelayStream(relayPeer p2p.Peer, targetAddr string, key string, size int64, src io.Reader) error {
	meta := &p2p.RelayStreamMeta{
		TargetAddr: targetAddr,
		OriginAddr: s.AdvertiseAddr,
		Key:        key,
		TotalSize:  size,
	}

	// write the type marker — exactly once. writeRelayStreamHeader does NOT
	// write the marker byte, it only writes [4-byte len][gob header].
	if err := relayPeer.Send([]byte{p2p.IncomingRelayStream}); err != nil {
		return fmt.Errorf("failed to send relay stream marker: %w", err)
	}

	// write the header (length + gob-encoded meta, no type marker)
	if err := writeRelayStreamHeader(relayPeer, meta); err != nil {
		return err
	}

	// stream the actual data
	n, err := io.Copy(relayPeer, io.LimitReader(src, size))
	if err != nil {
		return fmt.Errorf("relay stream send failed after %d/%d bytes: %w", n, size, err)
	}
	return nil
}

// writeRelayStreamHeader encodes ONLY the header portion into the connection.
// Format: [4-byte length] [gob-encoded RelayStreamMeta]
//
// IMPORTANT: this does NOT write the 0x3 type marker. The caller is responsible
// for writing that byte before calling this. This prevents the double-marker bug
// where both the originator and the relay would write 0x3.
func writeRelayStreamHeader(w io.Writer, meta *p2p.RelayStreamMeta) error {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(meta); err != nil {
		return fmt.Errorf("failed to encode relay stream header: %w", err)
	}

	headerLen := uint32(buf.Len())
	if err := binary.Write(w, binary.LittleEndian, headerLen); err != nil {
		return fmt.Errorf("failed to write relay stream header length: %w", err)
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write relay stream header: %w", err)
	}
	return nil
}

// -------- Store Manifest --------

func (s *FileServer) handleStoreManifest(from string, msg MessageStoreManifest) error {
	if s.RelayOnly {
		fmt.Printf("[%s] REJECTING manifest store for %s from %s: RelayOnly mode\n",
			s.Transport.Addr(), msg.Key, from)
		return nil
	}

	fmt.Printf("[%s] Storing manifest %s from %s (%d chunks)\n",
		s.Transport.Addr(), msg.Key, from, len(msg.Manifest.ChunkKeys))

	// serialize the manifest and store it in the CAS like any other blob
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(msg.Manifest); err != nil {
		return fmt.Errorf("failed to encode manifest: %w", err)
	}

	n, err := s.Store.WriteStream(msg.Key, &buf)
	if err != nil {
		return fmt.Errorf("failed to store manifest: %w", err)
	}
	fmt.Printf("[%s] Manifest %s stored: %d bytes\n", s.Transport.Addr(), msg.Key, n)
	return nil
}

// -------- Get Manifest --------

func (s *FileServer) handleGetManifest(from string, msg MessageGetManifest) error {
	response := MessageManifestResponse{
		Key:   msg.Key,
		Found: false,
	}

	if s.Store.Has(msg.Key) {
		_, r, err := s.Store.ReadStream(msg.Key)
		if err == nil {
			defer r.Close()
			var manifest FileManifest
			if err := gob.NewDecoder(r).Decode(&manifest); err == nil {
				response.Found = true
				response.Manifest = manifest
			}
		}
	}

	respMsg := &Message{Payload: response}
	return s.sendToAddr(from, respMsg)
}

// handleManifestResponse processes an incoming manifest we requested.
// We just store it locally so GetFile can pick it up later.
func (s *FileServer) handleManifestResponse(from string, msg MessageManifestResponse) error {
	if !msg.Found {
		return nil // they don't have it, no big deal
	}

	// store it if we don't already have it
	if !s.Store.Has(msg.Key) {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(msg.Manifest); err != nil {
			return err
		}
		_, err := s.Store.WriteStream(msg.Key, &buf)
		if err != nil {
			return fmt.Errorf("failed to store received manifest: %w", err)
		}
		fmt.Printf("[%s] Stored manifest %s from %s\n", s.Transport.Addr(), msg.Key, from)
	}
	return nil
}

// -------- Store Chunk (direct stream) --------

// DEPRECATED: nothing sends MessageStoreChunk anymore — we switched to inline
// MessageChunkData. Kept for backward compat in case older nodes still use it.
func (s *FileServer) handleStoreChunk(from string, msg MessageStoreChunk) error {
	if s.RelayOnly {
		fmt.Printf("[%s] REJECTING chunk store for %s from %s: RelayOnly mode\n",
			s.Transport.Addr(), msg.ChunkKey, from)
		return nil
	}

	// only direct peers send StoreChunk — the data follows on the connection
	s.peersLock.Lock()
	peer, directConn := s.peers[from]
	s.peersLock.Unlock()

	if !directConn {
		// if not directly connected, the data will come via relay stream separately
		fmt.Printf("[%s] StoreChunk metadata from remote %s for %s — waiting for relay data\n",
			s.Transport.Addr(), from, msg.ChunkKey)
		return nil
	}

	fmt.Printf("[%s] Receiving %d bytes (direct) for chunk %s\n", s.Transport.Addr(), msg.Size, msg.ChunkKey)
	n, err := s.Store.WriteStream(msg.ChunkKey, io.LimitReader(peer, msg.Size))
	if err != nil {
		return err
	}

	peer.CloseStream()
	fmt.Printf("[%s] Stored chunk %s: %d bytes\n", s.Transport.Addr(), msg.ChunkKey, n)
	return nil
}

// -------- Get Chunk --------

func (s *FileServer) handleGetChunk(from string, msg MessageGetChunk) error {
	if !s.Store.Has(msg.ChunkKey) {
		return nil // we don't have it, silently ignore
	}

	size, r, err := s.Store.ReadStream(msg.ChunkKey)
	if err != nil {
		return err
	}

	// for chunks small enough to fit in a message, just send them inline.
	// this avoids the protocol complexity of setting up a stream for each chunk.
	const inlineMax = 900 * 1024 // 900KB fits comfortably in MaxMessageSize (2MB)
	if size <= inlineMax {
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}

		respMsg := &Message{
			Payload: MessageChunkData{
				ChunkKey: msg.ChunkKey,
				Data:     data,
			},
		}
		fmt.Printf("[%s] Sending chunk %s (%d bytes) inline to %s\n",
			s.Transport.Addr(), msg.ChunkKey[:16], len(data), from)
		return s.sendToAddr(from, respMsg)
	}
	r.Close() // close the size-check reader, we'll reopen in the loop for streaming

	// large chunk — use streaming relay to get it to the requester
	s.peersLock.Lock()
	var possibleRelays []p2p.Peer
	for _, p := range s.peers {
		possibleRelays = append(possibleRelays, p)
	}
	s.peersLock.Unlock()

	for _, relay := range possibleRelays {
		// open a fresh reader for each relay attempt
		_, rr, err := s.Store.ReadStream(msg.ChunkKey)
		if err != nil {
			continue
		}

		fmt.Printf("[%s] Relay-streaming chunk %s to %s via %s\n",
			s.Transport.Addr(), msg.ChunkKey[:16], from, relay.RemoteAddr().String())

		sendErr := s.sendRelayStream(relay, from, msg.ChunkKey, size, rr)
		rr.Close()

		if sendErr == nil {
			return nil
		}
	}

	return fmt.Errorf("[%s] can't serve chunk %s to %s: no path available", s.Transport.Addr(), msg.ChunkKey[:16], from)
}

// handleChunkData handles chunk data that arrived inside a relay message (small chunks fallback)
func (s *FileServer) handleChunkData(from string, msg MessageChunkData) error {
	if s.RelayOnly {
		return nil
	}

	// verify the hash before storing — a malicious peer could send
	// random bytes claiming they're chunk "abc123..."
	if err := verifyChunkHash(msg.ChunkKey, msg.Data); err != nil {
		return fmt.Errorf("[%s] REJECTING chunk from %s: %w", s.Transport.Addr(), from, err)
	}

	n, err := s.Store.WriteStream(msg.ChunkKey, bytes.NewReader(msg.Data))
	if err != nil {
		return fmt.Errorf("failed to store chunk data %s: %w", msg.ChunkKey, err)
	}
	fmt.Printf("[%s] Stored chunk %s (%d bytes, verified) from %s\n",
		s.Transport.Addr(), msg.ChunkKey[:16], n, from)
	s.notifyChunkArrived(msg.ChunkKey)
	return nil
}

// -------- Push chunk to a specific node --------

// pushChunkToAddr sends a chunk to a target node, using the best available path:
// for small chunks, we use inline MessageChunkData (fits in a normal message).
// for large chunks, we use streaming relay.
func (s *FileServer) pushChunkToAddr(addr string, chunkKey string) error {
	size, r, err := s.Store.ReadStream(chunkKey)
	if err != nil {
		return err
	}

	// for chunks small enough to fit in a message, send inline.
	// this is simpler and doesn't require the receiver to handle stream RPCs.
	const inlineMax = 900 * 1024
	if size <= inlineMax {
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}

		msg := &Message{
			Payload: MessageChunkData{
				ChunkKey: chunkKey,
				Data:     data,
			},
		}
		return s.sendToAddr(addr, msg)
	}
	r.Close() // close the size-check reader, we'll reopen in the loop for streaming

	// large chunk — need streaming relay
	s.peersLock.Lock()
	var possibleRelays []p2p.Peer
	for _, p := range s.peers {
		possibleRelays = append(possibleRelays, p)
	}
	s.peersLock.Unlock()

	for _, relay := range possibleRelays {
		// open a fresh reader for each relay attempt
		_, rr, err := s.Store.ReadStream(chunkKey)
		if err != nil {
			continue
		}

		fmt.Printf("[%s] Relay-streaming chunk %s to %s via %s\n",
			s.Transport.Addr(), chunkKey[:16], addr, relay.RemoteAddr().String())

		sendErr := s.sendRelayStream(relay, addr, chunkKey, size, rr)
		rr.Close()

		if sendErr == nil {
			return nil
		}
	}

	return fmt.Errorf("[%s] can't push chunk %s to %s: no relay available", s.Transport.Addr(), chunkKey[:16], addr)
}

// -------- Chunked StoreData --------

// StoreDataChunked encrypts, chunks, and stores a file in the network.
// Returns the Content ID (CID) — a SHA-256 hash of the encrypted content.
// The CID is how you retrieve the file later; it's collision-proof and
// means two different files can never overwrite each other's manifests.
func (s *FileServer) StoreDataChunked(originalName string, userEncryptionKey []byte, r io.Reader) (string, error) {
	// step 1: encrypt the whole file into a pipe
	userNonce := make([]byte, crypto.NonceSize)
	if _, err := randRead(userNonce); err != nil {
		return "", err
	}

	pr, pw := io.Pipe()
	encryptErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		// prepend the nonce so the decryptor knows what it is
		if _, err := pw.Write(userNonce); err != nil {
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}
		_, err := encryptFn(userEncryptionKey, userNonce, r, pw)
		if err != nil {
			pw.CloseWithError(err)
		}
		encryptErr <- err
	}()

	// step 2: hash the encrypted stream while chunking it.
	// TeeReader lets us compute SHA-256 of the entire ciphertext without
	// buffering it — the hasher sees every byte the chunker reads.
	hasher := sha256.New()
	tee := io.TeeReader(pr, hasher)

	chunks, err := s.Store.ChunkAndStore(tee, storage.DefaultChunkSize)
	pr.Close()

	if err != nil {
		return "", fmt.Errorf("chunking failed: %w", err)
	}
	if encErr := <-encryptErr; encErr != nil {
		return "", fmt.Errorf("encryption failed: %w", encErr)
	}

	// the CID is the hex-encoded SHA-256 of the entire encrypted content.
	// two different files will always produce different CIDs.
	cid := hex.EncodeToString(hasher.Sum(nil))

	// step 3: build the manifest
	chunkKeys := make([]string, len(chunks))
	var totalSize int64
	for i, c := range chunks {
		chunkKeys[i] = c.ChunkKey
		totalSize += c.Size
	}

	manifest := FileManifest{
		OriginalKey: originalName, // human-readable name, not the network key
		TotalSize:   totalSize,
		ChunkSize:   storage.DefaultChunkSize,
		ChunkKeys:   chunkKeys,
	}

	// store manifest locally under the CID
	manifestKey := cid + ".manifest"
	var manifestBuf bytes.Buffer
	if err := gob.NewEncoder(&manifestBuf).Encode(manifest); err != nil {
		return "", fmt.Errorf("failed to encode manifest: %w", err)
	}
	if _, err := s.Store.WriteStream(manifestKey, &manifestBuf); err != nil {
		return "", fmt.Errorf("failed to store manifest: %w", err)
	}

	fmt.Printf("[%s] File stored: CID=%s, name=%s, %d chunks, %d bytes\n",
		s.Transport.Addr(), cid[:16], originalName, len(chunks), totalSize)

	// step 4: replicate manifest + chunks to DHT-nearest nodes
	targetID := dht.NewID(cid)
	closest := s.DHT.NearestNodes(targetID, dht.K)

	// fall back to all direct peers if DHT is empty
	if len(closest) == 0 {
		s.peersLock.Lock()
		for _, p := range s.peers {
			closest = append(closest, dht.NodeInfo{Addr: p.RemoteAddr().String()})
		}
		s.peersLock.Unlock()
	}

	for _, node := range closest {
		if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
			continue
		}
		// skip relay-only nodes
		s.peersLock.Lock()
		isRelay := s.relayPeers[node.Addr]
		s.peersLock.Unlock()
		if isRelay {
			fmt.Printf("[%s] Skipping %s for replication (RelayOnly)\n", s.Transport.Addr(), node.Addr)
			continue
		}

		// send the manifest via normal message
		manifestMsg := &Message{
			Payload: MessageStoreManifest{
				Key:      manifestKey,
				Manifest: manifest,
			},
		}
		if err := s.sendToAddr(node.Addr, manifestMsg); err != nil {
			fmt.Printf("[%s] Failed to send manifest to %s: %v\n", s.Transport.Addr(), node.Addr, err)
			continue
		}

		// push each chunk
		for _, chunkKey := range chunkKeys {
			fmt.Printf("[%s] Pushing chunk %s to %s\n", s.Transport.Addr(), chunkKey[:16], node.Addr)
			if err := s.pushChunkToAddr(node.Addr, chunkKey); err != nil {
				fmt.Printf("[%s] Failed to push chunk %s to %s: %v\n",
					s.Transport.Addr(), chunkKey[:16], node.Addr, err)
			}
		}
	}
	// record in local index so we can list stored files later
	s.CIDIndex.Add(storage.CIDEntry{
		CID:          cid,
		OriginalName: originalName,
		Size:         totalSize,
		ChunkCount:   len(chunks),
	})

	return cid, nil
}

type multiReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (mrc *multiReadCloser) Close() error {
	var err error
	for _, c := range mrc.closers {
		if e := c.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// -------- Chunked GetFile --------

// GetFileChunked is the new chunked version of GetFile.
// It finds the manifest, then fetches missing chunks in parallel from the network.
func (s *FileServer) GetFileChunked(key string) (io.Reader, error) {
	manifestKey := key + ".manifest"

	// try to load manifest from local store first
	var manifest *FileManifest
	if s.Store.Has(manifestKey) {
		m, err := s.loadManifest(manifestKey)
		if err == nil {
			manifest = m
		}
	}

	// if we don't have it locally, ask the network
	if manifest == nil {
		fmt.Printf("[%s] Manifest for %s not found locally, asking network...\n", s.Transport.Addr(), key)

		getMsg := &Message{Payload: MessageGetManifest{Key: manifestKey}}
		s.broadcastToAll(getMsg)

		// give peers time to respond
		sleepFn(1500)

		// try again
		if s.Store.Has(manifestKey) {
			m, err := s.loadManifest(manifestKey)
			if err != nil {
				return nil, fmt.Errorf("manifest found but unreadable: %w", err)
			}
			manifest = m
		}
	}

	if manifest == nil {
		// fall back to legacy non-chunked GetFile for backward compat
		return s.GetFile(key)
	}

	fmt.Printf("[%s] Got manifest for %s: %d chunks, %d bytes\n",
		s.Transport.Addr(), key, len(manifest.ChunkKeys), manifest.TotalSize)

	// figure out which chunks we're missing
	var missingKeys []string
	for _, ck := range manifest.ChunkKeys {
		if !s.Store.Has(ck) {
			missingKeys = append(missingKeys, ck)
		}
	}

	if len(missingKeys) > 0 {
		fmt.Printf("[%s] Missing %d/%d chunks, fetching from network...\n",
			s.Transport.Addr(), len(missingKeys), len(manifest.ChunkKeys))
		s.fetchChunksParallel(missingKeys)
	}

	// reassemble: create a multi-reader from all chunks in order
	readers := make([]io.Reader, 0, len(manifest.ChunkKeys))
	closers := make([]io.Closer, 0, len(manifest.ChunkKeys))

	for _, ck := range manifest.ChunkKeys {
		if !s.Store.Has(ck) {
			// clean up already opened readers
			for _, c := range closers {
				c.Close()
			}
			return nil, fmt.Errorf("chunk %s still missing after network fetch", ck[:16])
		}
		_, r, err := s.Store.ReadStream(ck)
		if err != nil {
			// clean up already opened readers
			for _, c := range closers {
				c.Close()
			}
			return nil, fmt.Errorf("failed to read chunk %s: %w", ck[:16], err)
		}
		readers = append(readers, r)
		closers = append(closers, r)
	}

	return &multiReadCloser{
		Reader:  io.MultiReader(readers...),
		closers: closers,
	}, nil
}

// fetchChunksParallel spawns workers to fetch missing chunks concurrently.
// Each worker asks the DHT-nearest peers for a specific chunk.
func (s *FileServer) fetchChunksParallel(chunkKeys []string) {
	// cap concurrency at 4 to avoid overwhelming the network
	const maxWorkers = 4
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, ck := range chunkKeys {
		wg.Add(1)
		sem <- struct{}{} // acquire slot
		go func(chunkKey string) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			s.fetchSingleChunk(chunkKey)
		}(ck)
	}

	wg.Wait()
}

// fetchSingleChunk asks peers for a specific chunk
func (s *FileServer) fetchSingleChunk(chunkKey string) {
	// if we already have it (e.g. from a previous replication), skip the network
	if s.Store.Has(chunkKey) {
		return
	}

	// register a notification channel so handleChunkData / handleRelayStream
	// can wake us up the instant the chunk lands on disk
	ch := make(chan struct{}, 1)
	s.pendingChunks.Store(chunkKey, ch)
	defer s.pendingChunks.Delete(chunkKey)

	getMsg := &Message{Payload: MessageGetChunk{ChunkKey: chunkKey}}

	// ask DHT-nearest nodes first
	targetID := dht.NewID(chunkKey)
	closest := s.DHT.NearestNodes(targetID, dht.K)

	for _, node := range closest {
		if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
			continue
		}
		if err := s.sendToAddr(node.Addr, getMsg); err != nil {
			fmt.Printf("[%s] Failed to request chunk %s from %s: %v\n",
				s.Transport.Addr(), chunkKey[:16], node.Addr, err)
		}
	}

	// also ask all direct peers as fallback
	s.peersLock.Lock()
	peers := make([]string, 0, len(s.peers))
	for addr := range s.peers {
		if addr == s.AdvertiseAddr {
			continue
		}
		peers = append(peers, addr)
	}
	s.peersLock.Unlock()

	for _, addr := range peers {
		if err := s.sendToAddr(addr, getMsg); err != nil {
			fmt.Printf("[%s] Failed to request chunk %s from %s: %v\n",
				s.Transport.Addr(), chunkKey[:16], addr, err)
		}
	}

	// block until the chunk arrives or we time out.
	// the receive handlers (handleChunkData, handleRelayStream) will
	// call notifyChunkArrived which closes this channel instantly.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-ch:
		fmt.Printf("[%s] Chunk %s received!\n", s.Transport.Addr(), chunkKey[:16])
	case <-timer.C:
		fmt.Printf("[%s] WARNING: chunk %s not received after 5s timeout\n", s.Transport.Addr(), chunkKey[:16])
	}
}

// notifyChunkArrived signals any goroutine that's waiting for this chunk.
// safe to call even if nobody is waiting — the signal is just dropped.
func (s *FileServer) notifyChunkArrived(chunkKey string) {
	if val, ok := s.pendingChunks.LoadAndDelete(chunkKey); ok {
		ch := val.(chan struct{})
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// -------- Helpers --------

func (s *FileServer) loadManifest(manifestKey string) (*FileManifest, error) {
	_, r, err := s.Store.ReadStream(manifestKey)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var manifest FileManifest
	if err := gob.NewDecoder(r).Decode(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// broadcastToAll sends a message to every connected peer (unlike broadcast which
// does DHT-aware routing for store messages).
func (s *FileServer) broadcastToAll(msg *Message) {
	s.peersLock.Lock()
	var targets []p2p.Peer
	for _, p := range s.peers {
		targets = append(targets, p)
	}
	s.peersLock.Unlock()

	for _, peer := range targets {
		if err := s.sendToPeer(peer, msg); err != nil {
			fmt.Printf("[%s] broadcastToAll failed for %s: %v\n",
				s.Transport.Addr(), peer.RemoteAddr().String(), err)
		}
	}
}
