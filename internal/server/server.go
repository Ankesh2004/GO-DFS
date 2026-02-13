package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/storage"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

type FileServerOptions struct {
	ID             string
	RootDir        string
	AdvertiseAddr  string // the address we tell other nodes to dial us on (public IP:port)
	Transport      p2p.Transport
	BootstrapNodes []string
	RelayOnly      bool // if true, this node will act ONLY as a relay and won't store data
}

type FileServer struct {
	FileServerOptions

	ID          dht.ID
	DHT         *dht.Kademlia
	Store       *storage.Store
	quitChannel chan struct{}

	peers         map[string]p2p.Peer
	peersLock     sync.Mutex
	verifiedAddrs map[string]bool   // addresses that completed PeerExchange (safe to share/dial)
	addrMap       map[string]string // raw TCP remote addr → advertised listen addr
	relayPeers    map[string]bool   // map of advertised addrs that are RelayOnly=true
	pendingChunks sync.Map          // chunkKey → chan struct{}, signals when a requested chunk arrives
}

func NewFileServer(options FileServerOptions) *FileServer {
	store := storage.NewStore(options.RootDir)
	id := dht.NewID(options.ID)

	return &FileServer{
		FileServerOptions: options,
		ID:                id,
		DHT:               dht.NewKademlia(id),
		Store:             store,
		quitChannel:       make(chan struct{}),
		peers:             make(map[string]p2p.Peer),
		verifiedAddrs:     make(map[string]bool),
		addrMap:           make(map[string]string),
		relayPeers:        make(map[string]bool),
	}
}

// -------- Message Routing --------

func (s *FileServer) handleMessage(from string, msg *Message) error {
	switch v := msg.Payload.(type) {
	case MessageStoreFile:
		return s.handleMessageStoreFile(from, v)
	case MessageGetFile:
		return s.handleMessageGetFile(from, v)
	case MessageRelayData:
		return s.handleRelayData(from, v)
	case MessagePeerExchange:
		return s.handlePeerExchange(from, v)
	case MessageFindNode:
		return s.handleFindNode(from, v)
	case MessageFindNodeResponse:
		return s.handleFindNodeResponse(from, v)
	case MessageRelay:
		return s.handleRelay(from, v)
	case MessagePing:
		return s.handlePing(from)
	case MessagePong:
		return nil

	// chunk + manifest handlers
	case MessageStoreManifest:
		return s.handleStoreManifest(from, v)
	case MessageGetManifest:
		return s.handleGetManifest(from, v)
	case MessageManifestResponse:
		return s.handleManifestResponse(from, v)
	case MessageStoreChunk:
		return s.handleStoreChunk(from, v)
	case MessageGetChunk:
		return s.handleGetChunk(from, v)
	case MessageChunkData:
		return s.handleChunkData(from, v)

	default:
		return fmt.Errorf("unknown message type: %T", msg.Payload)
	}
}

// -------- Peer Exchange (runs right after connection) --------

// sendPeerExchange sends our ID, listen address, and a handful of known peers
// to a newly connected peer so it can populate its own routing table.
func (s *FileServer) sendPeerExchange(peer p2p.Peer) error {
	allNodes := s.DHT.RoutingTable.GetAllNodes()

	// Share up to K peers from our routing table
	// Only share peers we've verified through PeerExchange (no ephemeral addrs)
	s.peersLock.Lock()
	knownPeers := make([]PeerInfo, 0, dht.K)
	for _, n := range allNodes {
		if len(knownPeers) >= dht.K {
			break
		}
		if s.verifiedAddrs[n.Addr] {
			knownPeers = append(knownPeers, PeerInfo{ID: n.ID, Addr: n.Addr})
		}
	}
	s.peersLock.Unlock()

	msg := Message{
		Payload: MessagePeerExchange{
			ID:         s.ID,
			ListenAddr: s.AdvertiseAddr,
			KnownPeers: knownPeers,
			RelayOnly:  s.RelayOnly,
		},
	}
	return s.sendToPeer(peer, &msg)
}

func (s *FileServer) handlePeerExchange(from string, msg MessagePeerExchange) error {
	peerID := dht.ID(msg.ID)
	listenAddr := msg.ListenAddr

	// Use their advertised listen address instead of the raw TCP remote addr.
	// This is what makes remote discovery work: we now know how to reach them
	// even if the TCP connection came through NAT.
	if listenAddr != "" {
		s.peersLock.Lock()
		// Re-key the peer under its advertised listen address
		if peer, ok := s.peers[from]; ok {
			s.peers[listenAddr] = peer
			if from != listenAddr {
				delete(s.peers, from)
			}
		}
		s.peersLock.Unlock()

		// Remove the old temp entry (keyed by raw TCP addr) from the routing table
		// and add the proper one keyed by advertised listen addr
		oldTempID := dht.NewID(from)
		s.DHT.RoutingTable.RemoveNode(oldTempID)
		s.DHT.Update(peerID, listenAddr)

		// Mark this address as verified (safe to share with others)
		// and record the raw TCP → advertise mapping for future message routing
		s.peersLock.Lock()
		s.verifiedAddrs[listenAddr] = true
		if from != listenAddr {
			s.addrMap[from] = listenAddr
		}
		if msg.RelayOnly {
			s.relayPeers[listenAddr] = true
		}
		s.peersLock.Unlock()

		fmt.Printf("[%s] PeerExchange from %s → ID: %s, Listen: %s, shared %d peers\n",
			s.Transport.Addr(), from, peerID.String()[:8], listenAddr, len(msg.KnownPeers))
	} else {
		// No advertise addr provided, fall back to raw TCP address
		s.DHT.Update(peerID, from)
	}

	// Learn about the peers they shared with us
	for _, pi := range msg.KnownPeers {
		piID := dht.ID(pi.ID)
		if piID == s.ID {
			continue // don't add ourselves
		}
		// Also skip if the address is our own advertise address
		if pi.Addr == s.AdvertiseAddr || pi.Addr == s.Transport.Addr() {
			continue
		}
		s.DHT.Update(piID, pi.Addr)
	}

	// Try to connect to any new peers we just learned about
	go s.connectToNewPeers()

	return nil
}

// -------- FIND_NODE (core Kademlia lookup) --------

// sendFindNode asks a specific peer: "who do you know that's closest to targetID?"
func (s *FileServer) sendFindNode(peer p2p.Peer, targetID dht.ID) error {
	msg := Message{
		Payload: MessageFindNode{
			TargetID: targetID,
		},
	}
	return s.sendToPeer(peer, &msg)
}

func (s *FileServer) handleFindNode(from string, msg MessageFindNode) error {
	targetID := dht.ID(msg.TargetID)
	closest := s.DHT.NearestNodes(targetID, dht.K)

	response := make([]PeerInfo, 0, len(closest))
	for _, n := range closest {
		response = append(response, PeerInfo{ID: n.ID, Addr: n.Addr})
	}

	// Send the response back to whoever asked
	s.peersLock.Lock()
	peer, ok := s.peers[from]
	s.peersLock.Unlock()

	if !ok {
		return fmt.Errorf("peer %s not found for FindNode response", from)
	}

	respMsg := Message{
		Payload: MessageFindNodeResponse{
			ClosestPeers: response,
		},
	}
	return s.sendToPeer(peer, &respMsg)
}

func (s *FileServer) handleFindNodeResponse(_ string, msg MessageFindNodeResponse) error {
	// Add all discovered peers to our routing table
	for _, pi := range msg.ClosestPeers {
		piID := dht.ID(pi.ID)
		if piID == s.ID {
			continue
		}
		s.DHT.Update(piID, pi.Addr)
	}

	// Try connecting to any we don't already have
	go s.connectToNewPeers()
	return nil
}

// -------- Relay (the bridge between NAT'd nodes) --------

// handleRelay receives a message meant for another node and forwards it.
// If we ARE the target, we unwrap and process it. If not, we forward to the target.
// This is how two machines behind NAT communicate through a public bootstrap node.
func (s *FileServer) handleRelay(from string, msg MessageRelay) error {
	if msg.TTL <= 0 {
		return fmt.Errorf("relay TTL expired, dropping message from %s to %s", msg.OriginAddr, msg.TargetAddr)
	}

	// Are WE the intended target?
	if msg.TargetAddr == s.AdvertiseAddr || msg.TargetAddr == s.Transport.Addr() {
		// Unwrap the inner message and process it as if it came from the origin
		var innerMsg Message
		if err := gob.NewDecoder(bytes.NewReader(msg.InnerPayload)).Decode(&innerMsg); err != nil {
			return fmt.Errorf("failed to decode relayed inner message: %w", err)
		}
		fmt.Printf("[%s] Received relayed message from %s (via %s)\n", s.Transport.Addr(), msg.OriginAddr, from)
		return s.handleMessage(msg.OriginAddr, &innerMsg)
	}

	// We're not the target — forward it to the actual destination
	s.peersLock.Lock()
	targetPeer, ok := s.peers[msg.TargetAddr]
	s.peersLock.Unlock()

	if !ok {
		return fmt.Errorf("[%s] can't relay to %s: not in our peer list", s.Transport.Addr(), msg.TargetAddr)
	}

	// Decrement TTL and forward
	msg.TTL--
	relayMsg := Message{Payload: msg}
	fmt.Printf("[%s] Relaying message from %s → %s (TTL: %d)\n", s.Transport.Addr(), msg.OriginAddr, msg.TargetAddr, msg.TTL)
	return s.sendToPeer(targetPeer, &relayMsg)
}

// sendToAddr sends a message to a target address. If we have a direct connection,
// it sends directly. If not, it tries to relay through a connected peer.
// This is the key function that makes remote communication work even behind NAT.
func (s *FileServer) sendToAddr(targetAddr string, msg *Message) error {
	s.peersLock.Lock()
	peer, directlyConnected := s.peers[targetAddr]
	s.peersLock.Unlock()

	// Best case: we have a direct connection
	if directlyConnected {
		return s.sendToPeer(peer, msg)
	}

	// No direct connection — wrap the message in a relay envelope
	// and send it through any peer we DO have a connection to.
	// That peer will forward it to the target (or to someone closer).
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(msg); err != nil {
		return fmt.Errorf("failed to encode message for relay: %w", err)
	}

	relayMsg := Message{
		Payload: MessageRelay{
			TargetAddr:   targetAddr,
			OriginAddr:   s.AdvertiseAddr,
			InnerPayload: buf.Bytes(),
			TTL:          3, // max 3 hops to prevent infinite loops
		},
	}

	// Try each connected peer as a potential relay
	s.peersLock.Lock()
	var relayPeers []p2p.Peer
	for _, p := range s.peers {
		relayPeers = append(relayPeers, p)
	}
	s.peersLock.Unlock()

	for _, relay := range relayPeers {
		fmt.Printf("[%s] No direct connection to %s, relaying through %s\n",
			s.Transport.Addr(), targetAddr, relay.RemoteAddr().String())
		if err := s.sendToPeer(relay, &relayMsg); err == nil {
			return nil // successfully handed off to a relay
		}
	}

	return fmt.Errorf("[%s] can't reach %s: no direct connection and no relay available", s.Transport.Addr(), targetAddr)
}

// -------- Ping / Pong --------

func (s *FileServer) handlePing(from string) error {
	s.peersLock.Lock()
	peer, ok := s.peers[from]
	s.peersLock.Unlock()

	if !ok {
		return nil
	}

	msg := Message{Payload: MessagePong{}}
	return s.sendToPeer(peer, &msg)
}

// -------- Discovery Loop --------

// connectToNewPeers dials any node in the DHT routing table that we don't have
// an active TCP connection to yet.
func (s *FileServer) connectToNewPeers() {
	allKnown := s.DHT.RoutingTable.GetAllNodes()

	s.peersLock.Lock()
	existingPeers := make(map[string]bool, len(s.peers))
	for addr := range s.peers {
		existingPeers[addr] = true
	}
	verified := make(map[string]bool, len(s.verifiedAddrs))
	for addr := range s.verifiedAddrs {
		verified[addr] = true
	}
	s.peersLock.Unlock()

	for _, node := range allKnown {
		if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
			continue
		}
		if existingPeers[node.Addr] {
			continue
		}
		// Only dial addresses that were shared as verified advertise addresses
		// This prevents trying to connect to ephemeral TCP ports
		if !verified[node.Addr] {
			continue
		}

		fmt.Printf("[%s] Discovered new peer %s, dialing...\n", s.Transport.Addr(), node.Addr)
		go func(addr string) {
			if err := s.Transport.Dial(addr); err != nil {
				fmt.Printf("[%s] Failed to dial discovered peer %s: %v\n", s.Transport.Addr(), addr, err)
			}
		}(node.Addr)
	}
}

// discoveryLoop periodically asks random peers for nodes close to us.
// This is how a Kademlia node "fills in" its routing table over time.
func (s *FileServer) discoveryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.runDiscoveryRound()
		case <-s.quitChannel:
			return
		}
	}
}

func (s *FileServer) runDiscoveryRound() {
	s.peersLock.Lock()
	peerList := make([]p2p.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peerList = append(peerList, p)
	}
	s.peersLock.Unlock()

	if len(peerList) == 0 {
		return
	}

	// Ask each peer for nodes closest to our own ID (standard Kademlia self-lookup)
	for _, peer := range peerList {
		if err := s.sendFindNode(peer, s.ID); err != nil {
			fmt.Printf("[%s] Discovery FindNode failed: %v\n", s.Transport.Addr(), err)
		}
	}
}

// -------- Legacy File Operations (pre-chunking) --------
// DEPRECATED: Superseded by StoreDataChunked / GetFileChunked.
// Kept for backward compatibility (relay_test.go uses these).

func (s *FileServer) handleMessageStoreFile(from string, msg MessageStoreFile) error {
	if s.RelayOnly {
		fmt.Printf("[%s] REJECTING store request for key %s from %s: node is in RelayOnly mode\n",
			s.Transport.Addr(), msg.Key, from)
		return nil // Just drop it, we don't store.
	}
	fmt.Printf("[%s] Handling storefile metadata from %s...\n", s.Transport.Addr(), from)

	// Verify if we have a direct peer for streaming
	s.peersLock.Lock()
	peer, directConn := s.peers[from]
	s.peersLock.Unlock()

	if !directConn {
		// If it's not a direct connection, we don't do anything yet.
		// The data will arrive later via a MessageRelayData message.
		fmt.Printf("[%s] Metadata for %s from remote node %s - waiting for relayed data payload\n",
			s.Transport.Addr(), msg.Key, from)
		return nil
	}

	fmt.Printf("[%s] Receiving %d bytes via direct stream for key %s\n", s.Transport.Addr(), msg.Size, msg.Key)
	n, err := s.Store.WriteStream(msg.Key, io.LimitReader(peer, msg.Size))
	if err != nil {
		return err
	}
	fmt.Printf("[%s] Wrote %d bytes (direct stream) to file\n", s.Transport.Addr(), n)

	peer.CloseStream()
	return nil
}

func (s *FileServer) handleMessageGetFile(from string, msg MessageGetFile) error {
	if !s.Store.Has(msg.Key) {
		return fmt.Errorf("need to serve %s to peer %s, but file not found on [%s]", msg.Key, from, s.Transport.Addr())
	}
	fmt.Printf("[%s] serving file over network to [%s]\n", s.Transport.Addr(), from)

	fileSize, r, err := s.Store.ReadStream(msg.Key)
	if err != nil {
		return err
	}
	defer r.Close()

	// Check if we have a direct connection to the requester
	s.peersLock.Lock()
	peer, directConn := s.peers[from]
	s.peersLock.Unlock()

	if directConn {
		// Fast path: direct TCP streaming
		peer.Send([]byte{p2p.IncomingStream})
		binary.Write(peer, binary.LittleEndian, fileSize)
		n, err := io.Copy(peer, r)
		if err != nil {
			return err
		}
		fmt.Printf("[%s] Wrote %d bytes over the network to peer: %s\n", s.Transport.Addr(), n, from)
		return nil
	}

	// Slow path: no direct connection, send data inside a message via relay
	// Same size limit as pushToAddr — transport decoder caps at ~1MB
	const RelayMaxSize = 900 * 1024
	if fileSize > RelayMaxSize {
		return fmt.Errorf("[%s] file %s too large to serve via relay (%d bytes, max %d)", s.Transport.Addr(), msg.Key, fileSize, RelayMaxSize)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read file for relay: %w", err)
	}

	responseMsg := &Message{
		Payload: MessageRelayData{
			Key:  msg.Key,
			Data: data,
		},
	}

	fmt.Printf("[%s] Sending %d bytes via relay to %s\n", s.Transport.Addr(), len(data), from)
	return s.sendToAddr(from, responseMsg)
}

// handleRelayData handles file data that arrived through a relay (not direct stream)
func (s *FileServer) handleRelayData(from string, msg MessageRelayData) error {
	if s.RelayOnly {
		fmt.Printf("[%s] DROPPING relayed data for key %s from %s: node is in RelayOnly mode\n",
			s.Transport.Addr(), msg.Key, from)
		return nil
	}
	fmt.Printf("[%s] Received relayed file data for key [%s] (%d bytes) from %s\n",
		s.Transport.Addr(), msg.Key, len(msg.Data), from)

	// Write to our local store
	n, err := s.Store.WriteStream(msg.Key, bytes.NewReader(msg.Data))
	if err != nil {
		return fmt.Errorf("failed to store relayed data: %w", err)
	}
	fmt.Printf("[%s] Stored relayed file [%s]: %d bytes\n", s.Transport.Addr(), msg.Key, n)
	return nil
}

// -------- Broadcast (DHT-aware) --------

func (s *FileServer) broadcast(msg *Message) error {
	// For store messages, route specifically to the K closest nodes
	if storeMsg, ok := msg.Payload.(MessageStoreFile); ok {
		targetID := dht.NewID(storeMsg.Key)
		closest := s.DHT.NearestNodes(targetID, dht.K)

		fmt.Printf("[%s] Broadcasting store metadata for %s. DHT has %d potential targets.\n",
			s.Transport.Addr(), storeMsg.Key, len(closest))

		if len(closest) > 0 {
			for _, node := range closest {
				if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
					continue
				}
				fmt.Printf("[%s] Targeting node %s for store metadata\n", s.Transport.Addr(), node.Addr)
				if err := s.sendToAddr(node.Addr, msg); err != nil {
					fmt.Printf("[%s] Broadcast (Store) failed for %s: %v\n", s.Transport.Addr(), node.Addr, err)
				}
			}
			return nil
		}
		fmt.Printf("[%s] DHT empty, falling back to all direct peers for metadata broadcast\n", s.Transport.Addr())
	}

	// Default: send to ALL direct peers
	s.peersLock.Lock()
	var targets []p2p.Peer
	for _, p := range s.peers {
		targets = append(targets, p)
	}
	s.peersLock.Unlock()

	for _, peer := range targets {
		if err := s.sendToPeer(peer, msg); err != nil {
			fmt.Printf("[%s] Broadcast failed for %s: %v\n", s.Transport.Addr(), peer.RemoteAddr().String(), err)
		}
	}
	return nil
}

// sendToPeer sends a single message to a specific peer (not broadcast)
func (s *FileServer) sendToPeer(peer p2p.Peer, msg *Message) error {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(msg); err != nil {
		return err
	}
	msgBytes := buf.Bytes()
	msgLen := uint32(len(msgBytes))

	peer.Send([]byte{p2p.IncomingMessage})
	if err := binary.Write(peer, binary.LittleEndian, msgLen); err != nil {
		return err
	}
	return peer.Send(msgBytes)
}

// -------- GetFile / StoreData --------

// GetFile is the legacy (non-chunked) get method.
// DEPRECATED: use GetFileChunked instead. Kept as fallback for backward compat.
func (s *FileServer) GetFile(key string) (io.Reader, error) {
	// check in local storage first
	if s.Store.Has(key) {
		fmt.Printf("[%s] Serving file [%s] from local disk\n", s.Transport.Addr(), key)
		_, r, err := s.Store.ReadStream(key)
		return r, err
	}
	// fetch from the peers in the network
	fmt.Printf("File [%s] not found in local storage, fetching from network...\n", key)

	// Send GetFile to all peers (both direct and via relay)
	getMsg := &Message{Payload: MessageGetFile{Key: key}}

	s.peersLock.Lock()
	peerAddrs := make([]string, 0, len(s.peers))
	for addr := range s.peers {
		peerAddrs = append(peerAddrs, addr)
	}
	s.peersLock.Unlock()

	// Also check DHT for nodes we know about but aren't directly connected to
	targetID := dht.NewID(key)
	closest := s.DHT.NearestNodes(targetID, dht.K)
	for _, node := range closest {
		found := false
		for _, addr := range peerAddrs {
			if addr == node.Addr {
				found = true
				break
			}
		}
		if !found && node.Addr != s.AdvertiseAddr {
			peerAddrs = append(peerAddrs, node.Addr)
		}
	}

	for _, addr := range peerAddrs {
		if err := s.sendToAddr(addr, getMsg); err != nil {
			fmt.Printf("[%s] Failed to send GetFile to %s: %v\n", s.Transport.Addr(), addr, err)
		}
	}

	// Wait for responses (either streamed or relayed)
	time.Sleep(500 * time.Millisecond)

	// For directly connected peers, read the stream response
	s.peersLock.Lock()
	directPeers := make([]p2p.Peer, 0)
	for _, p := range s.peers {
		directPeers = append(directPeers, p)
	}
	s.peersLock.Unlock()

	for _, peer := range directPeers {
		// We use a small peek/read to see if a filesize is waiting
		// but we must be careful not to block forever.
		var filesize int64
		// This read is risky if no data is coming, but for this DFS model
		// it's how we signal the end of the RPC.
		if err := binary.Read(peer, binary.LittleEndian, &filesize); err != nil {
			continue
		}
		if filesize <= 0 {
			continue
		}

		n, err := s.Store.WriteStream(key, io.LimitReader(peer, filesize))
		if err != nil {
			fmt.Printf("Error writing file from peer %s: %v\n", peer.RemoteAddr().String(), err)
			continue
		}
		fmt.Printf("Received file [%s] of [%d] bytes from peer: %s\n", key, n, peer.RemoteAddr().String())
		peer.CloseStream()
	}

	// By now, either a direct stream or a relayed MessageRelayData
	// should have written the file to our store
	if !s.Store.Has(key) {
		return nil, fmt.Errorf("file [%s] not found after network fetch", key)
	}
	_, r, err := s.Store.ReadStream(key)
	return r, err
}

// CountingWriter tracks bytes written.
// DEPRECATED: only used by legacy StoreData.
type CountingWriter struct {
	W     io.Writer
	Count int64
}

func (cw *CountingWriter) Write(p []byte) (int, error) {
	n, err := cw.W.Write(p)
	cw.Count += int64(n)
	return n, err
}

// StoreData is the legacy (non-chunked) store method.
// DEPRECATED: use StoreDataChunked instead. Kept for backward compat.
func (s *FileServer) StoreData(key string, userEncryptionKey []byte, r io.Reader) error {
	userNonce := make([]byte, crypto.NonceSize)
	if _, err := rand.Read(userNonce); err != nil {
		return err
	}

	pr, pw := io.Pipe()

	encryptErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		if _, err := pw.Write(userNonce); err != nil {
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}
		_, err := crypto.Encrypt(userEncryptionKey, userNonce, r, pw)
		if err != nil {
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}
		encryptErr <- nil
	}()

	counter := &CountingWriter{}
	storagePR, storagePW := io.Pipe()
	counter.W = storagePW

	storageErr := make(chan error, 1)
	go func() {
		defer storagePR.Close()
		_, err := s.Store.WriteStream(key, storagePR)
		storageErr <- err
	}()

	_, copyErr := io.Copy(counter, pr)
	pr.Close()

	if copyErr != nil {
		storagePW.CloseWithError(copyErr)
		pw.CloseWithError(copyErr)
	} else {
		storagePW.Close()
	}

	if err := <-encryptErr; err != nil {
		return err
	}
	if copyErr != nil {
		return fmt.Errorf("streaming to storage failed: %w", copyErr)
	}
	if err := <-storageErr; err != nil {
		return fmt.Errorf("local storage failed: %w", err)
	}

	actualSize := counter.Count

	// Stage 1: Disseminate the intent to store (Broadcast metadata)
	msg := Message{
		Payload: MessageStoreFile{
			Key:  key,
			Size: actualSize,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return err
	}

	// Stage 2: Disseminate the actual data block
	// We only send to nodes the DHT thinks are "closest" to the file key
	targetID := dht.NewID(key)
	closest := s.DHT.NearestNodes(targetID, dht.K)

	// If DHT is empty, we must fallback to our direct neighbors
	if len(closest) == 0 {
		s.peersLock.Lock()
		for _, p := range s.peers {
			closest = append(closest, dht.NodeInfo{Addr: p.RemoteAddr().String()})
		}
		s.peersLock.Unlock()
	}

	for _, node := range closest {
		if node.Addr == s.AdvertiseAddr || node.Addr == s.Transport.Addr() {
			continue // skip self
		}
		// Skip nodes that announced they are RelayOnly
		s.peersLock.Lock()
		isRelay := s.relayPeers[node.Addr]
		s.peersLock.Unlock()

		if isRelay {
			fmt.Printf("[%s] Skipping replication to %s (RelayOnly node)\n", s.Transport.Addr(), node.Addr)
			continue
		}

		fmt.Printf("[%s] Pushing data replica to target: %s\n", s.Transport.Addr(), node.Addr)
		if err := s.pushToAddr(node.Addr, key); err != nil {
			fmt.Printf("[%s] Failed to push data replica to %s: %v\n", s.Transport.Addr(), node.Addr, err)
		}
	}

	return nil
}

// pushToAddr is the legacy data push helper.
// DEPRECATED: use pushChunkToAddr instead. Kept for backward compat.
func (s *FileServer) pushToAddr(addr string, key string) error {
	s.peersLock.Lock()
	peer, directConn := s.peers[addr]
	s.peersLock.Unlock()

	size, r, err := s.Store.ReadStream(key)
	if err != nil {
		return err
	}
	defer r.Close()

	if directConn {
		// Fast Path: Streaming
		// Send the stream marker
		if err := peer.Send([]byte{p2p.IncomingStream}); err != nil {
			return err
		}
		// Data follows immediately (size is already known by recipient from metadata)
		_, err := io.Copy(peer, r)
		return err
	}

	// Slow Path: Relayed message data
	// IMPORTANT: The transport decoder caps messages at p2p.MaxMessageSize (1MB).
	// A MessageRelayData is wrapped inside a MessageRelay, both gob-encoded,
	// so the actual data must be well under 1MB to fit after gob overhead.
	const RelayMaxSize = 900 * 1024 // ~900KB to leave room for gob framing
	if size > RelayMaxSize {
		return fmt.Errorf("file %s too large for relay (%d bytes, max %d). needs direct connection", key, size, RelayMaxSize)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	relayData := &Message{
		Payload: MessageRelayData{
			Key:  key,
			Data: data,
		},
	}
	return s.sendToAddr(addr, relayData)
}

// -------- Lifecycle --------

func (s *FileServer) GetPeers() map[string]p2p.Peer {
	return s.peers
}

func (s *FileServer) Start() error {
	if err := s.Transport.ListenAndAccept(); err != nil {
		return err
	}
	if len(s.BootstrapNodes) > 0 {
		s.bootstrapNetwork()
	}

	// Start the periodic discovery loop in the background
	go s.discoveryLoop()

	s.loop()
	return nil
}

func (s *FileServer) Stop() error {
	select {
	case <-s.quitChannel:
		return nil
	default:
		close(s.quitChannel)
	}
	return nil
}

func (s *FileServer) OnPeer(P p2p.Peer) error {
	s.peersLock.Lock()
	peerAddr := P.RemoteAddr().String()
	s.peers[peerAddr] = P
	s.peersLock.Unlock()

	// Temporarily add with raw address; PeerExchange will update with proper ID + listen addr
	peerID := dht.NewID(peerAddr)
	s.DHT.Update(peerID, peerAddr)
	fmt.Printf("[%s] New peer connected: %s (temp ID: %s)\n", s.Transport.Addr(), peerAddr, peerID.String()[:8])

	// Immediately exchange identities so both sides know who they're talking to
	if err := s.sendPeerExchange(P); err != nil {
		fmt.Printf("[%s] Failed to send PeerExchange to %s: %v\n", s.Transport.Addr(), peerAddr, err)
	}

	return nil
}

func (s *FileServer) bootstrapNetwork() {
	if len(s.BootstrapNodes) == 0 {
		return
	}
	for _, addr := range s.BootstrapNodes {
		if len(addr) == 0 {
			continue
		}
		fmt.Printf("[%s] Dialing bootstrap node: %s\n", s.Transport.Addr(), addr)
		go func(addr string) {
			if err := s.Transport.Dial(addr); err != nil {
				fmt.Printf("[%s] Failed to dial bootstrap %s: %v\n", s.Transport.Addr(), addr, err)
				return
			}
			// Once connected to bootstrap, run an initial discovery round to find other peers
			time.Sleep(500 * time.Millisecond) // wait for PeerExchange to complete
			s.runDiscoveryRound()
		}(addr)
	}
}

func (s *FileServer) loop() {
	defer func() {
		fmt.Println("FileServer loop stopped")
		if err := s.Transport.Close(); err != nil {
			fmt.Println("Error closing transport: ", err)
		}
	}()
	for {
		select {
		case rpc := <-s.Transport.Consume():
			// relay stream — the transport already decoded the header,
			// now we need to pipe the raw bytes to the right place
			if rpc.IsRelay && rpc.RelayMeta != nil {
				resolvedFrom := s.resolvePeerAddr(rpc.From)
				if err := s.handleRelayStream(resolvedFrom, rpc); err != nil {
					fmt.Printf("Error handling relay stream: %v\n", err)
				}
				continue
			}

			// normal message — decode the gob payload
			var msg Message
			if err := gob.NewDecoder(bytes.NewReader(rpc.Payload)).Decode(&msg); err != nil {
				fmt.Println("Error decoding payload: ", err)
				continue
			}
			resolvedFrom := s.resolvePeerAddr(rpc.From)
			if err := s.handleMessage(resolvedFrom, &msg); err != nil {
				fmt.Println("Error handling message: ", err)
				continue
			}
		case <-s.quitChannel:
			return
		}
	}
}
