package server

import (
	"encoding/gob"

	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

func init() {
	// Register all message types for gob encoding/decoding.
	// Without this, the Message.Payload interface{} won't deserialize properly.
	gob.Register(MessageStoreFile{})
	gob.Register(MessageGetFile{})
	gob.Register(MessagePeerExchange{})
	gob.Register(MessageFindNode{})
	gob.Register(MessageFindNodeResponse{})
	gob.Register(MessagePing{})
	gob.Register(MessagePong{})
	gob.Register(MessageRelay{})
	gob.Register(MessageRelayData{})

	// chunk + manifest messages
	gob.Register(MessageStoreManifest{})
	gob.Register(MessageGetManifest{})
	gob.Register(MessageManifestResponse{})
	gob.Register(MessageStoreChunk{})
	gob.Register(MessageGetChunk{})
	gob.Register(MessageChunkData{})

	// relay stream header — needed for the streaming relay protocol
	gob.Register(p2p.RelayStreamMeta{})
}

// Message is the wrapper for all inter-node communication
type Message struct {
	Payload any
}

// MessageStoreFile is sent when a node wants to store a file on peers
type MessageStoreFile struct {
	Key  string
	Size int64
}

// MessageGetFile is sent when a node wants to retrieve a file from peers
type MessageGetFile struct {
	Key string
}

// PeerInfo is a lightweight struct for sharing peer details over the wire.
// Kept separate from dht.NodeInfo to avoid import cycles.
type PeerInfo struct {
	ID   [32]byte // dht.ID is [32]byte
	Addr string   // the address other nodes should dial to reach this peer
}

// MessagePeerExchange is sent right after a connection is established.
// It lets both sides learn each other's DHT ID and reachable address.
type MessagePeerExchange struct {
	ID         [32]byte   // sender's DHT ID
	ListenAddr string     // sender's advertised listen address (public IP:port)
	KnownPeers []PeerInfo // share some of our routing table so the new node can bootstrap faster
	RelayOnly  bool       // if true, this node shouldn't be used for storage/replication
}

// MessageFindNode is the core Kademlia lookup RPC.
// "Give me the K closest nodes you know to this TargetID."
type MessageFindNode struct {
	TargetID [32]byte
}

// MessageFindNodeResponse is the reply to FindNode.
type MessageFindNodeResponse struct {
	ClosestPeers []PeerInfo
}

// MessagePing is a heartbeat / liveness check
type MessagePing struct{}

// MessagePong is the reply to a Ping
type MessagePong struct{}

// MessageRelay wraps another message and forwards it to a target node.
// Used when two nodes can't reach each other directly (both behind NAT).
// Flow: NodeA -> BootstrapNode -> NodeC
type MessageRelay struct {
	TargetAddr   string // the advertised address of the final destination
	OriginAddr   string // who originally sent this (so the destination can respond)
	InnerPayload []byte // gob-encoded Message to forward
	TTL          int    // prevent infinite relay loops
}

// MessageRelayData carries actual file data INSIDE a message (not as a raw stream).
// This is how file data travels through relay nodes when there's no direct connection.
// For direct peers, we still use the faster raw TCP streaming.
// For relayed transfers, we buffer the data into this message instead.
// DEPRECATED for large files — use the streaming relay protocol instead.
// Still used for small control payloads and backward compat.
type MessageRelayData struct {
	Key  string // file key
	Data []byte // the actual encrypted file bytes
}

// -------- Chunking & Manifest Messages --------

// FileManifest describes a chunked file — stored alongside the chunks in the CAS.
// The manifest itself is replicated to the K-closest nodes just like any chunk.
type FileManifest struct {
	OriginalKey string   // the user-facing filename/key
	TotalSize   int64    // original encrypted file size (sum of all chunks)
	ChunkSize   int64    // size of each chunk (last one may be smaller)
	ChunkKeys   []string // ordered list of chunk content-hash keys
}

// MessageStoreManifest tells a peer "here's the manifest for a file, store it"
type MessageStoreManifest struct {
	Key      string       // the manifest key (hash of the original key + ".manifest")
	Manifest FileManifest // the actual manifest data
}

// MessageGetManifest asks a peer for a file's manifest
type MessageGetManifest struct {
	Key string // manifest key
}

// MessageManifestResponse is the reply — sends the manifest back
type MessageManifestResponse struct {
	Key      string       // manifest key
	Manifest FileManifest // the manifest data
	Found    bool         // false if the peer doesn't have it
}

// MessageStoreChunk is the metadata message sent before streaming chunk data.
// For direct peers, the raw bytes follow on the TCP connection.
// For relayed transfers, a streaming relay or MessageChunkData is used.
type MessageStoreChunk struct {
	ChunkKey string // content-hash of this chunk
	Size     int64  // how many bytes of chunk data follow
}

// MessageGetChunk asks a peer for a specific chunk by its content hash
type MessageGetChunk struct {
	ChunkKey string
}

// MessageChunkData carries chunk bytes inside a relay message (fallback for small chunks)
type MessageChunkData struct {
	ChunkKey string
	Data     []byte
}
