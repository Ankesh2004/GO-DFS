package server

import "encoding/gob"

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
type MessageRelayData struct {
	Key  string // file key
	Data []byte // the actual encrypted file bytes
}
