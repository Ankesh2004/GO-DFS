package p2p

import "net"

// Peer := remote node
// Peer is basically a "connection" to remote node
type Peer interface {
	net.Conn // COMPOSITION : can hold net.TCPConn, net.QUICConn etc
	Send([]byte) error
	CloseStream() error
}

// High level transport interface : will be used further for TCP , QUIC etc
type Transport interface {
	PeerAddr() string
	Dial(addr string) error
	ListenAndAccept() error
	Consume() <-chan RPC
	Close() error
}
