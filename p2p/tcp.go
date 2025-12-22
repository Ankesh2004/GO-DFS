package p2p

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// ================== TCP Peer ==========================
type TCPPeer struct {
	net.Conn
	// isOutbound := true if we are the one who dialed the connection
	// isOutbound := false if we are the one who accepted the connection
	isOutbound bool
	wg         *sync.WaitGroup
}

func NewTCPPeer(isOutbound bool, conn net.Conn) (Peer, error) {
	p := &TCPPeer{
		isOutbound: isOutbound,
		Conn:       conn,
		wg:         &sync.WaitGroup{},
	}
	p.wg.Add(1)
	return p, nil
}

func (p *TCPPeer) CloseStream() error {
	p.wg.Done()
	return p.Conn.Close()
}

func (p *TCPPeer) Send(data []byte) error {
	n, err := p.Conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// ============ TCP Transport options (configurations required to create a transport) ============
type TCPTransportOptions struct {
	ListenPort string
	OnPeer     func(Peer) error
	Decoder    Decoder
	Handshake  Handshake
}

// ============= TCP Transport =================
type TCPTransport struct {
	TCPTransportOptions
	Listener   net.Listener
	rpcChannel chan RPC
}

func NewTCPTransport(options TCPTransportOptions) *TCPTransport {
	t := &TCPTransport{
		TCPTransportOptions: options,
		Listener:            nil, // will be added latr
		rpcChannel:          make(chan RPC, 1024),
	}
	return t
}

// consume return read-only channel to receive from another peer
func (t *TCPTransport) Consume() <-chan RPC {
	return t.rpcChannel
}

func (t *TCPTransport) Addr() string {
	return t.ListenPort
}

// Close closes the TCP listener and cleans up resources
func (t *TCPTransport) Close() error {
	if t.Listener != nil {
		return t.Listener.Close()
	}
	return nil
}

// Incoming connection
func (t *TCPTransport) ListenAndAccept() error {
	conn, err := net.Listen("tcp", t.ListenPort)
	if err != nil {
		return err
	}
	t.Listener = conn

	go t.acceptLoop() // run multiple accept loops so that if one is busy then other can accept new connections
	fmt.Println("Listening on port ", t.ListenPort)
	return nil
}

// Outogoing Connection

func (t *TCPTransport) Dial(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal("Failed to dial up")
		return err
	}
	go t.handleConnection(conn, true)
	return nil
}

func (t *TCPTransport) acceptLoop() {
	fmt.Println("Starting accept loop")
	for {
		conn, err := t.Listener.Accept()
		// if listener is closed then return
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.Fatal("Accept error: ", err)
			continue
		}
		//enables multiple peers at once
		go t.handleConnection(conn, false)
	}
}

func (t *TCPTransport) handleConnection(conn net.Conn, isOutbound bool) {
	defer func() {
		conn.Close()
		fmt.Println("Connection closed")
	}()
	peer, err := NewTCPPeer(isOutbound, conn)
	if err != nil {
		log.Fatal("Failed to create peer")
		return
	}
	if t.Handshake(peer) != nil {
		log.Fatal("Failed to handshake")
		return
	}
	fmt.Println("New connection....", peer)

	// Tell server to add peer in its list
	if t.OnPeer != nil {
		if err := t.OnPeer(peer); err != nil {
			return
		}
	}

	//now accept rpcs ---> decode ---> send to rpc channel
	// read loop
	rpc := RPC{}
	for {
		// This error can be due to 2 reasons:
		// 1. payload was not correct ---> continue
		// 2. the connection is dropped ---> here if we continue then we will go into read loop forever, wasting server's compute for a dead connection
		// ---> here we have to break the loop somehow  TODO
		if err := t.Decoder.Decode(conn, &rpc); err != nil {
			fmt.Println("failed to decodeeee")
			continue
		}
		rpc.From = conn.RemoteAddr().String()
		t.rpcChannel <- rpc // dump the data from this channel into (this)transport's channel
		// fmt.Println(string(rpc.Payload))
	}
}
