package p2p

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

// ================== TCP Peer ==========================
type TCPPeer struct {
	net.Conn
	// isOutbound := true if we are the one who dialed the connection
	// isOutbound := false if we are the one who accepted the connection
	isOutbound bool
	Wg         *sync.WaitGroup

	// tracks if there's actually a stream in progress - prevents negative WaitGroup
	// when CloseStream is called without an active stream
	streamMu     sync.Mutex
	streamActive bool
}

func NewTCPPeer(isOutbound bool, conn net.Conn) (Peer, error) {
	p := &TCPPeer{
		isOutbound:   isOutbound,
		Conn:         conn,
		Wg:           &sync.WaitGroup{},
		streamActive: false,
	}
	// p.wg.Add(1)
	return p, nil
}

func (p *TCPPeer) CloseStream() error {
	p.streamMu.Lock()
	defer p.streamMu.Unlock()

	// only call Done if we actually had an active stream - prevents panic on negative wg
	if p.streamActive {
		p.streamActive = false
		p.Wg.Done()
	}
	return nil
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
func (p *TCPPeer) RemoteAddr() net.Addr {
	return p.Conn.RemoteAddr()
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
	// THERE WAS A BUG HERE:
	// Use standard net.Listen instead of ListenConfig
	// The custom setSocketReuseAddr was causing Accept() to never return on Windows
	listener, err := net.Listen("tcp", t.ListenPort)
	if err != nil {
		return err
	}
	t.Listener = listener

	go t.acceptLoop()
	fmt.Println("Listening on port ", t.ListenPort)
	return nil
}

// Outogoing Connection

func (t *TCPTransport) Dial(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to dial up: %s error: %v", addr, err)
		return err
	}
	// TCP's 3-way handshake guarantees the remote's Accept() is complete before Dial() returns
	// our app-level Handshake in handleConnection provides the actual synchronization
	go t.handleConnection(conn, true)
	return nil
}

func (t *TCPTransport) acceptLoop() {
	fmt.Println("Starting accept loop")
	for {
		conn, err := t.Listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "[PANIC] in handleConnection: %v\n", r)
				}
			}()
			t.handleConnection(c, false)
		}(conn)
	}
}

func (t *TCPTransport) handleConnection(conn net.Conn, isOutbound bool) {
	defer func() {
		conn.Close()
		fmt.Println("Connection closed")
	}()
	peer, err := NewTCPPeer(isOutbound, conn)
	if err != nil {
		log.Printf("Failed to create peer: %v", err)
		return
	}
	if err := t.Handshake(peer); err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}
	fmt.Println("New connection....", peer)

	// Tell server to add peer in its list
	if t.OnPeer != nil {
		if err := t.OnPeer(peer); err != nil {
			return
		}
	}

	// read loop - after SecureHandshake, peer.Conn is encrypted SecurePeer
	for {
		rpc := RPC{}
		if err := t.Decoder.Decode(peer, &rpc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fmt.Printf("Decode error: %v\n", err)
			break
		}
		rpc.From = peer.RemoteAddr().String()
		if rpc.isStream {
			tcpPeer := peer.(*TCPPeer)
			tcpPeer.streamMu.Lock()
			tcpPeer.streamActive = true
			tcpPeer.Wg.Add(1)
			tcpPeer.streamMu.Unlock()
			fmt.Println("Waiting till stream finishes...")
			tcpPeer.Wg.Wait()
			fmt.Println("Stream done")
			continue
		}

		t.rpcChannel <- rpc // dump the data from this channel into (this)transport's channel
		// fmt.Println(string(rpc.Payload))
	}
}
