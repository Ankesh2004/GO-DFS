package main

import (
	"fmt"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

func OnPeerTest(peer p2p.Peer) error {
	fmt.Println("works")
	return nil
}

func createServer(addr string, nodes ...string) *FileServer {
	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: addr,
		Handshake:  p2p.SampleHandshake,
		Decoder:    p2p.SampleDecoder{},
		// OnPeer:     OnPeerTest,
	})
	options := FileServerOptions{
		rootDir:         "./cas",
		Transport:       transport,
		BooststrapNodes: nodes,
	}
	server := NewFileServer(options)
	transport.OnPeer = server.OnPeer
	return server
}
func main() {
	fmt.Println("This is GO-DFS")
	s1 := createServer("0.0.0.0:3000")
	s2 := createServer("0.0.0.0:3001", "0.0.0.0:3000")
	go s1.Start()
	go s2.Start()
	select {}

}
