package main

import (
	"fmt"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

func OnPeerTest(peer p2p.Peer) error {
	fmt.Println("works")
	return nil
}
func main() {
	fmt.Println("This is GO-DFS")

	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: "0.0.0.0:3000",
		Handshake:  p2p.SampleHandshake,
		Decoder:    p2p.SampleDecoder{},
		OnPeer:     OnPeerTest,
	})
	options := FileServerOptions{
		rootDir:   "./cas",
		Transport: transport,
	}
	server := NewFileServer(options)
	server.Start()
	select {}

}
