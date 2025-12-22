package main

import (
	"fmt"
	"log"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

func TestMain() {
	// TEST 1: Establish connection , use telnet to connect to port 3000
	options := p2p.TCPTransportOptions{
		ListenPort: "127.0.0.1:3000",
		Handshake:  p2p.SampleHandshake,
		Decoder:    p2p.SampleDecoder{},
		OnPeer:     OnPeerTest,
	}
	tr := p2p.NewTCPTransport(options)
	if err := tr.ListenAndAccept(); err != nil {
		fmt.Println("Error listening on port 3000")
		log.Fatal(err)
		return
	}
	// TEST 2: check if RPC channel is working fien
	// NET_TODO: TEST THIS
	// go func() {
	// 	for {
	// 		msg := <-tr.Consume()
	// 		fmt.Println(msg)
	// 	}
	// }()

	// TEST 3: failing onpeer function , that is if onPeer func fails ===> then connection drops
	select {}
}
