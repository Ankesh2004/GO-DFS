package main

import (
	"fmt"
	"log"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

func main() {
	fmt.Println("This is GO-DFS")
	// TEST 1: Establish connection , use telnet to connect to port 3000
	tr := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: ":3000",
		Handshake:  p2p.SampleHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	if err := tr.ListenAndAccept(); err != nil {
		fmt.Println("Error listening on port 3000")
		log.Fatal(err)
		return
	}

	select {}

}
