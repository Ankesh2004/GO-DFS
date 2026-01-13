package main

import (
	"bytes"
	"fmt"
	"time"

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
		rootDir:         "./cas" + addr[8:12],
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

	go func() {
		if err := s1.Start(); err != nil {
			fmt.Println("s1 Start error:", err)
		}
	}()
	time.Sleep(1 * time.Second) // Wait for s1 to start listening

	go func() {
		if err := s2.Start(); err != nil {
			fmt.Println("s2 Start error:", err)
		}
	}()
	time.Sleep(2 * time.Second) // Wait for s2 to connect to s1

	fmt.Printf("[%s] s2 has %d peers\n", s2.Transport.Addr(), len(s2.GetPeers()))
	s2.StoreData("mydatakey", bytes.NewReader([]byte("long_data_file111")))

	// for i := 0; i < 10; i++ {
	// 	if err := s2.StoreData(fmt.Sprintf("mydatakey%d", i), bytes.NewReader([]byte("long_data_file111"))); err != nil {
	// 		fmt.Println("StoreData error:", err)
	// 	}
	// 	time.Sleep(5 * time.Millisecond)
	// }

	// if r, err := s1.GetFile("mydatakey"); err != nil {
	// 	fmt.Println("GetFile error:", err)
	// } else {
	// 	b, _ := io.ReadAll(r)
	// 	fmt.Println("Data:", string(b))
	// 	r.(io.ReadCloser).Close()
	// }

	select {}
}
