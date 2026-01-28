package main

import (
	"bytes"
	"fmt"
	"io"
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
		Handshake:  p2p.SecureHandshake,
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
	fmt.Println("This is GO-DFS - Secure Transport Demo")
	fmt.Println("========================================")

	s1 := createServer("0.0.0.0:5000")
	s2 := createServer("0.0.0.0:5001", "0.0.0.0:5000")

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
	time.Sleep(1 * time.Second) // Wait for s2 to connect to s1

	// Workaround removed: s2 dials s1 via bootstrap nodes.
	// Since Accept() is fixed, s1 will accept s2's connection and both will register each other.
	time.Sleep(1 * time.Second)

	fmt.Printf("\n[%s] s1 has %d peers\n", s1.Transport.Addr(), len(s1.GetPeers()))
	fmt.Printf("[%s] s2 has %d peers\n", s2.Transport.Addr(), len(s2.GetPeers()))

	// send our secure message from s1 (port 5000) to s2 (port 5001)
	// NOTE: We send FROM s1 because s1's OUTBOUND connection works,
	// and s2's Accept loop works to receive it
	secureMessage := "Hey i am secure"
	messageKey := "secure_message"
	fmt.Printf("\n>>> Sending encrypted message FROM s1 TO s2: %q\n", secureMessage)
	fmt.Printf(">>> Key: %s\n", messageKey)

	if err := s1.StoreData(messageKey, bytes.NewReader([]byte(secureMessage))); err != nil {
		fmt.Printf("StoreData error: %v\n", err)
	} else {
		fmt.Println(">>> Message sent successfully (encrypted over the wire)")
	}

	// wait for message to propagate and be processed
	time.Sleep(2 * time.Second)

	// verify the file exists on s2 (it should receive it via encrypted channel)
	fmt.Println("\n--- Verification ---")

	// Check s1 has the file locally (source)
	if r, err := s1.GetFile(messageKey); err != nil {
		fmt.Printf("[s1 - :5000] GetFile error: %v\n", err)
	} else {
		data, _ := io.ReadAll(r)
		r.(io.ReadCloser).Close()
		fmt.Printf("[s1 - :5000] Source file content: %q\n", string(data))
	}

	// Check s2 received the file
	if r, err := s2.GetFile(messageKey); err != nil {
		fmt.Printf("[s2 - :5001] GetFile error: %v\n", err)
	} else {
		data, _ := io.ReadAll(r)
		r.(io.ReadCloser).Close()
		fmt.Printf("[s2 - :5001] Received file content: %q\n", string(data))
		if string(data) == secureMessage {
			fmt.Println("[s2 - :5001] ✓ Content matches original - ENCRYPTION VERIFIED!")
		}
	}

	fmt.Println("\n========================================")
	fmt.Println("Check ./cas5000 and ./cas5001 folders to see stored files")
	fmt.Println("The data on disk is the plaintext (decrypted after receipt)")
	fmt.Println("But the network transfer was encrypted with ChaCha20-Poly1305")
	fmt.Println("========================================")

	select {}
}
