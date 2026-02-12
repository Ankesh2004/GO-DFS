package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

func OnPeerTest(peer p2p.Peer) error {
	fmt.Println("works")
	return nil
}

func createServer(addr string, nodes ...string) *server.FileServer {
	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: addr,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	options := server.FileServerOptions{
		ID:             "shared",
		RootDir:        "./cas" + addr[8:12],
		Transport:      transport,
		BootstrapNodes: nodes,
	}
	s := server.NewFileServer(options)
	transport.OnPeer = s.OnPeer
	return s
}

func loadOrGenerateUserKey(filename string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := os.Stat(filename); err == nil {
		key, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Loaded user encryption key from %s\n", filename)
	} else {
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filename, key, 0600); err != nil {
			return nil, err
		}
		fmt.Printf("Generated and saved new user encryption key to %s\n", filename)
	}
	return key, nil
}

func RetrieveAndDecrypt(s *server.FileServer, key string, userKey []byte) error {
	fmt.Printf(">>> Retrieving file: %s\n", key)

	r, err := s.GetFile(key)
	if err != nil {
		return fmt.Errorf("failed to retrieve file: %w", err)
	}
	// Note: s.GetFile returns a reader that might be a file, so it might implement io.Closer
	if closer, ok := r.(io.Closer); ok {
		defer closer.Close()
	}

	encryptedBlob, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read blob: %w", err)
	}
	fmt.Printf("Received encrypted blob size: %d bytes\n", len(encryptedBlob))

	if len(encryptedBlob) < 12 {
		return fmt.Errorf("invalid blob size")
	}
	nonce := encryptedBlob[:12]
	ciphertext := encryptedBlob[12:]

	decryptedBuf := new(bytes.Buffer)
	if _, err := crypto.Decrypt(userKey, nonce, bytes.NewReader(ciphertext), decryptedBuf); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	destDir := "myFiles"
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	destPath := filepath.Join(destDir, key)
	if err := os.WriteFile(destPath, decryptedBuf.Bytes(), 0644); err != nil {
		return err
	}

	fmt.Printf("✓ File retrieved, decrypted, and saved to: %s\n", destPath)
	fmt.Printf("✓ Content: %s\n", decryptedBuf.String())
	return nil
}

func main() {
	fmt.Println("This is GO-DFS - Zero Trust Storage Demo")
	fmt.Println("========================================")

	s1 := createServer("0.0.0.0:7000")
	s2 := createServer("0.0.0.0:7001", "0.0.0.0:7000")

	go func() {
		if err := s1.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	time.Sleep(500 * time.Millisecond)
	go func() {
		if err := s2.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	time.Sleep(2 * time.Second)

	fmt.Printf("[%s] s1 peers: %d, s2 peers: %d\n", s1.Transport.Addr(), len(s1.GetPeers()), len(s2.GetPeers()))

	userKey, err := loadOrGenerateUserKey("myKey.key")
	if err != nil {
		log.Fatal(err)
	}

	messageKey := "secret_notes.txt"
	secureMessage := "This is a confidential note retrieved from the mesh network."

	fmt.Printf("\n>>> [S1] Storing file: %s\n", messageKey)
	if err := s1.StoreData(messageKey, userKey, bytes.NewReader([]byte(secureMessage))); err != nil {
		log.Fatal(err)
	}
	fmt.Println(">>> Store success.")

	time.Sleep(2 * time.Second)

	fmt.Println("\n>>> [S2] User requesting file download...")
	if err := RetrieveAndDecrypt(s2, messageKey, userKey); err != nil {
		log.Fatalf("Retrieval failed: %v", err)
	}

	fmt.Println("\n========================================")
	fmt.Println("Check 'myFiles/secret_notes.txt'!")
	fmt.Println("========================================")

	select {}
}
