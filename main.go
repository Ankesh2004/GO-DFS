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
	})
	options := FileServerOptions{
		ID:              "shared", // All nodes use same shared node-key (unused for storage now)
		rootDir:         "./cas" + addr[8:12],
		Transport:       transport,
		BooststrapNodes: nodes,
	}
	server := NewFileServer(options)
	transport.OnPeer = server.OnPeer
	return server
}

func loadOrGenerateUserKey(filename string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := os.Stat(filename); err == nil {
		// Load existing key
		key, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Loaded user encryption key from %s\n", filename)
	} else {
		// Generate new key
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

func DecryptAllLocalFiles(s *FileServer, userKey []byte, destDir string) error {
	rootDir := s.s.rootDir
	return filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Found a file (blob)
		fmt.Printf("Found encrypted blob: %s\n", info.Name())

		// Read Blob
		blob, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Attempt Decryption
		if len(blob) < 12 {
			// Too short to be a valid encrypted file
			return nil
		}
		nonce := blob[:12]
		ciphertext := blob[12:]

		decryptedBuf := new(bytes.Buffer)
		if _, err := decrypt(userKey, nonce, bytes.NewReader(ciphertext), decryptedBuf); err != nil {
			// Decryption failed (maybe different key or corruption)
			fmt.Printf("Failed to decrypt %s: %v\n", info.Name(), err)
			return nil
		}

		// Ensure destDir exists
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return err
		}

		// Save Decrypted
		destPath := filepath.Join(destDir, "decrypted_"+info.Name())
		if err := os.WriteFile(destPath, decryptedBuf.Bytes(), 0644); err != nil {
			return err
		}
		fmt.Printf("✓ Decrypted and saved to %s\n", destPath)
		return nil
	})
}

func RetrieveAndDecrypt(s *FileServer, key string, userKey []byte) error {
	fmt.Printf(">>> Retrieving file: %s\n", key)

	// 1. Query Network (Local + Peers)
	r, err := s.GetFile(key)
	if err != nil {
		return fmt.Errorf("failed to retrieve file: %w", err)
	}
	defer r.(io.Closer).Close()

	// 2. Read Encrypted Blob
	encryptedBlob, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read blob: %w", err)
	}
	fmt.Printf("Received encrypted blob size: %d bytes\n", len(encryptedBlob))

	// 3. Decrypt
	if len(encryptedBlob) < 12 {
		return fmt.Errorf("invalid blob size")
	}
	nonce := encryptedBlob[:12]
	ciphertext := encryptedBlob[12:]

	decryptedBuf := new(bytes.Buffer)
	if _, err := decrypt(userKey, nonce, bytes.NewReader(ciphertext), decryptedBuf); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// 4. Save to myFiles/
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

	// Start servers
	go func() { log.Fatal(s1.Start()) }()
	time.Sleep(500 * time.Millisecond)
	go func() { log.Fatal(s2.Start()) }()
	time.Sleep(2 * time.Second) // Wait for bootstrap

	fmt.Printf("[%s] s1 peers: %d, s2 peers: %d\n", s1.Transport.Addr(), len(s1.GetPeers()), len(s2.GetPeers()))

	// 1. Load User Identity
	userKey, err := loadOrGenerateUserKey("myKey.key")
	if err != nil {
		log.Fatal(err)
	}

	// 2. Store a File (Client Action)
	messageKey := "secret_notes.txt"
	secureMessage := "This is a confidential note retrieved from the mesh network."

	fmt.Printf("\n>>> [S1] Storing file: %s\n", messageKey)
	if err := s1.StoreData(messageKey, userKey, bytes.NewReader([]byte(secureMessage))); err != nil {
		log.Fatal(err)
	}
	fmt.Println(">>> Store success.")

	// Wait for network consistency
	time.Sleep(2 * time.Second)

	// 3. Retrieve and Decrypt (Client Action from S2)
	// Even though S1 stored it, we ask S2. S2 will fetch from S1.
	fmt.Println("\n>>> [S2] User requesting file download...")

	if err := RetrieveAndDecrypt(s2, messageKey, userKey); err != nil {
		log.Fatalf("Retrieval failed: %v", err)
	}

	fmt.Println("\n========================================")
	fmt.Println("Check 'myFiles/secret_notes.txt'!")
	fmt.Println("========================================")

	select {}
}
