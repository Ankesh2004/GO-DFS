package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"testing"
	"time"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

// Test that shared keys allow cross-node decryption
func TestSharedKeyDecryption(t *testing.T) {
	// Clean up from previous runs
	os.Remove("shared.key")
	os.RemoveAll("./test_shared_cas_7000")
	os.RemoveAll("./test_shared_cas_7001")
	defer os.Remove("shared.key")
	defer os.RemoveAll("./test_shared_cas_7000")
	defer os.RemoveAll("./test_shared_cas_7001")

	// Create two servers with SAME ID (shared key)
	s1 := createTestServerShared("7000", nil, t)
	s2 := createTestServerShared("7001", []string{":7000"}, t)
	defer s1.Stop()
	defer s2.Stop()

	// Start servers
	go s1.Start()
	time.Sleep(500 * time.Millisecond)
	go s2.Start()
	time.Sleep(1 * time.Second)

	// Test data
	originalData := []byte("Shared key test data")
	testKey := "shared_test_file"

	// User Key (Zero Trust)
	userKey := make([]byte, 32)
	rand.Read(userKey)

	// S1 stores the file (User Encrypted)
	t.Log("S1 storing file...")
	if err := s1.StoreData(testKey, userKey, bytes.NewReader(originalData)); err != nil {
		t.Fatalf("S1 failed to store: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// S2 should be able to read from its OWN local storage (received via network)
	// But it returns the ENCRYPTED blob.
	t.Log("S2 reading from local storage...")
	r, err := s2.GetFile(testKey)
	if err != nil {
		t.Fatalf("S2 failed to get file: %v", err)
	}
	encryptedBlob, _ := io.ReadAll(r)
	r.(io.Closer).Close()

	// Decrypt locally
	nonce := encryptedBlob[:12]
	decryptedBuf := new(bytes.Buffer)
	if _, err := decrypt(userKey, nonce, bytes.NewReader(encryptedBlob[12:]), decryptedBuf); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decryptedBuf.Bytes(), originalData) {
		t.Errorf("Data mismatch!\nExpected: %s\nGot: %s", originalData, decryptedBuf.Bytes())
	} else {
		t.Log("✓ S2 file retrieval + Header Decryption successful")
	}

	// Verify the shared key file exists (System property, even if unused for this file)
	if _, err := os.Stat("shared.key"); err != nil {
		t.Errorf("shared.key file not found!")
	} else {
		t.Log("✓ shared.key file created and persisted")
	}
}

func createTestServerShared(port string, bootstrap []string, t *testing.T) *FileServer {
	addr := ":" + port
	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: addr,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	dir := "./test_shared_cas_" + port

	options := FileServerOptions{
		ID:              "shared", // Same ID for all nodes
		rootDir:         dir,
		Transport:       transport,
		BooststrapNodes: bootstrap,
	}
	server := NewFileServer(options)
	transport.OnPeer = server.OnPeer
	return server
}
