package main

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

// Helper to create a test server with unique port and directory
func createTestServer(port string, bootstrap []string, t *testing.T) *FileServer {
	addr := ":" + port
	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: addr,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	// Use unique test directories
	dir := "./test_cas_" + port
	// Clean up previous runs
	os.RemoveAll(dir)

	options := FileServerOptions{
		rootDir:         dir,
		Transport:       transport,
		BooststrapNodes: bootstrap,
	}
	server := NewFileServer(options)
	transport.OnPeer = server.OnPeer
	return server
}

func TestEndToEndIntegrity(t *testing.T) {
	// Setup Server 1 (port 6000)
	s1 := createTestServer("6000", nil, t)
	defer s1.Stop()
	defer os.RemoveAll("./test_cas_6000") // Cleanup

	// Setup Server 2 (port 6001), bootstrapping to s1
	s2 := createTestServer("6001", []string{":6000"}, t)
	defer s2.Stop()
	defer os.RemoveAll("./test_cas_6001") // Cleanup

	// Start servers
	go func() {
		if err := s1.Start(); err != nil {
			t.Logf("s1 stopped: %v", err)
		}
	}()
	time.Sleep(500 * time.Millisecond)

	go func() {
		if err := s2.Start(); err != nil {
			t.Logf("s2 stopped: %v", err)
		}
	}()
	time.Sleep(1 * time.Second) // Wait for connection

	// Test Data
	originalData := []byte("This is a secret payload that must remain intact!")
	testKey := "integrity_check_data"

	// 1. Store data on S1 (encrypted at rest)
	t.Log("Storing data on S1...")
	if err := s1.StoreData(testKey, bytes.NewReader(originalData)); err != nil {
		t.Fatalf("Failed to store data on s1: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // Allow async broadcast

	// 2. Fetch data from S2 (should retrieve from S1)
	t.Log("Fetching data from S2...")
	r, err := s2.GetFile(testKey)
	if err != nil {
		t.Fatalf("Failed to retrieve file on s2: %v", err)
	}

	receivedData, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("Failed to read retrieved data: %v", err)
	}
	// Close the reader (important for file cleanup)
	if closer, ok := r.(io.Closer); ok {
		closer.Close()
	}

	// 3. VERIFICATION
	t.Logf("Original: %s", string(originalData))
	t.Logf("Received: %s", string(receivedData))

	if !bytes.Equal(originalData, receivedData) {
		t.Errorf("FATAL: Data mismatch!\nExpected: %v\nGot:      %v", originalData, receivedData)
	} else {
		t.Log("SUCCESS: Data integrity verified. S1 decrypted -> Network -> S2 decrypted match perfectly.")
	}

	// Double Check: Ensure data is actually encrypted on disk for S2
	// We cheat and peek at the file on disk directly
	encryptedPathS2 := s2.s.getCASPath(testKey).FullPath()
	encryptedContentS2, err := os.ReadFile(encryptedPathS2)
	if err != nil {
		t.Fatalf("Failed to read raw file from S2 disk: %v", err)
	}

	encryptedPathS1 := s1.s.getCASPath(testKey).FullPath()
	encryptedContentS1, err := os.ReadFile(encryptedPathS1)
	if err != nil {
		t.Fatalf("Failed to read raw file from S1 disk: %v", err)
	}

	t.Log("--- Storage Verification ---")

	// 1. Check S2 Storage Encryption
	if bytes.Contains(encryptedContentS2, originalData) {
		t.Errorf("SECURITY FAIL: S2 stored plaintext data!")
	} else {
		t.Log("SUCCESS: S2 stored encrypted data.")
	}

	// 2. Check S1 Storage Encryption (Source) - correcting user assumption that it's only on S2
	if bytes.Contains(encryptedContentS1, originalData) {
		t.Errorf("SECURITY FAIL: S1 stored plaintext data!")
	} else {
		t.Log("SUCCESS: S1 (Source) stored encrypted data.")
	}

	// 3. Compare S1 vs S2 Encrypted Content
	// Since we generate a NEW random nonce every time we write to disk (WriteStreamEncrypted),
	// the file on S1 and the file on S2 should be different (different nonces),
	// even though they decrypt to the same content.
	if bytes.Equal(encryptedContentS1, encryptedContentS2) {
		t.Errorf("SECURITY WARNING: S1 and S2 have IDENTICAL encrypted files. Expected unique nonces for each write!")
	} else {
		t.Log("SUCCESS: S1 and S2 have different encrypted files (Unique Nonces confirmed).")
	}

	// 4. Verify comparing encrypted vs unencrypted (User Request)
	if bytes.Equal(encryptedContentS2, originalData) {
		t.Errorf("FAIL: Encrypted data matches plaintext!")
	} else {
		t.Log("SUCCESS: Encrypted data != Plaintext data.")
	}
}
