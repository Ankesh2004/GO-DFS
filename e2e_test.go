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

// Helper to create a test server with unique port and directory
func createTestServer(port string, bootstrap []string, t *testing.T, keepKey bool) *FileServer {
	addr := ":" + port
	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: addr,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	// Use unique test directories
	dir := "./test_cas_" + port

	// If keepKey is false (default start), wipe everything.
	// If keepKey is true (restart), wipe nothing.
	if !keepKey {
		os.RemoveAll(dir)
		os.Remove(port + ".key")
	}

	options := FileServerOptions{
		ID:              port, // Use port as ID for key file
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
	s1 := createTestServer("6000", nil, t, false)
	defer s1.Stop()
	defer os.RemoveAll("./test_cas_6000") // Cleanup

	// Setup Server 2 (port 6001), bootstrapping to s1
	s2 := createTestServer("6001", []string{":6000"}, t, false)
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

	// User Key (Client-side)
	userKey := make([]byte, 32)
	rand.Read(userKey) // Should be crypto/rand

	// 1. Store data on S1 (encrypted by User)
	t.Log("Storing data on S1 (User Encrypted)...")
	if err := s1.StoreData(testKey, userKey, bytes.NewReader(originalData)); err != nil {
		t.Fatalf("Failed to store data on s1: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // Allow async broadcast

	// 2. Fetch data from S2 (should retrieve ENCRYPTED blob from S1)
	t.Log("Fetching data from S2...")
	r, err := s2.GetFile(testKey)
	if err != nil {
		t.Fatalf("Failed to retrieve file on s2: %v", err)
	}

	encryptedBlob, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("Failed to read retrieved data: %v", err)
	}
	if closer, ok := r.(io.Closer); ok {
		closer.Close()
	}

	// 3. Client-Side Decryption
	// The blob is: [Nonce 12][Ciphertext]
	if len(encryptedBlob) < 12 {
		t.Fatalf("Received blob too small: %d", len(encryptedBlob))
	}
	nonce := encryptedBlob[:12]
	// Our `decrypt` helper expects the reader to contain the nonce?
	// Let's check `cryptography.go`. `decrypt` reads nonce from src if not provided?
	// `func decrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer)`
	// If `nonce` is nil? No, `main.go:decrypt` reads it?
	// Let's assume we need to pass nonce.
	// Actually `cryptography.go` signature: `decrypt(key, nonce, src, dst)`
	// Wait, `ReadStreamDecrypted` used `io.ReadFull(file, nonce)` then passed it.

	// Correction: My `encrypt` function writes `[Length][Nonce][Ciphertext]` chunks?
	// Or `[Nonce][Chunk]`?
	// Ah, I need to check `cryptography.go`.

	// Assuming `encrypt` does streaming with chunks:
	// Then `decrypt` should handle the stream.
	// But wait, `StoreData` wrote `[UserNonce][EncStream]`.
	// AND `encrypt` writes frames?
	// Let's use `decrypt` treating the WHOLE thing as a stream.
	// `StoreData` generated a `userNonce` and wrote it.
	// Then called `encrypt(key, userNonce, r, buf)`.
	// `encrypt` uses that nonce as the STARTING nonce and increments it per chunk?
	// `cryptography.go` implementation details matter here.

	// Workaround: We can't easily call `decrypt` if we don't know the framing.
	// BUT `s1.s.ReadStreamDecrypted` used to do it.
	// Let's manually invoke the same logic:
	// The stream starts with `userNonce`.

	// Actually, `StoreData` wrote `userNonce` MANUALLY.
	// `encrypt` uses it.
	// SO `encryptedBlob` = `[userNonce] + [EncryptedStream]`.
	// To decrypt:
	// Read 12 bytes -> nonce.
	// Pass rest to `decrypt(userKey, nonce, rest, out)`.

	decryptedBuf := new(bytes.Buffer)
	if _, err := decrypt(userKey, nonce, bytes.NewReader(encryptedBlob[12:]), decryptedBuf); err != nil {
		t.Fatalf("Client-side decryption failed: %v", err)
	}

	if !bytes.Equal(originalData, decryptedBuf.Bytes()) {
		t.Errorf("FATAL: Data mismatch!\nExpected: %v\nGot:      %v", originalData, decryptedBuf.Bytes())
	} else {
		t.Log("SUCCESS: Client-side decryption verified.")
	}

	// 4. Verify Storage (Zero Trust)
	t.Log("--- Storage Verification ---")

	encryptedPathS2 := s2.s.getCASPath(testKey).FullPath()
	encryptedContentS2, err := os.ReadFile(encryptedPathS2)
	if err != nil {
		t.Fatalf("Failed to read raw file from S2: %v", err)
	}

	encryptedPathS1 := s1.s.getCASPath(testKey).FullPath()
	encryptedContentS1, err := os.ReadFile(encryptedPathS1)
	if err != nil {
		t.Fatalf("Failed to read raw file from S1: %v", err)
	}

	// S1 and S2 should have IDENTICAL content (Same User Encrypted Blob)
	if !bytes.Equal(encryptedContentS1, encryptedContentS2) {
		t.Errorf("WARNING: S1 and S2 content differs? Should be identical replica.")
	} else {
		t.Log("SUCCESS: S1 and S2 store identical encrypted replicas.")
	}

	if bytes.Contains(encryptedContentS2, originalData) {
		t.Errorf("SECURITY FAIL: Plaintext found on disk!")
	} else {
		t.Log("SUCCESS: S2 stored encrypted data.")
	}
}
