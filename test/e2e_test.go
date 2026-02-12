package test

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"testing"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

func createTestServer(port string, bootstrap []string, t *testing.T, keepKey bool) *server.FileServer {
	addr := ":" + port
	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: addr,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	dir := "./test_cas_" + port

	if !keepKey {
		os.RemoveAll(dir)
	}

	options := server.FileServerOptions{
		ID:             port,
		RootDir:        dir,
		Transport:      transport,
		BootstrapNodes: bootstrap,
	}
	s := server.NewFileServer(options)
	transport.OnPeer = s.OnPeer
	return s
}

func TestEndToEndIntegrity(t *testing.T) {
	s1 := createTestServer("6000", nil, t, false)
	defer s1.Stop()
	defer os.RemoveAll("./test_cas_6000")

	s2 := createTestServer("6001", []string{":6000"}, t, false)
	defer s2.Stop()
	defer os.RemoveAll("./test_cas_6001")

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
	time.Sleep(1 * time.Second)

	originalData := []byte("This is a secret payload that must remain intact!")
	testKey := "integrity_check_data"

	userKey := make([]byte, 32)
	rand.Read(userKey)

	t.Log("Storing data on S1 (User Encrypted)...")
	if err := s1.StoreData(testKey, userKey, bytes.NewReader(originalData)); err != nil {
		t.Fatalf("Failed to store data on s1: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

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

	if len(encryptedBlob) < 12 {
		t.Fatalf("Received blob too small: %d", len(encryptedBlob))
	}
	nonce := encryptedBlob[:12]

	decryptedBuf := new(bytes.Buffer)
	if _, err := crypto.Decrypt(userKey, nonce, bytes.NewReader(encryptedBlob[12:]), decryptedBuf); err != nil {
		t.Fatalf("Client-side decryption failed: %v", err)
	}

	if !bytes.Equal(originalData, decryptedBuf.Bytes()) {
		t.Errorf("FATAL: Data mismatch!\nExpected: %v\nGot:      %v", originalData, decryptedBuf.Bytes())
	} else {
		t.Log("SUCCESS: Client-side decryption verified.")
	}

	t.Log("--- Storage Verification ---")

	pathS2 := s2.Store.GetCASPath(testKey).FullPath()
	contentS2, err := os.ReadFile(pathS2)
	if err != nil {
		t.Fatalf("Failed to read raw file from S2: %v", err)
	}

	pathS1 := s1.Store.GetCASPath(testKey).FullPath()
	contentS1, err := os.ReadFile(pathS1)
	if err != nil {
		t.Fatalf("Failed to read raw file from S1: %v", err)
	}

	if !bytes.Equal(contentS1, contentS2) {
		t.Errorf("WARNING: S1 and S2 content differs? Should be identical replica.")
	} else {
		t.Log("SUCCESS: S1 and S2 store identical encrypted replicas.")
	}

	if bytes.Contains(contentS2, originalData) {
		t.Errorf("SECURITY FAIL: Plaintext found on disk!")
	} else {
		t.Log("SUCCESS: S2 stored encrypted data.")
	}
}
