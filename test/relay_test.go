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

// TestThreeNodeRelay verifies that file data can travel through a relay node.
//
// Topology:
//
//	S2 <----> S1 (bootstrap) <----> S3
//	S2 and S3 have NO direct connection
//
// Flow:
//  1. Start S1 (bootstrap)
//  2. S2 and S3 connect to S1 (they remain isolated from each other)
//  3. S2 stores a file.
//  4. S2 attempts to replicate to the "K-closest" nodes.
//  5. S3 (being a node in the network) receives a Push/RelayData from S2 via S1.
//
// This proves that remote nodes behind NAT can participate in the
// full lifecycle (Storage and Retrieval) via the relay.
func TestThreeNodeRelay(t *testing.T) {
	// --- Setup 3 nodes on isolated ports ---
	t1 := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: ":6200",
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	s1 := server.NewFileServer(server.FileServerOptions{
		ID:            "bootstrap",
		RootDir:       "./test_relay_cas_6200",
		AdvertiseAddr: "127.0.0.1:6200",
		Transport:     t1,
		RelayOnly:     true,
	})
	t1.OnPeer = s1.OnPeer
	defer s1.Stop()
	defer os.RemoveAll("./test_relay_cas_6200")

	t2 := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: ":6201",
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	s2 := server.NewFileServer(server.FileServerOptions{
		ID:             "storer",
		RootDir:        "./test_relay_cas_6201",
		AdvertiseAddr:  "127.0.0.1:6201",
		Transport:      t2,
		BootstrapNodes: []string{"127.0.0.1:6200"},
	})
	t2.OnPeer = s2.OnPeer
	defer s2.Stop()
	defer os.RemoveAll("./test_relay_cas_6201")

	t3 := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: ":6202",
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	s3 := server.NewFileServer(server.FileServerOptions{
		ID:             "requester",
		RootDir:        "./test_relay_cas_6202",
		AdvertiseAddr:  "127.0.0.1:6202",
		Transport:      t3,
		BootstrapNodes: []string{"127.0.0.1:6200"},
	})
	t3.OnPeer = s3.OnPeer
	defer s3.Stop()
	defer os.RemoveAll("./test_relay_cas_6202")

	// Start all nodes
	go s1.Start()
	time.Sleep(200 * time.Millisecond)
	go s2.Start()
	time.Sleep(200 * time.Millisecond)
	go s3.Start()
	time.Sleep(1 * time.Second)

	// Verify everyone is connected to S1
	t.Logf("S1 peers: %d, S2 peers: %d, S3 peers: %d",
		len(s1.GetPeers()), len(s2.GetPeers()), len(s3.GetPeers()))

	// S1 should see both. S2 and S3 should see only S1.
	if len(s1.GetPeers()) < 2 {
		t.Fatalf("S1 should have 2 peers, got %d", len(s1.GetPeers()))
	}

	// Wait for PeerExchange AND Discovery Rounds to settle so S2 knows about S3
	// S2 --(Discovery)--> S1 --(Response)--> S2 (now knows about S3)
	time.Sleep(5 * time.Second)

	// --- S2 stores a file ---
	originalData := []byte("Remote replication via relay works!")
	testKey := "global_relay_test"
	userKey := make([]byte, 32)
	rand.Read(userKey)

	t.Log("S2 storing file and attempting global replication...")
	if err := s2.StoreData(testKey, userKey, bytes.NewReader(originalData)); err != nil {
		t.Fatalf("S2 failed to store: %v", err)
	}

	// Give it some time to relay the data to S3
	time.Sleep(2 * time.Second)

	// CRITICAL CHECK: Does S3 have the file ALREADY?
	// It was never asked to fetch it. It should have received it via replication push.
	if !s3.Store.Has(testKey) {
		t.Fatal("FAILED: S3 did NOT receive the pushed replica from S2 via relay through S1")
	}
	t.Log("SUCCESS: S3 received pushed replica via relay!")

	// VERIFY S1 (Relay) does NOT have the file
	if s1.Store.Has(testKey) {
		t.Error("FAILED: S1 (RelayOnly) stored a local copy of the file! It should have been a pure relay.")
	} else {
		t.Log("SUCCESS: S1 (RelayOnly) did NOT store any data.")
	}

	// Final verification: can S3 read it?
	size, reader, err := s3.Store.ReadStream(testKey)
	if err != nil {
		t.Fatalf("S3 can't read its local copy: %v", err)
	}
	defer reader.Close()
	t.Logf("S3 verifying %d bytes of local data", size)

	blob, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Read failure: %v", err)
	}

	if len(blob) < 12 {
		t.Fatalf("Blob too small: %d", len(blob))
	}
	nonce := blob[:12]
	decryptedBuf := new(bytes.Buffer)
	if _, err := crypto.Decrypt(userKey, nonce, bytes.NewReader(blob[12:]), decryptedBuf); err != nil {
		t.Fatalf("Decryption failure on S3: %v", err)
	}

	if !bytes.Equal(originalData, decryptedBuf.Bytes()) {
		t.Errorf("Mismatch! Expected %s, got %s", originalData, decryptedBuf.Bytes())
	} else {
		t.Log("SUCCESS: All data verified on the remote node.")
	}
}
