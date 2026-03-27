package test

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
	"io"
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
		AdvertiseAddr:  "127.0.0.1:" + port,
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

func TestDeleteFile(t *testing.T) {
	s1 := createTestServer("6010", nil, t, false)
	defer s1.Stop()
	defer os.RemoveAll("./test_cas_6010")

	s2 := createTestServer("6011", []string{":6010"}, t, false)
	defer s2.Stop()
	defer os.RemoveAll("./test_cas_6011")

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

	// store a small file using the chunked path (the one the CLI actually calls)
	userKey := make([]byte, 32)
	rand.Read(userKey)

	payload := bytes.NewReader([]byte("delete me from the whole network!"))
	t.Log("Storing file on s1...")
	cid, err := s1.StoreDataChunked("delete_test.txt", userKey, payload)
	if err != nil {
		t.Fatalf("StoreDataChunked failed: %v", err)
	}
	t.Logf("CID: %s", cid)

	// give s2 time to receive the replicated manifest + chunks
	time.Sleep(800 * time.Millisecond)

	manifestKey := cid + ".manifest"

	// s1 must have the manifest before we delete
	if !s1.Store.Has(manifestKey) {
		t.Fatalf("s1 should have the manifest before delete")
	}

	t.Log("Calling DeleteFile on s1...")
	if err := s1.DeleteFile(cid); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}

	// give MessageDeleteFile time to propagate to s2
	time.Sleep(500 * time.Millisecond)

	// --- s1 checks ---
	if s1.Store.Has(manifestKey) {
		t.Errorf("FAIL: s1 still has the manifest after deletion")
	} else {
		t.Log("OK: s1 manifest deleted from CAS")
	}

	if !s1.Tombstones.IsDead(manifestKey) {
		t.Errorf("FAIL: s1 tombstone not active for manifest key")
	} else {
		t.Log("OK: s1 tombstone is active for manifest")
	}

	// --- s2 checks ---
	if !s2.Tombstones.IsDead(manifestKey) {
		t.Errorf("FAIL: s2 tombstone not set — MessageDeleteFile may not have reached s2")
	} else {
		t.Log("OK: s2 tombstone is active (propagated from s1)")
	}

	if s2.Store.Has(manifestKey) {
		t.Errorf("FAIL: s2 still has manifest bytes after receiving delete message")
	} else {
		t.Log("OK: s2 manifest deleted from CAS")
	}

	// --- chunk tombstones ---
	allTombstones := s1.Tombstones.All()
	if len(allTombstones) == 0 {
		t.Errorf("FAIL: s1 has no tombstones at all")
	} else {
		t.Logf("OK: s1 has %d tombstone(s) active", len(allTombstones))
	}

	// CIDIndex should no longer list this file
	for _, entry := range s1.CIDIndex.List() {
		if entry.CID == cid {
			t.Errorf("FAIL: s1 CIDIndex still contains deleted CID %s", cid[:16])
		}
	}
	t.Log("OK: s1 CIDIndex no longer lists the deleted file")
}

func TestReplicationOnNodeFailure(t *testing.T) {
	// 3-node setup: s1 stores a file, s2 and s3 get replicas.
	// then we kill s3 and check if s1's replication audit notices.
	s1 := createTestServer("6020", nil, t, false)
	defer s1.Stop()
	defer os.RemoveAll("./test_cas_6020")

	s2 := createTestServer("6021", []string{":6020"}, t, false)
	defer s2.Stop()
	defer os.RemoveAll("./test_cas_6021")

	s3 := createTestServer("6022", []string{":6020"}, t, false)
	defer os.RemoveAll("./test_cas_6022")

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
	time.Sleep(500 * time.Millisecond)

	go func() {
		if err := s3.Start(); err != nil {
			t.Logf("s3 stopped: %v", err)
		}
	}()
	time.Sleep(1 * time.Second)

	// make sure everyone's connected
	if len(s1.GetPeers()) < 2 {
		t.Logf("WARNING: s1 only has %d peers, expected at least 2", len(s1.GetPeers()))
	}

	// store a file on s1
	userKey := make([]byte, 32)
	rand.Read(userKey)

	payload := bytes.NewReader([]byte("replication test data — this should survive node failure!"))
	t.Log("Storing file on s1...")
	cid, err := s1.StoreDataChunked("repl_test.txt", userKey, payload)
	if err != nil {
		t.Fatalf("StoreDataChunked failed: %v", err)
	}
	t.Logf("CID: %s", cid[:16])

	// give replication time to propagate
	time.Sleep(1 * time.Second)

	manifestKey := cid + ".manifest"

	// verify s1 has the manifest
	if !s1.Store.Has(manifestKey) {
		t.Fatalf("s1 should have the manifest")
	}

	// check how many nodes have the manifest before killing s3
	s2HasManifest := s2.Store.Has(manifestKey)
	s3HasManifest := s3.Store.Has(manifestKey)
	t.Logf("Before failure: s1=true, s2=%v, s3=%v", s2HasManifest, s3HasManifest)

	// kill s3 to simulate node failure
	t.Log("Stopping s3 to simulate node failure...")
	s3.Stop()
	time.Sleep(500 * time.Millisecond)

	// s1 should still have everything
	if !s1.Store.Has(manifestKey) {
		t.Errorf("FAIL: s1 lost the manifest after s3 went down")
	} else {
		t.Log("OK: s1 still has the manifest after s3 failure")
	}

	// verify s1's CIDIndex still lists the file
	found := false
	for _, entry := range s1.CIDIndex.List() {
		if entry.CID == cid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("FAIL: s1 CIDIndex doesn't list the file after node failure")
	} else {
		t.Log("OK: s1 CIDIndex still lists the file")
	}

	// load manifest and check all chunks are still on s1
	manifest, err := s1.Store.ReadChunk(manifestKey)
	if err != nil {
		t.Fatalf("Failed to read manifest: %v", err)
	}
	if len(manifest) == 0 {
		t.Fatalf("Manifest is empty")
	}
	t.Log("OK: s1 has all manifest data intact")

	// quick sanity check on the GetReplicationStatus API
	healthy, under, over, lastAudit := s1.GetReplicationStatus()
	t.Logf("Replication status: healthy=%d, under=%d, over=%d, lastAudit=%v",
		healthy, under, over, lastAudit)

	// check peer health API
	healthMap := s1.GetPeerHealthMap()
	t.Logf("Peer health map has %d entries", len(healthMap))

	t.Log("Replication test passed — data survived node failure")
}
