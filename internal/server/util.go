package server

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
)

// function variables so chunked_ops can use them without importing directly.
// also makes testing easier if we ever need to stub these out.
var (
	randRead  = func(b []byte) (int, error) { return rand.Read(b) }
	encryptFn = crypto.Encrypt
	sleepFn   = func(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }
)

// resolvePeerAddr translates a raw TCP address to the advertised address.
// After PeerExchange, peers are keyed by their advertised addr in s.peers,
// but incoming RPCs still use the raw TCP remote addr. This bridges that gap.
func (s *FileServer) resolvePeerAddr(rawAddr string) string {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()

	if mapped, ok := s.addrMap[rawAddr]; ok {
		return mapped
	}
	return rawAddr
}

// LoadOrGenerateNodeID loads a persistent ID from disk or generates a new one.
// This ensures the node identity remains stable even if the IP address changes.
func LoadOrGenerateNodeID(dataDir string) (string, error) {
	idPath := filepath.Join(dataDir, "node.id")
	if _, err := os.Stat(idPath); err == nil {
		id, err := os.ReadFile(idPath)
		if err != nil {
			return "", err
		}
		return string(id), nil
	}

	// Generate a random ID (16 bytes hex = 32 chars)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := fmt.Sprintf("%x", b)

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(idPath, []byte(id), 0644); err != nil {
		return "", err
	}
	return id, nil
}

// DecryptStream is a helper exposed for the CLI layer — it reads encrypted
// data with the prepended nonce, decrypts, and writes to dst.
func DecryptStream(userKey []byte, src io.Reader, dst io.Writer) error {
	nonce := make([]byte, crypto.NonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}
	_, err := crypto.Decrypt(userKey, nonce, src, dst)
	return err
}
