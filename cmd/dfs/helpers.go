package main

import (
	"fmt"
	"os"

	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
)

// loadKeyFromPath loads an encryption key from a file, or generates one if missing.
// used by both the node daemon and the demo mode.
func loadKeyFromPath(keyPath string) ([]byte, error) {
	return crypto.LoadOrGenerateKey(keyPath)
}

// apiURL builds the full URL for a control API endpoint.
// e.g. apiURL("put") → "http://localhost:9000/api/put"
func apiURL(endpoint string) string {
	return fmt.Sprintf("http://%s/api/%s", apiAddr, endpoint)
}

// fatalf prints an error and exits with code 1.
// keeps the cli commands clean — no need for log.Fatal everywhere.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
