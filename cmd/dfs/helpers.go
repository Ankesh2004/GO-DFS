package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// resolveAPIToken attempts to grab the control API token from flags or local cas_* dirs.
// it allows thin CLI commands to work magically without passing --api-token manually,
// as long as they are run in the same directory where a GO-DFS node is operating.
func resolveAPIToken() string {
	if apiToken != "" {
		return apiToken
	}
	matches, _ := filepath.Glob("cas_*/api_token")
	if len(matches) == 1 {
		b, err := os.ReadFile(matches[0])
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// authTransport is an http.RoundTripper that automatically sets the local security token.
type authTransport struct {
	rt    http.RoundTripper
	token string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		req.Header.Set("X-Local-Auth", t.token)
	}
	return t.rt.RoundTrip(req)
}

// newCLIHTTPClient returns a timeout-bound HTTP client (matching the 5s DHT discovery timeout)
// used by the CLI subcommands (id, peers, get, etc.) to prevent hanging if the daemon is unresponsive.
func newCLIHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &authTransport{rt: http.DefaultTransport, token: resolveAPIToken()},
	}
}

// newCLIStreamingClient returns an HTTP client specifically tuned for large file transfers (get, put).
// It has NO absolute timeout blocking the connection, preventing 5s crashes during multi-GB file uploads/downloads.
func newCLIStreamingClient() *http.Client {
	return &http.Client{
		Transport: &authTransport{rt: http.DefaultTransport, token: resolveAPIToken()},
	}
}
