package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
)

// APIServer is the localhost HTTP control API for the running node.
// CLI commands hit this to interact with the mesh without being a node themselves.
type APIServer struct {
	fileServer *FileServer
	userKey    []byte // loaded once at startup, held in memory
	keyPath    string // path to the loaded encryption key
	httpServer *http.Server
}

// StartAPI fires up the HTTP control API on the given address.
// addr should be something like ":9000" — we force-bind to 127.0.0.1
// so it's never exposed to the network. the encryption key is loaded
// from keyPath and kept in memory for put/get operations.
func (s *FileServer) StartAPI(addr string, keyPath string) (*APIServer, error) {
	userKey, err := crypto.LoadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption key from %s: %w", keyPath, err)
	}

	api := &APIServer{
		fileServer: s,
		userKey:    userKey,
		keyPath:    keyPath,
	}

	// Generate or load a secure API token for local auth
	tokenPath := filepath.Join(s.RootDir, "api_token")
	var apiToken string
	if b, err := os.ReadFile(tokenPath); err == nil {
		apiToken = strings.TrimSpace(string(b))
	} else {
		tokenBytes := make([]byte, 32)
		rand.Read(tokenBytes)
		apiToken = hex.EncodeToString(tokenBytes)
		os.WriteFile(tokenPath, []byte(apiToken), 0600)
	}

	mux := http.NewServeMux()

	// local daemon security middleware
	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Local-Auth")
			if token == "" {
				token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			if token != apiToken {
				jsonError(w, http.StatusUnauthorized, "invalid or missing control API auth token ("+tokenPath+")")
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/put", authMiddleware(api.handlePut))
	mux.HandleFunc("/api/get/", authMiddleware(api.handleGet))
	mux.HandleFunc("/api/ls", authMiddleware(api.handleList))
	mux.HandleFunc("/api/rm/", authMiddleware(api.handleDelete))
	mux.HandleFunc("/api/peers", authMiddleware(api.handlePeers))
	mux.HandleFunc("/api/status", authMiddleware(api.handleStatus))
	mux.HandleFunc("/api/id", authMiddleware(api.handleID))

	// force localhost binding - this API should NEVER be reachable from outside
	listenAddr := addr
	if !strings.Contains(listenAddr, ":") {
		listenAddr = ":" + listenAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid API address %s: %w", addr, err)
	}

	if host == "" || host == "localhost" {
		host = "127.0.0.1"
	} else {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid API host %q (must be an IP address or 'localhost')", host)
		}
		if !ip.IsLoopback() {
			return nil, fmt.Errorf("control API must be bound to a loopback address, refusing to bind to: %s", host)
		}
	}
	listenAddr = net.JoinHostPort(host, port)

	api.httpServer = &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second, // file transfers can be slow
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind API on %s: %w", listenAddr, err)
	}

	go func() {
		fmt.Printf("[API] Control API listening on http://%s\n", listenAddr)
		if err := api.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[API] HTTP server error: %v\n", err)
		}
	}()

	return api, nil
}

// jsonReply is a tiny helper to send JSON responses without repeating ourselves.
func jsonReply(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// jsonError sends a JSON error response.
func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonReply(w, status, map[string]string{"error": msg})
}

// -------- PUT --------

// handlePut accepts a multipart file upload, encrypts it, chunks it,
// stores it in the mesh, and returns the CID.
func (api *APIServer) handlePut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	// 64MB max memory for multipart parsing — bigger files stream to disk
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("invalid multipart form: %v", err))
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("missing 'file' field: %v", err))
		return
	}
	defer file.Close()

	originalName := header.Filename
	if originalName == "" {
		originalName = "unnamed"
	}

	cid, err := api.fileServer.StoreDataChunked(originalName, api.userKey, file)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("store failed: %v", err))
		return
	}

	// grab the entry we just stored for size + chunk info
	entries := api.fileServer.CIDIndex.List()
	var size int64
	var chunkCount int
	for _, e := range entries {
		if e.CID == cid {
			size = e.Size
			chunkCount = e.ChunkCount
			break
		}
	}

	jsonReply(w, http.StatusOK, map[string]any{
		"cid":        cid,
		"name":       originalName,
		"size":       size,
		"chunkCount": chunkCount,
	})
}

// -------- GET --------

// handleGet retrieves a file by CID, decrypts it, and streams back the raw bytes.
// the client can save it to whatever filename it wants.

type responseStreamer struct {
	w     http.ResponseWriter
	wrote bool
}

func (rs *responseStreamer) Write(p []byte) (int, error) {
	if !rs.wrote {
		rs.wrote = true
		rs.w.WriteHeader(http.StatusOK)
	}
	return rs.w.Write(p)
}

func (api *APIServer) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	// extract CID from URL: /api/get/<CID>
	cid := strings.TrimPrefix(r.URL.Path, "/api/get/")
	if cid == "" {
		jsonError(w, http.StatusBadRequest, "missing CID in URL")
		return
	}

	reader, err := api.fileServer.GetFileChunked(cid)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("file not found: %v", err))
		return
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}

	// figure out the original filename from the CID index
	filename := cid
	entries := api.fileServer.CIDIndex.List()
	for _, e := range entries {
		if e.CID == cid {
			filename = e.OriginalName
			break
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("X-Original-Name", filename)

	// stream decryption directly to the response
	streamer := &responseStreamer{w: w}
	if err := DecryptStream(api.userKey, reader, streamer); err != nil {
		if !streamer.wrote {
			// clean up headers since we're pivoting to a JSON error
			w.Header().Del("Content-Type")
			w.Header().Del("Content-Disposition")
			w.Header().Del("X-Original-Name")
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("decryption failed: %v", err))
		} else {
			// HTTP status and partial body already sent; gracefully abort
			fmt.Printf("[API] Streaming decryption error for CID %s: %v\n", cid, err)
		}
	}
}

// -------- LS --------

// handleList returns all files stored by this node as a JSON array.
func (api *APIServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	entries := api.fileServer.CIDIndex.List()

	jsonReply(w, http.StatusOK, map[string]any{
		"files": entries,
		"count": len(entries),
	})
}

// -------- RM --------

// handleDelete tombstones a file and broadcasts deletion to the network.
func (api *APIServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "use DELETE")
		return
	}

	cid := strings.TrimPrefix(r.URL.Path, "/api/rm/")
	if cid == "" {
		jsonError(w, http.StatusBadRequest, "missing CID in URL")
		return
	}

	if err := api.fileServer.DeleteFile(cid); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("delete failed: %v", err))
		return
	}

	jsonReply(w, http.StatusOK, map[string]any{
		"ok":  true,
		"cid": cid,
	})
}

// -------- PEERS --------

// handlePeers returns the list of currently connected peers.
func (api *APIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	peers := api.fileServer.GetPeers()
	addrs := make([]string, 0, len(peers))
	for addr := range peers {
		addrs = append(addrs, addr)
	}

	jsonReply(w, http.StatusOK, map[string]any{
		"count": len(addrs),
		"peers": addrs,
	})
}

// -------- STATUS --------

// handleStatus returns peer health and replication audit results.
func (api *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	// peer health
	healthMap := api.fileServer.GetPeerHealthMap()
	peerHealth := make([]map[string]any, 0, len(healthMap))
	for addr, h := range healthMap {
		status := "HEALTHY"
		if h.MissedPings > 0 {
			status = fmt.Sprintf("WARNING (%d missed)", h.MissedPings)
		}
		peerHealth = append(peerHealth, map[string]any{
			"addr":        addr,
			"status":      status,
			"lastSeen":    h.LastSeen.Format(time.RFC3339),
			"missedPings": h.MissedPings,
		})
	}

	// replication
	healthy, under, over, lastAudit := api.fileServer.GetReplicationStatus()
	replication := map[string]any{
		"healthy":         healthy,
		"underReplicated": under,
		"overReplicated":  over,
	}
	if !lastAudit.IsZero() {
		replication["lastAudit"] = lastAudit.Format(time.RFC3339)
	}

	// file count
	entries := api.fileServer.CIDIndex.List()

	jsonReply(w, http.StatusOK, map[string]any{
		"peerHealth":  peerHealth,
		"replication": replication,
		"storedFiles": len(entries),
	})
}

// -------- ID --------

// handleID returns the node's identity info.
func (api *APIServer) handleID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	// figure out if the exact key path we loaded still exists
	keyExists := false
	if _, err := os.Stat(api.keyPath); err == nil {
		keyExists = true
	}

	jsonReply(w, http.StatusOK, map[string]any{
		"nodeID":        api.fileServer.ID.String(),
		"advertiseAddr": api.fileServer.AdvertiseAddr,
		"listenAddr":    api.fileServer.Transport.Addr(),
		"dataDir":       api.fileServer.RootDir,
		"relayOnly":     api.fileServer.RelayOnly,
		"keyLoaded":     keyExists,
	})
}
