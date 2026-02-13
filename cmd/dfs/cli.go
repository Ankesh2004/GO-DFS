package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ankesh2004/GO-DFS/internal/server"
)

// RetrieveAndDecrypt fetches a file by its CID, decrypts it, and saves locally.
// saveName is the filename to save as; if empty, falls back to the CID.
func RetrieveAndDecrypt(s *server.FileServer, cid string, saveName string, userKey []byte) error {
	fmt.Printf(">>> Retrieving CID: %s\n", cid)

	r, err := s.GetFileChunked(cid)
	if err != nil {
		return fmt.Errorf("failed to retrieve file: %w", err)
	}
	if closer, ok := r.(io.Closer); ok {
		defer closer.Close()
	}

	// decrypt as a stream — no need to load the whole thing into memory
	decryptedBuf := new(bytes.Buffer)
	if err := server.DecryptStream(userKey, r, decryptedBuf); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// use the provided name, or fall back to the CID
	if saveName == "" {
		saveName = cid
	}

	destDir := "myFiles"
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	destPath := filepath.Join(destDir, saveName)
	if err := os.WriteFile(destPath, decryptedBuf.Bytes(), 0644); err != nil {
		return err
	}

	fmt.Printf("✓ File retrieved, decrypted, and saved to: %s\n", destPath)
	fmt.Printf("✓ Size: %d bytes\n", decryptedBuf.Len())
	return nil
}

// commandLoop runs the interactive terminal for node interaction.
func commandLoop(s *server.FileServer, userKey []byte) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\n>>> [CLI] Interacting with the mesh network.")
	fmt.Println(">>> Type 'help' for available commands.")

	for {
		fmt.Print("\ndfs> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		parts := strings.Split(input, " ")
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "help":
			fmt.Println("Available Commands:")
			fmt.Println("  store <filename>       - Encrypt, chunk, and store a file (returns CID)")
			fmt.Println("  get <CID> [filename]   - Retrieve and decrypt a file by its CID")
			fmt.Println("  list                   - Show all files stored by this node")
			fmt.Println("  peers                  - List all currently connected peers")
			fmt.Println("  id                     - Show this node's identity and addresses")
			fmt.Println("  exit                   - Stop the node and exit")

		case "store":
			if len(args) < 1 {
				fmt.Println("Error: missing filename. Usage: store <filename>")
				continue
			}
			filePath := args[0]
			file, err := os.Open(filePath)
			if err != nil {
				fmt.Printf("Error: could not open file: %v\n", err)
				continue
			}
			originalName := filepath.Base(filePath)
			fmt.Printf("Storing '%s'...\n", originalName)
			cid, err := s.StoreDataChunked(originalName, userKey, file)
			file.Close()
			if err != nil {
				fmt.Printf("Error: store failed: %v\n", err)
			} else {
				fmt.Println("Store SUCCESS!")
				fmt.Printf("  CID: %s\n", cid)
				fmt.Println("  (use this CID to retrieve the file from any node with your key)")
			}

		case "get":
			if len(args) < 1 {
				fmt.Println("Error: missing CID. Usage: get <CID> [filename]")
				continue
			}
			cid := args[0]
			// optional: let the user override the save filename
			saveName := ""
			if len(args) >= 2 {
				saveName = args[1]
			}
			if err := RetrieveAndDecrypt(s, cid, saveName, userKey); err != nil {
				fmt.Printf("Error: retrieval failed: %v\n", err)
			}

		case "list":
			entries := s.CIDIndex.List()
			if len(entries) == 0 {
				fmt.Println("No files stored yet.")
				continue
			}
			fmt.Printf("Stored Files: %d\n", len(entries))
			fmt.Println("---")
			for _, e := range entries {
				fmt.Printf("  Name   : %s\n", e.OriginalName)
				fmt.Printf("  CID    : %s\n", e.CID)
				fmt.Printf("  Size   : %d bytes (%d chunks)\n", e.Size, e.ChunkCount)
				fmt.Printf("  Stored : %s\n", e.StoredAt)
				fmt.Println("---")
			}

		case "peers":
			peers := s.GetPeers()
			fmt.Printf("Connected Peers: %d\n", len(peers))
			for addr := range peers {
				fmt.Printf("  - %s\n", addr)
			}

		case "id":
			fmt.Printf("Node ID   : %s\n", s.ID.String())
			fmt.Printf("Advertise : %s\n", s.AdvertiseAddr)
			fmt.Printf("Listen    : %s\n", s.Transport.Addr())

		case "exit":
			fmt.Println("Stopping node...")
			s.Stop()
			return

		default:
			fmt.Printf("Unknown command: %s. Type 'help' for info.\n", cmd)
		}
	}
}
