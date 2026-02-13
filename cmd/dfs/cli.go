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

// RetrieveAndDecrypt fetches a file from the network, decrypts it, and saves locally.
func RetrieveAndDecrypt(s *server.FileServer, key string, userKey []byte) error {
	fmt.Printf(">>> Retrieving file: %s\n", key)

	r, err := s.GetFileChunked(key)
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

	destDir := "myFiles"
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	destPath := filepath.Join(destDir, key)
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
			fmt.Println("  store <filename>  - Encrypt, chunk, and store a file in the network")
			fmt.Println("  get <key>        - Retrieve and decrypt a file from the network")
			fmt.Println("  peers            - List all currently connected peers")
			fmt.Println("  id               - Show this node's identity and addresses")
			fmt.Println("  exit             - Stop the node and exit")

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
			key := filepath.Base(filePath)
			fmt.Printf("Storing '%s' as key '%s' (chunked)...\n", filePath, key)
			if err := s.StoreDataChunked(key, userKey, file); err != nil {
				fmt.Printf("Error: store failed: %v\n", err)
			} else {
				fmt.Println("Store SUCCESS!")
			}
			file.Close()

		case "get":
			if len(args) < 1 {
				fmt.Println("Error: missing key. Usage: get <key>")
				continue
			}
			key := args[0]
			if err := RetrieveAndDecrypt(s, key, userKey); err != nil {
				fmt.Printf("Error: retrieval failed: %v\n", err)
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
