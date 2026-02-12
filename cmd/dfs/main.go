package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

func loadOrGenerateUserKey(filename string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := os.Stat(filename); err == nil {
		key, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Loaded user encryption key from %s\n", filename)
	} else {
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filename, key, 0600); err != nil {
			return nil, err
		}
		fmt.Printf("Generated and saved new user encryption key to %s\n", filename)
	}
	return key, nil
}

func loadOrGenerateNodeID(dataDir string) (string, error) {
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

func RetrieveAndDecrypt(s *server.FileServer, key string, userKey []byte) error {
	fmt.Printf(">>> Retrieving file: %s\n", key)

	r, err := s.GetFile(key)
	if err != nil {
		return fmt.Errorf("failed to retrieve file: %w", err)
	}
	if closer, ok := r.(io.Closer); ok {
		defer closer.Close()
	}

	encryptedBlob, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read blob: %w", err)
	}
	fmt.Printf("Received encrypted blob size: %d bytes\n", len(encryptedBlob))

	if len(encryptedBlob) < 12 {
		return fmt.Errorf("invalid blob size")
	}
	nonce := encryptedBlob[:12]
	ciphertext := encryptedBlob[12:]

	decryptedBuf := new(bytes.Buffer)
	if _, err := crypto.Decrypt(userKey, nonce, bytes.NewReader(ciphertext), decryptedBuf); err != nil {
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
	fmt.Printf("✓ Content: %s\n", decryptedBuf.String())
	return nil
}

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
			fmt.Println("  store <filename>  - Encrypt and store a local file in the network")
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
			fmt.Printf("Storing '%s' as key '%s'...\n", filePath, key)
			if err := s.StoreData(key, userKey, file); err != nil {
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

func main() {
	// CLI flags for standalone node operation
	port := flag.String("port", ":7000", "Listen port for P2P traffic (e.g. :7000)")
	bootstrap := flag.String("bootstrap", "", "Comma-separated list of bootstrap node addresses (e.g. 1.2.3.4:7000,5.6.7.8:7000)")
	advertise := flag.String("advertise", "", "Address to advertise to other peers (e.g. 203.0.113.5:7000). Auto-detected if empty.")
	dataDir := flag.String("data", "", "Root directory for CAS storage. Defaults to ./cas_<port>")
	nodeID := flag.String("id", "", "Node identity string. Defaults to listen address.")
	relay := flag.Bool("relay", false, "If true, this node will act ONLY as a relay and won't store data")
	demo := flag.Bool("demo", false, "Run the built-in two-node demo (original behavior)")
	flag.Parse()

	if *demo {
		runDemo()
		return
	}
	runNode(*port, *bootstrap, *advertise, *dataDir, *nodeID, *relay)
}

func runNode(port, bootstrap, advertise, dataDir, nodeID string, relay bool) {
	fmt.Println("========================================")
	fmt.Println("  GO-DFS Node — Global P2P File System")
	fmt.Println("========================================")

	// Figure out our public-facing address
	if advertise == "" {
		resolved, err := dht.ResolveAdvertiseAddr(port, "")
		if err != nil {
			fmt.Printf("Warning: could not auto-detect advertise address: %v\n", err)
			advertise = port // worst case, use listen port
		} else {
			advertise = resolved
		}
	}

	if dataDir == "" {
		// Extract port number for directory name
		parts := strings.Split(port, ":")
		suffix := parts[len(parts)-1]
		dataDir = "./cas_" + suffix
	}

	if nodeID == "" {
		var err error
		nodeID, err = loadOrGenerateNodeID(dataDir)
		if err != nil {
			fmt.Printf("Warning: failed to load/generate persistent node ID: %v. Falling back to advertise addr.\n", err)
			nodeID = advertise
		} else {
			fmt.Printf("Persistent Node ID: %s (loaded from %s)\n", nodeID, dataDir)
		}
	}

	// Parse bootstrap nodes
	var bootstrapNodes []string
	if bootstrap != "" {
		bootstrapNodes = strings.Split(bootstrap, ",")
	}

	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: port,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	opts := server.FileServerOptions{
		ID:             nodeID,
		RootDir:        dataDir,
		AdvertiseAddr:  advertise,
		Transport:      transport,
		BootstrapNodes: bootstrapNodes,
		RelayOnly:      relay,
	}

	s := server.NewFileServer(opts)
	transport.OnPeer = s.OnPeer

	fmt.Printf("Node ID    : %s\n", s.ID.String()[:16])
	fmt.Printf("Listen     : %s\n", port)
	fmt.Printf("Advertise  : %s\n", advertise)
	fmt.Printf("Data Dir   : %s\n", dataDir)
	fmt.Printf("Bootstrap  : %v\n", bootstrapNodes)
	fmt.Printf("Relay Only : %v\n", relay)
	fmt.Println("========================================")

	// In runNode, we or generate a global user encryption key for this machine.
	// In a real app, this would be tied to a user login.
	userKey, err := loadOrGenerateUserKey("myKey.key")
	if err != nil {
		log.Fatalf("Failed to initialize user key: %v", err)
	}

	// Start the server in a goroutine so we can run the CLI loop
	go func() {
		if err := s.Start(); err != nil {
			log.Fatalf("Node failed: %v", err)
		}
	}()

	// Wait a bit for the bootstrap process to kick in
	time.Sleep(1 * time.Second)

	// Enter the interactive CLI loop
	commandLoop(s, userKey)
}

// runDemo keeps the original two-node local demo for quick testing
func runDemo() {
	fmt.Println("GO-DFS — Two-Node Local Demo")
	fmt.Println("========================================")

	t1 := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: ":7000",
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	s1 := server.NewFileServer(server.FileServerOptions{
		ID:            "node1",
		RootDir:       "./cas7000",
		AdvertiseAddr: "127.0.0.1:7000",
		Transport:     t1,
	})
	t1.OnPeer = s1.OnPeer

	t2 := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: ":7001",
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})
	s2 := server.NewFileServer(server.FileServerOptions{
		ID:             "node2",
		RootDir:        "./cas7001",
		AdvertiseAddr:  "127.0.0.1:7001",
		Transport:      t2,
		BootstrapNodes: []string{"127.0.0.1:7000"},
	})
	t2.OnPeer = s2.OnPeer

	go func() {
		if err := s1.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	time.Sleep(500 * time.Millisecond)
	go func() {
		if err := s2.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	time.Sleep(2 * time.Second)

	fmt.Printf("s1 peers: %d, s2 peers: %d\n", len(s1.GetPeers()), len(s2.GetPeers()))

	userKey, err := loadOrGenerateUserKey("myKey.key")
	if err != nil {
		log.Fatal(err)
	}

	messageKey := "secret_notes.txt"
	secureMessage := "This is a confidential note retrieved from the mesh network."

	fmt.Printf("\n>>> [S1] Storing file: %s\n", messageKey)
	if err := s1.StoreData(messageKey, userKey, bytes.NewReader([]byte(secureMessage))); err != nil {
		log.Fatal(err)
	}
	fmt.Println(">>> Store success.")

	time.Sleep(2 * time.Second)

	fmt.Println("\n>>> [S2] Retrieving file...")
	if err := RetrieveAndDecrypt(s2, messageKey, userKey); err != nil {
		log.Fatalf("Retrieval failed: %v", err)
	}

	fmt.Println("\n========================================")
	fmt.Println("Demo complete! Check 'myFiles/secret_notes.txt'")
	fmt.Println("========================================")

	select {}
}
