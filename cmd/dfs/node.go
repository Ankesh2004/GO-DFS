package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

var (
	nodePort      string
	nodeBootstrap string
	nodeAdvertise string
	nodeDataDir   string
	nodeID        string
	nodeRelay     bool
	nodeAPIPort   string
)

// nodeCmd is the parent for `dfs node <subcommand>`
var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Node management commands",
}

// nodeStartCmd is `dfs node start` — fires up the daemon
var nodeStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a GO-DFS node (daemon mode)",
	Long: `Starts the P2P node and the HTTP control API.
The node stays alive in the foreground, handling mesh traffic + accepting CLI commands via the API.

Example:
  dfs node start --port :7000
  dfs node start --port :7001 --bootstrap 127.0.0.1:7000`,
	Run: func(cmd *cobra.Command, args []string) {
		runNodeDaemon()
	},
}

func init() {
	nodeStartCmd.Flags().StringVar(&nodePort, "port", ":7000", "P2P listen port")
	nodeStartCmd.Flags().StringVar(&nodeBootstrap, "bootstrap", "", "comma-separated bootstrap node addresses")
	nodeStartCmd.Flags().StringVar(&nodeAdvertise, "advertise", "", "address to advertise to peers")
	nodeStartCmd.Flags().StringVar(&nodeDataDir, "data", "", "root directory for CAS storage (default: ./cas_<port>)")
	nodeStartCmd.Flags().StringVar(&nodeID, "id", "", "override node identity string")
	nodeStartCmd.Flags().BoolVar(&nodeRelay, "relay", false, "relay-only mode (no local storage)")
	nodeStartCmd.Flags().StringVar(&nodeAPIPort, "api-port", ":9000", "HTTP control API port (localhost only)")

	nodeCmd.AddCommand(nodeStartCmd)
	rootCmd.AddCommand(nodeCmd)
}

func runNodeDaemon() {
	fmt.Println("========================================")
	fmt.Println("  GO-DFS Node — P2P File System Daemon")
	fmt.Println("========================================")

	// 1. resolve advertise address
	advertise := nodeAdvertise
	if advertise == "" {
		resolved, err := dht.ResolveAdvertiseAddr(nodePort, "")
		if err != nil {
			fmt.Printf("Warning: auto-detect failed: %v. Using %s\n", err, nodePort)
			advertise = nodePort
		} else {
			advertise = resolved
		}
	}

	// 2. setup data directory — default to ./cas_<port_number>
	dataDir := nodeDataDir
	if dataDir == "" {
		parts := strings.Split(nodePort, ":")
		suffix := parts[len(parts)-1]
		dataDir = "./cas_" + suffix
	}

	// 3. persistent node identity
	idStr := nodeID
	if idStr == "" {
		var err error
		idStr, err = server.LoadOrGenerateNodeID(dataDir)
		if err != nil {
			fmt.Printf("Warning: node identity failure: %v. Falling back to addr.\n", err)
			idStr = advertise
		}
	}

	// 4. transport + server
	var bootstrapNodes []string
	if nodeBootstrap != "" {
		bootstrapNodes = strings.Split(nodeBootstrap, ",")
	}

	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: nodePort,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	s := server.NewFileServer(server.FileServerOptions{
		ID:             idStr,
		RootDir:        dataDir,
		AdvertiseAddr:  advertise,
		Transport:      transport,
		BootstrapNodes: bootstrapNodes,
		RelayOnly:      nodeRelay,
	})
	transport.OnPeer = s.OnPeer

	fmt.Printf("Node ID    : %s\n", s.ID.String()[:16])
	fmt.Printf("Listen     : %s\n", nodePort)
	fmt.Printf("Advertise  : %s\n", advertise)
	fmt.Printf("Data Dir   : %s\n", dataDir)
	fmt.Printf("Relay Mode : %v\n", nodeRelay)
	fmt.Printf("API Port   : %s\n", nodeAPIPort)
	fmt.Println("========================================")

	// 5. load encryption key and start the HTTP control API
	keyPath := filepath.Join(dataDir, "myKey.key")
	_, err := s.StartAPI(nodeAPIPort, keyPath)
	if err != nil {
		log.Fatalf("Fatal: failed to start control API: %v", err)
	}

	// 6. start the P2P node
	go func() {
		if err := s.Start(); err != nil {
			log.Fatalf("Critical: node crash: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	// 7. drop into the interactive REPL so existing users feel at home.
	//    the REPL and the HTTP API run side by side — you can use either.
	keyBytes, err := loadKeyFromPath(keyPath)
	if err != nil {
		log.Fatalf("Fatal: user key failure: %v", err)
	}
	commandLoop(s, keyBytes)
}
