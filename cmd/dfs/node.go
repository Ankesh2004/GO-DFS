package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

var (
	nodePort        string
	nodeBootstrap   string
	nodeAdvertise   string
	nodeDataDir     string
	nodeID          string
	nodeRelay       bool
	nodeAPIPort     string
	nodeInteractive bool

	// RL placement flags
	nodeStorageTier string
	nodeLatency     float64
	nodeCost        float64
	nodeBandwidth   float64
	nodeRLSidecar   string
	nodeRLEnabled   bool
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
	nodeStartCmd.Flags().BoolVarP(&nodeInteractive, "interactive", "i", false, "start the interactive REPL alongside the node")

	// RL placement flags -- set these to simulate different hardware tiers
	nodeStartCmd.Flags().StringVar(&nodeStorageTier, "tier", "ssd", "storage tier: nvme, ssd, or hdd")
	nodeStartCmd.Flags().Float64Var(&nodeLatency, "latency", 5.0, "simulated I/O latency in ms")
	nodeStartCmd.Flags().Float64Var(&nodeCost, "cost", 0.01, "simulated storage cost in $/GB/hour")
	nodeStartCmd.Flags().Float64Var(&nodeBandwidth, "bandwidth", 100.0, "network bandwidth in Mbps")
	nodeStartCmd.Flags().StringVar(&nodeRLSidecar, "rl-sidecar", "http://127.0.0.1:5100", "URL of the Python RL placement sidecar")
	nodeStartCmd.Flags().BoolVar(&nodeRLEnabled, "rl-enabled", false, "enable RL-based placement optimization")

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

	// 4b. parse the storage tier from the CLI flag
	var tier server.StorageTier
	switch strings.ToLower(nodeStorageTier) {
	case "nvme":
		tier = server.TierNVMe
	case "hdd":
		tier = server.TierHDD
	default:
		tier = server.TierSSD
	}

	// figure out the RL sidecar URL -- empty string disables it
	rlURL := ""
	if nodeRLEnabled {
		rlURL = nodeRLSidecar
	}

	s := server.NewFileServer(server.FileServerOptions{
		ID:             idStr,
		RootDir:        dataDir,
		AdvertiseAddr:  advertise,
		Transport:      transport,
		BootstrapNodes: bootstrapNodes,
		RelayOnly:      nodeRelay,
		StorageProfile: server.StorageProfile{
			Tier:          tier,
			LatencyMs:     nodeLatency,
			CostPerGBHour: nodeCost,
			BandwidthMbps: nodeBandwidth,
		},
		RLSidecarURL: rlURL,
	})
	transport.OnPeer = s.OnPeer
	// display first 16 only for clean display
	displayID := s.ID.String()
	if len(displayID) > 16 {
		displayID = displayID[:16]
	}
	fmt.Printf("Node ID    : %s\n", displayID)
	fmt.Printf("Listen     : %s\n", nodePort)
	fmt.Printf("Advertise  : %s\n", advertise)
	fmt.Printf("Data Dir   : %s\n", dataDir)
	fmt.Printf("Relay Mode : %v\n", nodeRelay)
	fmt.Printf("API Port   : %s\n", nodeAPIPort)
	fmt.Printf("Tier       : %s (latency=%.1fms, cost=$%.4f/GB/hr)\n", nodeStorageTier, nodeLatency, nodeCost)
	fmt.Printf("RL Enabled : %v\n", nodeRLEnabled)
	if nodeRLEnabled {
		fmt.Printf("RL Sidecar : %s\n", nodeRLSidecar)
	}
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

	// 7. run headlessly or with REPL
	if nodeInteractive {
		keyBytes, err := loadKeyFromPath(keyPath)
		if err != nil {
			log.Fatalf("Fatal: user key failure: %v", err)
		}
		commandLoop(s, keyBytes)
	} else {
		// block until OS signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\nReceived termination signal. Shutting down daemon...")
	}
}
