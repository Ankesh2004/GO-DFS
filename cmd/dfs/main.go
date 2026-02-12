package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

func main() {
	// CLI flags for standalone node operation
	port := flag.String("port", ":7000", "Listen port for P2P traffic (e.g. :7000)")
	bootstrap := flag.String("bootstrap", "", "Comma-separated list of bootstrap node addresses")
	advertise := flag.String("advertise", "", "Address to advertise (e.g. 203.0.113.5:7000)")
	dataDir := flag.String("data", "", "Root directory for CAS storage")
	nodeID := flag.String("id", "", "Node identity string (optional)")
	relay := flag.Bool("relay", false, "Enable RelayOnly mode (no local storage)")
	demo := flag.Bool("demo", false, "Run the built-in two-node local demo")
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

	// 1. Resolve Advertise Address
	if advertise == "" {
		resolved, err := dht.ResolveAdvertiseAddr(port, "")
		if err != nil {
			fmt.Printf("Warning: auto-detect failed: %v. Using %s\n", err, port)
			advertise = port
		} else {
			advertise = resolved
		}
	}

	// 2. Setup Data Directory
	if dataDir == "" {
		parts := strings.Split(port, ":")
		suffix := parts[len(parts)-1]
		dataDir = "./cas_" + suffix
	}

	// 3. Persistent Node Identity
	if nodeID == "" {
		var err error
		nodeID, err = server.LoadOrGenerateNodeID(dataDir)
		if err != nil {
			fmt.Printf("Warning: node identity failure: %v. Falling back to addr.\n", err)
			nodeID = advertise
		}
	}

	// 4. Transport and Server setup
	var bootstrapNodes []string
	if bootstrap != "" {
		bootstrapNodes = strings.Split(bootstrap, ",")
	}

	transport := p2p.NewTCPTransport(p2p.TCPTransportOptions{
		ListenPort: port,
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
	})

	s := server.NewFileServer(server.FileServerOptions{
		ID:             nodeID,
		RootDir:        dataDir,
		AdvertiseAddr:  advertise,
		Transport:      transport,
		BootstrapNodes: bootstrapNodes,
		RelayOnly:      relay,
	})
	transport.OnPeer = s.OnPeer

	fmt.Printf("Node ID    : %s\n", s.ID.String()[:16])
	fmt.Printf("Listen     : %s\n", port)
	fmt.Printf("Advertise  : %s\n", advertise)
	fmt.Printf("Relay Mode : %v\n", relay)
	fmt.Println("========================================")

	// 5. Initialize Keys and Start
	userKey, err := crypto.LoadOrGenerateKey("myKey.key")
	if err != nil {
		log.Fatalf("Fatal: user key failure: %v", err)
	}

	go func() {
		if err := s.Start(); err != nil {
			log.Fatalf("Critical: node crash: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)
	commandLoop(s, userKey)
}

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

	go s1.Start()
	time.Sleep(500 * time.Millisecond)
	go s2.Start()
	time.Sleep(2 * time.Second)

	fmt.Printf("s1 peers: %d, s2 peers: %d\n", len(s1.GetPeers()), len(s2.GetPeers()))

	userKey, err := crypto.LoadOrGenerateKey("myKey.key")
	if err != nil {
		log.Fatal(err)
	}

	// Just trigger the CLI loop on Node 1 for interaction
	commandLoop(s1, userKey)
}
