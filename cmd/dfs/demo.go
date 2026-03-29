package main

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ankesh2004/GO-DFS/internal/server"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run the built-in two-node local demo",
	Long: `Spins up two local nodes on :7000 and :7001, connects them,
and drops into an interactive REPL for testing.

Example:
  dfs demo`,
	Run: func(cmd *cobra.Command, args []string) {
		runDemo()
	},
}

func init() {
	rootCmd.AddCommand(demoCmd)
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

	userKey, err := loadKeyFromPath("myKey.key")
	if err != nil {
		log.Fatal(err)
	}

	// interactive REPL on node 1
	commandLoop(s1, userKey)
}
