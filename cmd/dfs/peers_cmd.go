package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all connected peers",
	Long: `Shows every peer currently connected to this node in the P2P mesh.

Example:
  dfs peers`,
	Run: func(cmd *cobra.Command, args []string) {
		runPeers()
	},
}

func init() {
	rootCmd.AddCommand(peersCmd)
}

func runPeers() {
	resp, err := http.Get(apiURL("peers"))
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	var result struct {
		Count int      `json:"count"`
		Peers []string `json:"peers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("failed to parse response: %v", err)
	}

	fmt.Printf("Connected Peers: %d\n", result.Count)
	if result.Count == 0 {
		fmt.Println("  No peers connected.")
		return
	}

	for i, addr := range result.Peers {
		fmt.Printf("  %d. %s\n", i+1, addr)
	}
}
