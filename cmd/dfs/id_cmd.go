package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var idCmd = &cobra.Command{
	Use:   "id",
	Short: "Show this node's identity and addresses",
	Long: `Displays the node ID, advertise address, listen address, and data directory.

Example:
  dfs id`,
	Run: func(cmd *cobra.Command, args []string) {
		runID()
	},
}

func init() {
	rootCmd.AddCommand(idCmd)
}

func runID() {
	client := newCLIHTTPClient()
	resp, err := client.Get(apiURL("id"))
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errEnv struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errEnv); err == nil && errEnv.Error != "" {
			fatalf("API error from %s: %s", apiURL("id"), errEnv.Error)
		}
		fatalf("API error from %s: status %d", apiURL("id"), resp.StatusCode)
	}

	var result struct {
		NodeID        string `json:"nodeID"`
		AdvertiseAddr string `json:"advertiseAddr"`
		ListenAddr    string `json:"listenAddr"`
		DataDir       string `json:"dataDir"`
		RelayOnly     bool   `json:"relayOnly"`
		KeyLoaded     bool   `json:"keyLoaded"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("failed to parse response: %v", err)
	}

	fmt.Println("Node Identity:")
	fmt.Printf("  Node ID    : %s\n", result.NodeID)
	fmt.Printf("  Advertise  : %s\n", result.AdvertiseAddr)
	fmt.Printf("  Listen     : %s\n", result.ListenAddr)
	fmt.Printf("  Data Dir   : %s\n", result.DataDir)
	fmt.Printf("  Relay Only : %v\n", result.RelayOnly)
	fmt.Printf("  Key Loaded : %v\n", result.KeyLoaded)
}
