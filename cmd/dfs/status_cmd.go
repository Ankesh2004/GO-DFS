package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cluster health and replication status",
	Long: `Displays peer health information and the latest replication audit results.

Example:
  dfs status`,
	Run: func(cmd *cobra.Command, args []string) {
		runStatus()
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus() {
	resp, err := http.Get(apiURL("status"))
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	var result struct {
		PeerHealth []struct {
			Addr        string `json:"addr"`
			Status      string `json:"status"`
			LastSeen    string `json:"lastSeen"`
			MissedPings int    `json:"missedPings"`
		} `json:"peerHealth"`
		Replication struct {
			Healthy         int    `json:"healthy"`
			UnderReplicated int    `json:"underReplicated"`
			OverReplicated  int    `json:"overReplicated"`
			LastAudit       string `json:"lastAudit,omitempty"`
		} `json:"replication"`
		StoredFiles int `json:"storedFiles"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("failed to parse response: %v", err)
	}

	// peer health section
	fmt.Printf("Peer Health (%d peers):\n", len(result.PeerHealth))
	if len(result.PeerHealth) == 0 {
		fmt.Println("  No peers connected.")
	} else {
		fmt.Println("─────────────────────────────────────────────────")
		for _, p := range result.PeerHealth {
			fmt.Printf("  %-25s %s (last: %s)\n", p.Addr, p.Status, p.LastSeen)
		}
		fmt.Println("─────────────────────────────────────────────────")
	}

	// replication section
	fmt.Println()
	if result.Replication.LastAudit == "" {
		fmt.Println("Replication Audit: not yet run")
	} else {
		fmt.Printf("Last Audit: %s\n", result.Replication.LastAudit)
		fmt.Printf("  Healthy chunks    : %d\n", result.Replication.Healthy)
		fmt.Printf("  Under-replicated  : %d\n", result.Replication.UnderReplicated)
		fmt.Printf("  Over-replicated   : %d\n", result.Replication.OverReplicated)
	}

	fmt.Printf("\nStored Files: %d\n", result.StoredFiles)
}
