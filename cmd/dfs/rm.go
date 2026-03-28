package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var rmCmd = &cobra.Command{
	Use:   "rm <CID>",
	Short: "Delete a file from the DFS network",
	Long: `Tombstones all chunks + manifest for the given CID and broadcasts
the deletion to the entire network. Peers will delete their copies.

Example:
  dfs rm a1b2c3d4e5f6...`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runRm(args[0])
	},
}

func init() {
	rootCmd.AddCommand(rmCmd)
}

func runRm(cid string) {
	fmt.Printf("Deleting CID: %s...\n", cid)

	// build a DELETE request
	req, err := http.NewRequest(http.MethodDelete, apiURL("rm/"+cid), nil)
	if err != nil {
		fatalf("failed to build request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("failed to parse response: %v", err)
	}

	if errMsg, ok := result["error"]; ok {
		fatalf("delete failed: %v", errMsg)
	}

	fmt.Println("✓ Deleted!")
	fmt.Println("  Tombstones broadcast to the network.")
	fmt.Println("  Peers will delete their copies within the GC window.")
}
