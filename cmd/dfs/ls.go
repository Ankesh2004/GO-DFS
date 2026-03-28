package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var lsJSON bool

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List all files stored on this node",
	Long: `Shows every file you've uploaded through this node, with CID, name, size, and chunk count.

Example:
  dfs ls
  dfs ls --json`,
	Run: func(cmd *cobra.Command, args []string) {
		runLs()
	},
}

func init() {
	lsCmd.Flags().BoolVar(&lsJSON, "json", false, "output as raw JSON (for scripting)")
	rootCmd.AddCommand(lsCmd)
}

// lsEntry matches the CIDEntry structure from the API response
type lsEntry struct {
	CID          string `json:"cid"`
	OriginalName string `json:"original_name"`
	Size         int64  `json:"size"`
	ChunkCount   int    `json:"chunk_count"`
	StoredAt     string `json:"stored_at"`
}

func runLs() {
	client := newCLIHTTPClient()
	resp, err := client.Get(apiURL("ls"))
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	var result struct {
		Files []lsEntry `json:"files"`
		Count int       `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("failed to parse response: %v", err)
	}

	// raw JSON mode — just dump it
	if lsJSON {
		out, _ := json.MarshalIndent(result.Files, "", "  ")
		fmt.Println(string(out))
		return
	}

	if result.Count == 0 {
		fmt.Println("No files stored yet.")
		return
	}

	fmt.Printf("Stored Files: %d\n", result.Count)
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("  %-20s %-18s %10s %8s  %s\n", "NAME", "CID", "SIZE", "CHUNKS", "STORED")
	fmt.Println("─────────────────────────────────────────────────────────────────")

	for _, f := range result.Files {
		// truncate CID for display
		cidShort := f.CID
		if len(cidShort) > 16 {
			cidShort = cidShort[:16] + "…"
		}
		name := f.OriginalName
		if len(name) > 18 {
			name = name[:15] + "..."
		}
		fmt.Printf("  %-20s %-18s %10s %8d  %s\n",
			name, cidShort, humanSize(f.Size), f.ChunkCount, f.StoredAt)
	}
	fmt.Println("─────────────────────────────────────────────────────────────────")
}
