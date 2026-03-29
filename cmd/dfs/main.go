package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// the API address that all client commands (put, get, ls, etc.) talk to.
// set via --api flag on root, inherited by all subcommands.
var apiAddr string

// the control API token (X-Local-Auth) to prevent unauthorized access.
var apiToken string

var rootCmd = &cobra.Command{
	Use:   "dfs",
	Short: "GO-DFS — Peer-to-peer distributed file system",
	Long: `A peer-to-peer distributed file system built from scratch in Go.
No IPFS, no libp2p — every byte is ours.

Start a node:    dfs node start --port :7000
Store a file:    dfs put myfile.txt
Retrieve a file: dfs get <CID>
List files:      dfs ls
Delete a file:   dfs rm <CID>

The node must be running (via 'dfs node start') before using put/get/ls/rm.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&apiAddr, "api", "localhost:9000",
		"address of the node's control API (used by all client commands)")
	rootCmd.PersistentFlags().StringVar(&apiToken, "api-token", "",
		"X-Local-Auth token for the control API (auto-loaded from local cas_* dirs if not set)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
