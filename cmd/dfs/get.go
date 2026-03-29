package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var getOutput string

var getCmd = &cobra.Command{
	Use:   "get <CID>",
	Short: "Retrieve a file from the DFS network",
	Long: `Fetches a file by its CID, decrypts it, and saves it locally.
By default saves to ./myFiles/<original_name>. Use -o to override.

Example:
  dfs get a1b2c3d4e5f6...
  dfs get a1b2c3d4e5f6... -o ./downloads/myfile.pdf`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runGet(args[0])
	},
}

func init() {
	getCmd.Flags().StringVarP(&getOutput, "output", "o", "", "output filepath (default: ./myFiles/<original_name>)")
	rootCmd.AddCommand(getCmd)
}

func runGet(cid string) {
	fmt.Printf("Retrieving CID: %s...\n", cid)

	client := newCLIStreamingClient()
	resp, err := client.Get(apiURL("get/" + cid))
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	// check for error responses (JSON with error field)
	if resp.Header.Get("Content-Type") == "application/json" {
		body, _ := io.ReadAll(resp.Body)
		fatalf("retrieval failed: %s", string(body))
	}

	// figure out save path
	savePath := getOutput
	if savePath == "" {
		// use the original filename from the header
		origName := resp.Header.Get("X-Original-Name")
		if origName != "" {
			// sanitize the path to prevent directory traversal (take base name)
			origName = filepath.Base(filepath.Clean(origName))
			if origName == "." || origName == "/" || origName == "\\" {
				origName = ""
			}
		}
		if origName == "" {
			origName = cid // fallback to CID if no valid name found
		}

		destDir := "myFiles"
		if err := os.MkdirAll(destDir, 0755); err != nil {
			fatalf("could not create directory: %v", err)
		}
		savePath = filepath.Join(destDir, origName)

		// ensure the final path remains inside destDir (double defense)
		absDest, err1 := filepath.Abs(destDir)
		absSave, err2 := filepath.Abs(savePath)
		if err1 == nil && err2 == nil {
			// ensure absSave starts with absDest + separator
			prefix := absDest + string(filepath.Separator)
			if len(absSave) <= len(absDest) || absSave[:len(prefix)] != prefix {
				// validation failed, fallback to secure CID path
				savePath = filepath.Join(destDir, cid)
			}
		}
	}

	// make sure the parent directory exists
	if err := os.MkdirAll(filepath.Dir(savePath), 0755); err != nil {
		fatalf("could not create directory: %v", err)
	}

	// save the file transparently to a temporary location first
	// this prevents corrupted/partial files holding the final destination name if networking crashes
	tempPath := savePath + ".tmp"
	outFile, err := os.Create(tempPath)
	if err != nil {
		fatalf("could not create temporary output file: %v", err)
	}

	written, err := io.Copy(outFile, resp.Body)
	if err != nil {
		outFile.Close()
		os.Remove(tempPath)
		fatalf("failed to save file: %v", err)
	}

	// ensure the file is closed so windows releases its file lock for rename
	outFile.Close()

	if err := os.Rename(tempPath, savePath); err != nil {
		os.Remove(tempPath)
		fatalf("failed to finalize downloaded file: %v", err)
	}

	fmt.Println("✓ Retrieved!")
	fmt.Printf("  Saved to : %s\n", savePath)
	fmt.Printf("  Size     : %s\n", humanSize(written))
}
