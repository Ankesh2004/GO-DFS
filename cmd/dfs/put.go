package main

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var putCmd = &cobra.Command{
	Use:   "put <filepath>",
	Short: "Upload a file to the DFS network",
	Long: `Encrypts, chunks, and stores a file in the mesh.
Returns the CID (Content ID) that you'll need to retrieve it later.

The node must be running (dfs node start) before using this command.

Example:
  dfs put ./myfile.pdf
  dfs put ~/photos/vacation.jpg`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runPut(args[0])
	},
}

func init() {
	rootCmd.AddCommand(putCmd)
}

func runPut(filePath string) {
	// open the file
	file, err := os.Open(filePath)
	if err != nil {
		fatalf("could not open file: %v", err)
	}
	defer file.Close()

	// get file info for the name
	stat, err := file.Stat()
	if err != nil {
		fatalf("could not stat file: %v", err)
	}

	fmt.Printf("Uploading '%s' (%d bytes)...\n", stat.Name(), stat.Size())

	// build multipart request iteratively via an io.Pipe to prevent OOM on large files
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		part, err := writer.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			pw.CloseWithError(err)
			return
		}
		if err := writer.Close(); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	// POST to the control API
	req, err := http.NewRequest(http.MethodPost, apiURL("put"), pr)
	if err != nil {
		fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := newCLIStreamingClient()
	resp, err := client.Do(req)
	if err != nil {
		fatalf("failed to connect to node API at %s: %v\nIs the node running? (dfs node start)", apiAddr, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("failed to parse response: %v", err)
	}

	if errMsg, ok := result["error"]; ok {
		fatalf("store failed: %v", errMsg)
	}

	// print the result nicely
	fmt.Println("✓ Stored!")
	fmt.Printf("  CID    : %s\n", result["cid"])
	fmt.Printf("  Name   : %s\n", result["name"])
	if size, ok := result["size"].(float64); ok {
		fmt.Printf("  Size   : %s\n", humanSize(int64(size)))
	}
	if chunks, ok := result["chunkCount"].(float64); ok {
		fmt.Printf("  Chunks : %d\n", int(chunks))
	}
	fmt.Println("\n  Use this CID to retrieve the file from any node with your key.")
}

// humanSize converts bytes to a readable string.
func humanSize(bytes int64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
