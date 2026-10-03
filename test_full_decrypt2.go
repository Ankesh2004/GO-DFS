package main
import (
	"fmt"
	"io"
	"os"
	"bytes"
	"github.com/Ankesh2004/GO-DFS/internal/server"
)
func main() {
	f, _ := os.Open("cas_7000/9b9636d2/7dc23302/cc4ab127/8a6fd0ef/9b9636d27dc23302cc4ab1278a6fd0ef2ae096449c0c80d993186724e5cbeee4")
	
	keyFile, _ := os.Open("cas_7000/myKey.key")
	userKey := make([]byte, 32)
	io.ReadFull(keyFile, userKey)

	var out bytes.Buffer
	err := server.DecryptStream(userKey, f, &out)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Decrypted size: %d\n", out.Len())
	}
}
