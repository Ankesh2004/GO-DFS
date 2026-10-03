package main
import (
	"fmt"
	"io"
	"os"
	"bytes"
	"github.com/Ankesh2004/GO-DFS/internal/server"
)
func main() {
	f, _ := os.Open("cas_7000/0c0d800c/c170de55/cf966445/9b83e03f/0c0d800cc170de55cf9664459b83e03f0dd05632b0cfb6868e37e32493fb1671")
	
	keyFile, _ := os.Open("cas_7000/myKey.key")
	userKey := make([]byte, 32)
	io.ReadFull(keyFile, userKey)

	var out bytes.Buffer
	err := server.DecryptStream(userKey, f, &out)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Decrypted: %s\n", out.String())
	}
}
