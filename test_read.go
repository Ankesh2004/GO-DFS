package main
import (
	"fmt"
	"os"
)
func main() {
	f, _ := os.Open("cas_7000/0c0d800c/c170de55/cf966445/9b83e03f/0c0d800cc170de55cf9664459b83e03f0dd05632b0cfb6868e37e32493fb1671")
	buf := make([]byte, 32)
	n, _ := f.Read(buf)
	fmt.Printf("Read %d bytes: %x\n", n, buf)
}
