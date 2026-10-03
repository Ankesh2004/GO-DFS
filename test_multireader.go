package main
import (
	"fmt"
	"io"
	"os"
	"encoding/binary"
)
type multiReadCloser struct {
	io.Reader
	closers []io.Closer
}
func main() {
	f, _ := os.Open("cas_7000/0c0d800c/c170de55/cf966445/9b83e03f/0c0d800cc170de55cf9664459b83e03f0dd05632b0cfb6868e37e32493fb1671")
	
	mrc := &multiReadCloser{
		Reader: io.MultiReader(f),
		closers: []io.Closer{f},
	}

	nonce := make([]byte, 24)
	io.ReadFull(mrc, nonce)
	fmt.Printf("Nonce: %x\n", nonce)
	
	var frameLen uint32
	binary.Read(mrc, binary.LittleEndian, &frameLen)
	fmt.Printf("FrameLen: %d (%x)\n", frameLen, frameLen)
}
