package main
import (
	"encoding/gob"
	"fmt"
	"os"
)
type FileManifest struct {
	OriginalKey string
	TotalSize   int64
	ChunkSize   int64
	ChunkKeys   []string
}
func main() {
	f, _ := os.Open("cas_7000/7e2707dd/308b1713/d9bd7ed6/d2959190/7e2707dd308b1713d9bd7ed6d29591908f892a8e9570aa94056e619259922a27")
	var m FileManifest
	gob.NewDecoder(f).Decode(&m)
	fmt.Printf("%+v\n", m)
}
