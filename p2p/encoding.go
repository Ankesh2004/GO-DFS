package p2p

import (
	"encoding/gob"
	"fmt"
	"io"
)

type Decoder interface {
	Decode(io.Reader, *RPC) error
}

// GOBDecoder implements Decoder interface
type GOBDecoder struct {
}

// using by value receiver -- as multiple peers needs different decoder
func (d GOBDecoder) Decode(r io.Reader, rpc *RPC) error {
	return gob.NewDecoder(r).Decode(rpc) // decode data from reader into v
}

type SampleDecoder struct {
}

func (d SampleDecoder) Decode(r io.Reader, rpc *RPC) error {
	buffer := make([]byte, 1024)
	n, err := r.Read(buffer)

	if err != nil {
		fmt.Println("Failed to decode")
		return err
	}
	rpc.Payload = buffer[:n]
	return nil
}
