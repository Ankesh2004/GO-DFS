package p2p

import (
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
)

const MaxMessageSize = 1024 * 1024 // 1MB maximum for metadata messages

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
	peekBuf := make([]byte, 1)
	if _, err := r.Read(peekBuf); err != nil {
		return err
	}

	// Case 1: Stream. Just set flag and let the consumer handle the rest.
	if peekBuf[0] == IncomingStream {
		rpc.isStream = true
		return nil
	}

	// Case 2: Message. We expect a 4-byte length prefix.
	if peekBuf[0] != IncomingMessage {
		return fmt.Errorf("invalid message type: %d", peekBuf[0])
	}

	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return fmt.Errorf("failed to read message length: %w", err)
	}

	// Security: Validate message length to prevent memory exhaustion attacks (DoS)
	if length == 0 || length > MaxMessageSize {
		return fmt.Errorf("invalid message length: %d (must be between 1 and %d bytes)", length, MaxMessageSize)
	}

	rpc.Payload = make([]byte, int(length))
	if _, err := io.ReadFull(r, rpc.Payload); err != nil {
		return fmt.Errorf("failed to read message payload (%d bytes): %w", length, err)
	}

	return nil
}

/*
Protocol Synchronization & Precise Framing Explanation:

It handles the transition reliably because we moved from "Guesstimating" to "Exact Byte Counting."
Here is the mechanical breakdown of why it works now:

1. The Problem: "Over-reading"
Previously, the SampleDecoder worked like this:
  1. Read 1 byte (Message Type).
  2. If it was a message, it called r.Read(buffer) into a 1024-byte chunk.
  3. The Race: If the network was fast, the sender might have sent the Message AND the start
     of the Stream simultaneously. The Decoder would accidentally "swallow" the Stream
     start byte while trying to read the Message.

The time.Sleep(5ms) was a hack to try and ensure the Decoder finished its work and
returned control to the main loop before the next batch of stream bytes arrived.

2. The Solution: Framed Precision
Now, the protocol looks like this on the wire:
[TYPE (1 byte)] [LENGTH (4 bytes)] [PAYLOAD (N bytes)]

The code now does this:
  // 1. Read EXACTLY 4 bytes for length
  binary.Read(r, binary.LittleEndian, &length)
  // 2. Read EXACTLY 'length' bytes
  rpc.Payload = make([]byte, length)
  io.ReadFull(r, rpc.Payload) // This is the key!

io.ReadFull is guaranteed to stop reading the very microsecond it hits the length count.
It doesn't matter how fast the sender is or how much data is sitting in the OS buffer—the
Decoder will never touch a single bit of data that belongs to the next packet.

3. The Handover
Because the Decoder is now perfectly precise, the handleConnection loop in p2p/tcp.go
works in a clean sequence:
  1. Iteration 1: Decode reads exactly N bytes of the Message. It returns immediately.
  2. Processing: The Server handles the message (e.g., preparing to receive a file).
  3. Iteration 2: The loop calls Decode again.
  4. Instant Capture: Since the previous read stopped exactly at the end of the message,
     the very next byte waiting in the buffer is the IncomingStream (0x02) byte.

By using Framing, we synchronized the byte-stream logically rather than trying to
synchronize it with a clock. This means even if you have a 10Gbps connection and zero
latency, the bytes will always align perfectly.
*/
