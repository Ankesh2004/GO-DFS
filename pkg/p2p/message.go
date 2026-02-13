package p2p

const IncomingMessage = 0x1
const IncomingStream = 0x2
const IncomingRelayStream = 0x3 // relay node pipes raw bytes between two peers

// RelayStreamMeta carries the header info that comes with a relay stream.
// The relay node reads this first, then just io.Copy's the rest to the target.
type RelayStreamMeta struct {
	TargetAddr string // who should ultimately receive this data
	OriginAddr string // who started the transfer
	Key        string // file/chunk identifier so the receiver knows what it's getting
	TotalSize  int64  // how many bytes will follow after the header
}

// Holds data of any msg sent between any 2 clients
type RPC struct {
	From      string           // Who is sending the message?
	Payload   []byte           // data
	IsStream  bool             // true when the peer sent IncomingStream
	IsRelay   bool             // true when the peer sent IncomingRelayStream
	RelayMeta *RelayStreamMeta // only set when IsRelay == true
}
