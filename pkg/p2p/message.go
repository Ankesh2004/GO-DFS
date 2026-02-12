package p2p

const IncomingMessage = 0x1
const IncomingStream = 0x2

// type Payload struct {
// 	Key  string
// 	Data []byte
// }

// Holds data of any msg sent between any 2 clietns
type RPC struct {
	From     string // Who is sending the message?
	Payload  []byte //data
	isStream bool
}
