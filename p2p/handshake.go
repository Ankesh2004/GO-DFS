package p2p

// TODO:
// run just after establishing connection
// TODO: handle credentials verification here
type Handshake func(peer Peer) error

// sample does no operation - just passes the request
func SampleHandshake(peer Peer) error {
	return nil
}
