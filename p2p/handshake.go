package p2p

import "net"

// TODO:
// run just after establishing connection
// TODO: handle credentials verification here
func (opt *TCPTransportOptions) Handshake(conn net.Conn) bool {
	return true
}
