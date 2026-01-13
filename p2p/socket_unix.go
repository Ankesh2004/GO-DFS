//go:build !windows

package p2p

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setSocketReuseAddr sets SO_REUSEADDR on the socket to allow port reuse
// This is the Unix/Linux/macOS implementation
func setSocketReuseAddr(network, address string, c syscall.RawConn) error {
	var setSockOptErr error
	err := c.Control(func(fd uintptr) {
		// Set SO_REUSEADDR to allow port reuse
		setSockOptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if setSockOptErr != nil {
			return
		}
		// Also set SO_REUSEPORT on Unix systems that support it
		setSockOptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return setSockOptErr
}
