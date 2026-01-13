//go:build windows
// +build windows

package p2p

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// setSocketReuseAddr sets SO_REUSEADDR on the socket to allow port reuse
// This is the Windows-specific implementation
func setSocketReuseAddr(network, address string, c syscall.RawConn) error {
	var setSockOptErr error
	err := c.Control(func(fd uintptr) {
		// On Windows, we use SO_REUSEADDR
		setSockOptErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return setSockOptErr
}
