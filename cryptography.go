package main

import (
	"crypto/cipher"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
)

// FOR TESTING : WE ARE CURRENTLY HAVING KEY ON SERVER , LATER DO AN KEY MGMT SERVICE OR SOMETHING (TODO)

// we will use chacha20 for encryption , not CTR as  in CTR mode we don't have authentication
func encrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer) (int64, error) {
	// key and nonce ---> server generated
	// create a chacha20 stream
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return 0, err
	}
	return copyStream(stream, src, dst)
}

func decrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer) (int64, error) {
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return 0, err
	}
	return copyStream(stream, src, dst)
}

func copyStream(stream cipher.Stream, src io.Reader, dst io.Writer) (int64, error) {
	var wb int64 = 0
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		// Process data BEFORE checking error (Read can return data AND EOF)
		if n > 0 {
			stream.XORKeyStream(buf[:n], buf[:n])
			nw, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return wb, fmt.Errorf("failed to write to stream: %w", writeErr)
			}
			fmt.Printf("COPIED :: %s\n", string(buf[:n]))
			wb += int64(nw)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return wb, fmt.Errorf("failed to read from stream: %w", err)
		}
	}
	return wb, nil
}
