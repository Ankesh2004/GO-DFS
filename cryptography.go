package main

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// FOR TESTING : WE ARE CURRENTLY HAVING KEY ON SERVER , LATER DO AN KEY MGMT SERVICE OR SOMETHING (TODO)

const (
	nonceSize    = 12
	maxFrameSize = 32 * 1024 // 32KB chunks
)

// encrypt uses ChaCha20-Poly1305 to encrypt data from src to dst.
// It uses a chunked format: [4-byte length][ciphertext + tag].
// encrypt reads plaintext from src and writes ChaCha20-Poly1305–encrypted frames to dst.
// 
// It copies the provided nonce, encrypts the input in up to 32KB chunks, and for each chunk
// writes a 4-byte little-endian length followed by the ciphertext. The nonce is incremented
// once per chunk so each frame is encrypted with a distinct nonce. Returns the total number
// of bytes written to dst (including 4-byte frame headers) and any error encountered.
func encrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer) (int64, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, err
	}

	// Make a copy of nonce so we can increment it without affecting caller
	currentNonce := make([]byte, nonceSize)
	copy(currentNonce, nonce)

	buf := make([]byte, maxFrameSize)
	var totalWritten int64 = 0

	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Encrypt chunk
			ciphertext := aead.Seal(nil, currentNonce, buf[:n], nil)

			// Increment nonce
			incrementNonce(currentNonce)

			// Frame: [4-byte len][ciphertext]
			frameLen := uint32(len(ciphertext))
			// Write length
			if err := binary.Write(dst, binary.LittleEndian, frameLen); err != nil {
				return totalWritten, err
			}
			// Write ciphertext
			nw, err := dst.Write(ciphertext)
			if err != nil {
				return totalWritten, err
			}
			totalWritten += int64(4 + nw)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalWritten, err
		}
	}
	return totalWritten, nil
}

// decrypt reads a stream of framed ChaCha20-Poly1305 ciphertexts from src,
// decrypts each frame using key and nonce, and writes the concatenated
// plaintext to dst.
// 
// Frames are encoded as a 4-byte little-endian length followed by that many
// bytes of ciphertext. The provided nonce is copied and incremented once per
// frame; if a frame fails to decrypt or an I/O error occurs, the function
// returns the number of plaintext bytes successfully written and the error.
// It returns (totalWritten, nil) when the input reaches EOF normally.
func decrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer) (int64, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, err
	}

	currentNonce := make([]byte, nonceSize)
	copy(currentNonce, nonce)

	var totalWritten int64 = 0

	for {
		// Read Frame Len
		var frameLen uint32
		if err := binary.Read(src, binary.LittleEndian, &frameLen); err != nil {
			if err == io.EOF {
				break
			}
			return totalWritten, err
		}

		// Read Ciphertext
		ciphertext := make([]byte, frameLen)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return totalWritten, err
		}

		// Decrypt
		plaintext, err := aead.Open(nil, currentNonce, ciphertext, nil)
		if err != nil {
			return totalWritten, err
		}

		incrementNonce(currentNonce)

		nw, err := dst.Write(plaintext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += int64(nw)
	}
	return totalWritten, nil
}

// incrementNonce increments nonce by one, treating the slice as a little-endian unsigned integer.
// It increments bytes starting at index 0 and stops when a byte does not wrap to zero.
// If all bytes wrap, the nonce becomes zero (full wraparound).
func incrementNonce(nonce []byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}