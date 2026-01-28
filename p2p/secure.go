package p2p

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Secure Peer (AEAD encrypted wrapper)

// SecurePeer wraps a net.Conn with ChaCha20-Poly1305 AEAD encryption
// It handles all the framing, encryption, and buffering for secure communication
type SecurePeer struct {
	net.Conn             // underlying connection (raw TCP)
	enc      cipher.AEAD // cipher for encrypting outgoing data
	dec      cipher.AEAD // cipher for decrypting incoming data
	encNonce []byte      // 12-byte nonce for writes, incremented after each frame
	decNonce []byte      // 12-byte nonce for reads, incremented after each frame
	leftover []byte      // leftover decrypted data from partial reads
	writeMu  sync.Mutex  // guards Write for concurrent access
	readMu   sync.Mutex  // guards Read for concurrent access
}

// we will write : [Length (4 bytes)] + [Ciphertext] OVER THE WIRE
const (
	// nonceSize is 12 bytes for ChaCha20-Poly1305
	nonceSize = 12
	// lengthPrefix is 4 bytes for frame length
	lengthPrefix = 4
	// maxFrameSize caps how big a single encrypted frame can be (16KB plaintext max)
	maxFrameSize = 16 * 1024
)

// incrementNonce bumps the nonce by 1 in little-endian order
// this ensures each frame uses a unique nonce (critical for AEAD security, else Replay attack can happen )
func incrementNonce(nonce []byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break // no carry, we're done
		}
	}
}

// Write encrypts data and sends it over the wire with length-prefix framing
// Format: [4-byte length of ciphertext][ciphertext with auth tag]
func (s *SecurePeer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// break large writes into chunks (maxFrameSize plaintext per frame)
	totalWritten := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrameSize {
			chunk = p[:maxFrameSize]
		}
		p = p[len(chunk):]

		// encrypt: ciphertext = plaintext + 16-byte poly1305 tag
		ciphertext := s.enc.Seal(nil, s.encNonce, chunk, nil)
		incrementNonce(s.encNonce)

		// frame it: [length][ciphertext]
		frameLen := uint32(len(ciphertext))
		if err := binary.Write(s.Conn, binary.BigEndian, frameLen); err != nil {
			return totalWritten, fmt.Errorf("failed to write frame length: %w", err)
		}
		if _, err := s.Conn.Write(ciphertext); err != nil {
			return totalWritten, fmt.Errorf("failed to write ciphertext: %w", err)
		}
		totalWritten += len(chunk)
	}
	return totalWritten, nil
}

// Read decrypts and returns data from the wire
// Handles partial reads by buffering leftover plaintext
func (s *SecurePeer) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// first, drain any leftover data from previous reads
	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}

	// read the 4-byte length prefix
	var frameLen uint32
	if err := binary.Read(s.Conn, binary.BigEndian, &frameLen); err != nil {
		if err == io.EOF {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("failed to read frame length: %w", err)
	}

	// sanity check: don't allocate crazy amounts of memory
	if frameLen > maxFrameSize+uint32(s.dec.Overhead()) {
		s.Conn.Close()
		return 0, errors.New("frame too large, possible attack")
	}

	// read the entire ciphertext frame
	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(s.Conn, ciphertext); err != nil {
		return 0, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// decrypt and verify the auth tag
	plaintext, err := s.dec.Open(nil, s.decNonce, ciphertext, nil)
	if err != nil {
		// auth failed = tampered data, close connection immediately --> MITM attack
		s.Conn.Close()
		return 0, fmt.Errorf("decryption failed (tamper detected): %w", err)
	}
	incrementNonce(s.decNonce)

	// copy what we can into the caller's buffer
	n := copy(p, plaintext)
	if n < len(plaintext) {
		// save the rest for next Read call
		s.leftover = plaintext[n:]
	}
	return n, nil
}

// ================== Key Exchange and Handshake ==========================

// SecureHandshake performs X25519 key exchange and sets up AEAD encryption
// This replaces the raw connection in TCPPeer with an encrypted SecurePeer
func SecureHandshake(peer Peer) error {
	tcpPeer, ok := peer.(*TCPPeer)
	if !ok {
		return fmt.Errorf("SecureHandshake: expected *TCPPeer, got %T", peer)
	}

	// generate our ephemeral X25519 keypair
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to compute public key: %w", err)
	}

	// exchange public keys with the peer
	// whoever dialed (outbound) sends first, acceptor (inbound) receives first
	// this prevents deadlock where both sides wait to receive
	var peerPubKey []byte
	if tcpPeer.isOutbound {
		// we dialed, so send our key first
		if _, err := tcpPeer.Conn.Write(pubKey); err != nil {
			return fmt.Errorf("failed to send public key: %w", err)
		}
		peerPubKey = make([]byte, 32)
		if _, err := io.ReadFull(tcpPeer.Conn, peerPubKey); err != nil {
			return fmt.Errorf("failed to receive peer public key: %w", err)
		}
	} else {
		// we accepted, so receive first
		peerPubKey = make([]byte, 32)
		if _, err := io.ReadFull(tcpPeer.Conn, peerPubKey); err != nil {
			return fmt.Errorf("failed to receive peer public key: %w", err)
		}
		if _, err := tcpPeer.Conn.Write(pubKey); err != nil {
			return fmt.Errorf("failed to send public key: %w", err)
		}
	}

	// compute shared secret via ECDH
	sharedSecret, err := curve25519.X25519(privKey[:], peerPubKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// derive separate keys for read and write using HKDF
	// this is important: we need different keys for each direction
	// to prevent reflection attacks where someone replays our own messages
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("go-dfs-secure-transport"))

	// 32 bytes for write key + 32 bytes for read key = 64 bytes total
	keyMaterial := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, keyMaterial); err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	// the outbound side uses first 32 bytes for writing, second 32 for reading
	// the inbound side uses first 32 bytes for reading, second 32 for writing
	// this ensures: outbound.writeKey == inbound.readKey and vice versa
	var writeKey, readKey []byte
	if tcpPeer.isOutbound {
		writeKey = keyMaterial[:32]
		readKey = keyMaterial[32:]
	} else {
		readKey = keyMaterial[:32]
		writeKey = keyMaterial[32:]
	}

	// create the AEAD ciphers
	encCipher, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return fmt.Errorf("failed to create encryption cipher: %w", err)
	}
	decCipher, err := chacha20poly1305.New(readKey)
	if err != nil {
		return fmt.Errorf("failed to create decryption cipher: %w", err)
	}

	// build the SecurePeer wrapper
	securePeer := &SecurePeer{
		Conn:     tcpPeer.Conn,
		enc:      encCipher,
		dec:      decCipher,
		encNonce: make([]byte, nonceSize), // starts at zero
		decNonce: make([]byte, nonceSize), // starts at zero
		leftover: nil,
	}

	// swap the underlying connection!
	// now all reads/writes on tcpPeer go through encryption
	tcpPeer.Conn = securePeer

	return nil
}
