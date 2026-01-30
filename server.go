package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

type FileServerOptions struct {
	ID      string
	rootDir string
	// ?? is get cas func req ?
	Transport       p2p.Transport
	BooststrapNodes []string
}

type FileServer struct {
	FileServerOptions

	s           *Store
	quitChannel chan struct{}

	peers     map[string]p2p.Peer
	peersLock sync.Mutex
}

func NewFileServer(options FileServerOptions) *FileServer {
	store := NewStore(
		options.rootDir,
	)

	return &FileServer{
		FileServerOptions: options,
		s:                 store,
		quitChannel:       make(chan struct{}),
		peers:             make(map[string]p2p.Peer),
	}
}

func (s *FileServer) handleMessage(from string, msg *Message) error {
	switch msg.Payload.(type) {
	case MessageStoreFile:
		return s.handleMessageStoreFile(from, msg.Payload.(MessageStoreFile))
	case MessageGetFile:
		return s.handleMessageGetFile(from, msg.Payload.(MessageGetFile))
	default:
		return fmt.Errorf("unknown message type: %T", msg.Payload)
	}
}
func (s *FileServer) handleMessageStoreFile(from string, msg MessageStoreFile) error {
	fmt.Println("Handling storefile msg...")
	peer, ok := s.peers[from]
	if !ok {
		fmt.Printf("Peer not found in peer map of [%s]\n", s.Transport.Addr())
		return nil
	}
	fmt.Printf("%+v\n", msg)
	// Zero Trust: Store the RAW encrypted blob received from user (via peer). Do not re-encrypt.
	n, err := s.s.WriteStream(msg.Key, io.LimitReader(peer, msg.Size))
	if err != nil {
		return err
	}
	fmt.Println("Wrote ", n, " bytes to file")
	peer.CloseStream()
	return nil
}

func (s *FileServer) handleMessageGetFile(from string, msg MessageGetFile) error {
	if !s.s.Has(msg.Key) {
		return fmt.Errorf("Need to serve %s to peer %s, but file not found in local disk of [%s]", msg.Key, from, s.Transport.Addr())
	}
	fmt.Printf("[%s] serving file over network to [%s]\n", s.Transport.Addr(), from)

	// Zero Trust: Read RAW encrypted blob to send to peer. Do not attempt to decrypt.
	// Note: ReadStream returns (size, reader, error)
	fileSize, r, err := s.s.ReadStream(msg.Key)
	if err != nil {
		return err
	}
	defer r.Close()

	peer, ok := s.peers[from]
	if !ok {
		fmt.Printf("Peer not found in peer map of [%s]\n", s.Transport.Addr())
		return nil
	}
	// first , send the stream flag
	peer.Send([]byte{p2p.IncomingStream})
	// secondly, send the filesize
	binary.Write(peer, binary.LittleEndian, fileSize)
	// finally, we send the file
	n, err := io.Copy(peer, r)
	if err != nil {
		return err
	}
	fmt.Printf("[%s] Wrote %d bytes over the network to peer: %s\n", s.Transport.Addr(), n, from)
	return nil
}

func (s *FileServer) bootstrapNetwork() {
	if len(s.BooststrapNodes) == 0 {
		return
	}
	for _, addr := range s.BooststrapNodes {
		if len(addr) == 0 {
			continue
		}
		fmt.Println("Dailing node: ", addr)
		go func(addr string) {
			if err := s.Transport.Dial(addr); err != nil {
				fmt.Println("Error dialing node: ", addr, err)
				return
			}
		}(addr)
	}
}

func (s *FileServer) broadcast(msg *Message) error {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(msg); err != nil {
		return err
	}
	msgBytes := buf.Bytes()
	msgLen := uint32(len(msgBytes))

	for _, peer := range s.peers {
		peer.Send([]byte{p2p.IncomingMessage})
		if err := binary.Write(peer, binary.LittleEndian, msgLen); err != nil {
			return err
		}
		if err := peer.Send(msgBytes); err != nil {
			fmt.Printf("Error sending message to peer %s: %v\n", peer.LocalAddr().String(), err)
			continue
		}
	}
	return nil
}
func (s *FileServer) GetFile(key string) (io.Reader, error) {
	// check in local storage first
	if s.s.Has(key) {
		fmt.Printf("[%s] Serving file [%s] from local disk of [%s]", s.Transport.Addr(), key, s.Transport.Addr())
		// When retrieving a file that was stored with user encryption, we should read it
		// as a raw stream. The node does not hold any keys to decrypt it.
		_, r, err := s.s.ReadStream(key)
		return r, err
	}
	// fetch from the peers in the network
	fmt.Printf("File [%s] not found in local storage of [%s], fetching from network...\n", key, s.Transport.Addr())
	msg := Message{
		Payload: MessageGetFile{
			Key: key,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return nil, err
	}
	time.Sleep(500 * time.Millisecond)
	for _, peer := range s.peers {
		// first get the filesize , so that we don't keep hanging here
		var filesize int64
		binary.Read(peer, binary.LittleEndian, &filesize)

		// When receiving a file that was stored with user encryption, we should write it
		// as a raw stream. The node does not hold any keys to decrypt or re-encrypt it.
		n, err := s.s.WriteStream(key, io.LimitReader(peer, filesize))
		if err != nil {
			fmt.Printf("Error writing file to peer %s: %v\n", peer.RemoteAddr().String(), err)
			continue
		}
		fmt.Printf("Received file [%s] of [%d] bytes over the network from peer: %s\n", key, n, peer.RemoteAddr().String())
		peer.CloseStream()
	}
	_, r, err := s.s.ReadStream(key)
	return r, err
}

// CountingWriter tracks bytes written
type CountingWriter struct {
	w     io.Writer
	count int64
}

func (cw *CountingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.count += int64(n)
	return n, err
}

func (s *FileServer) StoreData(key string, userEncryptionKey []byte, r io.Reader) error {
	// Generate nonce for the user layer
	userNonce := make([]byte, 12)
	if _, err := rand.Read(userNonce); err != nil {
		return err
	}

	// Create pipe for streaming encryption
	pr, pw := io.Pipe()

	// Encrypt in background goroutine
	encryptErr := make(chan error, 1)
	go func() {
		defer pw.Close()

		// Write nonce first
		if _, err := pw.Write(userNonce); err != nil {
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}

		// Stream encrypt directly to pipe
		_, err := encrypt(userEncryptionKey, userNonce, r, pw)
		if err != nil {
			err = fmt.Errorf("user encryption failed: %w", err)
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}
		encryptErr <- nil
	}()

	// Use the global CountingWriter type
	counter := &CountingWriter{}

	// Create pipe for storage
	storagePR, storagePW := io.Pipe()
	counter.w = storagePW

	// Writijg to storage in background
	storageErr := make(chan error, 1)
	go func() {
		defer storagePR.Close() // Ensure reader closes to unblock writer
		_, err := s.s.WriteStream(key, storagePR)
		storageErr <- err
	}()

	// Copy from encryption pipe through counter to storage
	_, copyErr := io.Copy(counter, pr)

	// IMPORTANT: Close reader to unblock writer goroutine if io.Copy finishes early
	pr.Close()

	if copyErr != nil {
		storagePW.CloseWithError(copyErr)
		pw.CloseWithError(copyErr)
	} else {
		storagePW.Close()
	}

	if err := <-encryptErr; err != nil {
		return err
	}

	if copyErr != nil {
		return fmt.Errorf("streaming to storage failed: %w", copyErr)
	}

	if err := <-storageErr; err != nil {
		return fmt.Errorf("local storage failed: %w", err)
	}

	actualSize := counter.count

	// Broadcast metadata to Peers
	msg := Message{
		Payload: MessageStoreFile{
			Key:  key,
			Size: actualSize,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return err
	}

	// No sleep needed anymore due to framed message protocol

	// Read from local storage and multicast to all peers (no RAM buffer! but increase one disk read ;())
	if len(s.peers) > 0 {
		_, dataReader, err := s.s.ReadStream(key)
		if err != nil {
			return fmt.Errorf("failed to read back for broadcast: %w", err)
		}
		defer dataReader.Close()

		// Prepare all peers with stream indicator
		peerWriters := make([]io.Writer, 0, len(s.peers))
		for _, peer := range s.peers {
			peer.Send([]byte{p2p.IncomingStream})
			peerWriters = append(peerWriters, peer)
		}

		// Multiwrite to all peers simultaneously
		if len(peerWriters) > 0 {
			peerMW := io.MultiWriter(peerWriters...)
			if _, err := io.Copy(peerMW, dataReader); err != nil {
				return fmt.Errorf("failed to broadcast to peers: %w", err)
			}
		}
	}

	return nil
}
func (s *FileServer) GetPeers() map[string]p2p.Peer {
	return s.peers
}
func (s *FileServer) Start() error {
	if err := s.Transport.ListenAndAccept(); err != nil {
		return err
	}
	if len(s.BooststrapNodes) > 0 {
		s.bootstrapNetwork()
	}
	s.loop()
	return nil
}

func (s *FileServer) Stop() error {
	select {
	case <-s.quitChannel:
		return nil // already closed
	default:
		close(s.quitChannel)
	}
	return nil
}

func (s *FileServer) OnPeer(P p2p.Peer) error {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	s.peers[P.RemoteAddr().String()] = P
	fmt.Printf("[%s] New peer joined in: %s\n", s.Transport.Addr(), P.RemoteAddr().String())
	return nil
}

func (s *FileServer) loop() {
	defer func() {
		fmt.Println("FileServer loop stopped")
		if err := s.Transport.Close(); err != nil {
			fmt.Println("Error closing transport: ", err)
		}
	}()
	for {
		select {
		case rpc := <-s.Transport.Consume():
			var msg Message

			if err := gob.NewDecoder(bytes.NewReader(rpc.Payload)).Decode(&msg); err != nil {
				fmt.Println("Error decoding payload: ", err)
				continue
			}
			if err := s.handleMessage(rpc.From, &msg); err != nil {
				fmt.Println("Error handling message: ", err)
				continue
			}
			// fmt.Println("Got a msg: ", string(msg.Payload.(MessageStoreFile).Key))
			// peer, ok := s.peers[rpc.From]
			// if !ok {
			// 	fmt.Println("Peer not found in peer map: ", rpc.From)
			// 	continue
			// }
			// buff := make([]byte, 1000)

			// peer.Read(buff)
			// // panic("HHH")
			// fmt.Printf("Got big file: %s\n", string(buff))
			// fmt.Println("Got the data from broadcast")

		case <-s.quitChannel:
			return
		}
	}
}
