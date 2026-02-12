package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/internal/storage"
	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
	"github.com/Ankesh2004/GO-DFS/pkg/dht"
	"github.com/Ankesh2004/GO-DFS/pkg/p2p"
)

type FileServerOptions struct {
	ID             string
	RootDir        string
	Transport      p2p.Transport
	BootstrapNodes []string
}

type FileServer struct {
	FileServerOptions

	ID          dht.ID
	DHT         *dht.Kademlia
	Store       *storage.Store
	quitChannel chan struct{}

	peers     map[string]p2p.Peer
	peersLock sync.Mutex
}

func NewFileServer(options FileServerOptions) *FileServer {
	store := storage.NewStore(options.RootDir)
	id := dht.NewID(options.ID)

	return &FileServer{
		FileServerOptions: options,
		ID:                id,
		DHT:               dht.NewKademlia(id),
		Store:             store,
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
	n, err := s.Store.WriteStream(msg.Key, io.LimitReader(peer, msg.Size))
	if err != nil {
		return err
	}
	fmt.Println("Wrote ", n, " bytes to file")
	peer.CloseStream()
	return nil
}

func (s *FileServer) handleMessageGetFile(from string, msg MessageGetFile) error {
	if !s.Store.Has(msg.Key) {
		return fmt.Errorf("need to serve %s to peer %s, but file not found in local disk of [%s]", msg.Key, from, s.Transport.Addr())
	}
	fmt.Printf("[%s] serving file over network to [%s]\n", s.Transport.Addr(), from)

	// Zero Trust: Read RAW encrypted blob to send to peer. Do not attempt to decrypt.
	fileSize, r, err := s.Store.ReadStream(msg.Key)
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
	if len(s.BootstrapNodes) == 0 {
		return
	}
	for _, addr := range s.BootstrapNodes {
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

	// If it's a store message, we only send to the closest nodes in our DHT
	// This prevents network saturation
	var targetPeers []p2p.Peer

	if storeMsg, ok := msg.Payload.(MessageStoreFile); ok {
		targetID := dht.NewID(storeMsg.Key)
		closest := s.DHT.NearestNodes(targetID, dht.K)

		s.peersLock.Lock()
		for _, node := range closest {
			if p, ok := s.peers[node.Addr]; ok {
				targetPeers = append(targetPeers, p)
			}
		}
		s.peersLock.Unlock()

		// If we don't have enough specific peers yet, fall back to all known peers
		if len(targetPeers) == 0 {
			s.peersLock.Lock()
			for _, p := range s.peers {
				targetPeers = append(targetPeers, p)
			}
			s.peersLock.Unlock()
		}
	} else {
		// For other messages (e.g. discovery or search), broadcast to all known peers
		s.peersLock.Lock()
		for _, p := range s.peers {
			targetPeers = append(targetPeers, p)
		}
		s.peersLock.Unlock()
	}

	for _, peer := range targetPeers {
		peer.Send([]byte{p2p.IncomingMessage})
		if err := binary.Write(peer, binary.LittleEndian, msgLen); err != nil {
			return err
		}
		if err := peer.Send(msgBytes); err != nil {
			fmt.Printf("Error sending message to peer %s: %v\n", peer.RemoteAddr().String(), err)
			continue
		}
	}
	return nil
}

func (s *FileServer) GetFile(key string) (io.Reader, error) {
	// check in local storage first
	if s.Store.Has(key) {
		fmt.Printf("[%s] Serving file [%s] from local disk\n", s.Transport.Addr(), key)
		_, r, err := s.Store.ReadStream(key)
		return r, err
	}
	// fetch from the peers in the network
	fmt.Printf("File [%s] not found in local storage, fetching from network...\n", key)
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
		var filesize int64
		binary.Read(peer, binary.LittleEndian, &filesize)

		n, err := s.Store.WriteStream(key, io.LimitReader(peer, filesize))
		if err != nil {
			fmt.Printf("Error writing file from peer %s: %v\n", peer.RemoteAddr().String(), err)
			continue
		}
		fmt.Printf("Received file [%s] of [%d] bytes from peer: %s\n", key, n, peer.RemoteAddr().String())
		peer.CloseStream()
	}
	_, r, err := s.Store.ReadStream(key)
	return r, err
}

// CountingWriter tracks bytes written
type CountingWriter struct {
	W     io.Writer
	Count int64
}

func (cw *CountingWriter) Write(p []byte) (int, error) {
	n, err := cw.W.Write(p)
	cw.Count += int64(n)
	return n, err
}

func (s *FileServer) StoreData(key string, userEncryptionKey []byte, r io.Reader) error {
	// Generate nonce
	userNonce := make([]byte, crypto.NonceSize)
	if _, err := rand.Read(userNonce); err != nil {
		return err
	}

	pr, pw := io.Pipe()

	encryptErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		if _, err := pw.Write(userNonce); err != nil {
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}
		_, err := crypto.Encrypt(userEncryptionKey, userNonce, r, pw)
		if err != nil {
			pw.CloseWithError(err)
			encryptErr <- err
			return
		}
		encryptErr <- nil
	}()

	counter := &CountingWriter{}
	storagePR, storagePW := io.Pipe()
	counter.W = storagePW

	storageErr := make(chan error, 1)
	go func() {
		defer storagePR.Close()
		_, err := s.Store.WriteStream(key, storagePR)
		storageErr <- err
	}()

	_, copyErr := io.Copy(counter, pr)
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

	actualSize := counter.Count

	msg := Message{
		Payload: MessageStoreFile{
			Key:  key,
			Size: actualSize,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return err
	}

	if len(s.peers) > 0 {
		_, dataReader, err := s.Store.ReadStream(key)
		if err != nil {
			return fmt.Errorf("failed to read back for broadcast: %w", err)
		}
		defer dataReader.Close()

		peerWriters := make([]io.Writer, 0, len(s.peers))
		for _, peer := range s.peers {
			peer.Send([]byte{p2p.IncomingStream})
			peerWriters = append(peerWriters, peer)
		}

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
	if len(s.BootstrapNodes) > 0 {
		s.bootstrapNetwork()
	}
	s.loop()
	return nil
}

func (s *FileServer) Stop() error {
	select {
	case <-s.quitChannel:
		return nil
	default:
		close(s.quitChannel)
	}
	return nil
}

func (s *FileServer) OnPeer(P p2p.Peer) error {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()

	peerAddr := P.RemoteAddr().String()
	s.peers[peerAddr] = P

	// Add to DHT Routing Table
	// For now we use the hash of the address as the ID since we don't exchange IDs yet
	peerID := dht.NewID(peerAddr)
	s.DHT.Update(peerID, peerAddr)

	fmt.Printf("[%s] New peer joined: %s (ID: %s)\n", s.Transport.Addr(), peerAddr, peerID.String()[:8])
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
		case <-s.quitChannel:
			return
		}
	}
}
