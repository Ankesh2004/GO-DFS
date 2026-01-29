package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/p2p"
	"golang.org/x/crypto/chacha20poly1305"
)

type Payload struct {
	Key  string
	Data []byte
}

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

	// for encryption
	key []byte
}

// NewFileServer creates and initializes a FileServer configured by options.
// It constructs the local store at options.rootDir, loads or generates a persistent
// encryption key for options.ID (saving it to disk if newly generated), and returns
// a FileServer with its quit channel, peers map, and encryption key populated.
// NewFileServer panics if the key cannot be loaded or generated.
func NewFileServer(options FileServerOptions) *FileServer {
	store := NewStore(
		options.rootDir,
	)

	key, err := loadOrGenerateKey(options.ID)
	if err != nil {
		panic(fmt.Sprintf("failed to load/generate key: %v", err))
	}

	return &FileServer{
		FileServerOptions: options,
		s:                 store,
		quitChannel:       make(chan struct{}),
		peers:             make(map[string]p2p.Peer),
		key:               key,
	}
}

// loadOrGenerateKey loads a ChaCha20-Poly1305 key from "<id>.key" if it exists, otherwise it
// generates a new key, saves it to that path with permission 0600, and returns it.
// 
// The returned byte slice is the encryption key and must have length chacha20poly1305.KeySize.
// An error is returned if reading, validating, generating, or persisting the key fails.
func loadOrGenerateKey(id string) ([]byte, error) {
	keyPath := fmt.Sprintf("%s.key", id)
	// 1. Try to load
	if _, err := os.Stat(keyPath); err == nil {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("key file is corrupted (size %d)", len(key))
		}
		return key, nil
	}

	// 2. Generate new
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// 3. Save for persistence
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save key file: %w", err)
	}
	fmt.Printf("[%s] Generated and saved new encryption key to %s\n", id, keyPath)
	return key, nil
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
	n, err := s.s.WriteStreamEncrypted(s.key, msg.Key, io.LimitReader(peer, msg.Size))
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
	fileSize, r, err := s.s.ReadStreamDecrypted(s.key, msg.Key)
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
	for _, addr := range s.BooststrapNodes {
		// dial each node
		fmt.Println("Dailing node: ", addr)
		go func(addr string) {
			if err := s.Transport.Dial(addr); err != nil {
				fmt.Println("Error dialing node: ", addr, err)
				return
			}
		}(addr)
	}
}
func (s *FileServer) stream(p *Payload) error {
	peers := []io.Writer{}
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	if len(peers) == 0 {
		fmt.Printf("No peers to broadcast to (total registered: %d)\n", len(s.peers))
		return nil
	}
	mw := io.MultiWriter(peers...)
	payloadBytes, err := encodePayload(p)
	if err != nil {
		return err
	}
	rpc := p2p.RPC{
		Payload: payloadBytes,
		From:    s.Transport.Addr(),
	}
	// encode and send for SECURITY PURPOSES
	return gob.NewEncoder(mw).Encode(rpc)
}

type Message struct {
	Payload any
}
type MessageStoreFile struct {
	Key  string
	Size int64
}
type MessageGetFile struct {
	Key string
}

func (s *FileServer) broadcast(msg *Message) error {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(msg); err != nil {
		return err
	}
	for _, peer := range s.peers {
		peer.Send([]byte{p2p.IncomingMessage})
		if err := peer.Send(buf.Bytes()); err != nil {
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
		_, r, err := s.s.ReadStreamDecrypted(s.key, key)
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

		n, err := s.s.WriteStreamEncrypted(s.key, key, io.LimitReader(peer, filesize))
		if err != nil {
			fmt.Printf("Error writing file to peer %s: %v\n", peer.RemoteAddr().String(), err)
			continue
		}
		fmt.Printf("Received file [%s] of [%d] bytes over the network from peer: %s\n", key, n, peer.RemoteAddr().String())
		peer.CloseStream()
	}
	_, r, err := s.s.ReadStreamDecrypted(s.key, key)
	return r, err
}
func (s *FileServer) StoreData(key string, r io.Reader) error {
	// 1. write to local storage
	// 2. send to all known peers

	fileBuffer := new(bytes.Buffer)
	tee := io.TeeReader(r, fileBuffer) // tee reads from reader r and writes to fileBuffer too
	// because if we directly write to local then reader will become empty , so we need to store in fileBuffer
	// also so that it can be broadcasted later
	n, err := s.s.WriteStreamEncrypted(s.key, key, tee)
	if err != nil {
		return err
	}
	// 2.1 first a msg is sent
	msg := Message{
		Payload: MessageStoreFile{
			Key:  key,
			Size: n,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return err
	}

	//2.2 now we will send the actual file
	time.Sleep(5 * time.Millisecond)
	// TODO: use multiwriter

	for _, peer := range s.peers {
		peer.Send([]byte{p2p.IncomingStream})
		// creating a new reader for each peer to avoid reader exhaustion
		n, err := io.Copy(peer, bytes.NewReader(fileBuffer.Bytes()))
		if err != nil {
			return err
		}
		fmt.Printf("[%s] Sent %d bytes to peer: %s\n", s.Transport.Addr(), n, peer.RemoteAddr())
	}
	return nil

	// p := &Payload{
	// 	Key:  key,
	// 	Data: buf.Bytes(),
	// }

	// fmt.Println(buf.Bytes())

	// return s.broadcast(p)

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

func encodePayload(p *Payload) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func init() {
	gob.Register(MessageStoreFile{})
	gob.Register(MessageGetFile{})
}