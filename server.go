package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

type Payload struct {
	Key  string
	Data []byte
}

type FileServerOptions struct {
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
		fmt.Println("Peer not found in peer map: ", from)
		return nil
	}
	fmt.Printf("%+v\n", msg)
	n, err := s.s.WriteStream(msg.Key, io.LimitReader(peer, msg.Size))
	if err != nil {
		return err
	}
	fmt.Println("Wrote ", n, " bytes to file")
	peer.(*p2p.TCPPeer).Wg.Done()
	return nil
}

func (s *FileServer) handleMessageGetFile(from string, msg MessageGetFile) error {
	if !s.s.Has(msg.Key) {
		return fmt.Errorf("Need to server %s to peer %s, but file not found in local disk", msg.Key, from)
	}
	r, err := s.s.ReadStream(msg.Key)
	if err != nil {
		return err
	}
	peer, ok := s.peers[from]
	if !ok {
		fmt.Println("Peer not found in peer map: ", from)
		return nil
	}
	n, err := io.Copy(peer, r)
	if err != nil {
		return err
	}
	fmt.Println("Wrote ", n, " bytes over the network to peer: ", from)
	peer.(*p2p.TCPPeer).Wg.Done()
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
			fmt.Printf("Error sending message to peer %d\n: ", peer.LocalAddr().String(), err)
			continue
		}
	}
	return nil
}
func (s *FileServer) GetFile(key string) (io.Reader, error) {
	// check in local storage first
	if s.s.Has(key) {
		return s.s.ReadStream(key)
	}
	// fetch from the peers in the network
	fmt.Printf("File %s not found in local storage, fetching from network...\n", key)
	msg := Message{
		Payload: MessageGetFile{
			Key: key,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return nil, err
	}
	return nil, nil
}
func (s *FileServer) StoreData(key string, r io.Reader) error {
	// 1. write to local storage
	// 2. send to all known peers

	fileBuffer := new(bytes.Buffer)
	tee := io.TeeReader(r, fileBuffer) // tee reads from reader r and writes to fileBuffer too
	// because if we directly write to local then reader will become empty , so we need to store in fileBuffer
	// also so that it can be broadcasted later
	n, err := s.s.WriteStream(key, tee)
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
		n, err := io.Copy(peer, fileBuffer)
		if err != nil {
			return err
		}
		fmt.Println("received and wrote ", n, " bytes over the network to peer: ", peer.RemoteAddr().String())
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
	// send signal to quit the loop
	close(s.quitChannel)
	return nil
}

func (s *FileServer) OnPeer(P p2p.Peer) error {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	s.peers[P.RemoteAddr().String()] = P
	fmt.Println("New peer joined in: ", P.RemoteAddr().String())
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
