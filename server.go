package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"sync"

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
func (s *FileServer) broadcast(p *Payload) error {
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
func (s *FileServer) StoreData(key string, r io.Reader) error {
	// 1. write to local storage
	// 2. send to all known peers

	buf := new(bytes.Buffer)
	tee := io.TeeReader(r, buf) // tee reads from reader r and writes to buf too
	// because if we directly write to local then reader will become empty , so we need to store in buf
	// also so that it can be broadcasted later
	if err := s.s.WriteStream(key, tee); err != nil {
		return err
	}

	p := &Payload{
		Key:  key,
		Data: buf.Bytes(),
	}

	fmt.Println(buf.Bytes())

	return s.broadcast(p)

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
			var p Payload
			if err := gob.NewDecoder(bytes.NewReader(rpc.Payload)).Decode(&p); err != nil {
				fmt.Println("Error decoding payload: ", err)
				continue
			}
			fmt.Println("Got the data from broadcast")
			fmt.Println(string(p.Data))
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
