package main

import (
	"fmt"
	"sync"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

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
			fmt.Println(rpc)
		case <-s.quitChannel:
			return
		}
	}
}
