package main

import (
	"fmt"

	"github.com/Ankesh2004/GO-DFS/p2p"
)

type FileServerOptions struct {
	rootDir string
	// ?? is get cas func req ?
	Transport p2p.Transport
}

type FileServer struct {
	FileServerOptions
	s           *Store
	quitChannel chan struct{}
}

func NewFileServer(options FileServerOptions) *FileServer {
	store := NewStore(
		options.rootDir,
	)
	return &FileServer{
		FileServerOptions: options,
		s:                 store,
		quitChannel:       make(chan struct{}),
	}
}

func (s *FileServer) Start() error {
	if err := s.Transport.ListenAndAccept(); err != nil {
		return err
	}
	fmt.Println("Hahaha")
	s.loop()
	return nil
}

func (s *FileServer) Stop() error {
	// send signal to quit the loop
	close(s.quitChannel)
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
