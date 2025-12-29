package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type Path struct {
	path     string
	filename string
}

// Store struct consists whole logic of storage of data nodes
// CAS is used because:
//  1. it prevents a single directory from having a large number of files (so making a tree like structure) ,
//     havinf less files in a directory makes the searching faster
//  2. it is spliting 32 bytes SHA-256 hash into 8 parts
type Store struct {
	rootDir string
}

func NewStore(rootDir string) *Store {
	return &Store{
		rootDir: rootDir,
	}
}

func (s *Store) getCASPath(key string) Path {
	hash256 := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(hash256[:])

	// MAKE IT BETTER WITH LOOPS
	// TODO : ALSO WHAT WOULD BE AN OPTIMAL NUMBER OF DIRECTORIES ?? TEST SOME METRIC  ON DIFFERENT NUMBER OF NESTINGS
	casPath := s.rootDir + "/" + hash[0:8] + "/" + hash[8:16] + "/" + hash[16:24] + "/" + hash[24:32]
	cas := Path{
		path:     casPath,
		filename: hash, // filename is hash, so we can retrieve it later
	}
	return cas
}

// We are reading and writing using streams because buffer is not optimal as it needs to store entire object in RAM first.
func (s *Store) WriteStream(key string, r io.Reader) (int64, error) {
	cas := s.getCASPath(key)
	if err := os.MkdirAll(cas.path, 0755); err != nil {
		return 0, err
	}
	fmt.Println(cas.FullPath())
	file, err := os.Create(cas.FullPath())
	if err != nil {
		return 0, err
	}
	defer file.Close()
	n, err := io.Copy(file, r)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) ReadStream(key string) (io.Reader, error) {
	//1. open the file
	fullPath := s.getCASPath(key).FullPath()
	file, err := os.Open(fullPath)

	if err != nil {
		return nil, err
	}
	defer file.Close()
	// info, err := file.Stat()
	// if err != nil {
	// 	return 0, nil, err
	// }
	buff := new(bytes.Buffer)
	n, err := io.Copy(buff, file)
	if err != nil {
		return nil, err
	}
	fmt.Println("Read bytes: ", n)
	fmt.Println(buff.String())
	return buff, nil
}

func (s *Store) DeleteStream(key string) error {
	fullPath := s.getCASPath(key).FullPath()
	// TODO: remove all empty directories
	// Deleting the first path is not good ???, it may delete other BRANCHES of different files
	return os.Remove(fullPath)
}

func (s *Store) Has(key string) bool {
	fullPath := s.getCASPath(key).FullPath()
	_, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return false
	}
	return true
}

func (s *Store) Wipe() error {
	return os.RemoveAll(s.rootDir)
}

func (p Path) FullPath() string {
	return p.path + "/" + p.filename
}
