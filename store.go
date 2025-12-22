package main

import (
	"crypto/sha256"
	"encoding/hex"
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

func NewStore() *Store {
	return &Store{
		rootDir: "./dfs",
	}
}

func (s *Store) getCASPath(key string) Path {
	hash256 := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(hash256[:])
	casPath := s.rootDir + "/cas/" + hash[0:8] + "/" + hash[8:16] + "/" + hash[16:24] + "/" + hash[24:32]
	cas := Path{
		path:     casPath,
		filename: key,
	}
	return cas
}

// We are reading and writing using streams because buffer is not optimal as it needs to store entire object in RAM first.
func (s *Store) WriteStream(key string, r io.Reader) error {
	cas := s.getCASPath(key)
	if err := os.MkdirAll(cas.path, 0755); err != nil {
		return err
	}
	file, err := os.Create(cas.path + "/" + cas.filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, r); err != nil {
		return err
	}
	return nil
}

func (s *Store) ReadStream(key string) (int64, io.ReadCloser, error) {
	casPath := s.getCASPath(key).path
	file, err := os.Open(casPath)
	if err != nil {
		return 0, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return 0, nil, err
	}
	var r io.ReadCloser = file
	return info.Size(), r, nil
}

func (s *Store) DeleteStream(key string) error {
	casPath := s.getCASPath(key).path
	return os.Remove(casPath)
}

func (s *Store) HasStream(key string) (bool, error) {
	casPath := s.getCASPath(key).path
	_, err := os.Stat(casPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Store) Wipe() error {
	return os.RemoveAll(s.rootDir)
}
