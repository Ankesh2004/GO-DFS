package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type Path struct {
	Path     string
	Filename string
}

func (p Path) FullPath() string {
	return p.Path + "/" + p.Filename
}

// Store struct consists whole logic of storage of data nodes
// CAS is used because:
//  1. it prevents a single directory from having a large number of files (so making a tree like structure) ,
//     having less files in a directory makes the searching faster
//  2. it is splitting 32 bytes SHA-256 hash into 8 parts
type Store struct {
	RootDir string
}

func NewStore(rootDir string) *Store {
	return &Store{
		RootDir: rootDir,
	}
}

func (s *Store) GetCASPath(key string) Path {
	hash256 := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(hash256[:])

	casPath := s.RootDir + "/" + hash[0:8] + "/" + hash[8:16] + "/" + hash[16:24] + "/" + hash[24:32]
	cas := Path{
		Path:     casPath,
		Filename: hash,
	}
	return cas
}

// WriteStream reads from r and writes to the CAS store.
func (s *Store) WriteStream(key string, r io.Reader) (int64, error) {
	cas := s.GetCASPath(key)
	if err := os.MkdirAll(cas.Path, 0755); err != nil {
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

// ReadStream retrieves a stream for the given key.
func (s *Store) ReadStream(key string) (int64, io.ReadCloser, error) {
	fullPath := s.GetCASPath(key).FullPath()
	file, err := os.Open(fullPath)
	if err != nil {
		return 0, nil, err
	}

	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return 0, nil, err
	}
	return fi.Size(), file, nil
}

func (s *Store) DeleteStream(key string) error {
	fullPath := s.GetCASPath(key).FullPath()
	return os.Remove(fullPath)
}

func (s *Store) Has(key string) bool {
	fullPath := s.GetCASPath(key).FullPath()
	_, err := os.Stat(fullPath)
	return err == nil
}

func (s *Store) Wipe() error {
	return os.RemoveAll(s.RootDir)
}
