package main

import (
	"crypto/rand"
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
func (s *Store) WriteStreamEncrypted(encKey []byte, key string, r io.Reader) (int64, error) {
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

	// GENERATE UNIQUE NONCE PER FILE
	nonce := make([]byte, 12) // 12 bytes for ChaCha20-Poly1305
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Write nonce to the beginning of the file
	if _, err := file.Write(nonce); err != nil {
		return 0, fmt.Errorf("failed to write nonce to file: %w", err)
	}

	n, err := encrypt(encKey, nonce, r, file)
	if err != nil {
		return 0, err
	}
	return n + 12, nil // Total size includes nonce
}

func (s *Store) ReadStream(key string) (int64, io.ReadCloser, error) {
	fullPath := s.getCASPath(key).FullPath()
	file, err := os.Open(fullPath)
	if err != nil {
		return 0, nil, err
	}

	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return 0, nil, err
	}
	// NOTE: WE ARE NOT CLOSING THE file (WHICH ACTS AS READER) HERE,
	// HENCE, WE NEED TO CLOSE IT WHEREVER WE CALL ReadStream() function
	return fi.Size(), file, nil
}

// decryptedReader wraps the pipe reader and source file to properly close both
type decryptedReader struct {
	pr   *io.PipeReader
	file *os.File
}

func (d *decryptedReader) Read(p []byte) (n int, err error) {
	return d.pr.Read(p)
}

func (d *decryptedReader) Close() error {
	prErr := d.pr.Close()
	fileErr := d.file.Close()
	if prErr != nil {
		return prErr
	}
	return fileErr
}

func (s *Store) ReadStreamDecrypted(encKey []byte, key string) (int64, io.ReadCloser, error) {
	fullPath := s.getCASPath(key).FullPath()
	file, err := os.Open(fullPath)
	if err != nil {
		return 0, nil, err
	}

	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return 0, nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer file.Close() // Close file after decryption completes

		// Read the nonce from the beginning of the file
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(file, nonce); err != nil {
			pw.CloseWithError(fmt.Errorf("failed to read nonce: %w", err))
			return
		}

		// Decrypt the rest
		_, err := decrypt(encKey, nonce, file, pw)
		if err != nil {
			pw.CloseWithError(fmt.Errorf("failed to decrypt: %w", err))
		}
	}()
	// The size returned is basically the original encrypted file size minus nonce?
	// Actually, the caller often ignores size or uses it for progress.
	// We can't know the exact decrypted size without decrypting because of the tag overhead
	// But giving the file size is a reasonable approximation for now.
	return fi.Size(), &decryptedReader{pr: pr, file: file}, nil
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
