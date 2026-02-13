package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

// 8MB per chunk — sweet spot between parallelism and overhead.
// Small enough that a failed transfer only loses 8MB of progress,
// large enough that we don't create thousands of chunks for normal files.
const DefaultChunkSize = 8 * 1024 * 1024

// bufPool reuses chunk-sized buffers so we're not allocating 8MB every time.
// This matters a lot when multiple stores/fetches happen concurrently.
var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, DefaultChunkSize)
		return &buf
	},
}

// ChunkResult holds the outcome of chunking a single piece of data
type ChunkResult struct {
	Index    int    // position in the original file (0-based)
	ChunkKey string // SHA-256 hex of the chunk content
	Size     int64  // actual bytes written (last chunk may be smaller)
}

// ChunkAndStore reads from src in fixed-size pieces, writes each chunk
// to the CAS under its content hash, and returns the chunk keys in order.
// If the input is smaller than chunkSize, we still produce one chunk.
func (s *Store) ChunkAndStore(src io.Reader, chunkSize int64) ([]ChunkResult, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	var results []ChunkResult
	index := 0

	for {
		// grab a buffer from the pool
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr

		// make sure the buffer is at least chunkSize (in case pool has old smaller ones)
		if int64(len(buf)) < chunkSize {
			buf = make([]byte, chunkSize)
			bufPtr = &buf
		}

		// read up to chunkSize bytes
		n, err := io.ReadFull(src, buf[:chunkSize])
		if n == 0 {
			bufPool.Put(bufPtr)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // done, no more data
			}
			if err != nil {
				return nil, fmt.Errorf("chunk %d read error: %w", index, err)
			}
			break
		}

		chunkData := buf[:n]

		// content-addressed key: SHA-256 of the raw chunk bytes
		hash := sha256.Sum256(chunkData)
		chunkKey := hex.EncodeToString(hash[:])

		// write to CAS — using the content hash as the key means
		// duplicate chunks across files are automatically deduplicated
		written, writeErr := s.WriteRaw(chunkKey, chunkData)
		bufPool.Put(bufPtr) // return buffer ASAP

		if writeErr != nil {
			return nil, fmt.Errorf("chunk %d write error: %w", index, writeErr)
		}

		results = append(results, ChunkResult{
			Index:    index,
			ChunkKey: chunkKey,
			Size:     written,
		})

		index++

		// io.ReadFull returns ErrUnexpectedEOF when it reads < chunkSize bytes,
		// which means we hit EOF mid-chunk — this was the last chunk
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("chunk %d read error: %w", index, err)
		}
	}

	return results, nil
}

// WriteRaw writes raw bytes to the CAS under the given key.
// Unlike WriteStream which takes an io.Reader, this takes a byte slice
// so we can avoid extra copying when we already have the data in memory.
func (s *Store) WriteRaw(key string, data []byte) (int64, error) {
	cas := s.GetCASPath(key)
	if err := mkdirAll(cas.Path); err != nil {
		return 0, err
	}

	file, err := createFile(cas.FullPath())
	if err != nil {
		return 0, err
	}
	defer file.Close()

	n, err := file.Write(data)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

// ReadChunk reads a chunk's raw bytes from the CAS.
// Returns the data and its size for convenience.
func (s *Store) ReadChunk(chunkKey string) ([]byte, error) {
	size, r, err := s.ReadStream(chunkKey)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk %s: %w", chunkKey, err)
	}
	return data, nil
}
