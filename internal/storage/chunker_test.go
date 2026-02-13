package storage

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestChunkSmallFile(t *testing.T) {
	s := NewStore("./test_chunk_cas")
	defer s.Wipe()

	// small file — should produce exactly 1 chunk
	data := []byte("hello, chunker!")
	chunks, err := s.ChunkAndStore(bytes.NewReader(data), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	// verify the chunk is actually in the store
	if !s.Has(chunks[0].ChunkKey) {
		t.Fatal("chunk not found in store")
	}

	// read it back and compare
	readBack, err := s.ReadChunk(chunks[0].ChunkKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, readBack) {
		t.Fatalf("data mismatch: got %q, want %q", readBack, data)
	}
}

func TestChunkMultipleChunks(t *testing.T) {
	s := NewStore("./test_chunk_multi_cas")
	defer s.Wipe()

	// use a small chunk size to force multiple chunks
	chunkSize := int64(1024) // 1KB
	totalSize := int64(5000) // 5KB → should get 5 chunks (4x1024 + 1x904)

	data := make([]byte, totalSize)
	rand.Read(data)

	chunks, err := s.ChunkAndStore(bytes.NewReader(data), chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	expectedChunks := 5 // ceil(5000/1024)
	if len(chunks) != expectedChunks {
		t.Fatalf("expected %d chunks, got %d", expectedChunks, len(chunks))
	}

	// verify total size matches
	var total int64
	for _, c := range chunks {
		total += c.Size
	}
	if total != totalSize {
		t.Fatalf("total size mismatch: got %d, want %d", total, totalSize)
	}

	// reassemble and verify content
	var reassembled bytes.Buffer
	for _, c := range chunks {
		chunkData, err := s.ReadChunk(c.ChunkKey)
		if err != nil {
			t.Fatal(err)
		}
		reassembled.Write(chunkData)
	}

	if !bytes.Equal(data, reassembled.Bytes()) {
		t.Fatal("reassembled data doesn't match original")
	}
}

func TestChunkExactBoundary(t *testing.T) {
	s := NewStore("./test_chunk_boundary_cas")
	defer s.Wipe()

	// file size is exactly 2x chunk size — should produce exactly 2 chunks
	chunkSize := int64(512)
	data := make([]byte, chunkSize*2)
	rand.Read(data)

	chunks, err := s.ChunkAndStore(bytes.NewReader(data), chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	// both should be exactly chunkSize
	for i, c := range chunks {
		if c.Size != chunkSize {
			t.Fatalf("chunk %d: expected size %d, got %d", i, chunkSize, c.Size)
		}
	}
}

func TestChunkDeduplication(t *testing.T) {
	s := NewStore("./test_chunk_dedup_cas")
	defer s.Wipe()

	// two identical chunks should produce the same key
	data := bytes.Repeat([]byte("A"), 1024)
	doubleData := append(data, data...) // 2KB of the same byte

	chunks, err := s.ChunkAndStore(bytes.NewReader(doubleData), 1024)
	if err != nil {
		t.Fatal(err)
	}

	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	// since both chunks have identical content, they should have the same key
	if chunks[0].ChunkKey != chunks[1].ChunkKey {
		t.Fatal("duplicate chunks should have the same content-hash key")
	}
}

func TestChunkEmptyInput(t *testing.T) {
	s := NewStore("./test_chunk_empty_cas")
	defer s.Wipe()

	chunks, err := s.ChunkAndStore(bytes.NewReader(nil), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	if len(chunks) != 0 {
		t.Fatalf("expected 0 chunks for empty input, got %d", len(chunks))
	}
}

func TestChunkLargeRandom(t *testing.T) {
	s := NewStore("./test_chunk_large_cas")
	defer s.Wipe()

	// 1MB file with 256KB chunks → 4 chunks
	chunkSize := int64(256 * 1024)
	totalSize := int64(1024 * 1024)
	data := make([]byte, totalSize)
	rand.Read(data)

	chunks, err := s.ChunkAndStore(bytes.NewReader(data), chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}

	// reassemble and verify
	var reassembled bytes.Buffer
	for _, c := range chunks {
		chunkData, err := s.ReadChunk(c.ChunkKey)
		if err != nil {
			t.Fatal(err)
		}
		reassembled.Write(chunkData)
	}

	if !bytes.Equal(data, reassembled.Bytes()) {
		t.Fatal("reassembled data mismatch")
	}

	// verify we can also read them as streams
	for _, c := range chunks {
		size, r, err := s.ReadStream(c.ChunkKey)
		if err != nil {
			t.Fatalf("ReadStream(%s) failed: %v", c.ChunkKey[:8], err)
		}
		readData, _ := io.ReadAll(r)
		r.Close()
		if int64(len(readData)) != size {
			t.Fatalf("ReadStream size mismatch: got %d, want %d", len(readData), size)
		}
	}
}
