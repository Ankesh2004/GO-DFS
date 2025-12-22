package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestStore(t *testing.T) {
	s := NewStore()
	data := bytes.NewReader([]byte("Hello"))
	if err := s.WriteStream("testdata2", data); err != nil {
		t.Error(err)
		return
	}
	if err := s.ReadStream("testdata2"); err != nil {
		t.Error(err)
		return
	}
	fmt.Println("Write ahppdhf !!!!!")
}
