package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestStore(t *testing.T) {
	s := NewStore("./cas")
	data := bytes.NewReader([]byte("Hello"))
	if err := s.WriteStream("testdata2", data); err != nil {
		t.Error(err)
		return
	}
	fmt.Println("Write ahppdhf !!!!!")
}

func TestRead(t *testing.T) {
	s := NewStore("./cas")
	data := bytes.NewReader([]byte("Hello"))
	if err := s.WriteStream("testdata2", data); err != nil {
		t.Error(err)
		return
	}
	if err := s.ReadStream("testdata2"); err != nil {
		t.Error(err)
		return
	}
}

func TestDelete(t *testing.T) {
	s := NewStore("./cas")
	data := bytes.NewReader([]byte("Hello my boi"))
	if err := s.WriteStream("testdata3", data); err != nil {
		t.Error(err)
		return
	}
	if err := s.DeleteStream("testdata3"); err != nil {
		t.Error(err)
		return
	}
}
