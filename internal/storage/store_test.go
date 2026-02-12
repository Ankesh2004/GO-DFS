package storage

import (
	"bytes"
	"testing"
)

func TestStore(t *testing.T) {
	s := NewStore("./test_cas")
	defer s.Wipe()

	data := bytes.NewReader([]byte("Hello"))
	if _, err := s.WriteStream("testdata2", data); err != nil {
		t.Error(err)
		return
	}
}

func TestRead(t *testing.T) {
	s := NewStore("./test_cas")
	defer s.Wipe()

	content := []byte("Hello")
	data := bytes.NewReader(content)
	if _, err := s.WriteStream("testdata2", data); err != nil {
		t.Error(err)
		return
	}
	size, r, err := s.ReadStream("testdata2")
	if err != nil {
		t.Error(err)
		return
	}
	defer r.Close()

	if size != int64(len(content)) {
		t.Errorf("Expected size %d, got %d", len(content), size)
	}
}

func TestDelete(t *testing.T) {
	s := NewStore("./test_cas")
	defer s.Wipe()

	data := bytes.NewReader([]byte("Hello my boi"))
	if _, err := s.WriteStream("testdata3", data); err != nil {
		t.Error(err)
		return
	}
	if err := s.DeleteStream("testdata3"); err != nil {
		t.Error(err)
		return
	}
	if s.Has("testdata3") {
		t.Error("expected file to be deleted")
	}
}
