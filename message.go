package main

import "encoding/gob"

func init() {
	// Register message types for gob encoding/decoding
	// This is required for the Message.Payload interface{} to work properly
	gob.Register(MessageStoreFile{})
	gob.Register(MessageGetFile{})
}

// Message is the wrapper for all inter-node communication
type Message struct {
	Payload any
}

// MessageStoreFile is sent when a node wants to store a file on peers
type MessageStoreFile struct {
	Key  string
	Size int64
}

// MessageGetFile is sent when a node wants to retrieve a file from peers
type MessageGetFile struct {
	Key string
}
