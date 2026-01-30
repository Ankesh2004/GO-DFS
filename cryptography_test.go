package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// generateKeyAndNonce creates random key and nonce for testing
func generateKeyAndNonce() ([]byte, []byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// TestCryptoRoundtrip tests that encrypt followed by decrypt returns original data
func TestCryptoRoundtrip(t *testing.T) {
	key, nonce, err := generateKeyAndNonce()
	if err != nil {
		t.Fatalf("Failed to generate key/nonce: %v", err)
	}

	testData := []byte("Hello, this is a test message for encryption!")

	// Encrypt
	src := bytes.NewReader(testData)
	encrypted := new(bytes.Buffer)
	n, err := encrypt(key, nonce, src, encrypted)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	// With AEAD and framing, size will be larger than plaintext
	if n <= int64(len(testData)) {
		t.Errorf("Encrypted size %d should be larger than plaintext size %d", n, len(testData))
	}

	// Verify encrypted data is different from original
	if bytes.Equal(encrypted.Bytes(), testData) {
		t.Error("Encrypted data should be different from original")
	}

	// Decrypt
	decrypted := new(bytes.Buffer)
	_, err = decrypt(key, nonce, bytes.NewReader(encrypted.Bytes()), decrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decrypted data matches original
	if !bytes.Equal(decrypted.Bytes(), testData) {
		t.Errorf("Decrypted data doesn't match original.\nGot: %s\nExpected: %s",
			decrypted.String(), string(testData))
	}
}

// TestCryptoEmptyData tests encryption/decryption of empty data
func TestCryptoEmptyData(t *testing.T) {
	key, nonce, err := generateKeyAndNonce()
	if err != nil {
		t.Fatalf("Failed to generate key/nonce: %v", err)
	}

	testData := []byte{}

	// Encrypt
	encrypted := new(bytes.Buffer)
	_, err = encrypt(key, nonce, bytes.NewReader(testData), encrypted)
	if err != nil {
		t.Fatalf("Failed to encrypt empty data: %v", err)
	}

	// Decrypt
	decrypted := new(bytes.Buffer)
	_, err = decrypt(key, nonce, bytes.NewReader(encrypted.Bytes()), decrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if len(decrypted.Bytes()) != 0 {
		t.Errorf("Decrypted empty data should be empty, got %d bytes", len(decrypted.Bytes()))
	}
}

// TestCryptoLargeData tests encryption/decryption of 1MB data
func TestCryptoLargeData(t *testing.T) {
	key, nonce, err := generateKeyAndNonce()
	if err != nil {
		t.Fatalf("Failed to generate key/nonce: %v", err)
	}

	// Generate 1MB of random data
	dataSize := 1024 * 1024 // 1MB
	testData := make([]byte, dataSize)
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Encrypt
	encrypted := new(bytes.Buffer)
	n, err := encrypt(key, nonce, bytes.NewReader(testData), encrypted)
	if err != nil {
		t.Fatalf("Failed to encrypt large data: %v", err)
	}
	if n <= int64(dataSize) {
		t.Errorf("Encrypted size %d should be larger than plaintext %d", n, dataSize)
	}

	// Decrypt
	decrypted := new(bytes.Buffer)
	n, err = decrypt(key, nonce, bytes.NewReader(encrypted.Bytes()), decrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt large data: %v", err)
	}
	if n != int64(dataSize) {
		t.Errorf("Decrypted %d bytes, expected %d", n, dataSize)
	}

	// Verify data matches
	if !bytes.Equal(decrypted.Bytes(), testData) {
		t.Error("Decrypted large data doesn't match original")
	}
}

// TestCryptoWrongKey tests that decryption with wrong key FAILS (AEAD property)
func TestCryptoWrongKey(t *testing.T) {
	key1, nonce, err := generateKeyAndNonce()
	if err != nil {
		t.Fatalf("Failed to generate key/nonce: %v", err)
	}
	key2 := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}

	testData := []byte("Secret message that should not be readable with wrong key")

	// Encrypt with key1
	encrypted := new(bytes.Buffer)
	_, err = encrypt(key1, nonce, bytes.NewReader(testData), encrypted)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with key2 (wrong key)
	decrypted := new(bytes.Buffer)
	_, err = decrypt(key2, nonce, bytes.NewReader(encrypted.Bytes()), decrypted)
	// WE EXPECT ERROR HERE because AEAD verifies the tag
	if err == nil {
		t.Fatal("Decryption with wrong key should fail with AEAD, but it succeeded")
	}
}

// TestCryptoStoreIntegration tests the store's ability to handle encrypted blobs correctly
func TestCryptoStoreIntegration(t *testing.T) {
	key, nonce, err := generateKeyAndNonce()
	if err != nil {
		t.Fatalf("Failed to generate key/nonce: %v", err)
	}

	s := NewStore("./test_crypto_cas")
	defer s.Wipe()

	testData := []byte("Integration test data for encrypted store operations")
	testKey := "crypto_test_key"

	// 1. Manually Encrypt
	encBuffer := new(bytes.Buffer)
	// User layer protocol: Nonce followed by ciphertext
	encBuffer.Write(nonce)
	_, err = encrypt(key, nonce, bytes.NewReader(testData), encBuffer)
	if err != nil {
		t.Fatalf("Manual encryption failed: %v", err)
	}

	// 2. Write raw encrypted blob to store
	n, err := s.WriteStream(testKey, encBuffer)
	if err != nil {
		t.Fatalf("WriteStream failed: %v", err)
	}
	if n <= int64(len(testData))+12 {
		t.Errorf("Written size %d too small", n)
	}

	// 3. Verify file exists
	if !s.Has(testKey) {
		t.Fatal("File should exist after WriteStream")
	}

	// 4. Read back and manually decrypt
	_, rawReader, err := s.ReadStream(testKey)
	if err != nil {
		t.Fatalf("ReadStream failed: %v", err)
	}
	defer rawReader.Close()

	downloadedBlob, err := io.ReadAll(rawReader)
	if err != nil {
		t.Fatalf("Read downloaded blob failed: %v", err)
	}

	if len(downloadedBlob) < 12 {
		t.Fatalf("Downloaded blob too small: %d", len(downloadedBlob))
	}

	downloadedNonce := downloadedBlob[:12]
	decrypted := new(bytes.Buffer)
	_, err = decrypt(key, downloadedNonce, bytes.NewReader(downloadedBlob[12:]), decrypted)
	if err != nil {
		t.Fatalf("Manual decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), testData) {
		t.Errorf("Decrypted data doesn't match.\nGot: %s\nExpected: %s",
			decrypted.String(), string(testData))
	}
}

// TestCryptoMultipleChunks tests data that spans multiple buffer chunks
func TestCryptoMultipleChunks(t *testing.T) {
	key, nonce, err := generateKeyAndNonce()
	if err != nil {
		t.Fatalf("Failed to generate key/nonce: %v", err)
	}

	// Create data larger than the 32KB buffer used in copyStream
	dataSize := 100 * 1024 // 100KB (more than 3 chunks of 32KB each)
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Encrypt
	encrypted := new(bytes.Buffer)
	_, err = encrypt(key, nonce, bytes.NewReader(testData), encrypted)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted := new(bytes.Buffer)
	_, err = decrypt(key, nonce, bytes.NewReader(encrypted.Bytes()), decrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if !bytes.Equal(decrypted.Bytes(), testData) {
		t.Error("Multi-chunk data doesn't match after roundtrip")
	}
}
