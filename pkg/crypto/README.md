# GO-DFS Crypto Package (`pkg/crypto`)

The `crypto` package provides low-overhead, streaming authenticated encryption and decryption capabilities for **GO-DFS** using the **XChaCha20-Poly1305** AEAD cipher.

It enables transparent end-to-end and block-level encryption of streams (readers and writers) by breaking payload streams into bounded frames, authenticating each frame individually, and automatically managing per-chunk nonces.

---

## 🏗 Key Features & Architecture

* **Cipher Choice**: Uses **XChaCha20-Poly1305** (`golang.org/x/crypto/chacha20poly1305.NewX`), which features an extended 192-bit (24-byte) nonce to safely withstand random nonce generation without key reuse risks.
* **Streaming & Chunking**: Processes arbitrarily large `io.Reader` sources into `io.Writer` destinations in fixed **32 KB** plaintext chunks (`MaxFrameSize`), avoiding excessive memory consumption.
* **Framed Serialization**: Encloses each encrypted chunk in a simple binary frame header.
* **Sequential Nonce Counter**: Starting from a base 24-byte nonce, the nonce is automatically incremented sequentially after every frame encrypted/decrypted.
* **DoS / Memory Exhaustion Protection**: On decryption, frame lengths are validated against `MaxFrameSize + aead.Overhead()` before allocating memory to protect against corrupted or malicious frame headers.
* **Key Persistence**: Provides utility functions to load or generate secure 256-bit symmetric keys.

---

## 📦 Frame Layout (Wire Format)

Each frame in the encrypted binary output stream follows this format:

```text
+-----------------------+-------------------------------------------------------+
| Length (4 Bytes)      | Encrypted Payload + Auth Tag (N Bytes)               |
| uint32 (LittleEndian) | (Length - 16 bytes payload, 16 bytes Poly1305 tag)    |
+-----------------------+-------------------------------------------------------+
```

* **Length Header**: 4 bytes (`uint32`, Little-Endian) representing `len(ciphertext + tag)`.
* **Ciphertext Body**: `n` bytes of encrypted plaintext followed by the 16-byte Poly1305 authentication tag.
* **Max Encrypted Frame Size**: `32,768 bytes (MaxFrameSize) + 16 bytes (AEAD Overhead) = 32,784 bytes`.

---

## 🔑 Constants & API Reference

### Constants

| Constant | Value | Description |
| :--- | :--- | :--- |
| `NonceSize` | `24` | Required size in bytes for the XChaCha20 nonce (192 bits). |
| `MaxFrameSize` | `32 * 1024` (32 KB) | Maximum plaintext size processed per frame during streaming. |

### Core Functions

#### [`Encrypt`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/crypto/crypto.go#L23-L73)
```go
func Encrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer) (int64, error)
```
Reads data sequentially from `src` in chunks up to `MaxFrameSize`, encrypts each chunk using XChaCha20-Poly1305 with `currentNonce`, increments `currentNonce`, and writes the framing length header and ciphertext to `dst`. Returns the total number of bytes written to `dst`.

#### [`Decrypt`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/crypto/crypto.go#L75-L132)
```go
func Decrypt(key []byte, nonce []byte, src io.Reader, dst io.Writer) (int64, error)
```
Reads binary frames sequentially from `src`, validates frame length, decrypts and authenticates ciphertext using XChaCha20-Poly1305 with `currentNonce`, increments `currentNonce`, and writes decrypted plaintext to `dst`. Returns the total plaintext bytes written to `dst`.

#### [`LoadOrGenerateKey`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/crypto/crypto.go#L144-L162)
```go
func LoadOrGenerateKey(filename string) ([]byte, error)
```
Checks if a 32-byte key file exists at `filename`. If found, reads and returns the key. If missing, generates 32 cryptographically secure random bytes via `crypto/rand`, saves the file with `0600` permissions, and returns the key.

---

## 💡 Code Examples

### 1. File Encryption and Decryption

```go
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/Ankesh2004/GO-DFS/pkg/crypto"
)

func main() {
	// 1. Generate 32-byte key and 24-byte base nonce
	key := make([]byte, 32)
	nonce := make([]byte, crypto.NonceSize)
	rand.Read(key)
	rand.Read(nonce)

	plaintext := []byte("Hello, GO-DFS streaming encryption!")
	src := bytes.NewReader(plaintext)
	encryptedBuf := new(bytes.Buffer)

	// 2. Encrypt stream
	written, err := crypto.Encrypt(key, nonce, src, encryptedBuf)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Encrypted %d bytes into stream\n", written)

	// 3. Decrypt stream using original key and nonce
	decryptedBuf := new(bytes.Buffer)
	_, err = crypto.Decrypt(key, nonce, encryptedBuf, decryptedBuf)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted message: %s\n", decryptedBuf.String())
}
```

### 2. Loading or Generating Persistent Keys

```go
key, err := crypto.LoadOrGenerateKey("dfs.key")
if err != nil {
    log.Fatalf("Failed to manage key: %v", err)
}
```

---

## 🛡 Security Considerations

1. **Nonce Uniqueness**: Nonces MUST NOT be reused across different streams under the same secret key. Because XChaCha20 uses a 192-bit nonce space, nonces generated using `crypto/rand` have virtually zero collision risk.
2. **Authentication & Tamper Resistance**: Poly1305 authentication tags guarantee that altered or corrupted frames are rejected during `Decrypt` before any unauthenticated plaintext is yielded.
3. **Bounded Allocations**: Prior to reading ciphertexts, `Decrypt` enforces strict upper limits on frame length (`frameLen <= 32,784 bytes`), guarding against heap exhaustion attacks caused by corrupt stream headers.

---

## 🧪 Testing

Unit tests for `pkg/crypto` are located in [`crypto_test.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/crypto/crypto_test.go).

Run the tests using standard Go commands:

```bash
go test -v ./pkg/crypto/...
```

Test cases cover:
* **Roundtrip verification**: Verifying encryption and decryption consistency.
* **Empty payloads**: Handling 0-byte stream inputs.
* **Multi-chunk & Large streams**: Validating streaming performance across 1MB+ payloads.
* **AEAD Tag validation**: Confirming decryption failure when an incorrect key or corrupted ciphertext is supplied.
