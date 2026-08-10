# `p2p` — P2P Transport & Security Layer

The `p2p` package provides the low-level peer-to-peer networking foundation for **GO-DFS** (Go Distributed File System). It manages TCP connection lifecycles, cryptographic handshakes, authenticated encryption, and deterministic protocol message framing/demuxing.

---

## Key Features

- **Decoupled Transport Abstractions**: Clean Go interfaces ([`Peer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go#L7-L11) and [`Transport`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go#L14-L20)) allowing transport implementation swapping (TCP, QUIC, etc.).
- **X25519 Key Agreement**: Ephemeral Diffie-Hellman handshake for key exchange with zero persistent key exposure.
- **ChaCha20-Poly1305 AEAD Encryption**: Authenticated Encryption with Associated Data (AEAD) wrapping underlying `net.Conn` streams to enforce confidentiality and tamper detection.
- **Direction-Separated HKDF Keys**: Independent read and write keys derived via HKDF-SHA256 to eliminate message reflection attacks.
- **Framed Protocol Framing & Demuxing**: Deterministic 4-byte length-prefix framing (`SampleDecoder`) preventing buffer over-reading, stream race conditions, and memory exhaustion DoS attacks.
- **Relay Stream Support**: Integrated header decoding for piped data transfers across relay nodes.
- **Cross-Platform Compatibility**: Platform-specific socket configuration (`SO_REUSEADDR` / `SO_REUSEPORT`) for Windows and Unix-like operating systems.

---

## Core Architecture & Execution Flow

```
+-------------------------------------------------------------------------------+
|                                  TCPTransport                                 |
|                                                                               |
|   +-----------------------+                    +--------------------------+   |
|   |  ListenAndAccept()    |                    |        Dial(addr)        |   |
|   +-----------+-----------+                    +------------+-------------+   |
|               |                                             |                 |
+---------------+---------------------------------------------+-----------------+
                |                                             |
                v                                             v
        [Inbound TCPConn]                             [Outbound TCPConn]
                |                                             |
                +----------------------+----------------------+
                                       |
                                       v
                             +--------------------+
                             |  SecureHandshake   |
                             |  (X25519 + HKDF)   |
                             +---------+----------+
                                       |
                                       v
                             +--------------------+
                             |     SecurePeer     |
                             | (ChaCha20-Poly1305)|
                             +---------+----------+
                                       |
                                       v
                             +--------------------+
                             |   SampleDecoder    |
                             | (Framed RPC Loop)  |
                             +---------+----------+
                                       |
                        +--------------+--------------+
                        |                             |
                        v                             v
               [IsStream / IsRelay]              [RPC Message]
                        |                             |
                        v                             v
               Stream WaitGroup Lock            rpcChannel <- rpc
```

### Connection Lifecycle

1. **Establishment**: [`TCPTransport`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/tcp.go#L73) listens for incoming TCP connections (`ListenAndAccept`) or initiates outbound connections (`Dial`).
2. **Secure Handshake**: On connection, [`SecureHandshake`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go#L148) executes:
   - Outbound peer sends its 32-byte X25519 public key first, then receives the remote key.
   - Inbound peer receives the remote key first, then sends its public key.
   - An ECDH shared secret is derived using Curve25519. Ephemeral secret material is zeroed immediately.
   - HKDF-SHA256 expands 64 bytes of key material, generating separate `writeKey` and `readKey` pairs for outbound and inbound peers.
   - The raw `net.Conn` inside [`TCPPeer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/tcp.go#L14) is replaced with an encrypted [`SecurePeer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go#L24).
3. **Framing & Demuxing Loop**: `handleConnection` iterates using the configured [`Decoder`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/encoding.go#L12) to parse incoming byte streams into [`RPC`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/message.go#L17) payloads.
4. **Stream Synchronization**: For direct (`IsStream`) or relayed (`IsRelay`) data streams, `TCPPeer` blocks its read loop using a `sync.WaitGroup` until the consumer finishes reading the raw stream, guaranteeing frame alignment.

---

## Wire Protocol & Frame Formats

### 1. Encrypted Frame Format (`SecurePeer`)

All encrypted network communications over `SecurePeer` use Big-Endian length-prefix framing:

| Field | Size | Description |
| :--- | :--- | :--- |
| `Length` | 4 bytes (uint32, Big-Endian) | Length of the subsequent ciphertext payload |
| `Ciphertext` | $N$ bytes (Max 16 KB plaintext) | Encrypted payload + 16-byte Poly1305 authentication tag |

Each frame increments a 12-byte nonce (little-endian order) independently for read and write channels to prevent replay attacks.

### 2. Protocol RPC Types (`message.go` & `encoding.go`)

The high-level protocol inspects the first byte of incoming plaintext:

| Type Identifier | Byte Flag | RPC Field Set | Description |
| :--- | :--- | :--- | :--- |
| `IncomingMessage` | `0x01` | `Payload` | Normal message carrying bounded byte data (capped at 2 MB). |
| `IncomingStream` | `0x02` | `IsStream = true` | Signals a raw stream handover for direct peer-to-peer file transfers. |
| `IncomingRelayStream` | `0x03` | `IsRelay = true`, `RelayMeta` | Signals a relayed stream with metadata header preceding the raw payload. |

#### Message Frame Structure (`0x01`)
```
[0x01 (1 byte)] + [Length (4 bytes, Little-Endian)] + [Payload (N bytes)]
```

#### Relay Stream Header Frame Structure (`0x03`)
```
[0x03 (1 byte)] + [Header Len (4 bytes, Little-Endian)] + [GOB-encoded RelayStreamMeta] + [Raw Data Bytes...]
```

---

## Key Interfaces & Types

### [`Peer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go#L7-L11)
```go
type Peer interface {
    net.Conn
    Send([]byte) error
    CloseStream() error
}
```
Represents a remote node connection. Wraps network I/O, stream locking, and write operations.

### [`Transport`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go#L14-L20)
```go
type Transport interface {
    Addr() string
    Dial(addr string) error
    ListenAndAccept() error
    Consume() <-chan RPC
    Close() error
}
```
High-level network transport interface for connection lifecycle management and RPC consumption.

### [`SecurePeer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go#L24-L33)
```go
type SecurePeer struct {
    net.Conn
    enc      cipher.AEAD
    dec      cipher.AEAD
    encNonce []byte
    decNonce []byte
    leftover []byte
    writeMu  sync.Mutex
    readMu   sync.Mutex
}
```
Transparent `net.Conn` wrapper enforcing ChaCha20-Poly1305 AEAD frame encryption, decryption, nonce stepping, and partial read buffering.

### [`SampleDecoder`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/encoding.go#L25-L26)
Decoder implementation handling precise byte-boundary reading for message payloads, direct stream signals, and relay metadata.

---

## Security Specifications

1. **Perfect Forward Secrecy**: Handshakes generate fresh ephemeral X25519 keypairs per connection.
2. **Key Isolation**: HKDF-SHA256 derives distinct 256-bit read and write keys per endpoint.
3. **Integrity & Authenticity**: ChaCha20-Poly1305 AEAD detects bit-flips and data tampering. Authentication failure triggers an immediate connection close.
4. **Memory Security**: Ephemeral private keys and intermediate HKDF materials are zeroed out via [`zero([]byte)`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go#L260) immediately after derivation.
5. **DoS Mitigation**:
   - `MaxMessageSize` is restricted to `2 MB` for standard RPC payloads.
   - `maxFrameSize` caps plaintext frame size to `16 KB`.
   - Relay header length check caps metadata headers at `64 KB`.

---

## Code Example

```go
package main

import (
	"fmt"
	"log"
	"p2p"
)

func main() {
	opts := p2p.TCPTransportOptions{
		ListenPort: ":3000",
		Handshake:  p2p.SecureHandshake,
		Decoder:    p2p.SampleDecoder{},
		OnPeer: func(peer p2p.Peer) error {
			fmt.Printf("Connected to peer: %s\n", peer.RemoteAddr())
			return nil
		},
	}

	transport := p2p.NewTCPTransport(opts)

	if err := transport.ListenAndAccept(); err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer transport.Close()

	// Consume incoming RPC messages
	for rpc := range transport.Consume() {
		fmt.Printf("Received RPC from %s: %s\n", rpc.From, string(rpc.Payload))
	}
}
```

---

## File Summary

| File | Description |
| :--- | :--- |
| [`transport.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go) | Defines top-level [`Peer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go#L7) and [`Transport`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/transport.go#L14) interfaces. |
| [`tcp.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/tcp.go) | Implementation of [`TCPTransport`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/tcp.go#L73) and [`TCPPeer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/tcp.go#L14) with connection loops and stream synchronization. |
| [`secure.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go) | Handshake logic ([`SecureHandshake`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go#L148)), X25519 key exchange, HKDF key derivation, and [`SecurePeer`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure.go#L24) AEAD encryption wrapper. |
| [`handshake.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/handshake.go) | Defines the [`Handshake`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/handshake.go#L6) function signature and sample pass-through handshake. |
| [`message.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/message.go) | Defines [`RPC`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/message.go#L17) structure, [`RelayStreamMeta`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/message.go#L9) structure, and protocol message constants (`0x01`, `0x02`, `0x03`). |
| [`encoding.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/encoding.go) | Implementations of [`Decoder`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/encoding.go#L12) ([`SampleDecoder`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/encoding.go#L25), [`GOBDecoder`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/encoding.go#L17)) and byte stream framing mechanisms. |
| [`socket_windows.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/socket_windows.go) | Windows-specific socket option configuration (`SO_REUSEADDR`). |
| [`socket_unix.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/socket_unix.go) | Unix/Linux/macOS socket option configuration (`SO_REUSEADDR`, `SO_REUSEPORT`). |
| [`secure_test.go`](file:///c:/UNIVERSE/Projects/GO-DFS/pkg/p2p/secure_test.go) | Comprehensive unit tests covering key agreement, tamper detection, and large payload (10 MB) encrypted transfers. |
