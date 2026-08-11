# GO-DFS Core Packages (`pkg/`)

Hey everyone! 👋 Welcome to the core packages directory for **GO-DFS**. 

I built these packages to be highly reusable and modular. They form the foundational blocks of our distributed file system, handling everything from secure P2P connections to decentralized routing and streaming encryption. 

Here's a breakdown of what each package does and how to use it.

---

## 🔐 Crypto (`pkg/crypto`)

### Purpose
I designed the `crypto` package to handle low-overhead, streaming authenticated encryption and decryption. It uses the **XChaCha20-Poly1305** AEAD cipher. The goal here is to enable transparent end-to-end and block-level encryption for our file streams without eating up all our memory.

### Key Features & Usage
- **Streaming & Chunking**: It processes huge `io.Reader` sources into `io.Writer` destinations by breaking them into fixed 32 KB plaintext chunks. This keeps our memory footprint tiny!
- **Sequential Nonces**: We start with a base 24-byte nonce and automatically increment it after every frame. No manual nonce management needed.
- **DoS Protection**: When decrypting, we validate frame lengths before allocating memory. This protects us from corrupted or malicious frames trying to exhaust our memory.
- **How to use**: Just grab `Encrypt(key, nonce, src, dst)` or `Decrypt(key, nonce, src, dst)` to start streaming data securely!

---

## 🗺️ DHT (`pkg/dht`)

### Purpose
This is our 256-bit **Kademlia Distributed Hash Table (DHT)** implementation. It's the brain of our peer discovery and routing. It allows us to find nodes, calculate XOR distances, and resolve IP addresses dynamically without any centralized server.

### Key Features & Usage
- **K-Buckets**: We maintain 256 buckets (indexed by Common Prefix Length), holding up to 20 peers each. It's fully thread-safe (`sync.RWMutex`).
- **Smart Eviction**: If a bucket is full and a new node wants in, we ping the oldest node first. We always prefer keeping long-lived, reliable nodes around over new random ones.
- **Address Discovery**: It includes a neat STUN-like mechanism to resolve public IPs and falls back to local IPs when needed.
- **How to use**: Spin up a `RoutingTable` and use the Kademlia coordinator to start sorting lookups and discovering peers on the network.

---

## 🕸️ P2P (`pkg/p2p`)

### Purpose
The `p2p` package is the bedrock of our network transport. It manages TCP connection lifecycles, handles our cryptographic handshakes, and takes care of message framing so we don't have to deal with messy raw sockets.

### Key Features & Usage
- **Transport Abstraction**: Built on clean `Peer` and `Transport` interfaces, meaning we can swap TCP for QUIC later if we want!
- **Solid Security**: Uses X25519 for ephemeral key exchange (zero persistent key exposure) and ChaCha20-Poly1305 for connection encryption. We even derive independent read/write keys via HKDF-SHA256 to stop reflection attacks dead in their tracks.
- **Deterministic Framing**: Uses a simple 4-byte length-prefix framing (`SampleDecoder`) so we never over-read buffers or run into stream race conditions.
- **How to use**: Initialize a `TCPTransport` with a socket. It handles `ListenAndAccept()` or `Dial(addr)` and automatically wraps the raw `net.Conn` with our `SecureHandshake` and `SecurePeer` layers.

---
<!-- Let me know if any of these packages need more features or if you find any bugs! I'll be constantly iterating on them. - Ankesh -->
