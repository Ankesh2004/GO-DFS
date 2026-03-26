# GO-DFS

It's a peer-to-peer distributed file system, built entirely from scratch in Go — (Golang File System OR GOD File System :-)  no IPFS, libp2p, or DFS libraries. Think "minimal IPFS" where you understand every byte.

### NOTE THAT : WE HAVE LOGICALLY SINGLE OWNERSHIP FOR EACH CHUNK
because....
chunkKey = SHA256(encrypt(userKey, randomNonce, plaintext))
---> same userKey + chunk + plainText is very very rare.

---> so we don't need to worry about cross-user dedup, and deletion of chunk by other user.


