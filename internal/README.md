# GO-DFS Internal Architecture 🚀

<!-- hey it's me Ankesh, this is the internal architecture docs. I wrote it down so I don't forget how my own baby works lol -->

Welcome to the internal architecture of **GO-DFS**, a high-performance distributed file system written in Go. This directory contains the core logic that powers our cluster, divided into two main sub-systems: `server` and `storage`.

---

## 🏗️ Overview

The `internal/` directory is logically separated into:

- **Server (`internal/server/`)**: Handles all node-to-node communication, routing, metrics, HTTP API endpoints, and the complex replication logic.
- **Storage (`internal/storage/`)**: Manages the local on-disk storage, chunking, CID index mapping, and tombstone management for deleted chunks.

---

## 🌐 1. API & Endpoints (`server/api.go`)

Our HTTP API acts as the gateway for external clients to interact with GO-DFS. It abstracts away the complex chunking and routing mechanics.

- **Endpoints**: Supports standard operations like file upload, download, and delete.
- **Handler Logic**: Receives a file, pipes it to the chunker, and then initiates placement and replication across the cluster.

<!-- Ankesh's tip: Always keep the API layer thin! Let the background workers do the heavy lifting -->

---

## 🚏 2. Routing & DHT (`server/dht_lookup.go`, `server/placement.go`)

To ensure data is distributed evenly and can be found without a centralized master node, we use a Distributed Hash Table (DHT) based approach.

- **DHT Lookups (`dht_lookup.go`)**: Determines which node is responsible for a given chunk based on its Content Identifier (CID).
- **Placement (`placement.go`)**: When a new file is uploaded, this decides the initial distribution of its chunks across available peers.

---

## 🔄 3. Replication & Auditing (`server/replication.go`)

High availability is non-negotiable. 

- **Replication Loop**: Continuously runs to ensure the replication factor is met for every chunk.
- **Audit**: Nodes challenge each other to prove they still hold the chunks they claim to have. If a node goes offline, the replication audit kicks in to re-replicate missing chunks to other healthy nodes.

<!-- man, writing distributed consensus is hard. good thing the audit loop catches the edge cases 😂 -->

---

## 💾 4. Chunk Storage (`storage/chunker.go`, `storage/store.go`)

We don't store full files; we store chunks.

- **Chunking (`chunker.go`)**: Splits incoming large files into fixed-size (or rabin-fingerprinted) chunks.
- **CID Indexing (`cid_index.go`)**: Maps the cryptographic hash (CID) of a chunk to its physical location on the disk.
- **Chunk Ledger & Tombstones (`chunk_ledger.go`, `tombstone.go`)**: Tracks chunk references. When a file is deleted, tombstones are placed, and chunks are eventually garbage collected when their reference count drops to zero.

---

## 📊 5. Metrics & Telemetry (`server/metrics.go`)

We need to know what's happening under the hood.

- **Counters & Gauges**: Tracks active connections, chunk upload/download latency, disk usage per node, and replication lag.
- **Prometheus Integration**: Metrics are exposed via an HTTP endpoint for easy scraping and visualization.

<!-- Ankesh out! Remember to run the tests after changing anything in here. -->
