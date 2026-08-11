# GO-DFS Web Dashboard & Landing Site

Hey there! 👋 Welcome to the frontend of **GO-DFS** — my peer-to-peer distributed file system. 

This repository contains the Next.js web interface I built from scratch to provide a beautiful, interactive presentation of the GO-DFS system. It's not just a landing page; it's a full-fledged dashboard that gives you deep visibility into the cluster.

---

## ✨ Features

I designed the dashboard to give you a god-eye view of your P2P network. Here are the core dashboard features I've implemented:

### 🗺️ Network Topology Map (`/network`)
- Real-time visualization of all active nodes in the DHT.
- Interactive force-directed graph to see connections, XOR distance, and K-bucket distribution.
- Node health statuses and routing table insights.

### 📁 Distributed File Browser (`/files`)
- A sleek file explorer interface to interact with the GO-DFS cluster.
- Upload files directly through the browser. The dashboard automatically tracks chunks and CIDs as they are routed to the backend.
- Download, decrypt, and verify files seamlessly.
- View CID manifests and replication status for each file.

### 📊 Cluster Metrics (`/metrics`)
- Live telemetry from the cluster.
- Storage capacity, active connections, total chunks stored, and bandwidth usage.
- Re-replication alerts and heartbeat failure logs.

---

## 🏗️ Architecture & Routing

The app is built on **Next.js 16 (App Router)** and **React 19**, styled with **Tailwind CSS v4** and **shadcn/ui**. I used a dark-themed glassmorphism aesthetic because, let's be honest, it looks way cooler.

### Directory Structure & Routing

```text
web/
├── app/
│   ├── api/                # API Proxies communicating with the GO-DFS Go backend
│   ├── files/              # Distributed file browser dashboard route
│   ├── metrics/            # Cluster metrics dashboard route
│   ├── network/            # Network topology map route
│   ├── globals.css         # Custom dark theme variables, glow effects & animations
│   ├── layout.tsx          # Root layout & Next-themes config
│   └── page.tsx            # Main landing page
├── components/             # Reusable React components (UI, Dashboard, Landing)
├── hooks/                  # Custom React hooks (e.g., scroll reveals, toast notifications)
└── lib/                    # Utility functions (like class merging)
```

### 🔌 API Proxies (`/app/api`)

To avoid CORS issues and keep the frontend secure, I've built API route handlers inside `/app/api`. 
These act as proxies between the Next.js frontend and the local GO-DFS control API (usually running on `localhost:9001` or `:7000`). 

- `GET /api/nodes` -> Fetches the routing table for the topology map.
- `POST /api/upload` -> Handles multipart file uploads and streams them to the Go backend.
- `GET /api/metrics` -> Polls cluster health and telemetry data.

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v18.0.0+
- **Package Manager**: `npm` or `pnpm` (I personally use pnpm)
- The GO-DFS Go backend running locally (otherwise the API proxies won't have a target to hit).

### Installation

1. Clone and `cd` into the web directory:
   ```bash
   cd web
   ```

2. Install the dependencies:
   ```bash
   npm install
   # or
   pnpm install
   ```

### Development Server

Fire up the dev server:
```bash
npm run dev
# or
pnpm dev
```
Then open [http://localhost:3000](http://localhost:3000) in your browser.

### Building for Production

To build the optimized Next.js bundle:
```bash
npm run build
npm run start
```

### Linting

Run ESLint to check for code style and syntax issues:
```bash
npm run lint
```

---

## 💡 A Quick Note on the Design
I spent a lot of time getting the aesthetics right. The glowing accents, the terminal simulator on the landing page, and the smooth transitions—it's all built using custom CSS keyframes and Radix UI primitives. If you're poking around the CSS, check out `globals.css` for the custom glow tokens and dark mode palette (`#0a0a0f`).

## 📄 License
Built by Ankesh Gupta. Part of the **GO-DFS** open-source project.
