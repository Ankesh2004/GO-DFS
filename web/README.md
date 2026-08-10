# GO-DFS Web Dashboard & Landing Site

A modern, responsive Next.js web interface and landing page for **GO-DFS** — a peer-to-peer distributed file system built from scratch in Go.

This package provides an interactive presentation of the GO-DFS system architecture, technical specifications, setup workflow, CLI terminal simulation, and open-source documentation.

---

## 🚀 Tech Stack

- **Framework**: [Next.js 16](https://nextjs.org/) (App Router) & [React 19](https://react.dev/)
- **Language**: [TypeScript 5.7](https://www.typescriptlang.org/)
- **Styling**: [Tailwind CSS v4](https://tailwindcss.com/) with custom dark theme, glassmorphism UI, glow accents, and CSS keyframe animations
- **UI Components**: [Radix UI](https://www.radix-ui.com/) primitives & [shadcn/ui](https://ui.shadcn.com/) component patterns
- **Icons**: [Lucide React](https://lucide.dev/)
- **Utilities**: `clsx`, `tailwind-merge`, `class-variance-authority`, `zod`, `react-hook-form`, `sonner`

---

## 📁 Directory Structure

```text
web/
├── app/
│   ├── globals.css         # Custom dark theme variables, glow tokens & keyframe animations
│   ├── layout.tsx          # Root layout & theme configuration
│   └── page.tsx            # Main landing page component tree
├── components/
│   ├── landing/            # Landing page sections & interactive components
│   │   ├── architecture.tsx    # 4-layer system architecture breakdown
│   │   ├── faq.tsx             # Expandable accordion answering core technical FAQs
│   │   ├── features.tsx        # Technical feature grid (DHT, Encryption, Chunks, etc.)
│   │   ├── footer.tsx          # Footer with repository links and copyright
│   │   ├── hero.tsx            # Hero section with primary CTAs and terminal mockup
│   │   ├── how-it-works.tsx    # 3-step cluster deployment and usage walkthrough
│   │   ├── navbar.tsx          # Floating glassmorphism navbar with scroll observer
│   │   ├── open-source.tsx     # GitHub integration cards (Repo, Issues, Fork)
│   │   ├── tech-stats.tsx      # Core protocol parameters badge ticker
│   │   └── terminal-mockup.tsx # Typewriter terminal simulator displaying CLI interaction
│   ├── theme-provider.tsx  # Next-themes wrapper
│   └── ui/                 # Reusable shadcn/ui components (accordion, button, card, dialog, etc.)
├── hooks/
│   ├── use-mobile.ts       # Viewport breakpoint detection hook
│   ├── use-scroll-reveal.ts# IntersectionObserver hook for scroll animations
│   └── use-toast.ts        # Toast notifications hook
├── lib/
│   └── utils.ts            # Utility functions (cn class merger)
├── next.config.mjs         # Next.js configuration
├── package.json            # Dependencies and scripts
├── postcss.config.mjs      # PostCSS setup for Tailwind CSS v4
└── tsconfig.json           # TypeScript configuration
```

---

## 📦 Key Components & Architecture

### 1. Navigation & Theme
- [`Navbar`](file:///c:/UNIVERSE/Projects/GO-DFS/web/components/landing/navbar.tsx): A floating glassmorphism navbar positioned at the bottom of the screen. Utilizes an `IntersectionObserver` to track the user's scroll position and auto-highlight the active section (`Hero`, `Features`, `Architecture`, `Quick Start`, `FAQ`).
- [`globals.css`](file:///c:/UNIVERSE/Projects/GO-DFS/web/app/globals.css): Enforces an immersive dark mode palette (`#0a0a0f`) with custom cyan (`#00e5ff`) and purple (`#7c3aed`) glow effects (`glow-cyan`, `glow-purple`), diagonal grid background pattern, and staggered scroll-reveal animations.

### 2. Terminal Simulator
- [`TerminalMockup`](file:///c:/UNIVERSE/Projects/GO-DFS/web/components/landing/terminal-mockup.tsx): Simulates a live P2P node session in a CLI window. Renders step-by-step terminal outputs with typewriter timing when scrolled into view:
  - Node initialization and public relay bootstrap (`./dfs node start ...`)
  - Routing table discovery (`PeerExchange`)
  - Client-side file encryption, 256KB block chunking, CID generation (`dfs> store <file>`)
  - File retrieval, decryption, and verification (`dfs> get <cid>`)

### 3. System Architecture Breakdown
- [`Architecture`](file:///c:/UNIVERSE/Projects/GO-DFS/web/components/landing/architecture.tsx): Visualizes the bottom-up layer architecture of GO-DFS:
  - **Transport Layer** (`pkg/p2p`): Raw TCP with TLS 1.3 encryption, length-prefixed framing, stream vs message multiplexing.
  - **DHT Layer** (`pkg/dht`): Kademlia routing table, SHA-256 node IDs, XOR distance metric, k-buckets ($K=20$).
  - **Storage Layer** (`internal/storage`): Content-addressed chunk store, 256KB block chunker, CID manifest index, tombstone store.
  - **Server Layer** (`internal/server`): Message routing, relay forwarding, peer exchange, heartbeat failure detection, chunk replication audits, and HTTP API control interface.

### 4. Technical Feature Highlights
- [`Features`](file:///c:/UNIVERSE/Projects/GO-DFS/web/components/landing/features.tsx) & [`TechStats`](file:///c:/UNIVERSE/Projects/GO-DFS/web/components/landing/tech-stats.tsx): Highlight key system properties:
  - **AES-256-CTR Client Encryption**: Data encrypted before transmission.
  - **SHA-256 Content Addressing**: Deduplication and immutable CIDs.
  - **NAT Traversal & TTL Relay**: Message forwarding across cloud VPS relays.
  - **Self-Healing Replication**: Automatic detection and re-replication of under-replicated chunks.
  - **Cryptographic Tombstones**: Secure cluster-wide garbage collection.

### 5. Quick Start Walkthrough
- [`HowItWorks`](file:///c:/UNIVERSE/Projects/GO-DFS/web/components/landing/how-it-works.tsx): Provides copyable code blocks guiding users through launching a bootstrap relay node on a cloud instance, connecting local peers behind NAT, and performing file storage/retrieval operations via the interactive REPL.

---

## 🛠️ Getting Started

### Prerequisites

- **Node.js**: v18.0.0 or higher
- **Package Manager**: `npm` or `pnpm`

### Installation

1. Navigate to the `web` directory:
   ```bash
   cd web
   ```

2. Install dependencies:
   ```bash
   npm install
   # or
   pnpm install
   ```

### Development Server

Run the development server:
```bash
npm run dev
# or
pnpm dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser to view the application.

### Building for Production

Build the optimized Next.js bundle:
```bash
npm run build
```

Start the production server:
```bash
npm run start
```

### Linting

Run ESLint to check for code style and syntax issues:
```bash
npm run lint
```

---

## 🔌 Integration with GO-DFS Backend

The dashboard documents the HTTP Control API and CLI interface exposed by the Go backend:
- Default Node P2P Port: `:7000` / `:7001`
- Default Node Control API: `http://localhost:9001`
- Protocol Parameters: Chunk size `256 KB`, Replication factor `K=20`, TTL Relay Max Hops `3`.

---

## 📄 License

Part of the **GO-DFS** open-source project. Built by Ankesh Gupta.
