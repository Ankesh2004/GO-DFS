"use client"

import { ArrowRight, Star } from "lucide-react"
import { TerminalMockup } from "./terminal-mockup"

const terminalLines = [
  "$ ./dfs node start --port :7001 --bootstrap 52.15.x.x:7000 --api-port :9001 -i",
  "[node-a] Bootstrapping via 52.15.x.x:7000...",
  "[node-a] PeerExchange from 52.15.x.x:7000 → ID: a3f8c2b1, Listen: 52.15.x.x:7000",
  "[node-a] ✓ Connected to mesh. Listening on :7001 (API: :9001)",
  "",
  "dfs> store thesis.pdf",
  "✓ Encrypted, chunked (4 chunks × 256KB), replicated across 2 peers.",
  "  CID: b64730e9f1...",
  "",
  "dfs> get b64730e9f1... -o thesis.pdf",
  "✓ File retrieved, decrypted, and saved to: myFiles/thesis.pdf",
]

export function Hero() {
  return (
    <section
      id="hero"
      className="relative min-h-screen flex flex-col items-center justify-center px-4 pt-20 pb-32 overflow-hidden"
    >
      {/* Diagonal grid background */}
      <div className="absolute inset-0 diagonal-grid opacity-50" />
      
      {/* Radial gradient glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-gradient-to-br from-primary/10 via-secondary/5 to-transparent rounded-full blur-3xl pointer-events-none" />
      
      <div className="relative z-10 max-w-5xl mx-auto text-center">
        {/* Main title */}
        <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-black tracking-tight mb-6 gradient-text">
          GO-DFS
        </h1>
        
        {/* Tagline */}
        <p className="text-lg sm:text-xl md:text-2xl text-muted-foreground max-w-3xl mx-auto mb-10 leading-relaxed text-balance">
          A peer-to-peer distributed file system, built entirely from scratch in Go. 
          No IPFS. No libp2p. Every byte, understood.
        </p>
        
        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
          <a
            href="#quickstart"
            className="group inline-flex items-center gap-2 px-8 py-4 bg-primary text-primary-foreground font-semibold rounded-full transition-all duration-300 hover:scale-105 glow-cyan"
          >
            Get Started
            <ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-1" />
          </a>
          <a
            href="https://github.com/Ankesh2004/GO-DFS"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-8 py-4 border border-border text-foreground font-semibold rounded-full transition-all duration-300 hover:bg-card-hover hover:border-primary/50"
          >
            <Star className="w-5 h-5" />
            Star on GitHub
          </a>
        </div>
        
        {/* Terminal Mockup */}
        <TerminalMockup 
          title="user@node-a:~" 
          lines={terminalLines}
        />
      </div>
    </section>
  )
}
