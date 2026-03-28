"use client"

import { useRef } from "react"
import { useScrollReveal } from "@/hooks/use-scroll-reveal"

const layers = [
  {
    color: "#3b82f6",
    layer: "Transport",
    pkg: "pkg/p2p",
    description: "Raw TCP with TLS 1.3 handshake. Length-prefixed framing. Stream vs message multiplexing. Platform-specific socket tuning.",
  },
  {
    color: "#7c3aed",
    layer: "DHT",
    pkg: "pkg/dht",
    description: "Kademlia-style distributed hash table. SHA-256 node IDs, XOR distance metric, k-bucket routing table with K=20 replication factor.",
  },
  {
    color: "#10b981",
    layer: "Storage",
    pkg: "internal/storage",
    description: "Content-addressed on-disk store. File chunker with 256KB blocks. CID index for file→chunk mapping. Tombstone store for delete propagation.",
  },
  {
    color: "#00e5ff",
    layer: "Server",
    pkg: "internal/server",
    description: "The brain. Message routing, peer exchange, relay forwarding, chunk replication audits, heartbeat failure detection, and the HTTP control API.",
  },
]

export function Architecture() {
  const sectionRef = useRef<HTMLElement>(null)
  const isVisible = useScrollReveal(sectionRef)

  return (
    <section
      id="architecture"
      ref={sectionRef}
      className="py-24 sm:py-32 px-4 bg-gradient-to-b from-transparent via-card/30 to-transparent"
    >
      <div className="max-w-5xl mx-auto">
        {/* Section header */}
        <div className={`text-center mb-16 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 gradient-text">
            System Architecture
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-balance">
            Four layers that make up the mesh, each built from raw TCP sockets up.
          </p>
        </div>

        {/* Architecture layers */}
        <div className="space-y-4">
          {layers.map((layer, index) => (
            <div
              key={layer.layer}
              className={`group relative flex flex-col sm:flex-row items-stretch rounded-xl border border-border bg-card overflow-hidden hover:bg-card-hover transition-all duration-300 ${
                isVisible ? `animate-fade-in-up stagger-${index + 1}` : "opacity-0"
              }`}
            >
              {/* Color accent bar */}
              <div
                className="w-full sm:w-2 h-2 sm:h-auto shrink-0"
                style={{ backgroundColor: layer.color }}
              />
              
              <div className="flex-1 p-6 flex flex-col sm:flex-row sm:items-center gap-4">
                {/* Layer name and package */}
                <div className="sm:w-48 shrink-0">
                  <h3 
                    className="text-xl font-bold mb-1"
                    style={{ color: layer.color }}
                  >
                    {layer.layer}
                  </h3>
                  <code className="text-sm text-muted-foreground font-mono bg-muted/50 px-2 py-1 rounded">
                    {layer.pkg}
                  </code>
                </div>
                
                {/* Description */}
                <p className="text-muted-foreground leading-relaxed flex-1">
                  {layer.description}
                </p>
              </div>
            </div>
          ))}
        </div>
        
        {/* Connection lines visualization */}
        <div className="hidden lg:flex justify-center mt-8">
          <div className="flex items-center gap-4 text-muted-foreground text-sm">
            <span className="w-3 h-3 rounded-full bg-[#3b82f6]" />
            <span>→</span>
            <span className="w-3 h-3 rounded-full bg-[#7c3aed]" />
            <span>→</span>
            <span className="w-3 h-3 rounded-full bg-[#10b981]" />
            <span>→</span>
            <span className="w-3 h-3 rounded-full bg-[#00e5ff]" />
            <span className="ml-4 font-mono">Bottom-up: TCP → DHT → Storage → Server</span>
          </div>
        </div>
      </div>
    </section>
  )
}
