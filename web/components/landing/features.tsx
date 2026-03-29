"use client"

import { useRef } from "react"
import { Network, Shield, Box, Globe, RefreshCw, Trash2 } from "lucide-react"
import { useScrollReveal } from "@/hooks/use-scroll-reveal"

const features = [
  {
    icon: Network,
    title: "Kademlia DHT",
    description: "XOR-distance routing, k-bucket tables, and iterative FIND_NODE lookups. Real Kademlia, not a wrapper around someone else's library.",
  },
  {
    icon: Shield,
    title: "AES-256 Encryption",
    description: "Every chunk is encrypted client-side with AES-256-CTR before it ever leaves your machine. Your key, your data. Even relay nodes can't read it.",
  },
  {
    icon: Box,
    title: "Content-Addressed Chunks",
    description: "Files are split into 256KB chunks, each keyed by SHA-256(encrypted_data). Dedup is automatic. CID = hash of the manifest.",
  },
  {
    icon: Globe,
    title: "NAT Traversal & Relay",
    description: "Nodes behind NAT communicate through relay peers with TTL-limited message forwarding. Works across the real internet, not just localhost.",
  },
  {
    icon: RefreshCw,
    title: "Automatic Replication",
    description: "Periodic audits detect under-replicated or over-replicated chunks. The mesh self-heals — no manual intervention.",
  },
  {
    icon: Trash2,
    title: "Tombstone Deletion",
    description: "Deletes propagate through the network via cryptographic tombstones. Chunks are garbage-collected across all peers.",
  },
]

export function Features() {
  const sectionRef = useRef<HTMLElement>(null)
  const isVisible = useScrollReveal(sectionRef)

  return (
    <section
      id="features"
      ref={sectionRef}
      className="py-24 sm:py-32 px-4"
    >
      <div className="max-w-6xl mx-auto">
        {/* Section header */}
        <div className={`text-center mb-16 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 gradient-text">
            Built Different. Built From Scratch.
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-balance">
            Every component — from the transport layer to the DHT — is hand-rolled. Zero external DFS dependencies.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <div
              key={feature.title}
              className={`group p-6 rounded-xl border border-border bg-card hover:bg-card-hover transition-all duration-300 hover:scale-[1.02] hover:border-primary/30 ${
                isVisible ? `animate-fade-in-up stagger-${index + 1}` : "opacity-0"
              }`}
            >
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                <feature.icon className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-xl font-semibold mb-2 text-foreground">
                {feature.title}
              </h3>
              <p className="text-muted-foreground leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
