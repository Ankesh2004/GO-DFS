"use client"

import { useRef } from "react"
import { useScrollReveal } from "@/hooks/use-scroll-reveal"

const stats = [
  { label: "AES-256-CTR", description: "Client-side encryption" },
  { label: "SHA-256", description: "Content addressing" },
  { label: "K=20", description: "Replication factor" },
  { label: "256KB", description: "Chunk size" },
  { label: "TLS 1.3", description: "Transport security" },
  { label: "TTL=3", description: "Max relay hops" },
]

export function TechStats() {
  const sectionRef = useRef<HTMLElement>(null)
  const isVisible = useScrollReveal(sectionRef)

  return (
    <section
      ref={sectionRef}
      className="py-16 px-4 border-y border-border bg-gradient-to-r from-transparent via-card/50 to-transparent"
    >
      <div className="max-w-6xl mx-auto">
        <div className={`flex flex-wrap justify-center gap-4 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}>
          {stats.map((stat, index) => (
            <div
              key={stat.label}
              className={`group flex items-center gap-3 px-5 py-3 rounded-full border border-border bg-card hover:bg-card-hover hover:border-primary/30 transition-all duration-300 ${
                isVisible ? `stagger-${index + 1}` : ""
              }`}
            >
              <span className="font-mono font-bold text-primary">{stat.label}</span>
              <span className="text-muted-foreground text-sm">{stat.description}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
