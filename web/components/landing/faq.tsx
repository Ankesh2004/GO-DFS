"use client"

import { useRef, useState } from "react"
import { ChevronDown } from "lucide-react"
import { useScrollReveal } from "@/hooks/use-scroll-reveal"

const faqs = [
  {
    question: "How is this different from IPFS?",
    answer: "GO-DFS is a learning-first project built entirely from scratch. IPFS uses libp2p, Bitswap, and many abstraction layers. Here, every component — TCP transport, Kademlia DHT, chunk encoding — is written by hand to understand distributed systems from the ground up.",
  },
  {
    question: "Is my data encrypted?",
    answer: "Yes. Files are encrypted with AES-256-CTR using your personal key BEFORE chunking and distribution. Even relay nodes that forward your data cannot read it. The chunk key itself is SHA-256(encrypted_data), so even the key is derived from ciphertext.",
  },
  {
    question: "Can it work across the internet (not just localhost)?",
    answer: "Absolutely. The relay system enables NAT traversal. Run a bootstrap node on a VPS, and local nodes behind NAT can communicate through it. This has been tested with real EC2 instances.",
  },
  {
    question: "What happens if a node goes down?",
    answer: "The replication audit system detects missing replicas via periodic heartbeat checks. Under-replicated chunks are automatically re-replicated to healthy peers. Over-replicated chunks are pruned.",
  },
  {
    question: "Can I delete a file from the network?",
    answer: "Yes. Deletion uses cryptographic tombstones that propagate through the mesh. All peers holding chunks of that file will garbage-collect them within the GC window.",
  },
]

export function FAQ() {
  const sectionRef = useRef<HTMLElement>(null)
  const isVisible = useScrollReveal(sectionRef)
  const [openIndex, setOpenIndex] = useState<number | null>(null)

  const toggleItem = (index: number) => {
    setOpenIndex(openIndex === index ? null : index)
  }

  return (
    <section
      id="faq"
      ref={sectionRef}
      className="py-24 sm:py-32 px-4 bg-gradient-to-b from-transparent via-card/30 to-transparent"
    >
      <div className="max-w-3xl mx-auto">
        {/* Section header */}
        <div className={`text-center mb-12 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 gradient-text">
            Frequently Asked Questions
          </h2>
        </div>

        {/* FAQ items */}
        <div className={`space-y-4 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}
             style={{ animationDelay: "0.2s" }}>
          {faqs.map((faq, index) => (
            <div
              key={index}
              className="rounded-xl border border-border bg-card overflow-hidden"
            >
              <button
                onClick={() => toggleItem(index)}
                className="w-full flex items-center justify-between p-5 text-left hover:bg-card-hover transition-colors"
              >
                <span className="text-lg font-medium text-foreground pr-4">
                  {faq.question}
                </span>
                <ChevronDown
                  className={`w-5 h-5 text-muted-foreground shrink-0 transition-transform duration-300 ${
                    openIndex === index ? "rotate-180" : ""
                  }`}
                />
              </button>
              <div
                className={`overflow-hidden transition-all duration-300 ${
                  openIndex === index ? "max-h-96" : "max-h-0"
                }`}
              >
                <p className="px-5 pb-5 text-muted-foreground leading-relaxed">
                  {faq.answer}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
