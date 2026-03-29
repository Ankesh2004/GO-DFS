"use client"

import { useRef } from "react"
import { Cloud, Monitor, FileText } from "lucide-react"
import { useScrollReveal } from "@/hooks/use-scroll-reveal"

const steps = [
  {
    icon: Cloud,
    number: 1,
    title: "Start the Relay (Cloud)",
    description: "Spin up a public node on EC2 or any VPS. It acts as the bootstrap peer and NAT bridge.",
    code: "./dfs node start --port :7000 --relay --advertise <PUBLIC_IP>:7000",
  },
  {
    icon: Monitor,
    number: 2,
    title: "Join the Mesh (Local)",
    description: "Start your local node. It bootstraps through the relay, discovers peers, and builds its routing table.",
    code: "./dfs.exe node start --port :7001 --bootstrap <PUBLIC_IP>:7000 --api-port :9001 -i",
  },
  {
    icon: FileText,
    number: 3,
    title: "Store & Retrieve",
    description: "Store a file from any node — it gets encrypted, chunked, and replicated. Retrieve it from any other node using the CID.",
    code: `dfs> store my_file.txt
# CID: b64730e9f1...

dfs> get b64730e9f1... -o downloaded.txt
✓ File retrieved, decrypted, and saved.`,
  },
]

export function HowItWorks() {
  const sectionRef = useRef<HTMLElement>(null)
  const isVisible = useScrollReveal(sectionRef)

  return (
    <section
      id="quickstart"
      ref={sectionRef}
      className="py-24 sm:py-32 px-4"
    >
      <div className="max-w-4xl mx-auto">
        {/* Section header */}
        <div className={`text-center mb-16 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 gradient-text">
            Three Nodes. Three Steps. Real Networking.
          </h2>
        </div>

        {/* Timeline */}
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-8 top-0 bottom-0 w-px bg-gradient-to-b from-primary via-secondary to-accent hidden sm:block" />
          
          <div className="space-y-12">
            {steps.map((step, index) => (
              <div
                key={step.number}
                className={`relative flex flex-col sm:flex-row gap-6 ${
                  isVisible ? `animate-fade-in-up stagger-${index + 1}` : "opacity-0"
                }`}
              >
                {/* Step number circle */}
                <div className="relative z-10 w-16 h-16 rounded-full bg-background border-2 border-primary flex items-center justify-center shrink-0 glow-cyan">
                  <step.icon className="w-7 h-7 text-primary" />
                </div>
                
                {/* Content */}
                <div className="flex-1 pb-8">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-sm font-mono text-primary">Step {step.number}</span>
                  </div>
                  <h3 className="text-xl sm:text-2xl font-bold mb-2 text-foreground">
                    {step.title}
                  </h3>
                  <p className="text-muted-foreground mb-4 leading-relaxed">
                    {step.description}
                  </p>
                  
                  {/* Code block */}
                  <div className="rounded-lg bg-[#0d0d14] border border-border p-4 overflow-x-auto">
                    <pre className="text-sm font-mono text-foreground whitespace-pre-wrap">
                      <code>{step.code}</code>
                    </pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
