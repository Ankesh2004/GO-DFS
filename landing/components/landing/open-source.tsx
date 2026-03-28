"use client"

import { useRef } from "react"
import { Github, AlertCircle, GitFork } from "lucide-react"
import { useScrollReveal } from "@/hooks/use-scroll-reveal"

const actions = [
    {
        icon: Github,
        title: "View on GitHub",
        description: "Explore the complete source code",
        href: "https://github.com/Ankesh2004/GO-DFS",
    },
    {
        icon: AlertCircle,
        title: "Report Issues",
        description: "Found a bug? Let us know",
        href: "https://github.com/Ankesh2004/GO-DFS/issues",
    },
    {
        icon: GitFork,
        title: "Fork Project",
        description: "Make it your own",
        href: "https://github.com/Ankesh2004/GO-DFS/fork",
    },
]

export function OpenSource() {
    const sectionRef = useRef<HTMLElement>(null)
    const isVisible = useScrollReveal(sectionRef)

    return (
        <section
            ref={sectionRef}
            className="py-24 sm:py-32 px-4"
        >
            <div className="max-w-4xl mx-auto">
                {/* Section header */}
                <div className={`text-center mb-12 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}>
                    <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 gradient-text">
                        Open Source & Yours to Hack
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-balance">
                        GO-DFS is completely open source. Dive into the code, break it, improve it, or fork it.
                    </p>
                </div>

                {/* Action cards */}
                <div className={`grid grid-cols-1 sm:grid-cols-3 gap-4 ${isVisible ? "animate-fade-in-up" : "opacity-0"}`}
                    style={{ animationDelay: "0.2s" }}>
                    {actions.map((action) => (
                        <a
                            key={action.title}
                            href={action.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="group flex flex-col items-center text-center p-6 rounded-xl border border-border bg-card hover:bg-card-hover hover:border-primary/30 transition-all duration-300 hover:scale-[1.02]"
                        >
                            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                                <action.icon className="w-6 h-6 text-primary" />
                            </div>
                            <h3 className="text-lg font-semibold mb-1 text-foreground">
                                {action.title}
                            </h3>
                            <p className="text-sm text-muted-foreground">
                                {action.description}
                            </p>
                        </a>
                    ))}
                </div>
            </div>
        </section>
    )
}
