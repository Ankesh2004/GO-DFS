"use client"

import { useEffect, useState, useRef } from "react"

interface TerminalMockupProps {
  title: string
  lines: string[]
  className?: string
}

export function TerminalMockup({ title, lines, className = "" }: TerminalMockupProps) {
  const [visibleLines, setVisibleLines] = useState<string[]>([])
  const [isVisible, setIsVisible] = useState(false)
  const terminalRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true)
          observer.disconnect()
        }
      },
      { threshold: 0.3 }
    )

    if (terminalRef.current) {
      observer.observe(terminalRef.current)
    }

    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    if (!isVisible || !lines || lines.length === 0) return

    setVisibleLines([])
    let currentLine = 0
    
    const interval = setInterval(() => {
      if (currentLine < lines.length) {
        const lineToAdd = lines[currentLine]
        if (lineToAdd !== undefined) {
          setVisibleLines(prev => [...prev, lineToAdd])
        }
        currentLine++
      } else {
        clearInterval(interval)
      }
    }, 120)

    return () => clearInterval(interval)
  }, [isVisible, lines])

  return (
    <div
      ref={terminalRef}
      className={`w-full max-w-3xl mx-auto rounded-xl overflow-hidden border border-border bg-[#0d0d14] shadow-2xl ${className}`}
    >
      {/* Terminal header */}
      <div className="flex items-center gap-3 px-4 py-3 bg-[#1a1a24] border-b border-border">
        <div className="terminal-dots flex gap-2">
          <span />
          <span />
          <span />
        </div>
        <span className="text-sm text-muted-foreground font-mono">{title}</span>
      </div>
      
      {/* Terminal content */}
      <div className="p-4 sm:p-6 font-mono text-sm sm:text-base text-left min-h-[300px] overflow-x-auto">
        {visibleLines.map((line, index) => {
          const text = line ?? ""
          const getColorClass = () => {
            if (text.startsWith("$") || text.startsWith("dfs>")) return "text-foreground"
            if (text.startsWith("✓")) return "text-accent"
            if (text.startsWith("[")) return "text-primary"
            return "text-muted-foreground"
          }
          return (
            <div 
              key={index} 
              className={`whitespace-pre ${getColorClass()}`}
            >
              {text || "\u00A0"}
            </div>
          )
        })}
        {visibleLines.length < lines.length && (
          <span className="inline-block w-2 h-5 bg-primary animate-pulse" />
        )}
      </div>
    </div>
  )
}
