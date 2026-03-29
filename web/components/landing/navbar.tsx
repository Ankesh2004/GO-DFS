"use client"

import { useState, useEffect } from "react"
import { Home, Zap, Box, Rocket, HelpCircle, Github } from "lucide-react"

const navItems = [
  { id: "hero", icon: Home, label: "Home" },
  { id: "features", icon: Zap, label: "Features" },
  { id: "architecture", icon: Box, label: "Architecture" },
  { id: "quickstart", icon: Rocket, label: "Quick Start" },
  { id: "faq", icon: HelpCircle, label: "FAQ" },
]

export function Navbar() {
  const [activeSection, setActiveSection] = useState("hero")
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    // Delay showing navbar for better initial experience
    const timer = setTimeout(() => setIsVisible(true), 500)
    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    const observerOptions = {
      root: null,
      rootMargin: "-30% 0px -30% 0px",
      threshold: 0.1,
    }

    const observerCallback = (entries: IntersectionObserverEntry[]) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          setActiveSection(entry.target.id)
        }
      })
    }

    const observer = new IntersectionObserver(observerCallback, observerOptions)

    navItems.forEach(({ id }) => {
      const element = document.getElementById(id)
      if (element) {
        observer.observe(element)
      }
    })

    return () => observer.disconnect()
  }, [])

  const scrollToSection = (id: string) => {
    setActiveSection(id)
    const element = document.getElementById(id)
    if (element) {
      element.scrollIntoView({ behavior: "smooth" })
    }
  }

  return (
    <nav
      className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-50 transition-all duration-500 ${
        isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-10"
      }`}
    >
      <div className="flex items-center gap-1 px-2 py-2 rounded-full glass">
        {navItems.map(({ id, icon: Icon, label }) => (
          <button
            key={id}
            onClick={() => scrollToSection(id)}
            className={`group relative p-3 rounded-full transition-all duration-300 ${
              activeSection === id
                ? "bg-primary/20 text-primary"
                : "text-muted-foreground hover:text-foreground hover:bg-card-hover"
            }`}
            aria-label={label}
          >
            <Icon className="w-5 h-5" />
            
            {/* Tooltip */}
            <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-foreground bg-popover border border-border rounded-md opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap">
              {label}
            </span>
          </button>
        ))}
        
        {/* Divider */}
        <div className="w-px h-6 bg-border mx-1" />
        
        {/* GitHub link */}
        <a
          href="https://github.com/Ankesh2004/GO-DFS"
          target="_blank"
          rel="noopener noreferrer"
          className="group relative p-3 rounded-full text-muted-foreground hover:text-foreground hover:bg-card-hover transition-all duration-300"
          aria-label="GitHub"
        >
          <Github className="w-5 h-5" />
          
          {/* Tooltip */}
          <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-foreground bg-popover border border-border rounded-md opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap">
            GitHub
          </span>
        </a>
      </div>
    </nav>
  )
}
