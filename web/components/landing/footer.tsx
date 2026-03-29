import { Github, ExternalLink } from "lucide-react"

const projectLinks = [
  { label: "Features", href: "#features" },
  { label: "Architecture", href: "#architecture" },
  { label: "Quick Start", href: "#quickstart" },
  { label: "GitHub", href: "https://github.com/Ankesh2004/GO-DFS", external: true },
]

const communityLinks = [
  { label: "Issues", href: "https://github.com/Ankesh2004/GO-DFS/issues", external: true },
  { label: "Discussions", href: "https://github.com/Ankesh2004/GO-DFS/discussions", external: true },
  { label: "Contributing", href: "https://github.com/Ankesh2004/GO-DFS/blob/main/CONTRIBUTING.md", external: true },
]

export function Footer() {
  return (
    <footer className="border-t border-border py-12 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-10 mb-10">
          {/* Brand */}
          <div>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
                <span className="text-primary-foreground font-bold text-sm">DFS</span>
              </div>
              <span className="text-xl font-bold text-foreground">GO-DFS</span>
            </div>
            <p className="text-muted-foreground text-sm">
              Built from scratch, byte by byte.
            </p>
            <a
              href="https://github.com/Ankesh2004/GO-DFS"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 mt-4 text-muted-foreground hover:text-primary transition-colors"
            >
              <Github className="w-5 h-5" />
              <span>Star on GitHub</span>
            </a>
          </div>

          {/* Project links */}
          <div>
            <h4 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
              Project
            </h4>
            <ul className="space-y-2">
              {projectLinks.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    target={link.external ? "_blank" : undefined}
                    rel={link.external ? "noopener noreferrer" : undefined}
                    className="text-muted-foreground hover:text-primary transition-colors inline-flex items-center gap-1"
                  >
                    {link.label}
                    {link.external && <ExternalLink className="w-3 h-3" />}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Community links */}
          <div>
            <h4 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
              Community
            </h4>
            <ul className="space-y-2">
              {communityLinks.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-muted-foreground hover:text-primary transition-colors inline-flex items-center gap-1"
                  >
                    {link.label}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="pt-8 border-t border-border text-center text-sm text-muted-foreground">
          © {new Date().getFullYear()} GO-DFS. Built by Ankesh Gupta.
        </div>
      </div>
    </footer>
  )
}
