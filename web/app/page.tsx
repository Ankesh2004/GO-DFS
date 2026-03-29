import { Hero } from "@/components/landing/hero"
import { Features } from "@/components/landing/features"
import { Architecture } from "@/components/landing/architecture"
import { HowItWorks } from "@/components/landing/how-it-works"
import { TechStats } from "@/components/landing/tech-stats"
import { OpenSource } from "@/components/landing/open-source"
import { FAQ } from "@/components/landing/faq"
import { Footer } from "@/components/landing/footer"
import { Navbar } from "@/components/landing/navbar"

export default function HomePage() {
  return (
    <main className="min-h-screen w-full overflow-x-hidden bg-background">
      <Navbar />
      <Hero />
      <Features />
      <Architecture />
      <HowItWorks />
      <TechStats />
      <OpenSource />
      <FAQ />
      <Footer />
    </main>
  )
}
