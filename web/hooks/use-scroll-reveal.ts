"use client"

import { useEffect, useState, RefObject } from "react"

interface UseScrollRevealOptions {
  threshold?: number
  rootMargin?: string
}

export function useScrollReveal(
  ref: RefObject<HTMLElement | null>,
  options: UseScrollRevealOptions = {}
): boolean {
  const [isVisible, setIsVisible] = useState(false)
  const { threshold = 0.15, rootMargin = "0px 0px -50px 0px" } = options

  useEffect(() => {
    const element = ref.current
    if (!element) return

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true)
          observer.disconnect()
        }
      },
      { threshold, rootMargin }
    )

    observer.observe(element)

    return () => observer.disconnect()
  }, [ref, threshold, rootMargin])

  return isVisible
}
