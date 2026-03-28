import type { Metadata, Viewport } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import './globals.css'

const inter = Inter({ 
  subsets: ['latin'],
  weight: ['400', '700', '900'],
  variable: '--font-inter',
})

const jetbrainsMono = JetBrains_Mono({ 
  subsets: ['latin'],
  weight: ['400'],
  variable: '--font-jetbrains-mono',
})

export const metadata: Metadata = {
  title: 'GO-DFS | Peer-to-Peer Distributed File System',
  description: 'A peer-to-peer distributed file system built entirely from scratch in Go. No IPFS. No libp2p. Every byte, understood.',
  keywords: ['distributed file system', 'p2p', 'Go', 'Kademlia', 'DHT', 'encryption', 'decentralized'],
  authors: [{ name: 'Ankesh Gupta' }],
  openGraph: {
    title: 'GO-DFS | Peer-to-Peer Distributed File System',
    description: 'A peer-to-peer distributed file system built entirely from scratch in Go.',
    type: 'website',
    url: 'https://github.com/Ankesh2004/GO-DFS',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'GO-DFS | Peer-to-Peer Distributed File System',
    description: 'A peer-to-peer distributed file system built entirely from scratch in Go.',
  },
}

export const viewport: Viewport = {
  themeColor: '#0a0a0f',
  width: 'device-width',
  initialScale: 1,
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
        {children}
        <Analytics />
      </body>
    </html>
  )
}
