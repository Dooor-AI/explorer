import type { Metadata } from 'next'
import { GeistSans } from 'geist/font/sans'
import { GeistMono } from 'geist/font/mono'
import './globals.css'

export const metadata: Metadata = {
  title: 'TEE Explorer - Trusted Execution Environment Security Suite',
  description: 'Validate Google Cloud TEE attestation tokens and run transparent code audits to ensure you are communicating with a legitimate and secure Trusted Execution Environment.',
  icons: {
    icon: '/icon.ico',
  },
  openGraph: {
    title: 'TEE Explorer - Trusted Execution Environment Security Suite',
    description: 'Validate Google Cloud TEE attestation tokens and run transparent code audits to ensure you are communicating with a legitimate and secure Trusted Execution Environment.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'TEE Explorer - Trusted Execution Environment Security Suite',
    description: 'Validate Google Cloud TEE attestation tokens and run transparent code audits to ensure you are communicating with a legitimate and secure Trusted Execution Environment.',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`dark ${GeistSans.variable} ${GeistMono.variable}`}>
      <body>{children}</body>
    </html>
  )
}
