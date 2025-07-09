import type { Metadata } from 'next'
import { GeistSans } from 'geist/font/sans'
import { GeistMono } from 'geist/font/mono'
import './globals.css'

export const metadata: Metadata = {
  title: 'TEE Dooor Explorer - Trusted Execution Environment Security Suite',
  description: 'Validate Google Cloud TEE attestation tokens and run transparent code audits to ensure you are communicating with a legitimate and secure Trusted Execution Environment.',
  icons: [
    {
      rel: 'icon',
      type: 'image/x-icon',
      sizes: '48x48',
      url: '/favicon.ico',
    },
    {
      rel: 'icon',
      type: 'image/png',
      sizes: '32x32',
      url: '/favicon-32x32.png',
    },
    {
      rel: 'icon',
      type: 'image/png',
      sizes: '16x16',
      url: '/favicon-16x16.png',
    },
    {
      rel: 'apple-touch-icon',
      sizes: '180x180',
      url: '/apple-touch-icon.png',
    },
  ],
  openGraph: {
    title: 'TEE Dooor Explorer - Trusted Execution Environment Security Suite',
    description: 'Validate Google Cloud TEE attestation tokens and run transparent code audits to ensure you are communicating with a legitimate and secure Trusted Execution Environment.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'TEE Dooor Explorer - Trusted Execution Environment Security Suite',
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
