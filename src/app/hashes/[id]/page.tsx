'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScanHash } from '@/lib/types'
import { Activity, ServerCrash, ArrowLeft, ShieldCheck, ShieldAlert, BadgeCheck, XCircle } from 'lucide-react'

// Helper to convert PEM to ArrayBuffer
function pemToArrayBuffer(pem: string) {
  const b64 = pem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\n/g, '');
  const binary_string = window.atob(b64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to convert a DER-encoded signature to the raw (r,s) format WebCrypto expects.
function derToRaw(signature: ArrayBuffer): ArrayBuffer {
  console.log("DER to Raw Converter: Starting...");
  const signatureBytes = new Uint8Array(signature);
  if (signatureBytes[0] !== 0x30) {
    throw new Error('Invalid signature format: not a DER sequence.');
  }

  // Get length of R
  let rLength = signatureBytes[3];
  let rOffset = 4;

  // If R has a leading zero, skip it
  if (rLength === 33 && signatureBytes[rOffset] === 0x00) {
    rLength--;
    rOffset++;
  }
  const r = signatureBytes.slice(rOffset, rOffset + rLength);
  console.log(`DER to Raw: R (len=${r.length}):`, r);

  // Get length of S
  let sLength = signatureBytes[rOffset + rLength + 1];
  let sOffset = rOffset + rLength + 2;

  // If S has a leading zero, skip it
  if (sLength === 33 && signatureBytes[sOffset] === 0x00) {
    sLength--;
    sOffset++;
  }
  const s = signatureBytes.slice(sOffset, sOffset + sLength);
  console.log(`DER to Raw: S (len=${s.length}):`, s);

  if (r.length > 32 || s.length > 32) {
    throw new Error('Invalid signature format: R or S length is incorrect for P-256.');
  }

  // Concatenate R and S into a 64-byte raw signature
  const rawSignature = new Uint8Array(64);
  rawSignature.set(r, 32 - r.length);
  rawSignature.set(s, 64 - s.length);

  console.log("DER to Raw Converter: Finished. Raw Signature:", rawSignature);
  return rawSignature.buffer;
}


export default function HashDetailPage() {
  const params = useParams()
  const router = useRouter()
  const id = params.id as string

  const [hashDetail, setHashDetail] = useState<ScanHash | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [messageToVerify, setMessageToVerify] = useState('')
  const [isVerifying, setIsVerifying] = useState(false)
  const [verificationResult, setVerificationResult] = useState<'idle' | 'success' | 'failed'>('idle')
  const [verificationError, setVerificationError] = useState<string | null>(null)
  
  const fetchHashDetail = useCallback(async (hashId: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`https://api-tee.dooor.ai/v1/scans/hashs/${hashId}`)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      const data: ScanHash = await response.json()
      setHashDetail(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const handleVerification = async () => {
    if (!messageToVerify || !hashDetail) return;
    
    console.clear();
    console.log("--- Starting Signature Verification ---");

    setIsVerifying(true)
    setVerificationResult('idle')
    setVerificationError(null)

    try {
      // 1. Fetch the attested public key
      console.log("Step 1: Fetching TEE public key...");
      const keyRes = await fetch('https://api-tee.dooor.ai/v1/tee/attested-public-key')
      if (!keyRes.ok) throw new Error('Could not fetch TEE public key.')
      const { publicKey: publicKeyPem } = await keyRes.json()
      console.log("Public Key PEM:\n", publicKeyPem);

      // 2. Import the public key
      console.log("\nStep 2: Importing public key...");
      const keyBuffer = pemToArrayBuffer(publicKeyPem);
      const publicKey = await crypto.subtle.importKey(
        'spki',
        keyBuffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
      console.log("Public key imported successfully.", publicKey);

      // 3. Prepare the data that was signed
      console.log("\nStep 3: Preparing data for verification...");
      const originalMessage = `${hashDetail.messageId}:${messageToVerify}`
      console.log("Original message string to be verified:", originalMessage);

      const encoder = new TextEncoder()
      const dataToSign = encoder.encode(originalMessage)
      console.log("Original data buffer to be passed to verify():", dataToSign);
      
      // 4. Prepare the signature
      console.log("\nStep 4: Preparing signature...");
      const signatureB64 = hashDetail.hash;
      console.log("Signature from details (Base64):", signatureB64);
      
      const signatureDer = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0)).buffer;
      console.log("Signature decoded (DER format):", new Uint8Array(signatureDer));

      const signatureRaw = derToRaw(signatureDer);
      console.log("Signature converted to Raw format:", new Uint8Array(signatureRaw));

      // 5. Verify the signature
      console.log("\nStep 5: Verifying signature...");
      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        publicKey,
        signatureRaw,
        dataToSign
      );
      
      console.log("\n--- Verification Result ---");
      console.log("isValid:", isValid);

      setVerificationResult(isValid ? 'success' : 'failed')
    } catch (err) {
      console.error("--- VERIFICATION FAILED ---", err);
      setVerificationResult('failed')
      setVerificationError(err instanceof Error ? err.message : 'An unknown error occurred')
    } finally {
      setIsVerifying(false)
    }
  }

  useEffect(() => {
    if (id) {
      fetchHashDetail(id)
    }
  }, [id, fetchHashDetail])

  return (
    <div className="p-6">
      <Button onClick={() => router.back()} variant="outline" size="sm" className="mb-6 flex items-center gap-2">
        <ArrowLeft className="w-4 h-4" />
        Back
      </Button>
      <div className="space-y-6">
        <Card className="floating-card bg-secondary/30 border-secondary/50">
          <CardHeader>
            <CardTitle>Hash Details</CardTitle>
            <CardDescription>Detailed view of a specific scanned hash from the TEE.</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center h-64">
                <Activity className="w-8 h-8 animate-pulse text-primary" />
              </div>
            ) : error ? (
              <div className="flex items-center justify-center h-64 flex-col">
                <ServerCrash className="w-8 h-8 text-destructive" />
                <p className="mt-4 text-destructive font-medium">Error: {error}</p>
              </div>
            ) : hashDetail && (
              <div className="space-y-4 text-sm">
                {Object.entries(hashDetail).map(([key, value]) => (
                  <div key={key} className="flex flex-col md:flex-row md:items-center">
                    <strong className="capitalize w-full md:w-1/4 text-muted-foreground">{key.replace(/([A-Z])/g, ' $1')}:</strong>
                    <span className="font-mono text-xs break-all w-full md:w-3/4 bg-muted/30 p-2 rounded">{String(value)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="floating-card bg-secondary/30 border-secondary/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-primary" /> Signature Verification
            </CardTitle>
            <CardDescription>
              Paste the original message content to verify the signature (hash) against the TEE's public key.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="message-input">Original Message Content</Label>
              <Input
                id="message-input"
                placeholder='Paste the raw "message" content here'
                value={messageToVerify}
                onChange={(e) => setMessageToVerify(e.target.value)}
                disabled={isVerifying}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground mt-2">
                This should be the exact content of the `message` field from the AI response that was signed. For debugging, open your browser's developer console.
              </p>
            </div>
            <Button onClick={handleVerification} disabled={isVerifying || !messageToVerify || !hashDetail}>
              {isVerifying ? (
                <>
                  <Activity className="w-4 h-4 mr-2 animate-spin" /> Verifying...
                </>
              ) : (
                'Verify Signature'
              )}
            </Button>
            {verificationResult !== 'idle' && (
              <div className={`mt-4 p-4 rounded-lg flex items-center gap-3 ${
                verificationResult === 'success'
                  ? 'bg-tee-success/10 border-tee-success/20'
                  : 'bg-destructive/10 border-destructive/20'
              }`}>
                {verificationResult === 'success' ? (
                  <BadgeCheck className="w-8 h-8 text-tee-success flex-shrink-0" />
                ) : (
                  <XCircle className="w-8 h-8 text-destructive flex-shrink-0" />
                )}
                <div>
                  <h4 className={`font-bold ${
                    verificationResult === 'success' ? 'text-tee-success' : 'text-destructive'
                  }`}>
                    {verificationResult === 'success' ? 'Verification Successful' : 'Verification Failed'}
                  </h4>
                  <p className="text-sm">
                    {verificationResult === 'success' 
                      ? "The signature is valid for the provided message and was signed by the TEE's private key."
                      : "The signature is invalid. The message may have been altered, was not signed by the TEE, or there was a format error."
                    }
                  </p>
                  {verificationError && <p className="text-xs text-destructive mt-2">Error: {verificationError}</p>}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
} 