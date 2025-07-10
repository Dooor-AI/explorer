'use client'

import React, { useState, useRef, useEffect } from 'react'
import { 
  Shield, 
  Zap, 
  Search, 
  FileCheck, 
  Key, 
  CheckCircle, 
  Activity,
  Code,
  BookOpen,
  Info,
  Lock,
  FileText,
  Calendar,
  AlertTriangle,
  Package,
  Globe,
  Wrench,
  Download,
  BrainCircuit,
  ListChecks,
  History,
  ShieldCheck,
  ChevronDown,
  BarChart
} from 'lucide-react'
import { 
  FaShieldAlt, 
  FaMicrochip, 
  FaLock, 
  FaCode, 
  FaServer, 
  FaNetworkWired, 
  FaEye, 
  FaFingerprint,
  FaTools,
  FaBug
} from 'react-icons/fa'
import { 
  MdError, 
  MdCheckCircle, 
  MdWarning,
  MdSecurity,
  MdBugReport
} from 'react-icons/md'
import * as jose from 'jose'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Badge } from './ui/badge'
import { 
  Sidebar, 
  SidebarHeader, 
  SidebarSection, 
  SidebarItem 
} from './ui/sidebar'
import { TEEAttestationValidator } from '@/lib/tee-api'
import { 
  TEEValidationReport, 
  TEEAuditResult, 
  TEEAuditHealth,
} from '@/lib/types'
import TeeOperations from './tee-operations'

type ActiveSection = 'operations' | 'live-tee' | 'attested-key' | 'manual-jwt' | 'auditor' | 'learn' | 'about'
type LearnTab = 'overview' | 'technical' | 'security' | 'implementation' | 'troubleshooting'

interface AttestedKeyResult {
  publicKey: string
  attestationJwt: string
  verification: {
    jwtVerified: boolean
    nonceMatches: boolean
    jwtClaims: jose.JWTPayload
    publicKeyHash: string
    eatNonce: string
  } | null
}

export default function TEEExplorer() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('operations')
  const [activeLearnTab, setActiveLearnTab] = useState<LearnTab>('overview')
  const [teeUrl, setTeeUrl] = useState('https://api-tee.dooor.ai')
  const [jwtToken, setJwtToken] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [validationResult, setValidationResult] = useState<TEEValidationReport | null>(null)
  const [auditorResult, setAuditorResult] = useState<TEEAuditResult | null>(null)
  const [auditorHealth, setAuditorHealth] = useState<TEEAuditHealth | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attestedKeyResult, setAttestedKeyResult] = useState<AttestedKeyResult | null>(null)
  const [isVerifyingKey, setIsVerifyingKey] = useState(false)
  const [loadingAction, setLoadingAction] = useState<string | null>(null)
  const [isTransparencyOpen, setIsTransparencyOpen] = useState(false)
  const auditorResultsRef = useRef<HTMLDivElement>(null)
  const validationResultsRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if ((auditorResult || auditorHealth || error) && activeSection === 'auditor') {
      setTimeout(() => {
        auditorResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    }
  }, [auditorResult, auditorHealth, error, activeSection])

  useEffect(() => {
    if ((validationResult || error) && activeSection === 'live-tee') {
      setTimeout(() => {
        validationResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    }
  }, [validationResult, error, activeSection])

  const validator = new TEEAttestationValidator({
    projectId: 'dooor-core',
    zone: 'us-central1-a',
    instanceName: 'tee-vm1'
  })

  const handleLiveTEEValidation = async (type: 'quick' | 'detailed' | 'security' | 'complete') => {
    setIsLoading(true)
    setError(null)
    setValidationResult(null)

    try {
      const response = await fetch(`${teeUrl}/v1/tee/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()
      const attestationJWT = typeof data === 'string' ? data : data.attestation_jwt

      if (!attestationJWT) {
        throw new Error('No attestation_jwt found in response')
      }

      let result: TEEValidationReport

      switch (type) {
        case 'quick':
          const isValid = await validator.isValidTEE(attestationJWT)
          result = {
            valid: isValid,
            summary: {
              trusted: isValid,
              hardware: 'Unknown',
              project: 'dooor-core',
              instance: 'tee-vm1',
              zone: 'us-central1-a'
            },
            errors: isValid ? [] : ['TEE validation failed']
          }
          break
        case 'detailed':
          const jwtResult = await validator.getValidationReport(attestationJWT)
          const securityResult = await validator.validateSecurityConfiguration(teeUrl)
          
          // Combine JWT validation with security information
          result = {
            ...jwtResult,
            summary: {
              ...jwtResult.summary,
              firewall_active: securityResult.summary.firewall_active,
              whitelisted_domains: securityResult.summary.whitelisted_domains,
              total_http_calls: securityResult.summary.total_http_calls,
              last_updated: securityResult.summary.last_updated
            },
            securityConfig: securityResult.securityConfig,
            securityErrors: securityResult.errors,
            securityWarnings: securityResult.warnings
          }
          break
        case 'security':
          result = await validator.validateSecurityConfiguration(teeUrl)
          break
        case 'complete':
          result = await validator.validateCompleteTEE(teeUrl)
          break
      }

      setValidationResult(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const handleAttestedKeyValidation = async () => {
    setIsVerifyingKey(true)
    setError(null)
    setAttestedKeyResult(null)

    let data: { publicKey: string, attestationJwt: string } | null = null

    try {
      const response = await fetch(`${teeUrl}/v1/tee/attested-public-key`)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      data = await response.json()
      const { publicKey, attestationJwt } = data as any

      const textEncoder = new TextEncoder()
      const keyData = textEncoder.encode(publicKey)
      const hashBuffer = await crypto.subtle.digest('SHA-256', keyData)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const publicKeyHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

      const jwksUrl = new URL('https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com')
      const JWKS = jose.createRemoteJWKSet(jwksUrl)
      
      const { payload: jwtClaims } = await jose.jwtVerify(attestationJwt, JWKS, {
        audience: 'tee-key-attestation',
      })

      const jwtVerified = true
      const eatNonce = jwtClaims.eat_nonce as string
      
      const nonceMatches = (eatNonce === publicKeyHash)
      
      setAttestedKeyResult({
        publicKey,
        attestationJwt,
        verification: {
          jwtVerified,
          nonceMatches,
          jwtClaims,
          publicKeyHash,
          eatNonce,
        }
      })

    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred')
      if (data) {
        setAttestedKeyResult({
          publicKey: data.publicKey,
          attestationJwt: data.attestationJwt,
          verification: null,
        })
      }
    } finally {
      setIsVerifyingKey(false)
    }
  }

  const handleManualJWTValidation = async (decodeOnly = false) => {
    if (!jwtToken.trim()) {
      setError('Please enter a JWT token')
      return
    }

    setIsLoading(true)
    setError(null)
    setValidationResult(null)

    try {
      if (decodeOnly) {
        const decoded = validator.decodeJWT(jwtToken)
        if (decoded) {
          setValidationResult({
            valid: true,
            summary: {
              trusted: true,
              hardware: 'Decoded Only',
              project: 'Manual',
              instance: 'Manual',
              zone: 'Manual'
            },
            claims: decoded.payload as Record<string, unknown>,
            errors: []
          })
        } else {
          throw new Error('Invalid JWT format')
        }
      } else {
        const result = await validator.getValidationReport(jwtToken)
        setValidationResult(result)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const handleAuditorAction = async (action: 'hash' | 'health' | 'verify' | 'run' | 'report' | 'logs') => {
    setLoadingAction(action)
    setError(null)
    setAuditorResult(null)
    setAuditorHealth(null)

    try {
      const endpoint = {
        hash: '/v1/tee/auditor/hash',
        health: '/v1/tee/auditor/health',
        verify: '/v1/tee/auditor/verify',
        run: '/v1/tee/auditor/run',
        report: '/v1/tee/auditor/results',
        logs: '/v1/tee/auditor/execution-log'
      }[action]

      const method = action === 'run' ? 'POST' : 'GET'
      const body = action === 'run' ? JSON.stringify({
        files: ['src/agents-nl/agents-nl.module.ts']
      }) : undefined

      const response = await fetch(`${teeUrl}${endpoint}`, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()

      if (action === 'health') {
        setAuditorHealth(data)
      } else {
        setAuditorResult({ ...data, action })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoadingAction(null)
    }
  }

  const renderContent = () => {
    switch (activeSection) {
      case 'operations':
        return <TeeOperations teeUrl={teeUrl} />
      case 'attested-key':
        return (
          <div className="space-y-6">
            <Card className="floating-card bg-secondary/30 border-secondary/50">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                    <ShieldCheck className="w-6 h-6 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-xl text-card-foreground">Attested Public Key</CardTitle>
                    <CardDescription className="text-muted-foreground">
                      Fetch the TEE public key and verify its cryptographic attestation.
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Button 
                  onClick={handleAttestedKeyValidation}
                  disabled={isVerifyingKey}
                  variant="default"
                  className="flex items-center gap-2 h-12 bg-secondary/70 text-secondary-foreground hover:bg-secondary/90 border border-secondary/50"
                >
                  {isVerifyingKey ? <Activity className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  Fetch & Verify Key
                </Button>
              </CardContent>
            </Card>

            <Card className="floating-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><Info className="w-5 h-5 text-primary"/> How It Works</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-card-foreground/90">
                <p>
                  This feature demonstrates a critical security guarantee of a Trusted Execution Environment (TEE): <strong>cryptographic attestation</strong>. It allows an external client (like your browser) to obtain the TEE's public key and receive mathematical proof that this key is genuine and originates from within the secure, isolated environment.
                </p>
                <div className="p-4 bg-muted/20 border border-muted/30 rounded-lg">
                  <h4 className="font-medium text-card-foreground mb-3">The Verification Flow:</h4>
                  <ol className="list-decimal list-inside space-y-2 text-xs">
                    <li><strong>Request:</strong> The explorer requests the attested public key from the Dooor TEE Platform.</li>
                    <li><strong>Response:</strong> The TEE returns its public key along with a specially crafted JSON Web Token (JWT), the `attestationJwt`.</li>
                    <li><strong>Hashing:</strong> The explorer computes the SHA-256 hash of the received public key.</li>
                    <li><strong>JWT Verification:</strong> The signature of the `attestationJwt` is verified against Google's public keys. This proves the JWT was genuinely issued by Google Cloud for a specific TEE instance.</li>
                    <li><strong>Nonce Extraction:</strong> Inside the verified JWT, we find a special claim called `eat_nonce`.</li>
                    <li><strong>Comparison:</strong> The `eat_nonce` value is compared with the public key hash calculated in step 3.</li>
                  </ol>
                </div>
                <div className="p-4 bg-tee-success/10 border border-tee-success/20 rounded-lg">
                  <div className="flex items-start gap-3">
                    <ShieldCheck className="w-8 h-8 text-tee-success mt-1 flex-shrink-0" />
                    <div>
                      <h4 className="font-medium text-tee-success">The "Aha!" Moment</h4>
                      <p className="text-xs text-tee-success/90">
                        If the `eat_nonce` (a "nonce" provided by the entity being attested) matches the hash of the public key, we have cryptographic proof. It confirms that the Google-signed TEE is attesting to the authenticity of this specific public key, effectively saying: "I am a real TEE, and I vouch for this public key."
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {(attestedKeyResult || error) && (
              <Card className="floating-card bg-secondary/20 border-secondary/40">
                <CardHeader>
                  <CardTitle className="text-lg text-card-foreground">Verification Result</CardTitle>
                </CardHeader>
                <CardContent>
                  {error && (
                    <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg mb-4">
                      <div className="flex items-center gap-2">
                        <MdError className="w-5 h-5 text-destructive" />
                        <p className="text-destructive font-medium">Error: {error}</p>
                      </div>
                    </div>
                  )}
                  {attestedKeyResult && (
                    <div className="space-y-6">
                      {attestedKeyResult.verification && (
                        <div className={`p-4 rounded-lg border ${
                          attestedKeyResult.verification.jwtVerified && attestedKeyResult.verification.nonceMatches
                            ? 'bg-tee-success/10 border-tee-success/20' 
                            : 'bg-destructive/10 border-destructive/20'
                        }`}>
                          <div className="flex items-center gap-3">
                            <div className="text-2xl">
                              {attestedKeyResult.verification.jwtVerified && attestedKeyResult.verification.nonceMatches ? (
                                <MdCheckCircle className="w-8 h-8 text-tee-success" />
                              ) : (
                                <MdError className="w-8 h-8 text-destructive" />
                              )}
                            </div>
                            <div>
                              <p className={`font-medium text-lg ${
                                attestedKeyResult.verification.jwtVerified && attestedKeyResult.verification.nonceMatches
                                  ? 'text-tee-success' : 'text-destructive'
                              }`}>
                                {attestedKeyResult.verification.jwtVerified && attestedKeyResult.verification.nonceMatches
                                  ? 'Verification Successful' : 'Verification Failed'}
                              </p>
                              <p className="text-sm text-muted-foreground">
                                {attestedKeyResult.verification.jwtVerified && attestedKeyResult.verification.nonceMatches
                                  ? 'The public key has been cryptographically attested by the TEE.'
                                  : 'The public key could not be verified.'
                                }
                              </p>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                        <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                          <Key className="w-4 h-4" />
                          TEE Public Key
                        </h4>
                        <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
                          {attestedKeyResult.publicKey}
                        </pre>
                      </div>

                      {attestedKeyResult.verification && (
                        <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                          <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                            <ShieldCheck className="w-4 h-4" />
                            Verification Details
                          </h4>
                          <div className="space-y-3 text-sm">
                            <div className="flex justify-between items-center">
                              <span className="text-muted-foreground">JWT Signature Verified:</span>
                              {attestedKeyResult.verification.jwtVerified ? <Badge variant="default" className="bg-tee-success/80 text-tee-success-foreground">✅ Verified</Badge> : <Badge variant="destructive">❌ Failed</Badge>}
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-muted-foreground">Nonce Matches Hash:</span>
                              {attestedKeyResult.verification.nonceMatches ? <Badge variant="default" className="bg-tee-success/80 text-tee-success-foreground">✅ Match</Badge> : <Badge variant="destructive">❌ Mismatch</Badge>}
                            </div>
                            <div>
                              <div className="text-muted-foreground text-xs mb-1">Computed SHA256(PublicKey)</div>
                              <pre className="text-xs font-mono bg-background/50 p-2 rounded border break-all">{attestedKeyResult.verification.publicKeyHash}</pre>
                            </div>
                            <div>
                              <div className="text-muted-foreground text-xs mb-1">JWT `eat_nonce` Claim</div>
                              <pre className="text-xs font-mono bg-background/50 p-2 rounded border break-all">{attestedKeyResult.verification.eatNonce}</pre>
                            </div>
                          </div>
                        </div>
                      )}

                      {attestedKeyResult.verification?.jwtClaims && (
                        <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                          <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                            <FileText className="w-4 h-4" />
                            Attestation JWT Claims
                          </h4>
                          <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
                            {JSON.stringify(attestedKeyResult.verification.jwtClaims, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        )
      case 'live-tee':
        return (
          <div className="space-y-6">
            {/* Header Section */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Main Connection Card */}
              <div className="lg:col-span-2">
                <Card className="floating-card bg-secondary/30 border-secondary/50">
                  <CardHeader className="pb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                        <Zap className="w-6 h-6 text-primary" />
                      </div>
                      <div>
                        <CardTitle className="text-xl text-card-foreground">Live TEE Validation</CardTitle>
                        <CardDescription className="text-muted-foreground">
                          Validate Dooor TEE platform attestation tokens and test security features in real-time
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {/* URL Input Section */}
                    <div className="p-4 rounded-lg bg-muted/20 border border-muted/30">
                      <div className="space-y-3">
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-muted-foreground" />
                          <Label htmlFor="teeUrl" className="text-card-foreground font-medium">Dooor TEE Platform URL</Label>
                        </div>
                                                  <Input
                            id="teeUrl"
                            value={teeUrl}
                            onChange={(e) => setTeeUrl(e.target.value)}
                            placeholder="https://api-tee.dooor.ai (Dooor TEE platform)"
                            className="bg-input/50 border-border/50 text-foreground h-11 font-mono text-sm"
                          />
                      </div>
                    </div>

                    {/* Action Buttons Grid */}
                    <div className="grid grid-cols-2 gap-3">
                      
                      <Button 
                        onClick={() => handleLiveTEEValidation('detailed')}
                        disabled={isLoading}
                        variant="default"
                        className="flex items-center gap-2 h-12 bg-secondary/70 text-secondary-foreground hover:bg-secondary/90 border border-secondary/50"
                      >
                        <Search className="w-4 h-4" />
                        <span className="hidden sm:inline">Detailed Report</span>
                        <span className="sm:hidden">Detailed</span>
                      </Button>
                      
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Status Info Card */}
              <div className="space-y-4">
                <Card className="floating-card bg-secondary/20 border-secondary/40">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-lg text-card-foreground flex items-center gap-2">
                      <Activity className="w-5 h-5 text-muted-foreground" />
                      Connection Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Status</span>
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${isLoading ? 'bg-yellow-500 animate-pulse' : 'bg-gray-400'}`} />
                        <span className="text-sm font-medium text-card-foreground">
                          {isLoading ? 'Connecting...' : 'Ready'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Server</span>
                      <span className="text-sm font-medium text-card-foreground truncate max-w-[120px]">
                        {teeUrl ? String(new URL(teeUrl).hostname) : 'Not set'}
                      </span>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Project</span>
                      <span className="text-sm font-medium text-card-foreground">dooor-core</span>
                    </div>
                  </CardContent>
                </Card>

                {/* Quick Info Card */}
                <Card className="floating-card bg-muted/10 border-muted/30">
                  <CardContent className="p-4">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <FileCheck className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm font-medium text-card-foreground">Validation Types</span>
                      </div>
                      <div className="space-y-1 text-xs text-muted-foreground">
                        <div>• Quick: Basic JWT verification</div>
                        <div>• Detailed: Full attestation report</div>
                        <div>• Security: Firewall & configuration</div>
                        <div>• Complete: All validations combined</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Results Section */}
            <div ref={validationResultsRef}>
            {(validationResult || error) && (
              <Card className="floating-card bg-secondary/20 border-secondary/40">
                <CardHeader className="border-b border-secondary/30">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                      <CheckCircle className="w-5 h-5 text-primary" />
                    </div>
                    <CardTitle className="text-lg text-card-foreground">Validation Results</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="pt-6">
                  {error && (
                    <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg mb-4">
                      <div className="flex items-center gap-2">
                        <MdError className="w-5 h-5 text-destructive" />
                        <p className="text-destructive font-medium">Error: {error}</p>
                      </div>
                    </div>
                  )}
                  
                  {validationResult && (
                    <div className="space-y-6">
                      {/* Main Status */}
                      <div className={`p-4 rounded-lg border ${validationResult.valid 
                        ? 'bg-tee-success/10 border-tee-success/20' 
                        : 'bg-destructive/10 border-destructive/20'
                      }`}>
                        <div className="flex items-center gap-3">
                          <div className="text-2xl">
                            {validationResult.valid ? <MdCheckCircle className="w-8 h-8 text-tee-success" /> : <MdError className="w-8 h-8 text-destructive" />}
                          </div>
                          <div>
                            <p className={`font-medium text-lg ${validationResult.valid ? 'text-tee-success' : 'text-destructive'}`}>
                              {validationResult.valid ? 'TEE Validation Successful' : 'TEE Validation Failed'}
                            </p>
                            <p className="text-sm text-muted-foreground">
                              {validationResult.valid ? 'Dooor TEE platform is authenticated and secure' : 'Issues found with Dooor TEE verification'}
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      {/* Summary Grid */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="p-4 bg-muted/20 rounded-lg border border-muted/30">
                          <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Trusted</div>
                          <div className="font-medium text-card-foreground">
                            {validationResult.summary?.trusted ? 'Yes' : 'No'}
                          </div>
                        </div>
                        <div className="p-4 bg-muted/20 rounded-lg border border-muted/30">
                          <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Hardware</div>
                          <div className="font-medium text-card-foreground">
                            {validationResult.summary?.hardware || 'Unknown'}
                          </div>
                        </div>
                        <div className="p-4 bg-muted/20 rounded-lg border border-muted/30">
                          <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Instance</div>
                          <div className="font-medium text-card-foreground">
                            {validationResult.summary?.instance || 'tee-vm1'}
                          </div>
                        </div>
                        <div className="p-4 bg-muted/20 rounded-lg border border-muted/30">
                          <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Zone</div>
                          <div className="font-medium text-card-foreground">
                            {validationResult.summary?.zone || 'us-central1-a'}
                          </div>
                        </div>
                      </div>

                      {/* Errors Section */}
                      {validationResult.errors && validationResult.errors.length > 0 && (
                        <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-lg">
                          <h4 className="font-medium text-destructive mb-2 flex items-center gap-2">
                            <MdWarning className="w-4 h-4" /> Issues Found
                          </h4>
                          <ul className="space-y-1">
                            {validationResult.errors.map((error, index) => (
                              <li key={index} className="text-sm text-destructive/90 flex items-start gap-2">
                                <span className="text-destructive/60">•</span>
                                {error}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Claims Details */}
                      {validationResult.claims && (
                        <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                          <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                            <Key className="w-4 h-4" />
                            Attestation Claims
                          </h4>
                          <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
                            {String(JSON.stringify(validationResult.claims, null, 2))}
                          </pre>
                        </div>
                      )}

                      {/* Security Summary */}
                      {(validationResult.summary.firewall_active !== undefined || validationResult.securityConfig) && (
                        <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                          <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                            <Shield className="w-4 h-4" />
                            Security Summary
                          </h4>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Firewall Active:</span>
                              <span className="text-card-foreground font-medium">
                                {validationResult.summary.firewall_active ? 'Yes' : 'No'}
                              </span>
                            </div>
                            {validationResult.summary.whitelisted_domains !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Whitelisted Domains:</span>
                                <span className="text-card-foreground font-medium">
                                  {validationResult.summary.whitelisted_domains}
                                </span>
                              </div>
                            )}
                            {validationResult.summary.total_http_calls !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Total HTTP Calls:</span>
                                <span className="text-card-foreground font-medium">
                                  {validationResult.summary.total_http_calls}
                                </span>
                              </div>
                            )}
                            {validationResult.summary.last_updated && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Last Updated:</span>
                                <span className="text-card-foreground font-medium text-xs">
                                  {validationResult.summary.last_updated}
                                </span>
                              </div>
                            )}
                          </div>

                          {/* Firewall Configuration */}
                          {validationResult.securityConfig?.allowed_domains && (
                            <div className="mt-4 pt-3 border-t border-muted/30">
                              <h5 className="font-medium text-card-foreground mb-2 flex items-center gap-2">
                                <MdSecurity className="w-4 h-4" /> Firewall Configuration
                              </h5>
                              <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
{String(JSON.stringify(validationResult.securityConfig.allowed_domains, null, 2))}
                              </pre>
                            </div>
                          )}

                          {/* Security Errors */}
                          {validationResult.securityErrors && validationResult.securityErrors.length > 0 && (
                            <div className="mt-4 pt-3 border-t border-muted/30">
                              <h5 className="font-medium text-destructive mb-2 flex items-center gap-2">
                                <MdBugReport className="w-4 h-4" /> Security Errors:
                              </h5>
                              <ul className="space-y-1">
                                {validationResult.securityErrors.map((error, index) => (
                                  <li key={index} className="text-xs text-destructive">• {error}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Security Warnings */}
                          {validationResult.securityWarnings && validationResult.securityWarnings.length > 0 && (
                            <div className="mt-4 pt-3 border-t border-muted/30">
                              <h5 className="font-medium text-yellow-600 mb-2 flex items-center gap-2">
                                <MdWarning className="w-4 h-4" /> Security Warnings:
                              </h5>
                              <ul className="space-y-1">
                                {validationResult.securityWarnings.map((warning, index) => (
                                  <li key={index} className="text-xs text-yellow-600">• {warning}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
            </div>
          </div>
        )

      case 'manual-jwt':
        return (
          <div className="space-y-6">
            <Card className="floating-card">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <Key className="w-6 h-6 text-primary" />
                  <div>
                    <CardTitle className="text-xl text-card-foreground">Manual JWT Validation</CardTitle>
                    <CardDescription className="text-muted-foreground">
                      Paste an attestation JWT token to validate or decode it manually.
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="jwtToken" className="text-card-foreground">Attestation JWT</Label>
                  <Input
                    id="jwtToken"
                    value={jwtToken}
                    onChange={(e) => setJwtToken(e.target.value)}
                    placeholder="eyJhbGciOiJSUzI1NiIs..."
                    className="bg-input border-border text-foreground font-mono"
                  />
                </div>
                
                <div className="flex gap-2">
                  <Button 
                    onClick={() => handleManualJWTValidation(false)}
                    disabled={isLoading || !jwtToken.trim()}
                    variant="default"
                    className="flex items-center gap-2"
                  >
                    {isLoading ? <Activity className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                    Validate JWT
                  </Button>
                  <Button 
                    onClick={() => handleManualJWTValidation(true)}
                    disabled={isLoading || !jwtToken.trim()}
                    variant="outline"
                    className="flex items-center gap-2"
                  >
                    <Search className="w-4 h-4" />
                    Decode Only
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Results for Manual JWT */}
            {(validationResult || error) && (
              <Card className="floating-card">
                <CardHeader>
                  <CardTitle className="text-lg text-card-foreground">JWT Results</CardTitle>
                </CardHeader>
                <CardContent>
                  {error && (
                    <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                      <div className="flex items-center gap-2">
                        <MdError className="w-4 h-4" />
                        <p className="text-destructive font-medium">Error: {error}</p>
                      </div>
                    </div>
                  )}
                  
                  {validationResult && (
                    <div className="space-y-4">
                      <div className={`p-4 rounded-lg border ${validationResult.valid 
                        ? 'bg-tee-success/10 border-tee-success/20' 
                        : 'bg-destructive/10 border-destructive/20'
                      }`}>
                        <div className={`font-medium flex items-center gap-2 ${validationResult.valid ? 'text-tee-success' : 'text-destructive'}`}>
                          {validationResult.valid ? (
                            <>
                              <MdCheckCircle className="w-5 h-5" />
                              JWT Valid
                            </>
                          ) : (
                            <>
                              <MdError className="w-5 h-5" />
                              JWT Invalid
                            </>
                          )}
                        </div>
                      </div>
                      
                      {validationResult.claims && (
                        <div className="p-4 bg-muted/30 rounded-lg">
                          <h4 className="font-medium text-card-foreground mb-2">Decoded Payload</h4>
                          <pre className="text-xs text-muted-foreground overflow-x-auto">
                            {validationResult.claims ? String(JSON.stringify(validationResult.claims, null, 2)) : 'No payload data'}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        )

      case 'auditor':
        return (
          <div className="space-y-6">
            {/* Header Section */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Main Auditor Card */}
              <div className="lg:col-span-2 space-y-6">
                <Card className="floating-card bg-secondary/30 border-secondary/50">
                  <CardHeader className="pb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                        <Code className="w-6 h-6 text-primary" />
                      </div>
                      <div>
                        <CardTitle className="text-xl text-card-foreground">TEE Transparent Code Auditor</CardTitle>
                        <CardDescription className="text-muted-foreground">
                          Execute transparent code auditing with cryptographic proof of execution
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {/* Info Section */}
                    <div className="p-4 rounded-lg bg-muted/20 border border-muted/30">
                      <div className="flex items-center gap-2 mb-3">
                        <Shield className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm font-medium text-card-foreground">Auditor Capabilities</span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
                        <div>• GitHub repository analysis</div>
                        <div>• Cryptographic proof generation</div>
                        <div>• File integrity verification</div>
                        <div>• TEE attestation validation</div>
                      </div>
                    </div>

                    {/* Action Buttons Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      <Button 
                        onClick={() => handleAuditorAction('health')}
                        disabled={!!loadingAction}
                        variant="default"
                        className="flex items-center gap-2 h-12 bg-secondary/70 text-secondary-foreground hover:bg-secondary/90 border border-secondary/50"
                      >
                        {loadingAction === 'health' ? <Activity className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
                        <span className="hidden sm:inline">Health Check</span>
                        <span className="sm:hidden">Health</span>
                      </Button>
                      
                      <Button 
                        onClick={() => handleAuditorAction('run')}
                        disabled={!!loadingAction}
                        variant="default"
                        className="flex items-center gap-2 h-12 bg-secondary/70 text-secondary-foreground hover:bg-secondary/90 border border-secondary/50"
                      >
                        {loadingAction === 'run' ? <Activity className="w-4 h-4 animate-spin" /> : <Code className="w-4 h-4" />}
                        <span className="hidden sm:inline">Run Audit</span>
                        <span className="sm:hidden">Run</span>
                      </Button>
                      
                      <Button 
                        onClick={() => handleAuditorAction('report')}
                        disabled={!!loadingAction}
                        variant="default"
                        className="flex items-center gap-2 h-12 bg-secondary/70 text-secondary-foreground hover:bg-secondary/90 border border-secondary/50"
                      >
                        {loadingAction === 'report' ? <Activity className="w-4 h-4 animate-spin" /> : <FileCheck className="w-4 h-4" />}
                        <span className="hidden sm:inline">Latest Report</span>
                        <span className="sm:hidden">Report</span>
                      </Button>
                      
                      <Button 
                        onClick={() => handleAuditorAction('logs')}
                        disabled={!!loadingAction}
                        variant="default"
                        className="flex items-center gap-2 h-12 bg-secondary/70 text-secondary-foreground hover:bg-secondary/90 border border-secondary/50"
                      >
                        {loadingAction === 'logs' ? <Activity className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                        <span className="hidden sm:inline">Audit Logs</span>
                        <span className="sm:hidden">Logs</span>
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {/* Transparency Information */}
                <Card className="floating-card bg-muted/10 border-muted/30">
                  <CardHeader 
                    className="cursor-pointer"
                    onClick={() => setIsTransparencyOpen(!isTransparencyOpen)}
                  >
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <Globe className="w-5 h-5 text-muted-foreground" />
                        <CardTitle className="text-lg text-card-foreground">
                          Transparency & Open Source
                        </CardTitle>
                      </div>
                      <ChevronDown
                        className={`w-5 h-5 text-muted-foreground transition-transform transform ${
                          isTransparencyOpen ? 'rotate-180' : ''
                        }`}
                      />
                    </div>
                    <CardDescription className="text-card-foreground/80 pt-2">
                      Complete transparency in code auditing with verifiable execution
                    </CardDescription>
                  </CardHeader>
                  {isTransparencyOpen && (
                    <CardContent>
                      <div className="text-sm text-card-foreground/90 space-y-4">
                        <div>
                          <h4 className="font-semibold text-card-foreground mb-2 flex items-center gap-2">
                            <Search className="w-4 h-4" /> How This Auditor Works:
                          </h4>
                          <div className="space-y-2 text-xs pl-6">
                            <div><strong>1. Auditor Code:</strong> Complete source code available on GitHub</div>
                            <div><strong>2. Hash Verification:</strong> SHA256 hash verification against public repository</div>
                            <div><strong>3. Gemini AI Analysis:</strong> Google&apos;s Gemini AI analyzes code for vulnerabilities</div>
                            <div><strong>4. Transparent Results:</strong> All audit results publicly available</div>
                            <div><strong>5. Verifiable Process:</strong> Every audit logged with timestamp and hash</div>
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="font-semibold text-card-foreground mb-2 flex items-center gap-2">
                            <Shield className="w-4 h-4" /> Security Guarantees:
                          </h4>
                          <div className="space-y-1 text-xs pl-6">
                            <div>• Auditor runs inside Google Cloud TEE (Trusted Execution Environment)</div>
                            <div>• Network access restricted to whitelisted domains only</div>
                            <div>• All outbound HTTP calls logged and publicly visible</div>
                            <div>• Auditor code integrity cryptographically verifiable</div>
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="font-semibold text-card-foreground mb-2 flex items-center gap-2">
                            <Wrench className="w-4 h-4" /> Analysis Categories:
                          </h4>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs pl-6">
                            <div>• Authentication & Authorization</div>
                            <div>• Input validation issues</div>
                            <div>• Data exposure risks</div>
                            <div>• Dependency security</div>
                            <div>• Business logic flaws</div>
                            <div>• OWASP compliance</div>
                          </div>
                        </div>
                    </div>
                  </CardContent>
                  )}
                </Card>
              </div>

              {/* Auditor Status Card */}
              <div className="space-y-4">
                <Card className="floating-card bg-secondary/20 border-secondary/40">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-lg text-card-foreground flex items-center gap-2">
                      <Activity className="w-5 h-5 text-muted-foreground" />
                      Auditor Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Status</span>
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${
                          isLoading ? 'bg-yellow-500 animate-pulse' : 
                          auditorHealth?.status === 'healthy' ? 'bg-green-500' : 'bg-gray-400'
                        }`} />
                        <span className="text-sm font-medium text-card-foreground">
                          {isLoading ? 'Working...' : auditorHealth?.status === 'healthy' ? 'Healthy' : 'Ready'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Source</span>
                      <span className="text-sm font-medium text-card-foreground">GitHub</span>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Verification</span>
                      <span className="text-sm font-medium text-card-foreground">TEE Signed</span>
                    </div>
                  </CardContent>
                </Card>

                {/* Quick Reference Card */}
                <Card className="floating-card bg-muted/10 border-muted/30">
                  <CardContent className="p-4">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <FileCheck className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm font-medium text-card-foreground">Audit Process</span>
                      </div>
                      <div className="space-y-1 text-xs text-muted-foreground">
                        <div>1. Health: Check auditor readiness</div>
                        <div>2. Run: Execute transparent audit</div>
                        <div>3. Results: Get analysis findings</div>
                        <div>4. Log: View execution trace</div>
                        <div>5. Verify: Confirm authenticity</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Results Section */}
            <div ref={auditorResultsRef}>
            {(auditorResult || auditorHealth || error) && (
              <Card className="floating-card bg-secondary/20 border-secondary/40">
                <CardHeader className="border-b border-secondary/30">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                      <FileCheck className="w-5 h-5 text-primary" />
                    </div>
                    <CardTitle className="text-lg text-card-foreground">Auditor Results</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="pt-6">
                  {error && (
                    <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg mb-4">
                      <div className="flex items-center gap-2">
                        <MdError className="w-5 h-5 text-destructive" />
                        <p className="text-destructive font-medium">Error: {error}</p>
                      </div>
                    </div>
                  )}
                  
                  {auditorHealth && (
                    <div className="space-y-6">
                      {/* Health Status */}
                      <div className={`p-4 rounded-lg border ${auditorHealth.status === 'healthy' 
                        ? 'bg-tee-success/10 border-tee-success/20' 
                        : 'bg-destructive/10 border-destructive/20'
                      }`}>
                        <div className="flex items-center gap-3">
                          <div className="text-2xl">
                            {auditorHealth.status === 'healthy' ? <MdCheckCircle className="w-8 h-8 text-tee-success" /> : <MdError className="w-8 h-8 text-destructive" />}
                          </div>
                          <div>
                            <p className={`font-medium text-lg ${auditorHealth.status === 'healthy' ? 'text-tee-success' : 'text-destructive'}`}>
                              {auditorHealth.status === 'healthy' ? 'Auditor System Healthy' : 'Auditor System Issues'}
                            </p>
                            <p className="text-sm text-muted-foreground">
                              {auditorHealth.status === 'healthy' ? 'All systems operational and ready for auditing' : 'Please check system configuration'}
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      {/* Health Details */}
                      <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                        <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                          <Activity className="w-4 h-4" />
                          Health Details
                        </h4>
                        <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
                          {String(JSON.stringify(auditorHealth, null, 2))}
                        </pre>
                      </div>
                    </div>
                  )}
                  
                  {auditorResult && (
                    <div className="space-y-6">
                        {auditorResult.action === 'hash' && (
                          <div className="space-y-4">
                      <div className="p-4 bg-tee-success/10 border border-tee-success/20 rounded-lg">
                        <div className="flex items-center gap-3">
                                <MdCheckCircle className="w-8 h-8 text-tee-success" />
                                <div>
                                  <p className="font-medium text-lg text-tee-success">✅ Auditor Hash Verified</p>
                                  <p className="text-sm text-muted-foreground">Auditor integrity cryptographically confirmed</p>
                                </div>
                              </div>
                            </div>
                            <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                              <h4 className="font-medium text-card-foreground mb-3">📦 Hash Information</h4>
                              <div className="text-sm space-y-2 text-card-foreground/90">
                                <div><strong>📦 Auditor Hash:</strong> {auditorResult.auditor_hash}</div>
                                <div><strong>📅 Last Updated:</strong> {auditorResult.last_updated}</div>
                                <div><strong>🔢 Version:</strong> {auditorResult.version}</div>
                                <div className="flex items-center gap-2">
                                  <Globe className="w-4 h-4 text-muted-foreground" />
                                  <strong>🌐 Source Repository:</strong> {auditorResult.source_repo}
                                </div>
                                {auditorResult.included_files && (
                                  <div>
                                    <strong>📁 Included Files:</strong>
                                    <ul className="list-disc pl-4 mt-1 text-xs">
                                      {auditorResult.included_files.map((file: string, i: number) => (
                                        <li key={i}>{file}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        )}

                        {auditorResult.action === 'verify' && (
                          <div className="space-y-4">
                            <div className="p-4 bg-tee-success/10 border border-tee-success/20 rounded-lg">
                              <div className="flex items-center gap-3">
                                <MdCheckCircle className="w-8 h-8 text-tee-success" />
                          <div>
                            <p className="font-medium text-lg text-tee-success">
                                    {auditorResult.auditor_verified ? '✅' : '❌'} Complete Auditor Verification
                            </p>
                                  <p className="text-sm text-muted-foreground">Full system verification complete</p>
                          </div>
                        </div>
                      </div>
                            <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                              <div className="text-sm space-y-2 text-card-foreground/90">
                                <div className="flex items-center gap-2">
                                  <Shield className="w-4 h-4 text-muted-foreground" />
                                  <strong>🛡️ Auditor Verified:</strong> {auditorResult.auditor_verified ? 'YES' : 'NO'}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Activity className="w-4 h-4 text-muted-foreground" />
                                  <strong>💚 Health Status:</strong> {auditorResult.health_status === 'healthy' ? '✅' : '❌'} {auditorResult.health_status?.toUpperCase()}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Lock className="w-4 h-4 text-muted-foreground" />
                                  <strong>🔐 Auditor Hash:</strong> {auditorResult.auditor_hash}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Calendar className="w-4 h-4 text-muted-foreground" />
                                  <strong>📅 Verification Time:</strong> {auditorResult.verification_timestamp}
                                </div>
                                {auditorResult.last_audit && (
                                  <div>
                                    <strong>📊 Latest Audit Available:</strong>
                                    <div className="pl-4 text-xs mt-1">
                                      <div>• Files: {auditorResult.last_audit.audited_files?.join(', ')}</div>
                                      <div>• Score: {auditorResult.last_audit.security_score}/100</div>
                                      <div>• Date: {auditorResult.last_audit.audit_timestamp}</div>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        )}

                        {auditorResult.action === 'run' && (
                          <div className="space-y-4">
                            <div className="p-4 bg-tee-success/10 border border-tee-success/20 rounded-lg">
                              <div className="flex items-center gap-3">
                                <MdCheckCircle className="w-8 h-8 text-tee-success" />
                                <div>
                                  <p className="font-medium text-lg text-tee-success">✅ Security Audit Completed</p>
                                  <p className="text-sm text-muted-foreground">{auditorResult.message || 'Transparent audit executed with cryptographic proof'}</p>
                                </div>
                              </div>
                            </div>
                            <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                              <h4 className="font-medium text-card-foreground mb-3">Audit results</h4>
                              <div className="text-sm space-y-2 text-card-foreground/90">
                                <div className="flex items-center gap-2">
                                  <FileText className="w-4 h-4 text-muted-foreground" />
                                  <strong>Files Analyzed:</strong>{auditorResult.summary?.files_analyzed || 'N/A'}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Calendar className="w-4 h-4 text-muted-foreground" />
                                  <strong>Audit Time:</strong> {auditorResult.transparency_proof?.timestamp || auditorResult.audit_timestamp || 'N/A'}
                                </div>
                                <div className="flex items-center gap-2">
                                  <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                                  <strong>Critical Findings:</strong> {auditorResult.summary?.critical_findings ?? 'N/A'}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Lock className="w-4 h-4 text-muted-foreground" />
                                  <strong>Auditor Hash:</strong> {auditorResult.verification?.auditor_hash || 'N/A'}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Package className="w-4 h-4 text-muted-foreground" />
                                  <strong>Session ID:</strong> {auditorResult.session_id || 'N/A'}
                                </div>
                              </div>
                              
                              {/* Verification Section */}
                              {auditorResult.verification && (
                                <div className="mt-4">
                                  <h5 className="font-medium text-card-foreground mb-2">Verification:</h5>
                                  <div className="text-sm space-y-1 text-card-foreground/90">
                                    <div><strong>Execution Chain Hash:</strong> <span className="font-mono text-xs">{auditorResult.verification.execution_chain_hash}</span></div>
                                    <div><strong>TEE Signature:</strong> <span className="font-mono text-xs">{auditorResult.verification.tee_signature}</span></div>
                                  </div>
                                </div>
                              )}

                              {/* Transparency Proof Section */}
                              {auditorResult.transparency_proof && (
                                <div className="mt-4">
                                  <h5 className="font-medium text-card-foreground mb-2">Transparency proof:</h5>
                                  <div className="text-sm space-y-1 text-card-foreground/90">
                                    <div><strong>Public Auditor URL:</strong> <a href={auditorResult.transparency_proof.public_auditor_url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline break-all">{auditorResult.transparency_proof.public_auditor_url}</a></div>
                                    <div><strong>Execution Steps:</strong> {auditorResult.transparency_proof.execution_steps}</div>
                                    <div><strong>Timestamp:</strong> {auditorResult.transparency_proof.timestamp}</div>
                                  </div>
                                </div>
                              )}

                              {auditorResult.findings && auditorResult.findings.length > 0 && (
                                <div className="mt-4">
                                  <h5 className="font-medium text-card-foreground mb-2">Findings ({auditorResult.findings.length}):</h5>
                                  <div className="space-y-2">
                                    {auditorResult.findings.map((finding: { type: string; message: string; line?: number; suggestion?: string }, i: number) => (
                                      <div key={i} className={`p-3 rounded border-l-4 ${
                                        finding.type === 'critical' ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20' :
                                        finding.type === 'error' ? 'border-red-500 bg-red-50 dark:bg-red-900/20' :
                                        finding.type === 'warning' ? 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20' :
                                        'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                                      }`}>
                                        <div className="text-sm">
                                          <strong>{finding.type?.toUpperCase()}:</strong> {finding.message}
                                          {finding.line && <div className="text-xs mt-1">Line: {finding.line}</div>}
                                          {finding.suggestion && <div className="text-xs mt-1">💡 {finding.suggestion}</div>}
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {auditorResult.gemini_analysis && (
                                <div className="mt-4">
                                  <h5 className="font-medium text-card-foreground mb-2">Ai analysis:</h5>
                                  <div className="text-sm text-card-foreground/90 whitespace-pre-wrap">{auditorResult.gemini_analysis}</div>
                                </div>
                              )}

                              {/* Raw JSON Response */}
                              <div className="mt-4">
                                <h5 className="font-medium text-card-foreground mb-2">Raw response:</h5>
                                <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border whitespace-pre-wrap">
                                  {String(JSON.stringify(auditorResult, null, 2))}
                                </pre>
                              </div>
                            </div>
                          </div>
                        )}

                        {auditorResult.action === 'report' && (
                          <div className="space-y-4">
                            <div className="p-4 bg-tee-success/10 border border-tee-success/20 rounded-lg">
                              <div className="flex items-center gap-3">
                                <FileCheck className="w-8 h-8 text-tee-success" />
                                <div>
                                  <p className="font-medium text-lg text-tee-success">Latest audit report</p>
                                  <p className="text-sm text-muted-foreground">Most recent security audit results</p>
                                </div>
                              </div>
                            </div>
                            <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                              <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border whitespace-pre-wrap">
                                {String(JSON.stringify(auditorResult, null, 2))}
                              </pre>
                            </div>
                          </div>
                        )}

                        {auditorResult.action === 'logs' && (
                          <div className="space-y-6">
                            <div className="p-4 bg-primary/10 border border-primary/20 rounded-lg">
                              <div className="flex items-center gap-3">
                                <History className="w-8 h-8 text-primary" />
                                <div>
                                  <p className="font-medium text-lg text-primary">Execution Log</p>
                                  <p className="text-sm text-muted-foreground">Session ID: {auditorResult.session_id}</p>
                                </div>
                              </div>
                            </div>

                            {auditorResult.execution_trace ? (
                              <div className="space-y-6">
                                {/* Verification Info */}
                                {auditorResult.verification_info && (
                                  <Card className="bg-muted/20">
                                    <CardHeader>
                                      <CardTitle className="flex items-center gap-2 text-md">
                                        <ShieldCheck className="w-5 h-5" />
                                        Verification Details
                                      </CardTitle>
                                    </CardHeader>
                                    <CardContent className="text-sm space-y-2">
                                      <div className="flex items-center gap-2">
                                        {auditorResult.verification_info.each_step_is_hashed ? <CheckCircle className="w-4 h-4 text-green-500" /> : <MdError className="w-4 h-4 text-red-500" />}
                                        Each step is hashed
                                      </div>
                                      <div className="flex items-center gap-2">
                                        {auditorResult.verification_info.hash_chain_verified ? <CheckCircle className="w-4 h-4 text-green-500" /> : <MdError className="w-4 h-4 text-red-500" />}
                                        Hash chain verified
                                      </div>
                                      <div>
                                        <strong>Cryptographic Proof:</strong>
                                        <p className="text-xs font-mono break-all bg-background/50 p-2 rounded mt-1">{auditorResult.verification_info.cryptographic_proof}</p>
                                      </div>
                                    </CardContent>
                                  </Card>
                                )}

                                {/* Execution Trace */}
                                <div>
                                  <h4 className="text-lg font-semibold mb-3 flex items-center gap-2"><ListChecks /> Execution Trace</h4>
                                  <div className="space-y-4">
                                    {auditorResult.execution_trace.map((item, index) => {
                                      const Icon = {
                                        download_auditor: Download,
                                        read_file: FileText,
                                        gemini_analysis: BrainCircuit,
                                      }[item.action] || History

                                      return (
                                        <Card key={index} className="bg-secondary/30">
                                          <CardHeader className="pb-3">
                                            <CardTitle className="text-md flex items-center justify-between">
                                              <div className="flex items-center gap-2">
                                                <Icon className="w-5 h-5" />
                                                Step {item.step}: <span className="font-mono text-sm">{item.action}</span>
                                              </div>
                                              <span className="text-xs font-normal text-muted-foreground">{new Date(item.timestamp).toLocaleString()}</span>
                                            </CardTitle>
                                          </CardHeader>
                                          <CardContent>
                                            <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
                                              {JSON.stringify(item.data, null, 2)}
                                            </pre>
                                            <div className="mt-2">
                                              <strong className="text-xs">Step Hash:</strong>
                                              <p className="text-xs font-mono break-all">{item.hash}</p>
                                            </div>
                                          </CardContent>
                                        </Card>
                                      )
                                    })}
                                  </div>
                                </div>

                                {/* Transparency Notes */}
                                {auditorResult.transparency_notes && (
                                  <div>
                                    <h4 className="text-lg font-semibold mb-3 flex items-center gap-2"><Info /> Transparency Notes</h4>
                                    <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
                                      {auditorResult.transparency_notes.map((note, index) => (
                                        <li key={index}>{note}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            ) : (
                              <div className="text-sm text-card-foreground/70 p-4 bg-muted/20 rounded-lg">
                                📋 No audit logs available yet
                              </div>
                            )}
                          </div>
                        )}

                        {!auditorResult.action && (
                      <div className="p-4 bg-muted/10 border border-muted/30 rounded-lg">
                        <h4 className="font-medium text-card-foreground mb-3 flex items-center gap-2">
                          <Code className="w-4 h-4" />
                              Raw Response
                        </h4>
                        <pre className="text-xs text-muted-foreground overflow-x-auto p-3 bg-background/50 rounded border">
                          {String(JSON.stringify(auditorResult, null, 2))}
                        </pre>
                      </div>
                        )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
            </div>
          </div>
        )

      case 'learn':
        const learnTabs = [
          { id: 'overview' as LearnTab, label: 'Overview', icon: BookOpen },
          { id: 'technical' as LearnTab, label: 'Technical', icon: FaMicrochip },
          { id: 'security' as LearnTab, label: 'Security', icon: FaShieldAlt },
          { id: 'implementation' as LearnTab, label: 'Guide', icon: FaTools },
          { id: 'troubleshooting' as LearnTab, label: 'Debug', icon: FaBug }
        ]

        return (
          <div className="space-y-6">
            {/* Learn Header */}
            <Card className="floating-card">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <BookOpen className="w-6 h-6 text-primary" />
                  <div>
                    <CardTitle className="text-xl text-card-foreground">TEE Knowledge Center</CardTitle>
                    <CardDescription className="text-card-foreground/80">
                      Complete guide to Trusted Execution Environments and Dooor implementation
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
            </Card>

            {/* Sub-tabs Navigation */}
            <Card className="floating-card">
              <CardContent className="p-0">
                <div className="flex overflow-x-auto">
                  {learnTabs.map((tab) => {
                    const Icon = tab.icon
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveLearnTab(tab.id)}
                        className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all ${
                          activeLearnTab === tab.id
                            ? 'border-primary text-primary bg-primary/10'
                            : 'border-transparent text-card-foreground/70 hover:text-card-foreground hover:bg-accent/50'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                        {tab.label}
                      </button>
                    )
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Tab Content */}
            {activeLearnTab === 'overview' && (
              <Card className="floating-card">
                <CardHeader>
                  <CardTitle className="text-xl text-card-foreground">Understanding Trusted Execution Environments</CardTitle>
                  <CardDescription className="text-card-foreground/80">
                    Comprehensive guide to TEE technology and Dooor revolutionary implementation
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="prose prose-sm max-w-none text-card-foreground/90">
                    <h3 className="text-lg font-semibold text-card-foreground mb-3">What are Trusted Execution Environments?</h3>
                    <p className="mb-4">
                      Trusted Execution Environments (TEEs) represent the next evolution in computing security, providing 
                      hardware-enforced isolation that creates secure enclaves within a system. These environments guarantee 
                      that code and data remain protected from unauthorized access, even from privileged software like 
                      operating systems, hypervisors, or administrative users.
                    </p>
                    
                    <h4 className="text-md font-semibold text-card-foreground mb-2">Core TEE Capabilities:</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Shield className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Hardware Isolation</h5>
                        </div>
                        <p className="text-sm text-card-foreground/90">
                          CPU-level protection using dedicated security processors and encrypted memory regions 
                          that prevent unauthorized access even from root-level software.
                        </p>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Key className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Cryptographic Attestation</h5>
                        </div>
                        <p className="text-sm text-card-foreground/90">
                          Hardware-signed proof of system integrity, allowing remote verification of the 
                          TEE authenticity and the code running within it.
                        </p>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Lock className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Runtime Protection</h5>
                        </div>
                        <p className="text-sm text-card-foreground/90">
                          Continuous monitoring of execution state with automatic detection and prevention 
                          of code tampering or unauthorized modifications.
                        </p>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Activity className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Secure Communication</h5>
                        </div>
                        <p className="text-sm text-card-foreground/90">
                          Encrypted channels for secure data exchange with external systems, ensuring 
                          end-to-end protection throughout the entire data lifecycle.
                        </p>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">The TEE Advantage</h3>
                    <p className="mb-4">
                      Traditional security models create a fundamental trust gap: while data can be protected at rest 
                      (encrypted storage) and in transit (TLS/SSL), it becomes vulnerable during processing. TEEs 
                      revolutionize this paradigm by extending cryptographic protection to data in use, creating 
                      the first truly end-to-end secure computing environment.
                    </p>

                    <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg mb-6">
                      <h4 className="text-md font-semibold text-blue-600 mb-2">
                        <FaShieldAlt className="w-4 h-4 inline mr-2" />
                        Security Model Comparison
                      </h4>
                      <div className="text-sm text-card-foreground/90 space-y-2">
                        <div><strong>Traditional Computing:</strong> Data encrypted → Decrypted for processing → Re-encrypted</div>
                        <div><strong>TEE Computing:</strong> Data remains encrypted throughout entire processing lifecycle</div>
                        <div><strong>Result:</strong> Zero-trust computing where even the infrastructure operator cannot access processed data</div>
                      </div>
                    </div>

                                         <h3 className="text-lg font-semibold text-card-foreground mb-3">Dooor&apos;s TEE Innovation</h3>
                     <p className="mb-4">
                     Dooor has pioneered several breakthrough innovations in TEE technology, combining cutting-edge 
                       hardware security with AI-powered auditing to create the most advanced secure computing platform available.
                     </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaMicrochip className="w-4 h-4 text-primary" />
                          <h4 className="font-semibold text-card-foreground">Next-Gen Hardware</h4>
                        </div>
                        <ul className="text-sm text-card-foreground/90 list-disc pl-4 space-y-1">
                          <li>AMD SEV-SNP with ECDSA P-384 attestation</li>
                          <li>NVIDIA H100 GPU confidential computing</li>
                          <li>Hardware Security Modules (HSM) integration</li>
                          <li>Quantum-resistant cryptographic algorithms</li>
                        </ul>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaCode className="w-4 h-4 text-primary" />
                          <h4 className="font-semibold text-card-foreground">AI-Powered Security</h4>
                        </div>
                        <ul className="text-sm text-card-foreground/90 list-disc pl-4 space-y-1">
                          <li>Autonomous LLM-based code auditor</li>
                          <li>Real-time threat detection and response</li>
                          <li>Behavioral anomaly detection systems</li>
                          <li>Continuous compliance monitoring</li>
                        </ul>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaEye className="w-4 h-4 text-primary" />
                          <h4 className="font-semibold text-card-foreground">Complete Transparency</h4>
                        </div>
                        <ul className="text-sm text-card-foreground/90 list-disc pl-4 space-y-1">
                          <li>Open-source codebase for community verification</li>
                          <li>Public audit trails and attestation logs</li>
                          <li>Reproducible builds with hash verification</li>
                          <li>Independent third-party security assessments</li>
                        </ul>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaNetworkWired className="w-4 h-4 text-primary" />
                          <h4 className="font-semibold text-card-foreground">Zero-Trust Architecture</h4>
                        </div>
                        <ul className="text-sm text-card-foreground/90 list-disc pl-4 space-y-1">
                          <li>Default-deny network policies</li>
                          <li>Explicit endpoint whitelisting</li>
                          <li>Deep packet inspection and monitoring</li>
                          <li>Automated threat response systems</li>
                        </ul>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Use Cases & Applications</h3>
                    <div className="grid grid-cols-1 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">🏥 Healthcare & Medical Research</h4>
                        <p className="text-sm text-card-foreground/90">
                          Process sensitive patient data and conduct medical AI analysis while maintaining HIPAA compliance 
                          and ensuring patient privacy through hardware-enforced isolation.
                        </p>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">🏦 Financial Services</h4>
                        <p className="text-sm text-card-foreground/90">
                          Execute high-frequency trading algorithms, fraud detection, and risk analysis on sensitive 
                          financial data with PCI DSS compliance and mathematical privacy guarantees.
                        </p>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">🏛️ Government & Defense</h4>
                        <p className="text-sm text-card-foreground/90">
                          Handle classified information processing, intelligence analysis, and secure communications 
                          with FedRAMP certification and defense-grade security standards.
                        </p>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">🧬 Research & Development</h4>
                        <p className="text-sm text-card-foreground/90">
                          Protect intellectual property, conduct confidential research, and collaborate securely 
                          on sensitive projects while maintaining competitive advantages.
                        </p>
                      </div>
                    </div>

                    <div className="p-4 bg-gradient-to-r from-primary/10 to-purple-500/10 border border-primary/20 rounded-lg">
                      <h4 className="text-md font-semibold text-primary mb-2">
                        <Zap className="w-4 h-4 inline mr-2" />
                        Ready to Experience TEE Security?
                      </h4>
                      <p className="text-sm text-card-foreground/90">
                                                Use the validation tools above to test Dooor&apos;s TEE implementation and see firsthand 
                         how cryptographic attestation provides mathematical proof of security. This live TEE 
                         environment demonstrates real-world secure computing capabilities.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Technical Deep Dive Tab */}
            {activeLearnTab === 'technical' && (
              <Card className="floating-card">
                <CardHeader>
                  <CardTitle className="text-xl text-card-foreground">Technical Deep Dive</CardTitle>
                  <CardDescription className="text-card-foreground/80">
                    Advanced cryptographic fundamentals and hardware security architecture
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="prose prose-sm max-w-none text-card-foreground/90">
                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Cryptographic Foundations</h3>
                    <p className="mb-4">
                      TEEs implement multiple layers of cryptographic protection to ensure data confidentiality, integrity, 
                      and authenticity. Understanding these cryptographic mechanisms is crucial for trusting the TEE environment.
                    </p>

                    <h4 className="text-md font-semibold text-card-foreground mb-2">Digital Signatures & JWT Attestation</h4>
                    <div className="grid grid-cols-1 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h5 className="font-semibold text-card-foreground mb-2">RSA-256 Signature Verification</h5>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          Every TEE attestation is signed using RSA-256 with a hardware-protected private key. 
                          The verification process ensures:
                        </p>
                        <ul className="text-xs text-card-foreground/80 list-disc pl-4 space-y-1">
                          <li><strong>Key Authenticity:</strong> Public key is bound to Google Cloud&apos;s root CA</li>
                          <li><strong>Message Integrity:</strong> Hash(Header + Payload) must match signature</li>
                          <li><strong>Non-repudiation:</strong> Only TEE hardware can generate valid signatures</li>
                          <li><strong>Replay Protection:</strong> Timestamps prevent token reuse attacks</li>
                        </ul>
                      </div>
                    </div>

                    <h4 className="text-md font-semibold text-card-foreground mb-2">Cryptographic Hash Algorithms</h4>
                    <p className="mb-4">
                      TEEs use multiple hash algorithms for different security purposes, creating an interconnected 
                      web of cryptographic proofs that ensure system integrity.
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Key className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">SHA-256 Code Measurement</h5>
                        </div>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          Every code component is measured using SHA-256:
                        </p>
                        <div className="text-xs text-card-foreground/80 font-mono bg-black/20 p-2 rounded">
                          H(bootloader) → H(kernel) → H(hypervisor) → H(app)
                        </div>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Lock className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">HMAC-SHA384 Memory</h5>
                        </div>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          Memory pages are protected with keyed hashes:
                        </p>
                        <div className="text-xs text-card-foreground/80 font-mono bg-black/20 p-2 rounded">
                          HMAC-SHA384(page_data, hardware_key)
                        </div>
                      </div>
                    </div>

                    <h4 className="text-md font-semibold text-card-foreground mb-2">Advanced Cryptographic Operations</h4>
                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <h5 className="font-semibold text-card-foreground mb-2">Merkle Tree Verification</h5>
                      <p className="text-sm text-card-foreground/90 mb-2">
                        TEE state is organized in Merkle trees, allowing efficient verification of large datasets:
                      </p>
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{`Root Hash = H(H(H(L1) + H(L2)) + H(H(L3) + H(L4)))
├── H(L1): Code segment hash
├── H(L2): Data segment hash  
├── H(L3): Stack region hash
└── H(L4): Heap region hash

Verification: O(log n) vs O(n) for full state`}
                      </pre>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Hardware Security Architecture</h3>
                                          <p className="mb-4">
                                          Dooor TEE infrastructure leverages state-of-the-art hardware security features to provide 
                       unprecedented protection for sensitive computations.
                      </p>

                    <div className="grid grid-cols-1 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaMicrochip className="w-4 h-4 text-primary" />
                          <h4 className="font-semibold text-card-foreground">AMD SEV-SNP Deep Dive</h4>
                        </div>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          Secure Encrypted Virtualization with Secure Nested Paging provides:
                        </p>
                        <ul className="text-xs text-card-foreground/80 list-disc pl-4 space-y-1">
                          <li><strong>Memory Encryption:</strong> AES-128 with unique keys per VM</li>
                          <li><strong>Integrity Protection:</strong> AES-GMAC for tampering detection</li>
                          <li><strong>Nested Page Tables:</strong> Hardware-enforced memory isolation</li>
                          <li><strong>Attestation Reports:</strong> ECDSA P-384 signed hardware state</li>
                          <li><strong>Key Derivation:</strong> Hardware RNG + VM-specific entropy</li>
                        </ul>
                      </div>
                      
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaServer className="w-4 h-4 text-primary" />
                          <h4 className="font-semibold text-card-foreground">NVIDIA H100 Confidential Computing</h4>
                        </div>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          GPU-accelerated secure computing with:
                        </p>
                        <ul className="text-xs text-card-foreground/80 list-disc pl-4 space-y-1">
                          <li><strong>Secure Multi-Instance GPU:</strong> Hardware-isolated contexts</li>
                          <li><strong>Memory Protection Keys:</strong> Hardware-enforced data access</li>
                          <li><strong>Encrypted GPU Memory:</strong> On-die encryption for VRAM</li>
                          <li><strong>Attestation Extension:</strong> GPU state included in measurements</li>
                          <li><strong>Secure Boot:</strong> Verified GPU firmware loading</li>
                        </ul>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Cryptographic Key Management</h3>
                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <h4 className="font-semibold text-card-foreground mb-2">Hardware Security Module (HSM) Integration</h4>
                      <p className="text-sm text-card-foreground/90 mb-2">
                        All cryptographic keys are managed through hardware-protected storage:
                      </p>
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{"Key Hierarchy:\nRoot Key (HSM) → Platform Key → VM Key → Application Key\n\nDerivation Function:\nHKDF-SHA256(parent_key, vm_measurement, salt)"}
                      </pre>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Advanced Attestation Mechanisms</h3>
                    <div className="grid grid-cols-1 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">Quote Generation Process</h4>
                        <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{`1. Measure Code: SHA-256(bootloader || kernel || app)
2. Collect Runtime Data: memory_layout + execution_state
3. Generate Nonce: HMAC-SHA256(timestamp, hardware_rng)
4. Create Quote: ECDSA-P384(measurements + nonce, platform_key)
5. Package JWT: Base64(header) + Base64(payload) + Base64(signature)`}
                        </pre>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">Remote Attestation Verification</h4>
                        <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{`Client Verification Steps:
1. Extract public key from JWT header
2. Verify key chain: public_key → intermediate_ca → root_ca  
3. Decode payload: measurements + runtime_claims
4. Verify signature: ECDSA_verify(message, signature, public_key)
5. Validate measurements: compare against expected values
6. Check freshness: verify timestamp within tolerance`}
                        </pre>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Variable Processing & Memory Protection</h3>
                    <p className="mb-4">
                      TEE environments implement sophisticated memory protection schemes to prevent data leakage 
                      and ensure variable confidentiality during processing.
                    </p>

                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <h4 className="font-semibold text-card-foreground mb-2">Secure Variable Lifecycle</h4>
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{`1. Allocation: secure_malloc() → encrypted memory region
2. Assignment: variable = encrypt(value, memory_key)  
3. Processing: decrypt → process → re-encrypt in place
4. Transmission: additional_encrypt(data, session_key)
5. Deallocation: secure_free() → crypto_shred(memory)`}
                      </pre>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Security & Auditing Tab */}
            {activeLearnTab === 'security' && (
              <Card className="floating-card">
                <CardHeader>
                  <CardTitle className="text-xl text-card-foreground">Security & AI Auditing</CardTitle>
                  <CardDescription className="text-card-foreground/80">
                    Multi-layered security architecture with autonomous AI monitoring
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="prose prose-sm max-w-none text-card-foreground/90">
                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Advanced AI Security Auditor</h3>
                    <p className="mb-4">
                      Dooor&apos;s revolutionary AI auditor is a sophisticated LLM-based system that operates within the TEE itself, 
                      providing continuous security monitoring, threat detection, and compliance validation. The auditor 
                      uses machine learning models trained on security patterns to detect anomalies and vulnerabilities 
                      in real-time.
                    </p>

                    <div className="grid grid-cols-1 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaEye className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Multi-Layer Code Analysis</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>Static Code Analysis:</strong> AST parsing, control flow analysis, dependency scanning</li>
                          <li><strong>Dynamic Behavior Analysis:</strong> Runtime execution patterns, memory access monitoring</li>
                          <li><strong>AI-Powered Vulnerability Detection:</strong> ML models trained on CVE databases</li>
                          <li><strong>Security Pattern Recognition:</strong> Anti-patterns, insecure coding practices</li>
                          <li><strong>Compliance Validation:</strong> OWASP, NIST, SOC2 standards checking</li>
                          <li><strong>Zero-Day Detection:</strong> Novel threat pattern identification</li>
                        </ul>
                      </div>
                      
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaFingerprint className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Cryptographic Attestation Engine</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>Hash Chain Generation:</strong> SHA-3 Keccak for quantum resistance</li>
                          <li><strong>Digital Timestamps:</strong> RFC 3161 compliant timestamp authority</li>
                          <li><strong>Merkle Proof Generation:</strong> Efficient batch verification mechanisms</li>
                          <li><strong>Non-Repudiation:</strong> ECDSA P-521 signatures for long-term validity</li>
                          <li><strong>Audit Trail Integrity:</strong> Tamper-evident blockchain-like structure</li>
                          <li><strong>Cross-Reference Validation:</strong> Independent verification through multiple sources</li>
                        </ul>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaShieldAlt className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Advanced Data Protection</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>PII Detection:</strong> NLP models for automatic sensitive data identification</li>
                          <li><strong>Dynamic Anonymization:</strong> k-anonymity, l-diversity, t-closeness algorithms</li>
                          <li><strong>Differential Privacy:</strong> Mathematical privacy guarantees with ε-δ bounds</li>
                          <li><strong>Homomorphic Encryption:</strong> Computation on encrypted data without decryption</li>
                          <li><strong>Secure Multi-Party Computation:</strong> Privacy-preserving collaborative analysis</li>
                          <li><strong>GDPR/CCPA Compliance:</strong> Automated privacy regulation adherence</li>
                        </ul>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Network Security Architecture</h3>
                    <p className="mb-4">
                                             Dooor implements a military-grade network security architecture with zero-trust principles, 
                      deep packet inspection, and AI-powered threat detection to prevent any unauthorized data 
                      exfiltration or malicious network activity.
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaLock className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Zero-Trust Network Model</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>Default Deny All:</strong> Comprehensive traffic blocking by default</li>
                          <li><strong>Explicit Allow Lists:</strong> Domain, IP, and port-specific permissions</li>
                          <li><strong>Certificate Pinning:</strong> TLS certificate validation against known good certs</li>
                          <li><strong>Protocol Restrictions:</strong> Only HTTPS/TLS 1.3+ allowed for external comms</li>
                          <li><strong>Geo-blocking:</strong> Geographic restrictions based on threat intelligence</li>
                        </ul>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FaNetworkWired className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Real-Time Traffic Analysis</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>Deep Packet Inspection:</strong> Content analysis for data exfiltration attempts</li>
                          <li><strong>Behavioral Analytics:</strong> ML-based anomaly detection for network patterns</li>
                          <li><strong>DNS Monitoring:</strong> DNS queries analyzed for malicious domains</li>
                          <li><strong>Bandwidth Throttling:</strong> Rate limiting to prevent bulk data extraction</li>
                          <li><strong>Connection Fingerprinting:</strong> TLS handshake analysis for threat detection</li>
                        </ul>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Security Monitoring & Response</h3>
                    <div className="grid grid-cols-1 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">Security Event Correlation</h4>
                        <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{`Security Information and Event Management (SIEM):
1. Log Collection: System calls, network events, file access
2. Event Correlation: ML clustering of related security events  
3. Threat Scoring: Risk assessment based on multiple indicators
4. Incident Response: Automated containment and investigation
5. Forensic Analysis: Detailed post-incident reconstruction`}
                        </pre>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">Automated Threat Response</h4>
                        <pre className="text-xs text-card-foreground/80 overflow-x-auto bg-black/20 p-2 rounded">
{`Incident Response Pipeline:
• Anomaly Detection → Risk Assessment → Response Classification
• Low Risk: Log + Monitor
• Medium Risk: Alert + Throttle  
• High Risk: Block + Quarantine + Notify
• Critical: Immediate Shutdown + Evidence Preservation`}
                        </pre>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Compliance & Certification</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <CheckCircle className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Security Standards</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>SOC 2 Type II:</strong> Service Organization Control compliance</li>
                          <li><strong>ISO 27001:</strong> Information security management systems</li>
                          <li><strong>FIPS 140-2 Level 3:</strong> Cryptographic module validation</li>
                          <li><strong>Common Criteria EAL4+:</strong> Security evaluation criteria</li>
                          <li><strong>FedRAMP Moderate:</strong> Federal risk authorization management</li>
                        </ul>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <FileCheck className="w-4 h-4 text-primary" />
                          <h5 className="font-semibold text-card-foreground">Privacy Regulations</h5>
                        </div>
                        <ul className="text-sm space-y-1 list-disc pl-4 text-card-foreground/90">
                          <li><strong>GDPR Article 32:</strong> Security of processing requirements</li>
                          <li><strong>CCPA Section 1798.150:</strong> California Consumer Privacy Act</li>
                          <li><strong>HIPAA Security Rule:</strong> Healthcare data protection standards</li>
                          <li><strong>PCI DSS Level 1:</strong> Payment card industry data security</li>
                          <li><strong>PIPEDA:</strong> Personal Information Protection in Canada</li>
                        </ul>
                      </div>
                    </div>

                    <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg mt-6">
                      <h4 className="text-md font-semibold text-green-600 mb-2">
                        <FaShieldAlt className="w-4 h-4 inline mr-2" />
                        Security Guarantee Promise
                      </h4>
                      <p className="text-sm text-card-foreground/90">
                      Dooor&apos;s TEE environment provides mathematical guarantees of data protection through hardware-enforced 
                         isolation, cryptographic attestation, and zero-knowledge architectures. The security model ensures 
                         that even Dooor&apos;s own operators cannot access sensitive data during processing.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Implementation Guide Tab */}
            {activeLearnTab === 'implementation' && (
              <Card className="floating-card">
                <CardHeader>
                  <CardTitle className="text-xl text-card-foreground">Implementation Guide</CardTitle>
                  <CardDescription className="text-card-foreground/80">
                    Practical deployment and configuration examples
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="prose prose-sm max-w-none text-card-foreground/90">
                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Google Cloud TEE Deployment</h3>
                    <p className="mb-4">
                      Deploy your application on Google Cloud&apos;s Confidential Computing infrastructure with 
                      AMD SEV-SNP technology for maximum security and performance.
                    </p>

                    <h4 className="text-md font-semibold text-card-foreground mb-2">Setup Commands:</h4>
                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto whitespace-pre-wrap">
{`# Create TEE-enabled VM instance
gcloud compute instances create tee-vm1 \\
  --zone=us-central1-a \\
  --machine-type=c3-highmem-48 \\
  --confidential-compute \\
  --enable-display-device \\
  --maintenance-policy=TERMINATE

# Configure firewall rules
gcloud compute firewall-rules create tee-secure-access \\
  --allow tcp:3000,tcp:22 \\
  --source-ranges=YOUR_IP/32 \\
  --target-tags=tee-instance`}
                      </pre>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">NestJS Application Setup</h3>
                    <p className="mb-4">
                      Configure your NestJS application for TEE deployment with proper attestation and security.
                    </p>

                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <h4 className="font-semibold text-card-foreground mb-2">Environment Configuration</h4>
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto">
{`# .env.tee
NODE_ENV=production
TEE_ENABLED=true
ATTESTATION_ENABLED=true
SECURITY_LEVEL=maximum
CONFIDENTIAL_COMPUTING=true
FIREWALL_STRICT_MODE=true`}
                      </pre>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Docker Configuration</h3>
                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto whitespace-pre-wrap">
{`# Dockerfile.tee
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "start:prod"]`}
                      </pre>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Verification Steps</h3>
                    <ul className="list-disc pl-6 mb-4 space-y-1">
                      <li><strong>Attestation Check:</strong> Verify TEE attestation tokens are generated correctly</li>
                      <li><strong>Network Security:</strong> Confirm firewall rules are properly configured</li>
                      <li><strong>Code Integrity:</strong> Validate all code hashes and signatures</li>
                      <li><strong>Runtime Monitoring:</strong> Check auditor logs for security events</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Troubleshooting Tab */}
            {activeLearnTab === 'troubleshooting' && (
              <Card className="floating-card">
                <CardHeader>
                  <CardTitle className="text-xl text-card-foreground">Troubleshooting & Debug</CardTitle>
                  <CardDescription className="text-card-foreground/80">
                    Common issues and debugging techniques for TEE environments
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="prose prose-sm max-w-none text-card-foreground/90">
                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Common Issues</h3>
                    
                    <div className="space-y-4">
                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">
                          <FaBug className="w-4 h-4 inline mr-2" />
                          Attestation Validation Failed
                        </h4>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          JWT token validation failing due to incorrect project ID or instance configuration.
                        </p>
                        <div className="text-xs text-card-foreground/70">
                          <strong>Solution:</strong> Verify project ID, zone, and instance name match exactly.
                        </div>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">
                          <FaBug className="w-4 h-4 inline mr-2" />
                          Network Connection Blocked
                        </h4>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          HTTPS requests failing due to strict firewall configuration.
                        </p>
                        <div className="text-xs text-card-foreground/70">
                          <strong>Solution:</strong> Add destination to whitelist or check firewall rules.
                        </div>
                      </div>

                      <div className="p-4 bg-muted/30 rounded-lg">
                        <h4 className="font-semibold text-card-foreground mb-2">
                          <FaBug className="w-4 h-4 inline mr-2" />
                          Auditor Agent Unhealthy
                        </h4>
                        <p className="text-sm text-card-foreground/90 mb-2">
                          AI auditor not responding or providing incomplete security reports.
                        </p>
                        <div className="text-xs text-card-foreground/70">
                          <strong>Solution:</strong> Restart auditor service and check memory allocation.
                        </div>
                      </div>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Debug Commands</h3>
                    <div className="p-4 bg-muted/30 rounded-lg mb-4">
                      <pre className="text-xs text-card-foreground/80 overflow-x-auto whitespace-pre-wrap">
{`# Check TEE status
curl -X POST https://your-tee.com/v1/tee/connect

# Verify auditor health
curl https://your-tee.com/v1/tee/auditor/health

# Get detailed logs
sudo journalctl -u tee-service -f

# Check firewall configuration
sudo iptables -L -n -v`}
                      </pre>
                    </div>

                    <h3 className="text-lg font-semibold text-card-foreground mb-3">Security Validation</h3>
                    <ul className="list-disc pl-6 mb-4 space-y-1">
                      <li><strong>Hash Verification:</strong> Compare code hashes against expected values</li>
                      <li><strong>Memory Protection:</strong> Verify encrypted memory regions are active</li>
                      <li><strong>Network Isolation:</strong> Test unauthorized connection blocking</li>
                      <li><strong>Attestation Chain:</strong> Validate complete chain of trust</li>
                    </ul>

                    <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg mt-4">
                      <h4 className="text-md font-semibold text-yellow-600 mb-2">
                        <FaTools className="w-4 h-4 inline mr-2" />
                        Best Practices
                      </h4>
                      <ul className="text-sm text-card-foreground/90 list-disc pl-4 space-y-1">
                        <li>Always verify attestation before processing sensitive data</li>
                        <li>Monitor auditor health continuously</li>
                        <li>Keep firewall rules minimal and explicit</li>
                        <li>Regular security audits and code reviews</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )

      case 'about':
        return (
          <div className="space-y-6">
            {/* Server Status Card */}
            <Card className="floating-card">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <FaServer className="w-6 h-6 text-primary" />
                  <div>
                    <CardTitle className="text-xl text-card-foreground">Dooor TEE Platform Status</CardTitle>
                    <CardDescription className="text-card-foreground/80">
                      Running on Google Cloud Confidential Spaces with AMD SEV-SNP technology
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="prose prose-sm max-w-none text-card-foreground/90">
                  <p className="mb-4">
                    This Dooor TEE platform instance is currently deployed on Google Cloud&apos;s Confidential Computing 
                    infrastructure, providing hardware-enforced security through AMD SEV-SNP technology. All 
                    computations run within a verified Trusted Execution Environment with cryptographic attestation.
                  </p>
                  
                  <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg mb-4">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-sm font-medium text-green-600">TEE Environment Active</span>
                  </div>
                </div>
                
                {/* Server Configuration */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-card-foreground mb-3">Server Configuration</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-muted/30 rounded-lg border border-muted/50">
                      <div className="flex items-center gap-2 mb-2">
                        <FaMicrochip className="w-4 h-4 text-primary" />
                        <h4 className="font-semibold text-card-foreground">Project ID</h4>
                      </div>
                      <p className="text-sm text-card-foreground/80 font-mono bg-background/50 px-2 py-1 rounded">
                        dooor-core
                      </p>
                    </div>
                    
                    <div className="p-4 bg-muted/30 rounded-lg border border-muted/50">
                      <div className="flex items-center gap-2 mb-2">
                        <FaNetworkWired className="w-4 h-4 text-primary" />
                        <h4 className="font-semibold text-card-foreground">Zone</h4>
                      </div>
                      <p className="text-sm text-card-foreground/80 font-mono bg-background/50 px-2 py-1 rounded">
                        us-central1-a
                      </p>
                    </div>
                    
                    <div className="p-4 bg-muted/30 rounded-lg border border-muted/50">
                      <div className="flex items-center gap-2 mb-2">
                        <FaServer className="w-4 h-4 text-primary" />
                        <h4 className="font-semibold text-card-foreground">Instance Name</h4>
                      </div>
                      <p className="text-sm text-card-foreground/80 font-mono bg-background/50 px-2 py-1 rounded">
                        tee-vm1
                      </p>
                    </div>
                    
                    <div className="p-4 bg-muted/30 rounded-lg border border-muted/50">
                      <div className="flex items-center gap-2 mb-2">
                        <FaCode className="w-4 h-4 text-primary" />
                        <h4 className="font-semibold text-card-foreground">Version</h4>
                      </div>
                      <p className="text-sm text-card-foreground/80 font-mono bg-background/50 px-2 py-1 rounded">
                        1.0.0
                      </p>
                    </div>
                  </div>
                </div>

                {/* Security Features */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-card-foreground mb-3">Security Features</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                      <div className="flex items-center gap-2 mb-1">
                        <FaShieldAlt className="w-4 h-4 text-blue-500" />
                        <span className="text-sm font-medium text-blue-600">Hardware TEE</span>
                      </div>
                      <p className="text-xs text-card-foreground/70">AMD SEV-SNP</p>
                    </div>
                    
                    <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg">
                      <div className="flex items-center gap-2 mb-1">
                        <FaFingerprint className="w-4 h-4 text-purple-500" />
                        <span className="text-sm font-medium text-purple-600">Attestation</span>
                      </div>
                      <p className="text-xs text-card-foreground/70">Cryptographic</p>
                    </div>
                    
                    <div className="p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
                      <div className="flex items-center gap-2 mb-1">
                        <FaLock className="w-4 h-4 text-green-500" />
                        <span className="text-sm font-medium text-green-600">Firewall</span>
                      </div>
                      <p className="text-xs text-card-foreground/70">Strict Rules</p>
                    </div>
                  </div>
                </div>

                {/* Open Source Information */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-card-foreground mb-3">Open Source Frontend</h3>
                  
                  <div className="p-4 bg-muted/20 border border-muted/40 rounded-lg">
                    <div className="flex items-start gap-3">
                      <FaCode className="w-5 h-5 text-primary mt-1" />
                      <div className="flex-1">
                        <p className="text-sm text-card-foreground/90 mb-3">
                          This is an open source frontend application that performs security validations against the Dooor TEE server infrastructure. 
                          The complete source code, documentation, and contribution guidelines are publicly available for transparency and community collaboration.
                        </p>
                        
                        <div className="flex items-center gap-2 p-3 bg-primary/10 border border-primary/20 rounded-lg">
                          <FaEye className="w-4 h-4 text-primary" />
                          <span className="text-sm font-medium text-primary">
                            Repository: 
                            <a 
                              href="https://github.com/Dooor-AI/explorer" 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="ml-1 underline hover:text-primary/80 transition-colors"
                            >
                              https://github.com/Dooor-AI/explorer
                            </a>
                          </span>
                        </div>
                        
                        <div className="mt-3 text-xs text-card-foreground/70">
                          <p>Built with Next.js, TypeScript, and Tailwind CSS • Licensed under MIT</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar with secondary color */}
      <Sidebar className="shrink-0 bg-secondary">
        <SidebarHeader
          title="TEE Explorer"
          subtitle="Security Suite"
          logo={
            <div className="w-20 h-20 ">
              <img 
                src="/logo-ui.png" 
                alt="dooor Logo" 
                className="w-full h-full object-contain"
              />
            </div>
          }
        />
        
        <div className="flex-1 overflow-y-auto">
          <SidebarSection title="Main">
            <SidebarItem
              icon={BarChart}
              label="Operations"
              isActive={activeSection === 'operations'}
              onClick={() => setActiveSection('operations')}
            />
            <SidebarItem
              icon={Zap}
              label="Live TEE"
              isActive={activeSection === 'live-tee'}
              onClick={() => setActiveSection('live-tee')}
            />
            <SidebarItem
              icon={ShieldCheck}
              label="Attested Key"
              isActive={activeSection === 'attested-key'}
              onClick={() => setActiveSection('attested-key')}
            />
            <SidebarItem
              icon={Code}
              label="Code Auditor"
              isActive={activeSection === 'auditor'}
              onClick={() => setActiveSection('auditor')}
            />
            <SidebarItem
              icon={Key}
              label="Manual JWT"
              isActive={activeSection === 'manual-jwt'}
              onClick={() => setActiveSection('manual-jwt')}
            />
          </SidebarSection>
          
          <SidebarSection title="Other">
            <SidebarItem
              icon={BookOpen}
              label="Learn"
              isActive={activeSection === 'learn'}
              onClick={() => setActiveSection('learn')}
            />
            <SidebarItem
              icon={Info}
              label="Server"
              isActive={activeSection === 'about'}
              onClick={() => setActiveSection('about')}
            />
          </SidebarSection>
        </div>
      </Sidebar>

      {/* Main Content - Black background */}
      <div className="flex-1 overflow-y-auto bg-background">
        {/* Alpha Platform Warning Banner */}
        <div className="sticky top-0 z-50 bg-yellow-500/20 border-b border-yellow-500/30 backdrop-blur-sm">
          <div className="px-6 py-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
<MdWarning className="w-5 h-5 text-yellow-500" />
                <span className="text-sm font-medium text-yellow-600">ALPHA PLATFORM</span>
              </div>
              <div className="flex-1">
                <p className="text-sm text-yellow-600/90">
                  This is an experimental TEE debug environment for testing purposes only. Not for production use.
                </p>
              </div>
              <div className="text-xs text-yellow-600/70 font-mono">
                v0.1.0-alpha
              </div>
            </div>
          </div>
        </div>
        
        <main className="p-6 min-h-full">
          {renderContent()}
        </main>
      </div>
    </div>
  )
} 