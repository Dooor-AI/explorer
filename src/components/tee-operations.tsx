'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { TEEOperationsLog, ScanHash } from '@/lib/types'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from './ui/badge'
import { Activity, RefreshCw, ServerCrash, ShieldCheck, Copy, Check, Hash } from 'lucide-react'

interface TeeOperationsProps {
  teeUrl: string
}

export default function TeeOperations({ teeUrl }: TeeOperationsProps) {
  const [operationsLog, setOperationsLog] = useState<TEEOperationsLog | null>(null)
  const [hashes, setHashes] = useState<ScanHash[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)
  const [showAllHashes, setShowAllHashes] = useState(false)
  const [showAllOps, setShowAllOps] = useState(false)
  const router = useRouter()

  const copyToClipboard = (hash: string) => {
    navigator.clipboard.writeText(hash)
    setCopiedHash(hash)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const fetchAllData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    
    try {
      const [opsResponse, hashesResponse] = await Promise.all([
        fetch(`${teeUrl}/tee/operations?limit=500`),
        fetch(`${teeUrl}/scans/hashs`)
      ]);

      if (!opsResponse.ok) {
        throw new Error(`Operations fetch failed: HTTP ${opsResponse.status} ${opsResponse.statusText}`)
      }
      const opsData: TEEOperationsLog = await opsResponse.json()
      if (opsData && opsData.operations) {
        const filteredOps = opsData.operations.filter(op => op.endpoint !== '/v1');
        opsData.operations = filteredOps;
        opsData.total_operations = filteredOps.length;
      }
      setOperationsLog(opsData)

      if (!hashesResponse.ok) {
        throw new Error(`Hashes fetch failed: HTTP ${hashesResponse.status} ${hashesResponse.statusText}`)
      }
      const hashesData = await hashesResponse.json();
      setHashes(hashesData.hashs || []);

    } catch (err) {
      console.error(err)
      setHashes([])
      // setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }, [teeUrl])

  const handleRowClick = (hash: ScanHash) => {
    router.push(`/hashes/${hash.id}`)
  };

  useEffect(() => {
    fetchAllData()
  }, [fetchAllData])

  const getStatusVariant = (statusCode: number) => {
    if (statusCode >= 500) return 'destructive'
    if (statusCode >= 400) return 'secondary'
    if (statusCode >= 300) return 'outline'
    return 'default'
  }

  const getMethodVariant = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'default'
      case 'POST':
        return 'secondary'
      case 'PUT':
        return 'outline'
      case 'DELETE':
        return 'destructive'
      default:
        return 'default'
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Activity className="w-8 h-8 animate-pulse text-primary" />
        <p className="ml-4 text-muted-foreground">Loading TEE data...</p>
      </div>
    )
  }

  if (error) {
     return (
      <div className="flex items-center justify-center h-64 flex-col">
        <ServerCrash className="w-8 h-8 text-destructive" />
        <p className="mt-4 text-destructive font-medium">Error fetching data</p>
        <p className="text-sm text-muted-foreground">{error}</p>
      </div>
    )
  }

  const displayedHashes = showAllHashes ? hashes : hashes?.slice(0, 10) ?? []
  const displayedOps = showAllOps ? operationsLog?.operations ?? [] : (operationsLog?.operations.slice(0, 10) ?? [])

  return (
    <div className="space-y-6">
       <Card className="floating-card bg-secondary/30 border-secondary/50">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-xl text-card-foreground flex items-center gap-2">
              <Hash className="w-5 h-5"/> Scanned Hashes
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              Log of all hashes scanned and processed by the TEE.
            </CardDescription>
          </div>
          <Button onClick={fetchAllData} disabled={isLoading} variant="outline" size="icon">
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
        </CardHeader>
        <CardContent>
          {displayedHashes.length > 0 ? (
            <div className="overflow-hidden rounded-lg border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>From</TableHead>
                    <TableHead>Hash</TableHead>
                    <TableHead className="text-right">Processing Time (ms)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displayedHashes?.map((h) => (
                    <TableRow key={h.id} onClick={() => handleRowClick(h)} className="cursor-pointer hover:bg-muted/30">
                      <TableCell className="font-mono text-xs">{new Date(h?.createdAt).toLocaleString()}</TableCell>
                      <TableCell className="font-mono text-xs">{h?.from}</TableCell>
                      <TableCell className="font-mono text-xs">{h?.hash?.substring(0, 20)}...</TableCell>
                      <TableCell className="text-right">{h?.processingTimeMs}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {hashes.length > 10 && (
                <div className="flex justify-center mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowAllHashes(!showAllHashes)}
                  >
                    {showAllHashes ? 'See Less' : 'See More'}
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center h-40 flex items-center justify-center">
              <p className="text-muted-foreground">No hashes found.</p>
            </div>
          )}
        </CardContent>
      </Card>
      
      <Card className="floating-card bg-secondary/30 border-secondary/50">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-xl text-card-foreground">TEE Operation Transparency</CardTitle>
            <CardDescription className="text-muted-foreground">
              Real-time view of all API operations executed inside the TEE
            </CardDescription>
          </div>
          <Button onClick={fetchAllData} disabled={isLoading} variant="outline" size="icon">
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
        </CardHeader>
        <CardContent>
          {displayedOps.length > 0 ? (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <Card className="bg-muted/20 p-6 flex flex-col items-center justify-center">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Total Operations</CardTitle>
                  <p className="text-4xl font-bold mt-2">{operationsLog?.total_operations || 0}</p>
                </Card>
                <Card className="bg-muted/20 p-6 flex flex-col items-center justify-center">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Last Updated</CardTitle>
                  <p className="text-4xl font-bold mt-2">{new Date(operationsLog?.last_updated || '').toLocaleTimeString()}</p>
                </Card>
                <Card className="bg-muted/20 p-6 flex flex-col items-center justify-center text-center">
                  <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" /> TEE Verification
                  </CardTitle>
                  <p className="text-sm text-muted-foreground mt-2">
                    All logs are generated by TEE hardware and cannot be manipulated
                  </p>
                </Card>
              </div>

              <div className="overflow-hidden rounded-lg border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Method</TableHead>
                      <TableHead>Endpoint</TableHead>
                      <TableHead>Duration</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>User ID</TableHead>
                      <TableHead className="text-right">Operation Hash</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {displayedOps.map((op) => (
                      <TableRow key={op.id}>
                        <TableCell className="font-mono text-xs">{new Date(op.timestamp).toLocaleTimeString()}</TableCell>
                        <TableCell>
                          <Badge variant={getMethodVariant(op.method)}>{op.method}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{op.endpoint}</TableCell>
                        <TableCell>{op.execution_time_ms}ms</TableCell>
                        <TableCell>
                          <Badge variant={getStatusVariant(op.status_code)}>{op.status_code}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{op?.user_id?.substring(0, 8)}...</TableCell>
                        <TableCell className="font-mono text-xs text-right">
                          <div className="flex items-center justify-end gap-2">
                            <span>{op?.operation_hash?.substring(0, 8)}...</span>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="w-6 h-6"
                              onClick={() => copyToClipboard(op?.operation_hash)}
                            >
                              {copiedHash === op?.operation_hash ? (
                                <Check className="w-3 h-3 text-green-500" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {(operationsLog && operationsLog.operations.length > 10) && (
                <div className="flex justify-center mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowAllOps(!showAllOps)}
                  >
                    {showAllOps ? 'See Less' : 'See More'}
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="text-center h-64 flex items-center justify-center">
              <p className="text-muted-foreground">No operations found.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
} 