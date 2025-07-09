'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { TEEOperationsLog } from '@/lib/types'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from './ui/badge'
import { Activity, RefreshCw, ServerCrash, ShieldCheck, Copy, Check } from 'lucide-react'

interface TeeOperationsProps {
  teeUrl: string
}

export default function TeeOperations({ teeUrl }: TeeOperationsProps) {
  const [operationsLog, setOperationsLog] = useState<TEEOperationsLog | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)

  const copyToClipboard = (hash: string) => {
    navigator.clipboard.writeText(hash)
    setCopiedHash(hash)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const fetchOperations = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch(`${teeUrl}/v1/tee/operations?limit=500`)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      const data: TEEOperationsLog = await response.json()
      if (data && data.operations) {
        const filteredOps = data.operations.filter(op => op.endpoint !== '/v1');
        data.operations = filteredOps;
        data.total_operations = filteredOps.length;
      }
      setOperationsLog(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }, [teeUrl])

  useEffect(() => {
    fetchOperations()
  }, [fetchOperations])

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

  return (
    <div className="space-y-6">
      <Card className="floating-card bg-secondary/30 border-secondary/50">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-xl text-card-foreground">TEE Operation Transparency</CardTitle>
            <CardDescription className="text-muted-foreground">
              Real-time view of all API operations executed inside the TEE
            </CardDescription>
          </div>
          <Button onClick={fetchOperations} disabled={isLoading} variant="outline" size="icon">
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading && !operationsLog ? (
            <div className="flex items-center justify-center h-64">
              <Activity className="w-8 h-8 animate-pulse text-primary" />
              <p className="ml-4 text-muted-foreground">Loading operations...</p>
            </div>
          ) : error ? (
            <div className="flex items-center justify-center h-64 flex-col">
              <ServerCrash className="w-8 h-8 text-destructive" />
              <p className="mt-4 text-destructive font-medium">Error fetching operations</p>
              <p className="text-sm text-muted-foreground">{error}</p>
            </div>
          ) : operationsLog && operationsLog.operations.length > 0 ? (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <Card className="bg-muted/20 p-6 flex flex-col items-center justify-center">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Total Operations</CardTitle>
                  <p className="text-4xl font-bold mt-2">{operationsLog.total_operations}</p>
                </Card>
                <Card className="bg-muted/20 p-6 flex flex-col items-center justify-center">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Last Updated</CardTitle>
                  <p className="text-4xl font-bold mt-2">{new Date(operationsLog.last_updated).toLocaleTimeString()}</p>
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
                    {operationsLog.operations.map((op) => (
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
                        <TableCell className="font-mono text-xs">{op.user_id.substring(0, 8)}...</TableCell>
                        <TableCell className="font-mono text-xs text-right">
                          <div className="flex items-center justify-end gap-2">
                            <span>{op.operation_hash.substring(0, 8)}...</span>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="w-6 h-6"
                              onClick={() => copyToClipboard(op.operation_hash)}
                            >
                              {copiedHash === op.operation_hash ? (
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