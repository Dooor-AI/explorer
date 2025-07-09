export interface TEEValidationReport {
  valid: boolean
  summary: {
    trusted: boolean
    hardware: string
    project: string
    instance: string
    zone: string
    tee_authentic?: boolean
    firewall_secure?: boolean
    overall_trusted?: boolean
    whitelisted_domains?: number
    total_http_calls?: number
    last_updated?: string
    firewall_active?: boolean
  }
  claims?: unknown
  errors?: string[]
  warnings?: string[]
  securityConfig?: {
    allowed_domains: string[]
  }
  jwt_validation?: {
    valid: boolean
    errors?: string[]
  }
  security_validation?: {
    valid: boolean
    errors?: string[]
    warnings?: string[]
  }
}

export interface TEEConnection {
  id: string
  url: string
  name: string
  status: 'connected' | 'disconnected' | 'error' | 'validating'
  lastValidated?: string
  validationResult?: TEEValidationReport
}

export interface TEEAuditResult {
  session_id: string
  message: string
  summary?: {
    files_analyzed: number
    security_score: number
    critical_findings: number
  }
  verification?: {
    auditor_hash: string
    execution_chain_hash: string
    tee_signature: string
    auditor_code_hash?: string
    public_source?: string
  }
  transparency_proof?: {
    public_auditor_url: string
    execution_steps: number
    timestamp: string
  }
  audit_results?: unknown
  execution_summary?: {
    total_steps: number
    execution_time: string
  }
}

export interface TEEAuditHealth {
  status: 'healthy' | 'unhealthy'
  message: string
  capabilities?: {
    github_access: boolean
    file_reading: boolean
    cryptographic_proof: boolean
    tee_attestation: boolean
  }
  last_health_check: string
  auditor_source: string
}

export interface TEEExecutionLog {
  session_id: string
  verification_info?: {
    each_step_is_hashed: boolean
    hash_chain_verified: boolean
    cryptographic_proof: string
  }
  execution_trace: unknown[]
  transparency_notes?: string[]
}

export interface TEEVerificationInfo {
  auditor_transparency?: {
    public_repository: string
    source_code_url: string
    verification_instructions: string[]
  }
  latest_audit?: {
    session_id: string
    auditor_code_hash: string
    execution_chain_hash: string
    tee_signature: string
    timestamp: string
  }
  verification_endpoints?: {
    run_audit: string
    get_results: string
    execution_log: string
  }
}

export interface TEETransaction {
  id: string
  hash: string
  timestamp: string
  type: 'validation' | 'audit' | 'execution'
  status: 'pending' | 'success' | 'failed'
  tee_instance: string
  user_id?: string
  data?: unknown
  verification_proof?: string
}

export interface TEEInstance {
  id: string
  name: string
  project_id: string
  zone: string
  status: 'running' | 'stopped' | 'error'
  url: string
  created_at: string
  last_activity: string
  hardware_type: string
  security_level: 'high' | 'medium' | 'low' | 'critical'
  transactions_count: number
  uptime: number
}

export interface JWTPayload {
  header: {
    alg: string
    typ: string
    kid?: string
  }
  payload: {
    iss?: string
    sub?: string
    aud?: string
    exp?: number
    iat?: number
    nbf?: number
    jti?: string
    [key: string]: unknown
  }
}

export interface APIResponse<T = unknown> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

export type SecurityLevel = 'high' | 'medium' | 'low' | 'critical'
export type ValidationStatus = 'valid' | 'invalid' | 'pending' | 'error'
export type TEEStatus = 'connected' | 'disconnected' | 'error' | 'validating' 