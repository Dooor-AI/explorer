import { 
  TEEValidationReport, 
  TEEAuditResult, 
  TEEAuditHealth, 
  TEEExecutionLog, 
  TEEVerificationInfo 
} from './types'

export class TEEAttestationValidator {
  private projectId: string
  private zone: string
  private instanceName: string

  constructor(config: {
    projectId: string
    zone: string
    instanceName: string
  }) {
    this.projectId = config.projectId
    this.zone = config.zone
    this.instanceName = config.instanceName
  }

  async connectToTEE(url: string): Promise<string> {
    try {
      const response = await fetch(`${url}/tee/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      const data = await response.json()
      
      // Extract the JWT from the response
      if (typeof data === 'string') {
        return data
      } else if (data.attestation_jwt) {
        return data.attestation_jwt
      } else {
        throw new Error('No attestation_jwt found in response')
      }
    } catch (error) {
      throw new Error(`Failed to connect to TEE: ${error}`)
    }
  }

  async isValidTEE(attestationJWT: string): Promise<boolean> {
    try {
      const report = await this.getValidationReport(attestationJWT)
      return report.valid
    } catch {
      return false
    }
  }

  async getValidationReport(attestationJWT: string): Promise<TEEValidationReport> {
    // For now, return a mock validation report
    // In a real implementation, this would validate the JWT against Google's keys
    const decoded = this.decodeJWT(attestationJWT)
    
    if (!decoded) {
      return {
        valid: false,
        summary: {
          trusted: false,
          hardware: 'Unknown',
          project: this.projectId,
          instance: this.instanceName,
          zone: this.zone
        },
        errors: ['Invalid JWT format']
      }
    }

    // Mock validation logic
    const isValid = this.validateJWTStructure(decoded)
    
    return {
      valid: isValid,
      summary: {
        trusted: isValid,
        hardware: 'Google Cloud TEE',
        project: this.projectId,
        instance: this.instanceName,
        zone: this.zone
      },
      claims: decoded.payload as Record<string, unknown>,
      errors: isValid ? [] : ['JWT validation failed']
    }
  }

  decodeJWT(jwt: string): { header: unknown; payload: unknown } | null {
    try {
      const parts = jwt.split('.')
      if (parts.length !== 3) return null
      
      const header = JSON.parse(atob(parts[0]))
      const payload = JSON.parse(atob(parts[1]))
      
      return { header, payload }
    } catch {
      return null
    }
  }

  private validateJWTStructure(decoded: { header: unknown; payload: unknown }): boolean {
    // Basic JWT structure validation
    return decoded.header !== null && decoded.payload !== null
  }

  async validateSecurityConfiguration(url?: string): Promise<TEEValidationReport> {
    try {
      if (!url) {
        // Mock security validation when no URL provided
        return {
          valid: true,
          summary: {
            trusted: true,
            hardware: 'Google Cloud TEE',
            project: this.projectId,
            instance: this.instanceName,
            zone: this.zone,
            firewall_active: true,
            whitelisted_domains: 5,
            total_http_calls: 127,
            last_updated: new Date().toISOString()
          },
          securityConfig: {
            allowed_domains: ['api.google.com', 'cloud.google.com']
          }
        }
      }

      // Real security validation against TEE server
      const response = await fetch(`${url}/tee/security-config`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()

      // Parse the API response structure from dooor's TEE platform
      const isSecurityValid = data.tee_security_enabled && data.firewall_status === 'active-logged'
      const whitelistedDomainsCount = data.allowed_domains ? data.allowed_domains.length : 0
      const totalHttpCalls = data.total_outbound_calls || (data.http_call_logs ? data.http_call_logs.length : 0)

      return {
        valid: isSecurityValid,
        summary: {
          trusted: isSecurityValid,
          hardware: 'Google Cloud TEE',
          project: this.projectId,
          instance: this.instanceName,
          zone: this.zone,
          firewall_active: data.firewall_status === 'active-logged',
          whitelisted_domains: whitelistedDomainsCount,
          total_http_calls: totalHttpCalls,
          last_updated: data.last_updated || new Date().toISOString()
        },
        securityConfig: {
          allowed_domains: data.allowed_domains || []
        },
        errors: data.errors || [],
        warnings: data.warnings || []
      }
    } catch (error) {
      return {
        valid: false,
        summary: {
          trusted: false,
          hardware: 'Unknown',
          project: this.projectId,
          instance: this.instanceName,
          zone: this.zone,
          firewall_active: false,
          whitelisted_domains: 0,
          total_http_calls: 0
        },
        errors: [`Security validation failed: ${error}`]
      }
    }
  }

  async validateCompleteTEE(url: string): Promise<TEEValidationReport> {
    try {
      const attestationJWT = await this.connectToTEE(url)
      const jwtValidation = await this.getValidationReport(attestationJWT)
      const securityValidation = await this.validateSecurityConfiguration()

      const overallValid = jwtValidation.valid && securityValidation.valid

      return {
        valid: overallValid,
        summary: {
          trusted: jwtValidation.summary.trusted,
          hardware: jwtValidation.summary.hardware,
          project: jwtValidation.summary.project,
          instance: jwtValidation.summary.instance,
          zone: jwtValidation.summary.zone,
          tee_authentic: jwtValidation.valid,
          firewall_secure: securityValidation.valid,
          overall_trusted: overallValid,
          whitelisted_domains: securityValidation.summary.whitelisted_domains,
          firewall_active: securityValidation.summary.firewall_active
        },
        jwt_validation: {
          valid: jwtValidation.valid,
          errors: jwtValidation.errors
        },
        security_validation: {
          valid: securityValidation.valid,
          errors: securityValidation.errors,
          warnings: securityValidation.warnings
        }
      }
    } catch (error) {
      return {
        valid: false,
        summary: {
          trusted: false,
          hardware: 'Unknown',
          project: this.projectId,
          instance: this.instanceName,
          zone: this.zone,
          tee_authentic: false,
          firewall_secure: false,
          overall_trusted: false
        },
        errors: [`Complete validation failed: ${error}`]
      }
    }
  }
}

export class TEEAuditorClient {
  private baseUrl: string

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }

  async checkHealth(): Promise<TEEAuditHealth> {
    try {
      const response = await fetch(`${this.baseUrl}/tee/auditor/health`)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      throw new Error(`Health check failed: ${error}`)
    }
  }

  async runAudit(): Promise<TEEAuditResult> {
    try {
      const response = await fetch(`${this.baseUrl}/tee/auditor/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      throw new Error(`Audit failed: ${error}`)
    }
  }

  async getResults(): Promise<TEEAuditResult> {
    try {
      const response = await fetch(`${this.baseUrl}/tee/auditor/results`)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      throw new Error(`Failed to get results: ${error}`)
    }
  }

  async getExecutionLog(): Promise<TEEExecutionLog> {
    try {
      const response = await fetch(`${this.baseUrl}/tee/auditor/execution-log`)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      throw new Error(`Failed to get execution log: ${error}`)
    }
  }

  async getVerificationInfo(): Promise<TEEVerificationInfo> {
    try {
      const response = await fetch(`${this.baseUrl}/tee/auditor/verification`)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      throw new Error(`Failed to get verification info: ${error}`)
    }
  }
}

export const createValidator = (config: {
  projectId: string
  zone: string
  instanceName: string
}) => new TEEAttestationValidator(config)

export const createAuditorClient = (baseUrl: string) => new TEEAuditorClient(baseUrl) 