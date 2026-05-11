// lib/models/finding.ts

/**
 * This file defines the TYPE structure of a Finding
 * No logic, no DB, just shape of data in TypeScript
 */

export type Finding = {
  finding_id: string

  source: {
    scanner: 'zap' | 'openvas'
    scanner_version: string
    scan_id: string
    scan_timestamp: string // ISO string
  }

  vulnerability: {
    title: string
    description: string
    category: 'web' | 'network' | 'host' | 'config'
    cwe_ids: number[]
    cve_ids: string[]
    references: string[]
  }

  severity: {
    level: 'critical' | 'high' | 'medium' | 'low' | 'informational'
    cvss_score: number
    cvss_vector: string
    confidence: 'high' | 'medium' | 'low'
  }

  target: {
    host: string
    port: number
    protocol: 'tcp' | 'udp' | 'http' | 'https'
    url?: string | null
    asset_type: 'web_app' | 'network_service' | 'host'
  }

  evidence: {
    request?: string | null
    response?: string | null
    matched_content?: string | null
    parameter?: string | null
    attack_vector?: string | null
  }

  remediation: {
    solution: string
    solution_type: 'vendorfix' | 'workaround' | 'mitigation' | 'none'
  }

  metadata: {
    raw_plugin_id: string
    tags: string[]
    first_seen: string
    raw_source_data: any // original scanner payload for audit/debug
  }
}