// lib/schemas/finding.ts

import { z } from 'zod'

/**
 * Validation layer for incoming data
 * Ensures we never insert malformed findings into DB
 */

export const FindingSchema = z.object({
  finding_id: z.string().uuid(),

  source: z.object({
    scanner: z.enum(['zap', 'openvas']),
    scanner_version: z.string(),
    scan_id: z.string(),
    scan_timestamp: z.string()
  }),

  vulnerability: z.object({
    title: z.string(),
    description: z.string(),
    category: z.enum(['web', 'network', 'host', 'config']),
    cwe_ids: z.array(z.number()),
    cve_ids: z.array(z.string()),
    references: z.array(z.string())
  }),

  severity: z.object({
    level: z.enum(['critical', 'high', 'medium', 'low', 'informational']),
    cvss_score: z.number(),
    cvss_vector: z.string(),
    confidence: z.enum(['high', 'medium', 'low'])
  }),

  target: z.object({
    host: z.string(),
    port: z.number(),
    protocol: z.enum(['tcp', 'udp', 'http', 'https']),
    url: z.string().nullable().optional(),
    asset_type: z.enum(['web_app', 'network_service', 'host'])
  })
})

/**
 * Why this exists:
 * - protects DB from bad scanner data
 * - ensures consistent structure
 * - helps debugging ingestion issues early
 */