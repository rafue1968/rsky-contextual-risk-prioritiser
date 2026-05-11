// lib/db/findings.ts

import { supabase } from '../supabase/client'
import type { Finding } from '../models/finding'

/**
 * DB LAYER
 * This is the ONLY file allowed to talk to Supabase directly
 *
 * Rules:
 * - no validation here
 * - no transformation here
 * - just database operations
 */

/**
 * Insert a new Finding into Supabase
 */
export async function createFinding(finding: Finding) {
  const { data, error } = await supabase
    .from('findings')
    .insert(finding)
    .select()

  if (error) {
    // DB-level failure (constraint, connection, etc.)
    throw new Error(error.message)
  }

  return data
}

/**
 * Fetch all findings (basic version)
 * Later you will add pagination + filters
 */
export async function getFindings() {
  const { data, error } = await supabase
    .from('findings')
    .select('*')

  if (error) {
    throw new Error(error.message)
  }

  return data
}

/**
 * Fetch single finding by ID
 */
export async function getFindingById(id: string) {
  const { data, error } = await supabase
    .from('findings')
    .select('*')
    .eq('finding_id', id)
    .single()

  if (error) {
    throw new Error(error.message)
  }

  return data
}

/**
 * Why this layer exists:
 * - isolates Supabase dependency
 * - makes future migration easier (e.g. Postgres → API → Kafka)
 * - keeps routes clean
 */