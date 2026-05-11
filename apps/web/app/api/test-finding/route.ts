import { NextResponse } from "next/server";
import { createFinding } from "../../../lib/db/finding";

export async function GET() {
  const finding = await createFinding({
    finding_id: crypto.randomUUID(),
    source: {
      scanner: "zap",
      scanner_version: "2.15",
      scan_id: "scan-001",
      scan_timestamp: new Date().toISOString(),
    },
    vulnerability: {
      title: "SQL Injection",
      description: "test",
      category: "web",
      cwe_ids: [89],
      cve_ids: [],
      references: [],
    },
    severity: {
      level: "high",
      cvss_score: 8.8,
      cvss_vector: "AV:N",
      confidence: "high",
    },
    target: {
      host: "example.com",
      port: 443,
      protocol: "https",
      url: "https://example.com",
      asset_type: "web_app",
    },
    evidence: {},
    remediation: {
      solution: "Patch",
      solution_type: "vendorfix",
    },
    metadata: {
      raw_plugin_id: "1001",
      tags: ["sqli"],
      first_seen: new Date().toISOString(),
      raw_source_data: {},
    },
  });

  return NextResponse.json({ success: true, finding });
}