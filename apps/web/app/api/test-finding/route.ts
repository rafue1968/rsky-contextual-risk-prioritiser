import { NextResponse } from "next/server";
import { createFinding } from "../../../lib/db/finding"

export async function GET() {
  try {
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
        description: "Test finding",
        category: "web",
        cwe_ids: [89],
        cve_ids: [],
        references: [],
      },

      severity: {
        level: "high",
        cvss_score: 8.8,
        cvss_vector: "AV:N/AC:L",
        confidence: "high",
      },

      target: {
        host: "example.com",
        port: 443,
        protocol: "https",
        url: "https://example.com",
        asset_type: "web_app",
      },

      evidence: {
        request: null,
        response: null,
        matched_content: null,
        parameter: null,
        attack_vector: null,
      },

      remediation: {
        solution: "Patch application",
        solution_type: "vendorfix",
      },

      metadata: {
        raw_plugin_id: "1001",
        tags: ["sqli"],
        first_seen: new Date().toISOString(),
        raw_source_data: {},
      },
    });

    return NextResponse.json({
      success: true,
      finding,
    });
  } catch (error) {
    console.error(error);

    return NextResponse.json(
      {
        success: false,
        error,
      },
      { status: 500 }
    );
  }
}