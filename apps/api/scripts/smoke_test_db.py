"""Manual end-to-end test of the DB layer.

Constructs a Finding by hand, inserts it, reads it back, lists it,
asserts everything round-trips correctly. Run with:

    python apps/api/scripts/smoke_test_db.py
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from supabase import create_client

from config import settings
from db.findings_repo import (
    get_finding,
    insert_finding,
    list_findings,
)
from schemas.finding import Finding


def main() -> None:
    supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)

    # Hand-crafted Finding modelled on a real ZAP alert.
    finding = Finding(
        source_scanner="zap",
        source_finding_id="10038",
        scan_id="smoke-test-001",
        title="Content Security Policy (CSP) Header Not Set",
        description="Content Security Policy is an effective measure to protect "
                    "your site from XSS attacks.",
        vulnerability_category="web",
        cwe_ids=["693"],
        cve_ids=[],
        severity_level="medium",
        severity_score=6.1,
        target_host="localhost",
        target_url="http://localhost:3000/",
        target_port=3000,
        target_protocol="http",
        evidence={
            "method": "GET",
            "uri": "http://localhost:3000/",
            "matched_evidence": "",
        },
        remediation={
            "solution": "Ensure that your web server, application server, "
                        "load balancer, etc. is configured to set the "
                        "Content-Security-Policy header.",
        },
        metadata={"plugin_id": "10038", "confidence": "medium"},
        raw_payload={"alertRef": "10038-1", "riskcode": "2"},
    )

    print("1. Inserting finding...")
    new_id = insert_finding(supabase, finding)
    print(f"   Inserted with id: {new_id}")

    print("\n2. Reading it back...")
    fetched = get_finding(supabase, new_id)
    assert fetched is not None, "Finding should exist"
    assert fetched.title == finding.title, "Title round-trip failed"
    assert fetched.cwe_ids == finding.cwe_ids, "CWE ids round-trip failed"
    assert fetched.evidence == finding.evidence, "Evidence JSONB round-trip failed"
    print(f"   Title: {fetched.title}")
    print(f"   Severity: {fetched.severity_level} ({fetched.severity_score})")
    print(f"   Host: {fetched.target_host}")
    print(f"   CWE IDs: {fetched.cwe_ids}")

    print("\n3. Listing findings filtered by scanner=zap, severity=medium...")
    findings = list_findings(supabase, scanner="zap", severity="medium", limit=10)
    print(f"   Found {len(findings)} matching finding(s)")
    assert any(f.finding_id == new_id for f in findings), \
        "Our finding should appear in the list"

    print("\nAll assertions passed. DB layer is working.")


if __name__ == "__main__":
    main()