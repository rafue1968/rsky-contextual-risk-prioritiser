"""Manual end-to-end test of the DB layer.

Covers: insert, get, list, and upsert semantics. Run with:

    python apps/api/scripts/smoke_test_db.py

Run it twice in a row to prove the upsert is idempotent (the second
run should still leave exactly one row per natural key) — this still
works even with cleanup-after-test enabled, because each section
cleans up its OWN previous row before inserting again.
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
    upsert_finding,
)
from schemas.finding import Finding
from connectors.openvas import parse_openvas_file
from normalisers.openvas import OpenVASNormalizer


# Test scan IDs — used to clean up before each run so the test is
# repeatable. Keep these distinct from any real scan_ids.
INSERT_TEST_SCAN_ID = "smoke-test-insert-001"
UPSERT_TEST_SCAN_ID = "smoke-test-upsert-001"
OPENVAS_TEST_SCAN_ID = "smoke-test-openvas-insert-001"

# Toggle: should EVERY test row (ZAP sections 1 & 2, and the OpenVAS
# section 3) be deleted at the end of this run, so nothing is left
# behind in the shared Supabase database?
#
#   True  -> normal mode: insert, verify, then delete, for all three
#            sections. Nothing is left behind (default — leave as True).
#   False -> screenshot mode: insert and verify, but SKIP deletion for
#            all three, so the rows are still visible in Supabase's
#            Table Editor for you to screenshot. Once you've taken the
#            screenshot, set this back to True and re-run the script —
#            that will clean everything up (each section deletes its
#            own previous row before inserting a fresh one either way).
CLEANUP_AFTER_TEST = False


def _cleanup(supabase, scan_id: str) -> None:
    """Delete any findings from previous test runs so this run is clean."""
    supabase.table("findings").delete().eq("scan_id", scan_id).execute()


def _build_finding(scan_id: str, *, title: str, score: float) -> Finding:
    """Helper: construct a ZAP-shaped Finding with a specific scan_id."""
    return Finding(
        source_scanner="zap",
        source_finding_id="10038-1",
        scan_id=scan_id,
        title=title,
        description="Content Security Policy is an effective measure to protect "
                    "your site from XSS attacks.",
        vulnerability_category="web",
        cwe_ids=["693"],
        cve_ids=[],
        severity_level="medium",
        severity_score=score,
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
            "solution": "Configure the Content-Security-Policy header on your server.",
        },
        metadata={"plugin_id": "10038", "confidence": "medium"},
        raw_payload={"alertRef": "10038-1", "riskcode": "2"},
    )


def test_insert_and_read(supabase) -> None:
    """Section 1: original behaviour — insert, read back, list."""
    print("\n=== Section 1: insert + read + list ===")
    _cleanup(supabase, INSERT_TEST_SCAN_ID)

    finding = _build_finding(
        INSERT_TEST_SCAN_ID,
        title="Content Security Policy (CSP) Header Not Set",
        score=6.1,
    )

    print("Inserting finding...")
    new_id = insert_finding(supabase, finding)
    print(f"  Inserted with id: {new_id}")

    print("Reading it back...")
    fetched = get_finding(supabase, new_id)
    assert fetched is not None, "Finding should exist"
    assert fetched.title == finding.title, "Title round-trip failed"
    assert fetched.cwe_ids == finding.cwe_ids, "CWE ids round-trip failed"
    assert fetched.evidence == finding.evidence, "Evidence JSONB round-trip failed"
    print(f"  Title: {fetched.title}")
    print(f"  Severity: {fetched.severity_level} ({fetched.severity_score})")

    print("Listing scanner=zap, severity=medium...")
    findings = list_findings(supabase, scanner="zap", severity="medium", limit=10)
    assert any(f.finding_id == new_id for f in findings), \
        "Our finding should appear in the list"
    print(f"  Found {len(findings)} matching finding(s) in DB")

    # Clean up straight away, same as the other sections, so nothing
    # from this run is left sitting in the shared DB.
    if CLEANUP_AFTER_TEST:
        _cleanup(supabase, INSERT_TEST_SCAN_ID)
        print("  Cleaned up test row.")
    else:
        print(f"  Skipped cleanup on purpose (scan_id={INSERT_TEST_SCAN_ID}).")

    print("Section 1 passed.")


def test_upsert_is_idempotent(supabase) -> None:
    """Section 2: upsert with the same natural key updates, not duplicates."""
    print("\n=== Section 2: upsert idempotency ===")
    _cleanup(supabase, UPSERT_TEST_SCAN_ID)

    # First upsert — creates the row.
    original = _build_finding(
        UPSERT_TEST_SCAN_ID,
        title="Original title",
        score=5.0,
    )
    print("First upsert (creates row)...")
    id_first = upsert_finding(supabase, original)
    print(f"  finding_id: {id_first}")

    # Second upsert — same natural key, different content. Should UPDATE.
    updated = _build_finding(
        UPSERT_TEST_SCAN_ID,
        title="Updated title after rescan",
        score=7.5,
    )
    print("Second upsert (same natural key, new title and score)...")
    id_second = upsert_finding(supabase, updated)
    print(f"  finding_id: {id_second}")

    # Assertion 1: same finding_id (we updated, didn't create new).
    assert id_first == id_second, (
        f"Upsert created a new row instead of updating: "
        f"first={id_first}, second={id_second}"
    )

    # Assertion 2: row contents reflect the second (updated) version.
    fetched = get_finding(supabase, id_first)
    assert fetched is not None, "Finding should still exist after upsert"
    assert fetched.title == "Updated title after rescan", (
        f"Title was not updated. Got: {fetched.title!r}"
    )
    assert fetched.severity_score == 7.5, (
        f"Severity score was not updated. Got: {fetched.severity_score}"
    )

    # Assertion 3: only one row total for this scan_id.
    rows = list_findings(supabase, scan_id=UPSERT_TEST_SCAN_ID, limit=10)
    assert len(rows) == 1, (
        f"Expected exactly 1 row for scan_id={UPSERT_TEST_SCAN_ID}, got {len(rows)}"
    )
    print(f"  Confirmed exactly {len(rows)} row in DB for this scan.")

    # Clean up straight away, same as the other sections.
    if CLEANUP_AFTER_TEST:
        _cleanup(supabase, UPSERT_TEST_SCAN_ID)
        print("  Cleaned up test row.")
    else:
        print(f"  Skipped cleanup on purpose (scan_id={UPSERT_TEST_SCAN_ID}).")

    print("Section 2 passed.")


def test_openvas_insert_and_read(supabase) -> None:
    """Section 3: OpenVAS finding, built through the REAL parse+normalise
    pipeline (not hand-built like the ZAP helper above) — this proves
    the whole OpenVAS journey end to end, not just the DB layer."""
    print("\n=== Section 3: OpenVAS insert + read (persist step) ===")
    _cleanup(supabase, OPENVAS_TEST_SCAN_ID)

    # Reuse the same sample file local_openvas_test.py already proved
    # parses and normalises cleanly (151 OK, 0 failed).
    raw = parse_openvas_file("../../sample-data/openvas/openvas.xml")
    finding = OpenVASNormalizer().normalize(raw[0])
    finding.scan_id = OPENVAS_TEST_SCAN_ID  # tag it unmistakably as test data

    print("Inserting finding...")
    new_id = insert_finding(supabase, finding)
    print(f"  Inserted with id: {new_id}")

    print("Reading it back...")
    fetched = get_finding(supabase, new_id)
    assert fetched is not None, "Finding should exist"
    assert fetched.source_scanner == "openvas"
    assert fetched.raw_payload == finding.raw_payload, "raw_payload round-trip failed"
    print(f"  Title: {fetched.title}")
    print(f"  Severity: {fetched.severity_level} ({fetched.severity_score})")

    if CLEANUP_AFTER_TEST:
        _cleanup(supabase, OPENVAS_TEST_SCAN_ID)
        print("  Cleaned up test row.")
    else:
        print(f"  Skipped cleanup on purpose (scan_id={OPENVAS_TEST_SCAN_ID}).")

    print("Section 3 passed.")


def main() -> None:
    supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)

    test_insert_and_read(supabase)
    test_upsert_is_idempotent(supabase)
    test_openvas_insert_and_read(supabase)

    if CLEANUP_AFTER_TEST:
        print("\nAll sections passed. DB layer is hardened. No test rows left behind.")
    else:
        print(
            "\nAll sections passed. DB layer is hardened.\n"
            "NOTE: CLEANUP_AFTER_TEST is False — test rows are still in "
            "Supabase. Take your screenshots, then set it back to True "
            "and re-run this script to clean everything up."
        )


if __name__ == "__main__":
    main()