from types import SimpleNamespace
from uuid import uuid4

from dedup.canonical import classify_findings
from pipelines import ingestion_pipeline
from schemas.finding import Finding


class InMemorySupabase:
    """Small fluent Supabase fake for the ingestion-to-repository contract."""

    def __init__(self):
        self.rows = []
        self.operation = None
        self.fingerprints = []
        self.upsert_payload = None
        self.conflict_columns = None

    def table(self, table_name):
        assert table_name == "findings"
        return self

    def select(self, _columns):
        self.operation = "select"
        return self

    def in_(self, column, values):
        assert column == "fingerprint"
        self.fingerprints = values
        return self

    def upsert(self, payload, *, on_conflict):
        self.operation = "upsert"
        self.upsert_payload = payload
        self.conflict_columns = on_conflict
        return self

    def execute(self):
        if self.operation == "select":
            rows = [row for row in self.rows if row["fingerprint"] in self.fingerprints]
            return SimpleNamespace(data=rows)

        self.rows.extend(self.upsert_payload)
        return SimpleNamespace(
            data=[{"finding_id": row["finding_id"]} for row in self.upsert_payload]
        )


def test_ingestion_persists_canonical_and_duplicate_links_across_scans(monkeypatch):
    raw_findings = [
        {
            "source": "zap",
            "source_finding_id": "alert-1",
            "raw_id": "10012",
            "title": "Shared CVE alert",
            "risk": "3",
            "host": "example.test",
            "url": "https://example.test/a",
            "cve": ["CVE-2025-0001"],
            "raw": {"alert": "Shared CVE alert"},
        },
        {
            "source": "zap",
            "source_finding_id": "alert-2",
            "raw_id": "10012",
            "title": "Same CVE on the same host",
            "risk": "3",
            "host": "EXAMPLE.TEST",
            "url": "https://example.test/b",
            "cve": ["CVE-2025-0001"],
            "raw": {"alert": "Same CVE on the same host"},
        },
    ]
    monkeypatch.setattr(ingestion_pipeline, "parse_zap_file", lambda _path: raw_findings)
    supabase = InMemorySupabase()

    first_scan = ingestion_pipeline.run_ingestion_pipeline("zap", "scan.json", supabase)
    canonical_id = str(first_scan[0].finding_id)

    assert first_scan[0].is_canonical is True
    assert first_scan[0].canonical_finding_id is None
    assert first_scan[1].is_canonical is False
    assert str(first_scan[1].canonical_finding_id) == canonical_id
    assert len(supabase.rows) == 2
    assert supabase.rows[0]["is_canonical"] is True
    assert supabase.rows[0]["canonical_finding_id"] is None
    assert supabase.rows[1]["is_canonical"] is False
    assert supabase.rows[1]["canonical_finding_id"] == canonical_id
    assert supabase.conflict_columns == "source_scanner,scan_id,source_finding_id"

    second_scan = ingestion_pipeline.run_ingestion_pipeline("zap", "scan.json", supabase)

    assert len(supabase.rows) == 4
    assert all(finding.is_canonical is False for finding in second_scan)
    assert all(str(finding.canonical_finding_id) == canonical_id for finding in second_scan)
    assert all(row["canonical_finding_id"] == canonical_id for row in supabase.rows[2:])
    assert sum(row["is_canonical"] for row in supabase.rows) == 1


def test_existing_duplicate_keeps_its_canonical_reference_when_root_is_not_matched():
    canonical_id = uuid4()
    fingerprint = "same-finding-fingerprint"
    supabase = InMemorySupabase()
    supabase.rows = [
        {
            "finding_id": str(uuid4()),
            "fingerprint": fingerprint,
            "is_canonical": False,
            "canonical_finding_id": str(canonical_id),
        }
    ]
    finding = Finding(
        title="Repeated vulnerability",
        fingerprint=fingerprint,
        cve_ids=["CVE-2025-0001"],
    )

    classify_findings(supabase, [finding])

    assert finding.is_canonical is False
    assert finding.canonical_finding_id == canonical_id
