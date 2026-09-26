from types import SimpleNamespace
from uuid import uuid4

from pipelines import ingestion_pipeline


class FakeSupabase:
    def __init__(self, rows=None):
        self.rows = rows or []

    def table(self, _table_name):
        return self

    def select(self, _columns):
        return self

    def in_(self, _column, _values):
        return self

    def execute(self):
        return SimpleNamespace(data=self.rows)


def test_pipeline_normalizes_classifies_and_upserts_scanner_findings(monkeypatch):
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
            "title": "Same CVE on same host",
            "risk": "3",
            "host": "EXAMPLE.TEST",
            "url": "https://example.test/b",
            "cve": ["CVE-2025-0001"],
            "raw": {"alert": "Same CVE on same host"},
        },
    ]
    upsert_calls = []
    monkeypatch.setattr(ingestion_pipeline, "parse_zap_file", lambda _path: raw_findings)
    monkeypatch.setattr(
        ingestion_pipeline,
        "upsert_findings_bulk",
        lambda _client, findings: upsert_calls.append(findings) or [item.finding_id for item in findings],
    )

    findings = ingestion_pipeline.run_ingestion_pipeline(
        "zap", "sample.json", FakeSupabase()
    )

    assert len(findings) == 2
    assert findings[0].scan_id == findings[1].scan_id
    assert findings[0].fingerprint == findings[1].fingerprint
    assert findings[0].is_canonical is True
    assert findings[1].is_canonical is False
    assert findings[1].canonical_finding_id == findings[0].finding_id
    assert upsert_calls == [findings]


def test_pipeline_marks_existing_fingerprint_as_duplicate(monkeypatch):
    canonical_id = uuid4()
    raw = {
        "source": "openvas",
        "raw_id": "result-2",
        "source_finding_id": "result-2",
        "title": "Existing CVE on asset",
        "threat": "High",
        "severity": "8.0",
        "cvss_score": 8.0,
        "host": "192.0.2.5",
        "port": 443,
        "protocol": "tcp",
        "cve": ["CVE-2025-0002"],
        "raw": {"xml": "<result/>"},
    }
    persisted = []
    monkeypatch.setattr(ingestion_pipeline, "parse_openvas_file", lambda _path: [raw])
    monkeypatch.setattr(
        ingestion_pipeline,
        "upsert_findings_bulk",
        lambda _client, findings: persisted.extend(findings) or [item.finding_id for item in findings],
    )
    existing_fingerprint = ingestion_pipeline.generate_fingerprint(
        ingestion_pipeline.OpenVASNormalizer().normalize({**raw, "scan_id": "old-scan"})
    )
    supabase = FakeSupabase(
        rows=[{
            "finding_id": str(canonical_id),
            "fingerprint": existing_fingerprint,
            "is_canonical": True,
            "canonical_finding_id": None,
        }]
    )

    findings = ingestion_pipeline.run_ingestion_pipeline(
        "openvas", "sample.xml", supabase
    )

    assert len(findings) == 1
    assert findings[0].is_canonical is False
    assert findings[0].canonical_finding_id == canonical_id
    assert persisted == findings
