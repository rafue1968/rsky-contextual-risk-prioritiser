from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from connectors.openvas import parse_openvas_file
from connectors.zap import parse_zap_file
from dedup.fingerprint import generate_fingerprint
from db.findings_repo import _serialise_for_insert
from normalisers.openvas import OpenVASNormalizer
from normalisers.zap import ZapNormalizer
from pipelines import ingestion_pipeline
from schemas.finding import Finding


API_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = API_DIR.parents[1]
ZAP_SAMPLE = REPO_ROOT / "sample-data" / "zap" / "2026-04-30-ZAP-Report-.json"
OPENVAS_SAMPLE = REPO_ROOT / "sample-data" / "openvas" / "openvas.xml"


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


def test_zap_sample_flows_from_connector_to_finding():
    raw_findings = parse_zap_file(str(ZAP_SAMPLE))
    raw = next(
        finding
        for finding in raw_findings
        if finding["title"] == "CSP: Failure to Define Directive with No Fallback"
    )
    raw["scan_id"] = "zap-scan-test"

    finding = ZapNormalizer().normalize(raw)
    payload = _serialise_for_insert(finding)

    assert set(payload) == {
        "finding_id",
        "source_scanner",
        "source_finding_id",
        "scan_id",
        "title",
        "description",
        "vulnerability_category",
        "cve_ids",
        "cwe_ids",
        "severity_level",
        "severity_score",
        "target_host",
        "target_url",
        "target_port",
        "target_protocol",
        "evidence",
        "remediation",
        "metadata",
        "raw_payload",
        "fingerprint",
        "is_canonical",
        "canonical_finding_id",
    }
    assert finding.source_scanner == "zap"
    assert finding.source_finding_id == "10055-13@http://localhost:3000"
    assert finding.scan_id == "zap-scan-test"
    assert finding.severity_level == "medium"
    assert finding.target_host == "localhost"
    assert finding.target_protocol == "http"
    assert finding.target_url == "http://localhost:3000/assets"
    assert finding.target_port == 3000
    assert finding.cwe_ids == ["693"]
    assert finding.metadata["connector_output"]["scanner_version"] == "2.17.0"
    assert finding.metadata["connector_output"]["confidence"] == "3"
    assert finding.metadata["connector_output"]["method"] == "GET"
    assert finding.evidence["matched_content"] == "default-src 'none'"
    assert payload["raw_payload"] == raw["raw"]
    assert payload["source_scanner"] == "zap"
    assert payload["source_finding_id"] == finding.source_finding_id
    assert payload["scan_id"] == "zap-scan-test"
    assert payload["severity_level"] == "medium"
    assert payload["target_host"] == "localhost"
    assert payload["target_port"] == 3000
    assert payload["target_url"] == "http://localhost:3000/assets"
    assert payload["cwe_ids"] == ["693"]
    assert payload["metadata"]["connector_output"] == finding.metadata["connector_output"]


def test_openvas_sample_flows_from_connector_to_finding():
    raw_findings = parse_openvas_file(str(OPENVAS_SAMPLE))
    first_finding = OpenVASNormalizer().normalize(raw_findings[0])
    assert first_finding.target_port is None
    assert first_finding.remediation["solution"] is None
    assert first_finding.remediation["solution_type"] is None

    raw = next(
        finding
        for finding in raw_findings
        if finding["title"] == "TWiki XSS and Command Execution Vulnerabilities"
    )
    raw["scan_id"] = "openvas-scan-test"

    finding = OpenVASNormalizer().normalize(raw)
    payload = _serialise_for_insert(finding)

    assert finding.source_scanner == "openvas"
    assert finding.source_finding_id == raw["raw_id"]
    assert finding.scan_id == "openvas-scan-test"
    assert finding.cve_ids == ["CVE-2008-5304", "CVE-2008-5305"]
    assert finding.severity_level == "high"
    assert finding.target_host == "192.168.222.131"
    assert finding.target_port == 80
    assert finding.target_protocol == "tcp"
    assert finding.remediation["solution"].startswith("Upgrade to version 4.2.4")
    assert finding.remediation["solution_type"] == "vendorfix"
    assert payload["raw_payload"]
    assert raw["solution_type"] == "VendorFix"
    assert payload["metadata"]["connector_output"]["scanner_version"]
    assert payload["metadata"]["connector_output"]["source_finding_id"] == raw["source_finding_id"]


def test_ingestion_pipeline_fingerprints_and_upserts(monkeypatch):
    raw_findings = [
        {
            "source": "zap",
            "source_finding_id": "alert-1",
            "raw_id": "10012",
            "title": "Example vulnerability",
            "risk": "3",
            "host": "example.com",
            "url": "https://example.com/vulnerable",
            "cve": ["CVE-2024-0001"],
            "raw": {"pluginid": "10012"},
        },
        {
            "source": "zap",
            "source_finding_id": "alert-2",
            "raw_id": "10012",
            "title": "Same vulnerability reported at second URL",
            "risk": "3",
            "host": "EXAMPLE.COM",
            "url": "https://example.com/another-path",
            "cve": ["CVE-2024-0001"],
            "raw": {"pluginid": "10012"},
        },
    ]
    upserted = {}

    monkeypatch.setattr(ingestion_pipeline, "parse_zap_file", lambda _path: raw_findings)
    monkeypatch.setattr(
        ingestion_pipeline,
        "upsert_findings_bulk",
        lambda _supabase, findings: upserted.setdefault("findings", findings),
    )

    findings = ingestion_pipeline.run_ingestion_pipeline("zap", "unused.json", FakeSupabase())

    assert len(findings) == 2
    assert findings[0].source_finding_id == "alert-1"
    assert findings[0].fingerprint
    assert findings[0].scan_id
    assert findings[0].is_canonical is True
    assert findings[0].canonical_finding_id is None
    assert findings[1].is_canonical is False
    assert findings[1].canonical_finding_id == findings[0].finding_id
    assert _serialise_for_insert(findings[0])["finding_id"] == str(findings[0].finding_id)
    assert _serialise_for_insert(findings[1])["canonical_finding_id"] == str(findings[0].finding_id)
    assert upserted["findings"] == findings


def test_ingestion_pipeline_selects_openvas_connector_and_normalizer(monkeypatch):
    raw_findings = [
        {
            "source": "openvas",
            "raw_id": "result-1",
            "source_finding_id": "result-1",
            "title": "OpenVAS test finding",
            "threat": "High",
            "cvss_score": 8.1,
            "host": "192.0.2.10",
            "port": 443,
            "protocol": "tcp",
            "cve": ["CVE-2025-0001"],
            "raw": {"xml": "<result/>"},
        }
    ]
    upserted = {}

    monkeypatch.setattr(ingestion_pipeline, "parse_openvas_file", lambda _path: raw_findings)
    monkeypatch.setattr(
        ingestion_pipeline,
        "upsert_findings_bulk",
        lambda _supabase, findings: upserted.setdefault("findings", findings),
    )

    findings = ingestion_pipeline.run_ingestion_pipeline("OPENVAS", "unused.xml", FakeSupabase())

    assert len(findings) == 1
    assert findings[0].source_scanner == "openvas"
    assert findings[0].source_finding_id == "result-1"
    assert findings[0].severity_level == "high"
    assert findings[0].target_host == "192.0.2.10"
    assert findings[0].target_port == 443
    assert findings[0].cve_ids == ["CVE-2025-0001"]
    assert findings[0].scan_id
    assert upserted["findings"] == findings


def test_pipeline_marks_match_to_persisted_canonical_finding(monkeypatch):
    canonical_id = uuid4()
    raw_findings = [
        {
            "source": "zap",
            "source_finding_id": "new-alert",
            "raw_id": "10012",
            "title": "Existing vulnerability from another scan",
            "risk": "3",
            "host": "example.com",
            "url": "https://example.com/path",
            "cve": ["CVE-2024-0001"],
            "raw": {"pluginid": "10012"},
        }
    ]
    upserted = {}
    monkeypatch.setattr(ingestion_pipeline, "parse_zap_file", lambda _path: raw_findings)
    monkeypatch.setattr(
        ingestion_pipeline,
        "upsert_findings_bulk",
        lambda _supabase, findings: upserted.setdefault("findings", findings),
    )

    findings = ingestion_pipeline.run_ingestion_pipeline(
        "zap",
        "unused.json",
        FakeSupabase(
            rows=[{
                "finding_id": str(canonical_id),
                "fingerprint": generate_fingerprint(
                    ZapNormalizer().normalize({**raw_findings[0], "scan_id": "old-scan"})
                ),
                "is_canonical": True,
                "canonical_finding_id": None,
            }]
        ),
    )

    assert len(findings) == 1
    assert findings[0].is_canonical is False
    assert findings[0].canonical_finding_id == canonical_id
    assert upserted["findings"] == findings


def test_finding_coerces_malformed_scanner_values():
    finding = Finding(
        **{
            "source": {"scanner": "OpenVAS", "source_finding_id": 123},
            "vulnerability": {"title": None, "cwe_ids": 693},
            "severity": {"level": "not-a-severity", "cvss_score": "not-a-number"},
            "target": {"host": "example.test", "port": "443/tcp", "protocol": "TCP"},
            "metadata": {"raw_source_data": "<result/>"},
        }
    )

    assert finding.title == "Untitled finding"
    assert finding.source_scanner == "openvas"
    assert finding.source_finding_id == "123"
    assert finding.cwe_ids == ["693"]
    assert finding.severity_level == "informational"
    assert finding.severity_score is None
    assert finding.target_port == 443
    assert finding.target_protocol == "tcp"
    assert finding.raw_payload == {"raw": "<result/>"}


def test_fingerprint_uses_full_cve_set_asset_and_severity():
    common = {
        "title": "Shared vulnerability",
        "cve_ids": ["CVE-2025-0002", "CVE-2025-0001"],
        "severity_level": "high",
        "target_host": "Example.COM",
    }
    first_scan = Finding(
        **common,
        source_scanner="zap",
        scan_id="scan-1",
        source_finding_id="zap-alert-1",
    )
    second_scan = Finding(
        **{**common, "cve_ids": list(reversed(common["cve_ids"]))},
        source_scanner="openvas",
        scan_id="scan-2",
        source_finding_id="openvas-result-2",
    )

    fingerprint = generate_fingerprint(first_scan)

    assert fingerprint == generate_fingerprint(second_scan)
    assert fingerprint != generate_fingerprint(
        Finding(**{**common, "cve_ids": ["CVE-2025-0001"]})
    )
    assert fingerprint != generate_fingerprint(
        Finding(**{**common, "target_host": "other.example"})
    )
    assert fingerprint != generate_fingerprint(
        Finding(**{**common, "severity_level": "medium"})
    )
