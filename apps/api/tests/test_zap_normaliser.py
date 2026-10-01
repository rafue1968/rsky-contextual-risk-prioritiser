from pathlib import Path

from connectors.zap import parse_zap_file
from normalisers.zap import ZapNormalizer


API_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = API_DIR.parents[1]
ZAP_SAMPLE = REPO_ROOT / "sample-data" / "zap" / "2026-04-30-ZAP-Report-.json"


def test_zap_normalizer_maps_connector_alert_to_finding():
    raw_findings = parse_zap_file(str(ZAP_SAMPLE))
    raw = next(
        item
        for item in raw_findings
        if item["title"] == "CSP: Failure to Define Directive with No Fallback"
    )
    raw["scan_id"] = "zap-test-scan"

    finding = ZapNormalizer().normalize(raw)

    assert finding.source_scanner == "zap"
    assert finding.source_finding_id == "10055-13@http://localhost:3000"
    assert finding.scan_id == "zap-test-scan"
    assert finding.title == raw["title"]
    assert finding.severity_level == "medium"
    assert finding.target_host == "localhost"
    assert finding.target_port == 3000
    assert finding.target_url == "http://localhost:3000/assets"
    assert finding.cwe_ids == ["693"]
    assert finding.evidence["matched_content"] == "default-src 'none'"
    assert finding.metadata["connector_output"]["confidence"] == "3"
    assert finding.raw_payload == raw["raw"]
