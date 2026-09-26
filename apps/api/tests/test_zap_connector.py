from pathlib import Path

from connectors.zap import parse_zap_file


API_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = API_DIR.parents[1]
ZAP_SAMPLE = REPO_ROOT / "sample-data" / "zap" / "2026-04-30-ZAP-Report-.json"


def test_zap_connector_parses_sample_alerts_and_instance_fields():
    findings = parse_zap_file(str(ZAP_SAMPLE))

    assert len(findings) == 6
    finding = next(
        item
        for item in findings
        if item["title"] == "CSP: Failure to Define Directive with No Fallback"
    )
    assert finding["host"] == "localhost"
    assert finding["port"] == 3000
    assert finding["url"] == "http://localhost:3000/assets"
    assert finding["risk"] == "2"
    assert finding["cwe"] == ["693"]
    assert finding["raw_id"] == "10055"
    assert finding["source_finding_id"] == "10055-13@http://localhost:3000"
    assert finding["raw"]["pluginid"] == "10055"
