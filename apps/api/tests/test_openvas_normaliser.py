from pathlib import Path

from connectors.openvas import parse_openvas_file
from normalisers.openvas import OpenVASNormalizer


API_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = API_DIR.parents[1]
OPENVAS_SAMPLE = REPO_ROOT / "sample-data" / "openvas" / "openvas.xml"


def test_openvas_normalizer_maps_connector_result_to_finding():
    raw_findings = parse_openvas_file(str(OPENVAS_SAMPLE))
    raw = next(
        item
        for item in raw_findings
        if item["title"] == "TWiki XSS and Command Execution Vulnerabilities"
    )
    raw["scan_id"] = "openvas-test-scan"

    finding = OpenVASNormalizer().normalize(raw)

    assert finding.source_scanner == "openvas"
    assert finding.source_finding_id == raw["source_finding_id"]
    assert finding.scan_id == "openvas-test-scan"
    assert finding.title == raw["title"]
    assert finding.severity_level == "high"
    assert finding.severity_score == 10.0
    assert finding.target_host == "192.168.222.131"
    assert finding.target_port == 80
    assert finding.target_protocol == "tcp"
    assert finding.cve_ids == ["CVE-2008-5304", "CVE-2008-5305"]
    assert finding.remediation["solution"].startswith("Upgrade to version 4.2.4")
    assert finding.remediation["solution_type"] == "vendorfix"
    assert finding.metadata["connector_output"]["cvss_score"] == 10.0
    assert finding.raw_payload["xml"].startswith("<result")
