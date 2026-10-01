from pathlib import Path

from connectors.openvas import parse_openvas_file


API_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = API_DIR.parents[1]
OPENVAS_SAMPLE = REPO_ROOT / "sample-data" / "openvas" / "openvas.xml"


def test_openvas_connector_parses_sample_results_and_nvt_remediation():
    findings = parse_openvas_file(str(OPENVAS_SAMPLE))

    assert len(findings) == 133
    finding = next(
        item
        for item in findings
        if item["title"] == "TWiki XSS and Command Execution Vulnerabilities"
    )
    assert finding["host"] == "192.168.222.131"
    assert finding["port"] == 80
    assert finding["protocol"] == "tcp"
    assert finding["cve"] == ["CVE-2008-5304", "CVE-2008-5305"]
    assert finding["threat"] == "High"
    assert finding["cvss_score"] == 10.0
    assert finding["solution"].startswith("Upgrade to version 4.2.4")
    assert finding["solution_type"] == "VendorFix"
    assert finding["raw"]["xml"].startswith("<result")
