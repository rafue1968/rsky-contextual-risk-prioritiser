from db.findings_repo import _serialise_for_insert
from schemas.finding import Finding


def test_finding_model_accepts_normaliser_payload():
    payload = {
        "finding_id": "123e4567-e89b-12d3-a456-426614174000",
        "source": {
            "scanner": "zap",
            "scan_id": "scan-001",
            "scan_timestamp": "2026-01-01T00:00:00Z",
        },
        "vulnerability": {
            "title": "Reflected XSS",
            "description": "A reflected XSS issue was found.",
            "category": "web",
            "cwe_ids": ["79"],
            "cve_ids": ["CVE-2024-0001"],
        },
        "severity": {
            "level": "high",
            "cvss_score": 7.8,
        },
        "target": {
            "host": "example.com",
            "port": 443,
            "protocol": "https",
            "url": "https://example.com",
        },
        "evidence": {
            "request": "GET / HTTP/1.1",
            "response": "HTTP/1.1 200",
        },
        "remediation": {
            "solution": "Sanitize user input.",
            "solution_type": "mitigation",
        },
        "metadata": {
            "raw_plugin_id": "10012",
            "tags": ["web"],
            "raw_source_data": {"raw": True},
        },
    }

    finding = Finding(**payload)

    assert finding.source_scanner == "zap"
    assert finding.scan_id == "scan-001"
    assert finding.title == "Reflected XSS"
    assert finding.severity_level == "high"
    assert finding.target_protocol == "https"
    assert finding.raw_payload == {"raw": True}

    db_payload = _serialise_for_insert(finding)

    assert db_payload["source_scanner"] == "zap"
    assert db_payload["scan_id"] == "scan-001"
    assert db_payload["severity_level"] == "high"
    assert db_payload["metadata"]["raw_plugin_id"] == "10012"
