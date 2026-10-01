from types import SimpleNamespace

from dedup.fingerprint import generate_fingerprint


def _finding(*, cve_ids, target_host, severity_level):
    return SimpleNamespace(
        cve_ids=cve_ids,
        target_host=target_host,
        target_url=None,
        severity_level=severity_level,
    )


def test_same_cve_host_and_severity_produce_same_fingerprint():
    first = _finding(
        cve_ids=["CVE-2025-0001"],
        target_host="example.test",
        severity_level="high",
    )
    equivalent = _finding(
        cve_ids=["cve-2025-0001"],
        target_host="EXAMPLE.TEST",
        severity_level="HIGH",
    )

    assert generate_fingerprint(first) == generate_fingerprint(equivalent)


def test_different_host_produces_different_fingerprint():
    first = _finding(
        cve_ids=["CVE-2025-0001"],
        target_host="example.test",
        severity_level="high",
    )
    other_host = _finding(
        cve_ids=["CVE-2025-0001"],
        target_host="other.example",
        severity_level="high",
    )

    assert generate_fingerprint(first) != generate_fingerprint(other_host)
