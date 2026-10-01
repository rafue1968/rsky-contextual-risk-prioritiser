"""Tests for the OpenVAS connector + normaliser pipeline.

These are the automated, repeatable version of the manual checks done
in scripts/local_openvas_test.py — same sample file, same pipeline,
but as real pytest assertions instead of a printed pass/fail count.
Run with (from apps/api):

    pytest tests/test_openvas.py -v
"""
from connectors.openvas import parse_openvas_file
from normalisers.openvas import OpenVASNormalizer

SAMPLE_FILE = "../../sample-data/openvas/openvas.xml"
ALLOWED_PROTOCOLS = {"tcp", "udp", "http", "https"}


def test_parses_all_results_in_the_sample_file():
    """OpenVAS embeds duplicate stub copies of a finding inside other
    findings' <detection> sections — e.g. a single phpMyAdmin detection
    can appear nested inside 11 unrelated results that also picked it up,
    in addition to its own real top-level entry. The connector now reads
    only the canonical top-level results (root.findall(".//results/result"))
    so each real finding is counted once, matching the unique constraint
    on the findings table (source_scanner + scan_id + source_finding_id) —
    the duplicate stubs share an id with their canonical finding and would
    never persist as separate rows anyway. 133 is the correct count."""
    findings = parse_openvas_file(SAMPLE_FILE)
    assert len(findings) == 133


def test_every_parsed_finding_normalises_without_error():
    """End-to-end regression test: every raw finding the connector
    produces must turn into a valid Finding object. Before the fixes,
    ALL findings failed here — raw_payload was a raw XML string
    instead of a dict, which the schema rejects."""
    raw = parse_openvas_file(SAMPLE_FILE)
    normaliser = OpenVASNormalizer()

    failures = []
    for index, finding in enumerate(raw):
        try:
            normaliser.normalize(finding)
        except Exception as exc:
            failures.append((index, str(exc)))

    assert failures == [], f"{len(failures)} finding(s) failed to normalise: {failures[:3]}"


def test_raw_payload_is_a_dict_not_a_string():
    """Regression test for the raw_payload type mismatch specifically.
    The Finding schema requires raw_payload to be a dict; the OpenVAS
    connector's raw XML must be wrapped, never passed through as a
    bare string."""
    raw = parse_openvas_file(SAMPLE_FILE)
    normaliser = OpenVASNormalizer()

    finding = normaliser.normalize(raw[0])
    assert isinstance(finding.raw_payload, dict)


def test_non_standard_protocol_labels_dont_crash():
    """Regression test: some host-level OpenVAS checks label the
    "protocol" half of port as a scan type (icmp, CPE-T, SMBClient)
    rather than a real transport protocol. The connector's guard
    already converts these to protocol=None before the raw finding
    dict is even returned — so they never reach the normaliser as
    non-standard values in the first place. This test pins the fix to
    the three specific findings in the sample file that used to expose
    the bug, confirming they still normalise cleanly with
    target_protocol=None instead of the original label."""
    raw = parse_openvas_file(SAMPLE_FILE)
    normaliser = OpenVASNormalizer()

    known_affected_titles = {
        "ICMP Timestamp Detection",
        "CPE Inventory",
        "SMB Test with 'smbclient'",
    }
    affected = [f for f in raw if f["title"] in known_affected_titles]
    assert affected, "expected the known non-standard-protocol findings to still be present in the sample file"

    for f in affected:
        finding = normaliser.normalize(f)
        assert finding.target_protocol is None


def test_every_finding_has_a_non_empty_title():
    """Regression test: some OpenVAS results are software/version
    detection entries, not vulnerabilities — they have no top-level
    <name>, only a nested <details><detail name="source_name">. These
    must still get a usable title instead of failing the required
    `title: str` schema field."""
    raw = parse_openvas_file(SAMPLE_FILE)
    normaliser = OpenVASNormalizer()

    for f in raw:
        finding = normaliser.normalize(f)
        assert finding.title, f"finding produced an empty/missing title (raw_id={f.get('raw_id')})"


def test_non_numeric_port_becomes_none_instead_of_crashing():
    """Regression test: when the port value can't be converted to a
    number (e.g. the literal "general"), target_port should end up
    None rather than raising int("general")."""
    raw = parse_openvas_file(SAMPLE_FILE)
    normaliser = OpenVASNormalizer()

    affected = [f for f in raw if f["port"] is None and f["protocol"] is not None]
    assert affected, "expected at least one non-numeric-port finding in the sample file"

    finding = normaliser.normalize(affected[0])
    assert finding.target_port is None