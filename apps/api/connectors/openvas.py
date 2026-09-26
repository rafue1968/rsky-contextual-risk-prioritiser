import logging
import xml.etree.ElementTree as ET
from defusedxml.ElementTree import parse as safe_parse

logger = logging.getLogger(__name__)


def text_or_none(node, path: str):
    """
    Helper function to safely extract XML text.
    """
    child = node.find(path)
    return child.text.strip() if child is not None and child.text else None


def _split_values(value: str | None) -> list[str]:
    if not value or value.strip().upper() in {"NOCVE", "NOBID", "NOXREF"}:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_tag_values(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    parsed = {}
    for item in value.split("|"):
        key, separator, tag_value = item.partition("=")
        if separator:
            parsed[key.strip()] = tag_value.strip()
    return parsed


def parse_openvas_file(file_path: str) -> list[dict]:
    """
    Reads OpenVAS XML export and extracts findings into a flat structure.
    """

    findings = []

    # 1. Safely parse XML (prevents XML attacks / malformed input crashes)
    try:
        tree = safe_parse(file_path)
        root = tree.getroot()

    except Exception as e:
        logger.error(f"Failed to parse OpenVAS XML: {e}")
        return []

    # Only direct scan results; nested detection results are metadata, not findings.
    results = root.findall(".//results/result")
    if not results:
        logger.warning("No OpenVAS results found in %s", file_path)
        return []

    report = root.find(".//report")
    scanner_version = text_or_none(root, ".//omp/version")
    scan_timestamp = text_or_none(report, "creation_time") if report is not None else None

    for idx, result in enumerate(results):
        try:
            # 3. Extract fields (still raw, not normalized)
            tag_values = _parse_tag_values(text_or_none(result, ".//nvt/tags"))
            refs = result.findall(".//ref")

            cves = [
                r.attrib.get("id")
                for r in refs
                if r.attrib.get("type") == "cve"
            ]
            if not cves:
                nvt_cves = text_or_none(result, ".//nvt/cve")
                cves = _split_values(nvt_cves)

            urls = [
                r.attrib.get("id")
                for r in refs
                if r.attrib.get("type") == "url"
            ]
            if not urls:
                urls = [
                    item.removeprefix("URL:").strip()
                    for item in _split_values(text_or_none(result, ".//nvt/xref"))
                    if item.strip().upper().startswith("URL:")
                ]

            port = text_or_none(result, "port")

            port_number = None
            protocol = None

            score = text_or_none(result, "severity")

            try:
                score = float(score)
            except:
                score = None
            

            if port and "/" in port:
                raw_port_number, raw_protocol = port.split("/", 1)
                try:
                    port_number = int(raw_port_number)
                except ValueError:
                    port_number = None
                protocol = raw_protocol.lower()
                if protocol not in {"tcp", "udp"}:
                    protocol = None

            finding = {
                "source": "openvas",
                "scanner_version": scanner_version,
                "scan_timestamp": scan_timestamp,

                "raw_id": text_or_none(result, "id"),
                "source_finding_id": text_or_none(result, "id"),

                "host": text_or_none(result, "host"),

                "ip": text_or_none(result, "host"),

                "port": port_number,

                "protocol": protocol,

                "title": text_or_none(result, "name"),

                "description": text_or_none(result, "description"),

                "severity": text_or_none(result, "severity"),

                "threat": text_or_none(result, "threat"),

                "cvss_score": score,

                "cvss_vector": text_or_none(
                    result,
                    ".//cvss_base_vector",
                ),

                # CVEs are multiple values
                "cve": cves,

                "references": urls,

                "nvt": text_or_none(result, ".//oid"),

                "solution": text_or_none(result, ".//solution") or tag_values.get("solution"),



                "solution_type": (
                    text_or_none(result, ".//solution/type")
                    or tag_values.get("solution_type")
                ),

                "qod": text_or_none(result, ".//qod/value"),

                "tags": None,

                # Keep full XML string for debugging + traceability
                "raw": {
                    "xml": ET.tostring(result, encoding="unicode"),
                },
            }

            findings.append(finding)

        except Exception as e:
            logger.warning(f"Skipping OpenVAS result index={idx}: {e}")

    logger.info(f"Ingested {len(findings)} OpenVAS findings")

    return findings