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

    # 2. Find all vulnerability results
    results = root.findall(".//result")

    for idx, result in enumerate(results):
        try:
            # 3. Extract fields (still raw, not normalized)
            refs = result.findall(".//ref")

            cves = [
                r.attrib.get("id")
                for r in refs
                if r.attrib.get("type") == "cve"
            ]

            urls = [
                r.attrib.get("id")
                for r in refs
                if r.attrib.get("type") == "url"
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
                port_number, protocol = port.split("/")

            finding = {
                "source": "openvas",

                "raw_id": text_or_none(result, "id"),

                "host": text_or_none(result, "host"),

                "ip": text_or_none(result, "host"),

                "port": int(port_number) if port_number else None,

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

                "solution": text_or_none(result, ".//solution"),



                "solution_type": text_or_none(
                    result,
                    ".//solution/type",
                ),

                "qod": text_or_none(result, ".//qod/value"),

                "tags": None,

                # Keep full XML string for debugging + traceability
                "raw": ET.tostring(
                    result, 
                    encoding="unicode",
                ),
            }

            findings.append(finding)

        except Exception as e:
            logger.warning(f"Skipping OpenVAS result index={idx}: {e}")

    logger.info(f"Ingested {len(findings)} OpenVAS findings")

    return findings