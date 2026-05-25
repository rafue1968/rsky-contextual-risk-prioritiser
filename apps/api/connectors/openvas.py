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
            finding = {
                "source": "openvas",
                "raw_id": text_or_none(result, "id"),
                "host": text_or_none(result, "host"),
                "ip": text_or_none(result, "host"),
                "port": text_or_none(result, "port"),
                "service": text_or_none(result, "service"),
                "title": text_or_none(result, "name"),
                "description": text_or_none(result, "description"),
                "severity": text_or_none(result, "severity"),

                # CVEs are multiple values
                "cve": [c.text for c in result.findall(".//cve") if c.text],

                "nvt": text_or_none(result, "nvt"),
                "remediation": text_or_none(result, "solution"),

                "tags": None,

                # Keep full XML string for debugging + traceability
                "raw": ET.tostring(result, encoding="unicode"),
            }

            findings.append(finding)

        except Exception as e:
            logger.warning(f"Skipping OpenVAS result index={idx}: {e}")

    logger.info(f"Ingested {len(findings)} OpenVAS findings")

    return findings