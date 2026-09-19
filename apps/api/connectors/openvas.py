import logging
import xml.etree.ElementTree as ET

from defusedxml.ElementTree import parse as safe_parse

from schemas.finding import Finding


logger = logging.getLogger(__name__)


def text_or_none(node: ET.Element,path: str,) -> str | None:
    child = node.find(path)

    if child is not None and child.text:
        return child.text.strip()

    return None

def attribute_or_none(
    node: ET.Element,
    path: str,
    attribute: str,
) -> str | None:
    element = node.find(path)

    if element is None:
        return None

    return element.attrib.get(attribute)


def parse_port(value: str | None,) -> tuple[int | None, str | None]:
    if not value or "/" not in value:
        return None, None

    port_text, protocol = value.split("/", 1)

    try:
        return int(port_text), protocol.lower()
    except ValueError:
        return None, protocol.lower()


def parse_openvas_file(file_path: str,) -> list[Finding]:
    findings: list[Finding] = []

    try:
        tree = safe_parse(file_path)
        root = tree.getroot()
    except Exception as exc:
        logger.error(
            "Failed to parse OpenVAS XML: %s",
            exc,
        )
        return findings

    results = root.findall(".//result")

    for index, result in enumerate(results):
        try:
            refs = result.findall(".//ref")

            cve_ids = [
                ref.attrib["id"]
                for ref in refs
                if ref.attrib.get("type") == "cve"
                and ref.attrib.get("id")
            ]

            references = [
                ref.attrib["id"]
                for ref in refs
                if ref.attrib.get("type") == "url"
                and ref.attrib.get("id")
            ]

            port_number, protocol = parse_port(
                text_or_none(result, "port")
            )

            severity_text = text_or_none(
                result,
                "severity",
            )

            try:
                score = (
                    float(severity_text)
                    if severity_text is not None
                    else None
                )
            except ValueError:
                score = None

            raw_xml = ET.tostring(
                result,
                encoding="unicode",
            )

            finding = Finding(
                source_scanner="openvas",
                source_finding_id=attribute_or_none(result,".","id",),

                title=(
                    text_or_none(result, "name")
                    or "Untitled OpenVAS finding"
                ),
                description=text_or_none(
                    result,
                    "description",
                ),

                severity_score=score,

                target_host=text_or_none(
                    result,
                    "host",
                ),
                target_port=port_number,
                target_protocol=protocol,

                cve_ids=cve_ids,

                evidence={
                    "threat": text_or_none(
                        result,
                        "threat",
                    ),
                    "qod": text_or_none(
                        result,
                        ".//qod/value",
                    ),
                    "references": references,
                },

                remediation={
                    "solution": text_or_none(
                        result,
                        ".//solution",
                    ),
                    "solution_type": text_or_none(
                        result,
                        ".//solution/type",
                    ),
                },

                metadata={
                    "nvt": attribute_or_none(
                        result,
                        "nvt",
                        "oid",
                    ),
                },

                raw_payload={
                    "xml": raw_xml,
                },
            )

            findings.append(finding)

        except Exception as exc:
            logger.warning("Skipping OpenVAS result index=%d: %s", index, exc,)

    logger.info("Ingested %d OpenVAS findings", len(findings),)

    return findings