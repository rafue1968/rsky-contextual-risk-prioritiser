import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def parse_zap_file(file_path: str) -> list[dict]:
    """
    Reads OWASP ZAP JSON export and extracts findings into a simple structure.
    """

    findings = []

    # 1. Load JSON file safely
    try:
        with Path(file_path).open("r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as e:
        logger.error(f"Invalid ZAP JSON file: {e}")
        return []

    except Exception as e:
        logger.exception(f"Failed to load ZAP file: {e}")
        return []
    

    if not isinstance(data, dict):
        logger.error("Invalid ZAP JSON file: expected an object at the root")
        return []

    scanner_version = data.get("@version")
    scan_timestamp = data.get("@generated") or data.get("created")

    # 2. Navigate scanner structure (site → alerts)
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        logger.error("Invalid ZAP JSON file: expected 'site' to be a list")
        return []

    for site in sites:
        if not isinstance(site, dict):
            logger.warning("Skipping malformed ZAP site entry")
            continue

        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]
        if not isinstance(alerts, list):
            logger.warning("Skipping malformed ZAP alerts for site=%s", site.get("@name"))
            continue

        host = site.get("@host")
        port = site.get("@port")
        ssl = site.get("@ssl")

        for idx, alert in enumerate(alerts):
            try:

                if not isinstance(alert, dict):
                    raise ValueError("alert must be an object")

                instances = alert.get("instances") or [{}]
                if isinstance(instances, dict):
                    instances = [instances]
                if not isinstance(instances, list):
                    instances = [{}]
                instance = next(
                    (item for item in instances if isinstance(item, dict)), {}
                )

                alert_id = alert.get("alertRef") or alert.get("pluginid")
                site_id = site.get("@name") or host
                source_finding_id = (
                    f"{alert_id}@{site_id}" if alert_id and site_id else alert_id
                )
                try:
                    parsed_port = int(port) if port not in (None, "") else None
                except (TypeError, ValueError):
                    parsed_port = None

                raw_cwe = alert.get("cweid")
                cwe_ids = [str(raw_cwe)] if raw_cwe not in (None, "", "-1") else []
                raw_cve = alert.get("cve")
                if isinstance(raw_cve, str):
                    cve_ids = [item.strip() for item in raw_cve.split(",") if item.strip()]
                elif isinstance(raw_cve, list):
                    cve_ids = [str(item).strip() for item in raw_cve if str(item).strip()]
                else:
                    cve_ids = []

                # 3. Extract ONLY what we need (no heavy structuring)
                finding = {
                    "source": "zap",
                    "scanner_version": scanner_version,
                    "scan_timestamp": scan_timestamp,
                    
                    "host": host,
                    "port": parsed_port,
                    "ssl": ssl,

                    "raw_id": str(alert.get("pluginid")) if alert.get("pluginid") else None,
                    "source_finding_id": str(source_finding_id) if source_finding_id else None,
                    "title": alert.get("alert"),
                    "description": alert.get("desc"),

                    "risk": alert.get("riskcode"),
                    "confidence": alert.get("confidence"),

                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),

                    "cwe": cwe_ids,
                    "cve": cve_ids,

                    "url": instance.get("uri") or instance.get("url"),
                    "method": instance.get("method"),
                    "parameter": instance.get("param"),
                    "attack": instance.get("attack"),
                    "matched_content": instance.get("evidence"),

                    # Keep raw HTTP evidence (important for later ML/debugging)
                    "request": alert.get("request"),
                    "response": alert.get("response"),

                    "tags": alert.get("tags"),

                    # VERY IMPORTANT: full original scanner data preserved
                    "raw": alert,
                }

                findings.append(finding)

            except Exception as e:
                logger.warning(f"Skipping malformed ZAP alert index={idx}: {e}")

    logger.info(f"Ingested {len(findings)} ZAP findings")

    return findings