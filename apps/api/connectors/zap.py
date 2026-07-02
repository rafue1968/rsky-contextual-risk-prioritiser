import json
import logging

logger = logging.getLogger(__name__)


def parse_zap_file(file_path: str) -> list[dict]:
    """
    Reads OWASP ZAP JSON export and extracts findings into a simple structure.
    """

    findings = []

    # 1. Load JSON file safely
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as e:
        logger.error(f"Invalid ZAP JSON file: {e}")
        return []

    except Exception as e:
        logger.exception(f"Failed to load ZAP file: {e}")
        return []
    

    scanner_version = data.get("@version")
    scan_timestamp = data.get("@generated")

    # 2. Navigate scanner structure (site → alerts)
    sites = data.get("site", [])

    for site in sites:
        alerts = site.get("alerts", [])
        host = site.get("@host")
        port = site.get("@port")
        ssl = site.get("@ssl")

        for idx, alert in enumerate(alerts):
            try:

                instance = (
                    alert.get("instances", [{}])[0]
                    if alert.get("instances")
                    else {}
                )

                # 3. Extract ONLY what we need (no heavy structuring)
                finding = {
                    "source": "zap",
                    "scanner_version": scanner_version,
                    "scan_timestamp": scan_timestamp,
                    
                    "host": host,
                    "port": int(port) if port else None,
                    "ssl": ssl,

                    "raw_id": str(alert.get("pluginid")) if alert.get("pluginid") else None,
                    "title": alert.get("alert"),
                    "description": alert.get("desc"),

                    "risk": alert.get("riskcode"),
                    "confidence": alert.get("confidence"),

                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),

                    "cwe": [str(alert.get("cweid"))] if alert.get("cweid") else [],
                    "cve": alert.get("cve", []),

                    "url": instance.get("url"),
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