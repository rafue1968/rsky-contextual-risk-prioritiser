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

    # 2. Navigate scanner structure (site → alerts)
    sites = data.get("site", [])

    for site in sites:
        alerts = site.get("alerts", [])

        for idx, alert in enumerate(alerts):
            try:
                # 3. Extract ONLY what we need (no heavy structuring)
                finding = {
                    "source": "zap",
                    "raw_id": str(alert.get("pluginid")) if alert.get("pluginid") else None,
                    "title": alert.get("alert"),
                    "description": alert.get("desc"),
                    "risk": alert.get("riskcode"),
                    "url": alert.get("url"),
                    "endpoint": alert.get("uri"),
                    "cwe": [str(alert.get("cweid"))] if alert.get("cweid") else None,
                    "cve": alert.get("cve") or None,

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