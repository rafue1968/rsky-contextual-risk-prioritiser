import uuid
from datetime import datetime


def map_severity(risk):
    mapping = {
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "informational",
        "high": "high",
        "medium": "medium",
        "low": "low"
    }
    return mapping.get(str(risk).lower(), "informational")


def normalise_finding(raw: dict) -> dict:
    """
    Converts connector output → Nuhan unified schema
    """

    return {
        "finding_id": str(uuid.uuid4()),

        "source": {
            "scanner": raw.get("source"),
            "scanner_version": None,
            "scan_id": None,
            "scan_timestamp": None
        },

        "vulnerability": {
            "title": raw.get("title"),
            "description": raw.get("description"),
            "category": "web",
            "cwe_ids": raw.get("cwe") or [],
            "cve_ids": raw.get("cve") or [],
            "references": []
        },

        "severity": {
            "level": map_severity(raw.get("risk") or raw.get("severity")),
            "cvss_score": None,
            "cvss_vector": None,
            "confidence": "medium"
        },

        "target": {
            "host": raw.get("host"),
            "port": raw.get("port"),
            "protocol": "http",
            "url": raw.get("url"),
            "asset_type": "web_app"
        },

        "evidence": {
            "request": raw.get("request"),
            "response": raw.get("response"),
            "matched_content": None,
            "parameter": None,
            "attack_vector": None
        },

        "remediation": {
            "solution": raw.get("remediation"),
            "solution_type": "vendorfix"
        },

        "metadata": {
            "raw_plugin_id": raw.get("raw_id"),
            "tags": raw.get("tags") or [],
            "first_seen": datetime.utcnow().isoformat(),
            "raw_source_data": raw.get("raw")
        }
    }