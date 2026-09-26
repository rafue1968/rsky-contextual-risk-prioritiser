from typing import Dict, Any
from uuid import uuid4
from schemas.finding import Finding

class OpenVASNormalizer:
    """
    Normalizes OpenVAS intermediate findings into the Unified Finding Model.
    """


    SEVERITY_MAP = {
        "Log": "informational",
        "Low": "low",
        "Medium": "medium",
        "High": "high",
        "Critical": "critical",
    }
    

    def normalize(self, finding: Dict[str, Any]) -> Finding:
        data = {
            "finding_id": str(uuid4()),
            "source": self._build_source(finding),
            "vulnerability": self._build_vulnerability(finding),
            "severity": self._build_severity(finding),
            "target": self._build_target(finding),
            "evidence": self._build_evidence(finding),
            "remediation": self._build_remediation(finding),
            "metadata": self._build_metadata(finding),
        }

        return Finding(**data)
    
    
    def _build_source(self, finding):
        return {
            "scanner": finding.get("source"),
            "scanner_version": finding.get("scanner_version"),
            "scan_id": finding.get("scan_id"),
            "scan_timestamp": finding.get("scan_timestamp"),
            "source_finding_id": finding.get("source_finding_id") or finding.get("raw_id"),
        }
    
    
    def _build_vulnerability(self, finding):
        return {
            "title": finding.get("title"),
            "description": finding.get("description"),
            "category": "network",
            "cwe_ids": finding.get("cwe") or [],
            "cve_ids": [
                str(value).strip()
                for value in (finding.get("cve") or [])
                if str(value).strip().upper() not in {"NOCVE", "NONE"}
            ],
            "references": finding.get("references") or [],
        }
    
    
    def _build_severity(self, finding):
        severity = finding.get("threat")
        if severity is not None:
            severity = str(severity).strip().lower().title()
        if severity not in self.SEVERITY_MAP:
            score = finding.get("cvss_score")
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = None
            if score is not None:
                severity = (
                    "Critical" if score >= 9.0 else
                    "High" if score >= 7.0 else
                    "Medium" if score >= 4.0 else
                    "Low" if score > 0 else
                    "Log"
                )
            else:
                severity = finding.get("severity")
                severity = str(severity).strip().lower().title() if severity is not None else None
        return {
            "level": self.SEVERITY_MAP.get(
                severity,
                "informational"
            ),
            "cvss_score": finding.get("cvss_score"),
            "cvss_vector": finding.get("cvss_vector"),
    }
    
    def _build_target(self, finding):
        return {
            "host": finding.get("host"),
            "port": finding.get("port"),
            "protocol": (finding.get("protocol") or "").lower() or None,
            "url": None,
            "asset_type": "network_service",
        }
    
    def _build_evidence(self, finding):
        return {
            "request": None,
            "response": None,
            "matched_content": None, #finding.get("matched_content"),
            "parameter": None,
            "attack_vector": None,
        }
    

    def _build_remediation(self, finding):
        solution_type = finding.get("solution_type")
        return {
            "solution": finding.get("solution"), #finding.get("remediation"),
            "solution_type": str(solution_type).strip().lower() if solution_type else None,
        }
    
    def _build_metadata(self, finding):
        tags = finding.get("tags")

        if tags is None:
            tags = []

        return {
            "raw_plugin_id": finding.get("nvt"),
            "tags": tags,
            "first_seen": finding.get("scan_timestamp"),
            "raw_source_data": finding.get("raw"),
            "connector_output": {
                key: value for key, value in finding.items() if key != "raw"
            },
        }