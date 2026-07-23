from typing import Dict, Any, Optional
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
        }
    
    
    def _build_vulnerability(self, finding):
        return {
            "title": finding.get("title"),
            "description": finding.get("description"),
            "category": "network",
            "cwe_ids": finding.get("cwe") or [],
            "cve_ids": finding.get("cve") or [],
            "references": finding.get("references") or [],
        }
    
    
    def _build_severity(self, finding):
        return {
            "level": self.SEVERITY_MAP.get(
                finding.get("threat"),
                "unknown" if finding.get("threat") else finding.get("severity"),
            ),
            "cvss_score": finding.get("cvss_score"),
            "cvss_vector": finding.get("cvss_vector"),
            # "confidence": None,
        }
    
    def _build_target(self, finding):
        return {
            "host": finding.get("host"),
            "port": finding.get("port"),
            "protocol": finding.get("protocol"),
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
        return {
            "solution": finding.get("solution"), #finding.get("remediation"),
            "solution_type": (
                finding.get("solution_type") or "vendorfix"
                ).lower(),
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
        }