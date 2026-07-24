from typing import Dict, Any, Optional
from uuid import uuid4
from schemas.finding import Finding




class ZapNormalizer:
    """
    Normalizes OWASP ZAP intermediate findings into the Unified Finding Model.
    """

    RISK_MAP = {
        "0": "informational",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }


    def normalize(self, finding: Dict[str, Any]) -> Finding:
        """
        Convert a single OWASP ZAP intermediate finding into the Unified Finding Model.
        """

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
            "source_finding_id": finding.get("raw_id"),
        }
    

    def _build_vulnerability(self, finding):
        
        references = []

        if finding.get("reference"):
            references.append(finding["reference"])

        return {
            "title": finding.get("title"),
            "description": finding.get("description"),
            "category": "web",
            "cwe_ids": finding.get("cwe") or [],
            "cve_ids": finding.get("cve") or [],
            "references": references,
        }
    
    
    def _build_severity(self, finding):
        return {
            "level": self.RISK_MAP.get(
                str(finding.get("risk")), 
                "unknown"
            ),
            "cvss_score": None,
            "cvss_vector": None,
            "confidence": None,
        }
    

    def _build_target(self, finding):

        url = finding.get("url")

        protocol = None 
        
        if url:
            if url.startswith("https://"):
                protocol = "https"               
            elif url.startswith("http://"):
                protocol = "http"

        return {
            "host": None, #finding.get("host"),
            "port": None, #finding.get("port"),
            "protocol": protocol,
            "url": url,
            "asset_type": "web_app"
        }
    

    def _build_evidence(self, finding):
        return {
            "request": finding.get("request"),
            "response": finding.get("response"),
            "matched_content": finding.get("matched_content"),
            "parameter": finding.get("parameter"),
            "attack_vector": finding.get("attack"),
        }
    

    def _build_remediation(self, finding):
        return {
            "solution": finding.get("solution"),
            "solution_type": "mitigation",
        }
    
    def _build_metadata(self, finding):
        tags = finding.get("tags")

        if tags is None:
            tags = []

        return {
            "raw_plugin_id": finding.get("raw_id"),
            "tags": tags,
            "first_seen": finding.get("scan_timestamp"),
            "raw_source_data": finding.get("raw"),
        }