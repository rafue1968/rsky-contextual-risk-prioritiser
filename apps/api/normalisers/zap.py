from typing import Dict, Any, Optional




class UnifiedFindingNormalizer:
    """
    Normalizes OWASP ZAP intermediate findings into the Unified Finding Model.
    """

    SEVERITY_MAPPING = {
        0: "info",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }

    # CONFIDENCE_MAP = {
    #     "False Positive": "false_positive",
    #     "Low": "low",
    #     "Medium": "medium",
    #     "High": "high",
    #     "Confirmed": "confirmed",
    # }


    def _build_severity(self, risk_code: Optional[str]) -> str:
        if risk_code is None:
            return "unkown"
        
        return self.SEVERITY_MAPPING.get(str(risk_code), "unknown")


    def normalize(self, zap_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a single OWASP ZAP intermediate finding into the Unified Finding Model.
        """

        return {
            "id": self._build_finding_id(zap_finding),
            "title": zap_finding.get("title"),
            "description": self._build_description(zap_finding),
            "risk": self._build_risk(zap_finding),
            "severity": self._build_severity(
                zap_finding.get("risk")
            ),
            "cwe": zap_finding.get("cwe"),
            "url": zap_finding.get("endpoint"),
            "source": zap_finding.get("source"),
            "raw": zap_finding.get("raw"),
            # "tags": zap_finding.get("tags"),
            # "scanner_risk_code": 
        
        }