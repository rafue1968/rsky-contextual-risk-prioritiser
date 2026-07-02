from typing import Dict, Any, Optional

class OpenVASNormalizer:
    """
    Normalizes OpenVAS intermediate findings into the Unified Finding Model.
    """


    SEVERITY_MAPPING = {
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }


    def _build_severity(self, risk_code: Optional[str]) -> str:
        if risk_code is None:
            return "unknown"
        
        return self.SEVERITY_MAPPING.get(str(risk_code), "unknown")
    

    def normalize(self, openvas_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a single OpenVAS intermediate finding into the Unified Finding Model.
        """

        return {
            "id": openvas_finding.get("raw_id"), #self._build_finding_id(openvas_finding),
            "title": openvas_finding.get("title"),
            "description": openvas_finding.get("description"),
            "service": openvas_finding.get("service"),
            "severity": self._build_severity(
                openvas_finding.get("severity")
            ),
            "cwe": openvas_finding.get("cwe"),
            "url": openvas_finding.get("url"),
            "source": openvas_finding.get("source"),
            "raw": openvas_finding.get("raw"),
            "nvt": openvas_finding.get("nvt"),
            "remediation": openvas_finding.get("remediation"),
        }