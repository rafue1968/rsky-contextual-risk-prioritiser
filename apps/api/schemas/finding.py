# File defines the Pydantic model for a NORMALISED Finding, which represents a security issue identified by a scanner.
from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator

SeverityLevel = Literal["critical", "high", "medium", "low", "informational"]
Protocol = Literal["tcp", "udp", "http", "https"]
Scanner = Literal["zap", "openvas"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: Optional[UUID] = None

    # Source info
    source_scanner: Optional[Scanner] = None
    source_finding_id: Optional[str] = None
    scan_id: Optional[str] = None

    # Vulnerability info
    title: str
    description: Optional[str] = None
    vulnerability_category: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)

    # Severity info
    severity_level: Optional[SeverityLevel] = None
    severity_score: Optional[float] = None

    # Target info
    target_host: Optional[str] = None
    target_url: Optional[str] = None
    target_port: Optional[int] = None
    target_protocol: Optional[Protocol] = None

    # Scanner-specific data
    evidence: dict = Field(default_factory=dict)
    remediation: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)
    raw_payload: dict = Field(default_factory=dict)

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    fingerprint: Optional[str] = None

    is_canonical: bool = True

    canonical_finding_id: Optional[UUID] = None


    @model_validator(mode="before")
    @classmethod
    def _normalise_input(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        if any(key in data for key in ("source_scanner", "severity_level", "title", "target_host")):
            return cls._normalise_flat_fields(data)

        source = data.get("source") or {}
        vulnerability = data.get("vulnerability") or {}
        severity = data.get("severity") or {}
        target = data.get("target") or {}
        evidence = data.get("evidence") or {}
        remediation = data.get("remediation") or {}
        metadata = data.get("metadata") or {}

        normalised = {
            "finding_id": data.get("finding_id"),
            "source_scanner": data.get("source_scanner") or source.get("scanner"),
            "source_finding_id": data.get("source_finding_id"),
            "scan_id": data.get("scan_id") or source.get("scan_id"),
            "title": data.get("title") or vulnerability.get("title"),
            "description": data.get("description") or vulnerability.get("description"),
            "vulnerability_category": data.get("vulnerability_category") or vulnerability.get("category"),
            "cve_ids": data.get("cve_ids") or vulnerability.get("cve_ids") or [],
            "cwe_ids": data.get("cwe_ids") or vulnerability.get("cwe_ids") or [],
            "severity_level": cls._coerce_severity(data.get("severity_level") or severity.get("level")),
            "severity_score": data.get("severity_score") or severity.get("cvss_score"),
            "target_host": data.get("target_host") or target.get("host"),
            "target_url": data.get("target_url") or target.get("url"),
            "target_port": data.get("target_port") or target.get("port"),
            "target_protocol": data.get("target_protocol") or target.get("protocol"),
            "evidence": data.get("evidence") if data.get("evidence") is not None else evidence,
            "remediation": data.get("remediation") if data.get("remediation") is not None else remediation,
            "metadata": data.get("metadata") if data.get("metadata") is not None else metadata,
            "raw_payload": data.get("raw_payload") or metadata.get("raw_source_data") or {},
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
        }

        return cls._normalise_flat_fields(normalised)

    @classmethod
    def _normalise_flat_fields(cls, data: dict) -> dict:
        if isinstance(data.get("cve_ids"), str):
            data["cve_ids"] = [data["cve_ids"]]
        if isinstance(data.get("cwe_ids"), str):
            data["cwe_ids"] = [data["cwe_ids"]]

        if data.get("severity_level") is None:
            data["severity_level"] = "informational"
        else:
            data["severity_level"] = cls._coerce_severity(data["severity_level"])

        data.setdefault("evidence", {})
        data.setdefault("remediation", {})
        data.setdefault("metadata", {})
        data.setdefault("raw_payload", {})
        data.setdefault("cve_ids", [])
        data.setdefault("cwe_ids", [])
        return data

    @staticmethod
    def _coerce_severity(value: Any) -> Optional[SeverityLevel]:
        if value is None:
            return "informational"

        text = str(value).strip().lower()
        if text in {"unknown", "", "none", "null"}:
            return "informational"

        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "informational",
        }
        return mapping.get(text, "informational")
