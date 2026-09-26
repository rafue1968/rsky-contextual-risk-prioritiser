# File defines the Pydantic model for a NORMALISED Finding, which represents a security issue identified by a scanner.
from datetime import datetime
import math
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

        source = cls._as_dict(data.get("source"))
        vulnerability = cls._as_dict(data.get("vulnerability"))
        severity = cls._as_dict(data.get("severity"))
        target = cls._as_dict(data.get("target"))
        evidence = cls._as_dict(data.get("evidence"))
        remediation = cls._as_dict(data.get("remediation"))
        metadata = cls._as_dict(data.get("metadata"))
        raw_source_data = metadata.get("raw_source_data")
        connector_output = cls._as_dict(metadata.get("connector_output"))
        raw_source_dict = cls._as_dict(raw_source_data)
        title = (
            data.get("title")
            or vulnerability.get("title")
            or connector_output.get("title")
            or raw_source_dict.get("alert")
            or raw_source_dict.get("name")
            or "Untitled finding"
        )
        raw_payload = data.get("raw_payload")
        if raw_payload is None:
            raw_payload = raw_source_data

        normalised = {
            "finding_id": data.get("finding_id"),
            "source_scanner": cls._coerce_scanner(data.get("source_scanner") or source.get("scanner")),
            "source_finding_id": data.get("source_finding_id") or source.get("source_finding_id"),
            "scan_id": data.get("scan_id") or source.get("scan_id"),
            "title": title,
            "description": data.get("description") or vulnerability.get("description"),
            "vulnerability_category": data.get("vulnerability_category") or vulnerability.get("category"),
            "cve_ids": data.get("cve_ids") or vulnerability.get("cve_ids") or [],
            "cwe_ids": data.get("cwe_ids") or vulnerability.get("cwe_ids") or [],
            "severity_level": cls._coerce_severity(data.get("severity_level") or severity.get("level")),
            "severity_score": data.get("severity_score") if data.get("severity_score") is not None else severity.get("cvss_score"),
            "target_host": data.get("target_host") or target.get("host"),
            "target_url": data.get("target_url") or target.get("url"),
            "target_port": data.get("target_port") if data.get("target_port") is not None else target.get("port"),
            "target_protocol": data.get("target_protocol") or target.get("protocol"),
            "evidence": data.get("evidence") if data.get("evidence") is not None else evidence,
            "remediation": data.get("remediation") if data.get("remediation") is not None else remediation,
            "metadata": data.get("metadata") if data.get("metadata") is not None else metadata,
            "raw_payload": raw_payload,
            "fingerprint": data.get("fingerprint"),
            "is_canonical": data.get("is_canonical", True),
            "canonical_finding_id": data.get("canonical_finding_id"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
        }

        return cls._normalise_flat_fields(normalised)

    @classmethod
    def _normalise_flat_fields(cls, data: dict) -> dict:
        data = dict(data)
        data["cve_ids"] = cls._coerce_string_list(data.get("cve_ids"))
        data["cwe_ids"] = cls._coerce_string_list(data.get("cwe_ids"))
        data["title"] = cls._coerce_title(data.get("title"), data.get("metadata"))
        data["source_scanner"] = cls._coerce_scanner(data.get("source_scanner"))
        data["source_finding_id"] = cls._coerce_optional_text(data.get("source_finding_id"))
        data["scan_id"] = cls._coerce_optional_text(data.get("scan_id"))
        data["target_host"] = cls._coerce_optional_text(data.get("target_host"))
        data["target_url"] = cls._coerce_optional_text(data.get("target_url"))
        data["target_port"] = cls._coerce_port(data.get("target_port"))
        data["target_protocol"] = cls._coerce_protocol(data.get("target_protocol"))
        data["severity_score"] = cls._coerce_score(data.get("severity_score"))
        data["evidence"] = cls._as_dict(data.get("evidence"))
        data["remediation"] = cls._as_dict(data.get("remediation"))
        data["metadata"] = cls._as_dict(data.get("metadata"))
        data["raw_payload"] = cls._as_dict(data.get("raw_payload"))

        if data.get("severity_level") is None:
            data["severity_level"] = "informational"
        else:
            data["severity_level"] = cls._coerce_severity(data["severity_level"])

        return data

    @staticmethod
    def _as_dict(value: Any) -> dict:
        if isinstance(value, dict):
            return value
        return {} if value is None else {"raw": value}

    @staticmethod
    def _coerce_string_list(value: Any) -> list[str]:
        if value is None:
            return []
        values = value.split(",") if isinstance(value, str) else value
        if not isinstance(values, (list, tuple, set)):
            values = [values]
        return [str(item).strip() for item in values if str(item).strip()]

    @classmethod
    def _coerce_title(cls, value: Any, metadata: Any) -> str:
        if isinstance(value, str) and value.strip():
            return value.strip()
        metadata_dict = cls._as_dict(metadata)
        connector_output = cls._as_dict(metadata_dict.get("connector_output"))
        raw_source = cls._as_dict(metadata_dict.get("raw_source_data"))
        fallback = (
            connector_output.get("title")
            or raw_source.get("alert")
            or raw_source.get("name")
        )
        return str(fallback).strip() if fallback else "Untitled finding"

    @staticmethod
    def _coerce_optional_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _coerce_scanner(value: Any) -> Optional[Scanner]:
        if value is None:
            return None
        scanner = str(value).strip().lower()
        return scanner if scanner in {"zap", "openvas"} else None

    @staticmethod
    def _coerce_port(value: Any) -> Optional[int]:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if 0 <= value <= 65535 else None
        if isinstance(value, float):
            return int(value) if value.is_integer() and 0 <= value <= 65535 else None
        try:
            port = int(str(value).strip().split("/", 1)[0])
        except (TypeError, ValueError):
            return None
        return port if 0 <= port <= 65535 else None

    @staticmethod
    def _coerce_protocol(value: Any) -> Optional[Protocol]:
        if value is None:
            return None
        protocol = str(value).strip().lower()
        return protocol if protocol in {"tcp", "udp", "http", "https"} else None

    @staticmethod
    def _coerce_score(value: Any) -> Optional[float]:
        if value is None or isinstance(value, bool):
            return None
        try:
            score = float(value)
        except (TypeError, ValueError):
            return None
        return score if math.isfinite(score) else None

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
