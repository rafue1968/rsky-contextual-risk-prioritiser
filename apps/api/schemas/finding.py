# File defines the Pydantic model for a NORMALISED Finding, which represents a security issue identified by a scanner.
from datetime import datetime
from typing import Literal, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

SeverityLevel = Literal["critical", "high", "medium", "low", "informational"]
Protocol = Literal["tcp", "udp", "http", "https"]
Scanner = Literal["zap", "openvas"]

class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore") # ignore extra fields that are not defined in the model
    finding_id: Optional[UUID] = None

    # Source info
    source_scanner: Scanner
    source_finding_id: Optional[str] = None
    scan_id: Optional[str] = None

    # Vulnerability info
    title: str
    description: Optional[str] = None
    vulnerability_category: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)

    # Severity info
    severity_level: SeverityLevel
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