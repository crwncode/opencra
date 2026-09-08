"""Canonical OpenCRA scan and SBOM models shared by CLI and SaaS."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class FailOn(str, Enum):
    NONE = "none"
    KEV = "kev"
    CRITICAL = "critical"
    HIGH = "high"


class SbomTool(BaseModel):
    name: str
    version: str | None = None


class SbomMetadata(BaseModel):
    timestamp: datetime | None = None
    name: str | None = None
    version: str | None = None
    component_type: str = "application"
    tools: list[SbomTool] = Field(default_factory=list)


class Component(BaseModel):
    type: str = "library"
    name: str
    version: str | None = None
    purl: str | None = None
    licenses: list[str] = Field(default_factory=list)
    hashes: dict[str, str] = Field(default_factory=dict)
    skipped_reason: str | None = None


class VulnMatch(BaseModel):
    purl: str
    component_name: str | None = None
    component_version: str | None = None
    osv_id: str | None = None
    cve_id: str | None = None
    severity: str | None = None
    cvss_v3: float | None = None
    epss: float | None = None
    in_kev: bool = False
    kev_added_at: datetime | None = None
    kev_ransomware: str | None = None
    aliases: list[str] = Field(default_factory=list)
    status: str = "open"
    vex_status: str | None = None
    summary: str | None = None


class SbomDocument(BaseModel):
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    serial_number: str = Field(default_factory=lambda: f"urn:uuid:{uuid4()}")
    version: int = 1
    metadata: SbomMetadata = Field(default_factory=SbomMetadata)
    components: list[Component] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    target: str
    scanned_at: datetime
    sbom: SbomDocument
    matches: list[VulnMatch] = Field(default_factory=list)
    skipped_components: list[Component] = Field(default_factory=list)
    offline: bool = False
    warnings: list[str] = Field(default_factory=list)

    @property
    def kev_hits(self) -> list[VulnMatch]:
        return [m for m in self.matches if m.in_kev]

    def fails(self, threshold: FailOn) -> bool:
        if threshold is FailOn.NONE:
            return False
        if threshold is FailOn.KEV:
            return any(m.in_kev for m in self.matches)
        ranks = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        cutoff = 4 if threshold is FailOn.CRITICAL else 3
        for match in self.matches:
            rank = ranks.get((match.severity or "NONE").upper(), 0)
            if rank >= cutoff:
                return True
        return False
