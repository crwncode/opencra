"""OpenVEX document models and candidate-dismissal policy."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from opencra_shared.clocks import CaseStatus


class VexStatus(str, Enum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VexJustification(str, Enum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


ACKNOWLEDGED_STATUSES = {
    CaseStatus.ACKNOWLEDGED,
    CaseStatus.EARLY_WARNING_SUBMITTED,
    CaseStatus.NOTIFICATION_SUBMITTED,
    CaseStatus.AWAITING_FIX,
    CaseStatus.OVERDUE_EARLY_WARNING,
    CaseStatus.OVERDUE_NOTIFICATION,
    CaseStatus.OVERDUE_FINAL,
}


class VexProduct(BaseModel):
    id: str = Field(alias="@id")

    model_config = {"populate_by_name": True}


class VexVulnerability(BaseModel):
    name: str


class VexStatement(BaseModel):
    vulnerability: VexVulnerability
    products: list[VexProduct] = Field(default_factory=list)
    status: VexStatus
    justification: VexJustification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    status_notes: str | None = None

    @model_validator(mode="after")
    def require_not_affected_evidence(self) -> VexStatement:
        if self.status is VexStatus.NOT_AFFECTED:
            if self.justification is None and not self.impact_statement:
                raise ValueError(
                    "not_affected requires a justification label or an impact_statement"
                )
        return self


class OpenVexDocument(BaseModel):
    context: str = Field(
        default="https://openvex.dev/ns/v0.2.0",
        alias="@context",
    )
    id: str = Field(default_factory=lambda: f"https://open.cra/vex/{uuid4()}", alias="@id")
    author: str = "OpenCRA"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1
    statements: list[VexStatement] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class VexApplyResult(BaseModel):
    applied: bool
    requires_override: bool = False
    reason: str


def can_dismiss_case(case_status: CaseStatus) -> VexApplyResult:
    """VEX may dismiss candidates. Acknowledged Art. 14 cases need an override."""
    if case_status is CaseStatus.CANDIDATE:
        return VexApplyResult(applied=True, reason="candidate_dismissed")
    if case_status is CaseStatus.DISMISSED:
        return VexApplyResult(applied=False, reason="already_dismissed")
    if case_status in ACKNOWLEDGED_STATUSES:
        return VexApplyResult(
            applied=False,
            requires_override=True,
            reason="acknowledged_case_requires_compliance_officer_override",
        )
    return VexApplyResult(applied=False, reason=f"status_{case_status.value}_not_dismissable")


def parse_openvex(payload: dict[str, Any]) -> OpenVexDocument:
    return OpenVexDocument.model_validate(payload)


def serialize_openvex(document: OpenVexDocument) -> dict[str, Any]:
    return document.model_dump(by_alias=True, mode="json")
