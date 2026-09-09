"""SRP adapters. ENISA has no API at launch — portal-only is the default."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class SrpSubmission(BaseModel):
    stage: str
    fields: dict
    markdown: str


class SrpResult(BaseModel):
    submitted: bool
    reference_id: str | None = None
    message: str


class SrpAdapter(Protocol):
    def submit(self, packet: SrpSubmission) -> SrpResult: ...


class PortalOnlyAdapter:
    """Human files on the ENISA SRP web portal. We never POST to ENISA."""

    def submit(self, packet: SrpSubmission) -> SrpResult:
        return SrpResult(
            submitted=False,
            message=(
                "ENISA SRP has no public API. Copy the packet fields into the portal, "
                f"then mark this {packet.stage} as submitted in the control plane."
            ),
        )


def get_adapter() -> SrpAdapter:
    return PortalOnlyAdapter()
