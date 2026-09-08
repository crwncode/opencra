import pytest
from opencra_shared.clocks import CaseStatus
from opencra_shared.vex import (
    VexJustification,
    VexStatement,
    VexStatus,
    VexVulnerability,
    can_dismiss_case,
)


def test_not_affected_requires_justification_or_impact() -> None:
    with pytest.raises(ValueError):
        VexStatement(
            vulnerability=VexVulnerability(name="CVE-2024-0001"),
            status=VexStatus.NOT_AFFECTED,
        )
    ok = VexStatement(
        vulnerability=VexVulnerability(name="CVE-2024-0001"),
        status=VexStatus.NOT_AFFECTED,
        justification=VexJustification.COMPONENT_NOT_PRESENT,
    )
    assert ok.justification is VexJustification.COMPONENT_NOT_PRESENT


def test_vex_dismisses_candidate_not_acknowledged() -> None:
    assert can_dismiss_case(CaseStatus.CANDIDATE).applied is True
    blocked = can_dismiss_case(CaseStatus.ACKNOWLEDGED)
    assert blocked.applied is False
    assert blocked.requires_override is True
