"""Pure CRA Article 14 clock calculators.

A scanner hit is a candidate. Clocks start only when a human sets awareness_at.
The 14-day final report is measured from fix_available_at for vulnerabilities,
not from awareness. Severe incidents use one calendar month after notification.
"""

from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, Field


class CaseType(str, Enum):
    ACTIVELY_EXPLOITED_VULN = "actively_exploited_vuln"
    SEVERE_INCIDENT = "severe_incident"


class CaseStatus(str, Enum):
    CANDIDATE = "candidate"
    ACKNOWLEDGED = "acknowledged"
    EARLY_WARNING_SUBMITTED = "early_warning_submitted"
    NOTIFICATION_SUBMITTED = "notification_submitted"
    AWAITING_FIX = "awaiting_fix"
    FINAL_SUBMITTED = "final_submitted"
    CLOSED = "closed"
    DISMISSED = "dismissed"
    OVERDUE_EARLY_WARNING = "overdue_early_warning"
    OVERDUE_NOTIFICATION = "overdue_notification"
    OVERDUE_FINAL = "overdue_final"


class ClockSet(BaseModel):
    awareness_at: datetime | None = None
    early_warning_due_at: datetime | None = None
    notification_due_at: datetime | None = None
    fix_available_at: datetime | None = None
    notification_submitted_at: datetime | None = None
    final_report_due_at: datetime | None = None
    overdue: list[str] = Field(default_factory=list)


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def add_one_calendar_month(dt: datetime) -> datetime:
    """Add one calendar month, clamping the day to the last valid day."""
    dt = _ensure_aware(dt)
    month = dt.month + 1
    year = dt.year
    if month > 12:
        month = 1
        year += 1
    last_day = calendar.monthrange(year, month)[1]
    return dt.replace(year=year, month=month, day=min(dt.day, last_day))


def early_warning_due_at(awareness_at: datetime) -> datetime:
    return _ensure_aware(awareness_at) + timedelta(hours=24)


def notification_due_at(awareness_at: datetime) -> datetime:
    return _ensure_aware(awareness_at) + timedelta(hours=72)


def final_report_due_at(
    case_type: CaseType,
    *,
    fix_available_at: datetime | None = None,
    notification_submitted_at: datetime | None = None,
) -> datetime | None:
    if case_type is CaseType.ACTIVELY_EXPLOITED_VULN:
        if fix_available_at is None:
            return None
        return _ensure_aware(fix_available_at) + timedelta(days=14)
    if notification_submitted_at is None:
        return None
    return add_one_calendar_month(_ensure_aware(notification_submitted_at))


def compute_clocks(
    case_type: CaseType,
    *,
    awareness_at: datetime | None = None,
    fix_available_at: datetime | None = None,
    notification_submitted_at: datetime | None = None,
    now: datetime | None = None,
    early_warning_submitted: bool = False,
    notification_submitted: bool = False,
    final_submitted: bool = False,
) -> ClockSet:
    """Compute due dates. Does nothing if awareness_at is unset (candidate)."""
    now = _ensure_aware(now or datetime.now(timezone.utc))
    clocks = ClockSet(
        awareness_at=_ensure_aware(awareness_at) if awareness_at else None,
        fix_available_at=_ensure_aware(fix_available_at) if fix_available_at else None,
        notification_submitted_at=(
            _ensure_aware(notification_submitted_at) if notification_submitted_at else None
        ),
    )
    if awareness_at is None:
        return clocks

    clocks.early_warning_due_at = early_warning_due_at(awareness_at)
    clocks.notification_due_at = notification_due_at(awareness_at)
    clocks.final_report_due_at = final_report_due_at(
        case_type,
        fix_available_at=fix_available_at,
        notification_submitted_at=notification_submitted_at,
    )

    if not early_warning_submitted and now > clocks.early_warning_due_at:
        clocks.overdue.append("early_warning")
    if not notification_submitted and now > clocks.notification_due_at:
        clocks.overdue.append("notification")
    if (
        clocks.final_report_due_at is not None
        and not final_submitted
        and now > clocks.final_report_due_at
    ):
        clocks.overdue.append("final_report")
    return clocks
