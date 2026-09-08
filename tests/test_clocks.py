from datetime import datetime, timezone

from opencra_shared.clocks import (
    CaseType,
    add_one_calendar_month,
    compute_clocks,
    early_warning_due_at,
    final_report_due_at,
    notification_due_at,
)


def test_clocks_start_only_after_awareness() -> None:
    clocks = compute_clocks(CaseType.ACTIVELY_EXPLOITED_VULN)
    assert clocks.awareness_at is None
    assert clocks.early_warning_due_at is None
    assert clocks.overdue == []


def test_24h_and_72h_from_awareness() -> None:
    awareness = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)
    assert early_warning_due_at(awareness) == datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    assert notification_due_at(awareness) == datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)


def test_final_report_is_14_days_after_fix_not_awareness() -> None:
    awareness = datetime(2026, 9, 11, tzinfo=timezone.utc)
    fix = datetime(2026, 9, 20, tzinfo=timezone.utc)
    due = final_report_due_at(CaseType.ACTIVELY_EXPLOITED_VULN, fix_available_at=fix)
    assert due == datetime(2026, 10, 4, tzinfo=timezone.utc)
    assert due != awareness


def test_incident_final_is_one_calendar_month_after_notification() -> None:
    notified = datetime(2026, 1, 31, 12, 0, tzinfo=timezone.utc)
    due = final_report_due_at(
        CaseType.SEVERE_INCIDENT,
        notification_submitted_at=notified,
    )
    assert due == datetime(2026, 2, 28, 12, 0, tzinfo=timezone.utc)


def test_add_one_month_clamps_day() -> None:
    dt = datetime(2026, 1, 31, tzinfo=timezone.utc)
    assert add_one_calendar_month(dt).day == 28


def test_overdue_flags() -> None:
    awareness = datetime(2026, 9, 11, tzinfo=timezone.utc)
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)
    clocks = compute_clocks(
        CaseType.ACTIVELY_EXPLOITED_VULN,
        awareness_at=awareness,
        now=now,
    )
    assert "early_warning" in clocks.overdue
    assert "notification" in clocks.overdue
