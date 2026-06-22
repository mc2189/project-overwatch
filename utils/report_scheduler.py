"""Scheduled case report export (runs at app startup and when the Report tab is opened)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.db_setup import list_cases
from utils.report_builder import ReportOptions
from utils.report_export import batch_export_reports
from utils.report_settings import ReportSchedule, load_report_schedule, save_report_schedule


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def schedule_is_due(schedule: ReportSchedule, now: datetime | None = None) -> bool:
    if not schedule.enabled:
        return False
    now = now or datetime.now(timezone.utc)
    last_run = _parse_timestamp(schedule.last_run_at)
    if last_run is None:
        return True
    return now - last_run >= timedelta(hours=schedule.interval_hours)


def maybe_run_scheduled_exports(
    options: ReportOptions | None = None,
    output_dir: str = "reports",
) -> tuple[list[Path], str | None]:
    """
    Run scheduled exports if enabled and due.

    Returns saved paths and an optional status message.
    """
    schedule = load_report_schedule()
    if not schedule_is_due(schedule):
        return [], None

    cases = list_cases()
    if schedule.export_all_open_cases:
        case_ids = [case["id"] for case in cases if case.get("status", "open") == "open"]
    else:
        case_ids = [case["id"] for case in cases[:1]] if cases else []

    if not case_ids:
        schedule.last_run_at = datetime.now(timezone.utc).isoformat()
        save_report_schedule(schedule)
        return [], "Scheduled export ran: no open cases to export."

    saved_paths = batch_export_reports(
        case_ids,
        output_dir=output_dir,
        export_format=schedule.export_format,
        options=options,
    )
    schedule.last_run_at = datetime.now(timezone.utc).isoformat()
    save_report_schedule(schedule)
    return saved_paths, f"Scheduled export completed: {len(saved_paths)} file(s) saved."
