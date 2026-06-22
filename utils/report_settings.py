"""Local report branding and schedule settings (not committed to Git)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from database.db_setup import PROJECT_ROOT

CONFIG_DIR = PROJECT_ROOT / "config"
BRANDING_PATH = CONFIG_DIR / "report_settings.json"
SCHEDULE_PATH = CONFIG_DIR / "report_schedule.json"

ExportFormat = Literal["markdown", "html", "json", "pdf"]


@dataclass
class ReportBranding:
    organisation_name: str = ""
    analyst_name: str = ""
    classification_label: str = "INTERNAL USE ONLY"
    footer_text: str = ""


@dataclass
class ReportSchedule:
    enabled: bool = False
    interval_hours: int = 24
    export_format: ExportFormat = "markdown"
    export_all_open_cases: bool = True
    last_run_at: str | None = None


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_report_branding() -> ReportBranding:
    data = _read_json(BRANDING_PATH)
    return ReportBranding(
        organisation_name=data.get("organisation_name", ""),
        analyst_name=data.get("analyst_name", ""),
        classification_label=data.get("classification_label", "INTERNAL USE ONLY"),
        footer_text=data.get("footer_text", ""),
    )


def save_report_branding(branding: ReportBranding) -> None:
    _write_json(BRANDING_PATH, asdict(branding))


def load_report_schedule() -> ReportSchedule:
    data = _read_json(SCHEDULE_PATH)
    export_format = data.get("export_format", "markdown")
    if export_format not in ("markdown", "html", "json", "pdf"):
        export_format = "markdown"
    return ReportSchedule(
        enabled=bool(data.get("enabled", False)),
        interval_hours=max(int(data.get("interval_hours", 24)), 1),
        export_format=export_format,
        export_all_open_cases=bool(data.get("export_all_open_cases", True)),
        last_run_at=data.get("last_run_at"),
    )


def save_report_schedule(schedule: ReportSchedule) -> None:
    _write_json(SCHEDULE_PATH, asdict(schedule))


def branding_header_lines(branding: ReportBranding) -> list[str]:
    """Markdown lines for organisation branding at the top of a report."""
    lines: list[str] = []
    if branding.organisation_name:
        lines.append(f"**Organisation:** {branding.organisation_name}")
    if branding.analyst_name:
        lines.append(f"**Analyst:** {branding.analyst_name}")
    if branding.classification_label:
        lines.append(f"**Classification:** {branding.classification_label}")
    if lines:
        lines.append("")
    return lines


def branding_footer_lines(branding: ReportBranding) -> list[str]:
    if not branding.footer_text:
        return []
    return ["---", "", branding.footer_text, ""]
