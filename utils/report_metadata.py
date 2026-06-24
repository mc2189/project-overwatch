"""Report metadata sidecar helpers for Report Builder v2."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from version import PROJECT_VERSION


def build_report_metadata(
    *,
    case_id: int,
    report_type_id: str | None,
    operating_context: str | None,
    sections: list[str] | None,
    finding_selection_mode: str | None,
    template: str,
    output_path: Path,
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_version": PROJECT_VERSION,
        "case_id": case_id,
        "report_type_id": report_type_id,
        "operating_context": operating_context,
        "sections": sections or [],
        "finding_selection_mode": finding_selection_mode,
        "template": template,
        "output_file": str(output_path.name),
    }


def save_report_metadata_sidecar(output_path: Path, metadata: dict[str, Any]) -> Path:
    sidecar = output_path.with_suffix(output_path.suffix + ".meta.json")
    sidecar.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
    return sidecar
