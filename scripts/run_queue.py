#!/usr/bin/env python3
"""Run queued batch items from the CLI without the Streamlit UI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.batch_queue_runner import run_batch_queue_for_case  # noqa: E402
from utils.operating_context import CLIENT_ENGAGEMENT, PERSONAL_LAB, PASSIVE_RESEARCH  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute Project Overwatch batch queue items outside the UI.",
    )
    parser.add_argument(
        "--case-id",
        type=int,
        required=True,
        help="Case ID whose queued items should run.",
    )
    parser.add_argument(
        "--mode",
        choices=("passive", "active", "selected", "all"),
        default="passive",
        help="Which queued items to run (default: passive only).",
    )
    parser.add_argument(
        "--operating-context",
        choices=(PASSIVE_RESEARCH, PERSONAL_LAB, CLIENT_ENGAGEMENT),
        default=PERSONAL_LAB,
        help="Operating context for authorisation checks.",
    )
    parser.add_argument(
        "--authorisation-confirmed",
        action="store_true",
        help="Confirm authorisation for active queue items.",
    )
    parser.add_argument(
        "--personal-lab-confirmed",
        action="store_true",
        help="Confirm Personal Lab authorisation.",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=None,
        help="Courtesy delay between passive queue items.",
    )
    parser.add_argument(
        "--stop-after-first",
        action="store_true",
        help="Stop after the first executed queue item.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List queue items that would run without executing modules.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    outcome = run_batch_queue_for_case(
        int(args.case_id),
        mode=args.mode,
        operating_context=args.operating_context,
        authorisation_confirmed=args.authorisation_confirmed,
        personal_lab_confirmed=args.personal_lab_confirmed,
        delay_seconds=args.delay_seconds,
        stop_after_first=args.stop_after_first,
        dry_run=args.dry_run,
    )

    for message in outcome.get("messages") or []:
        print(message)

    if args.dry_run and outcome.get("preview"):
        for row in outcome["preview"]:
            print(
                f"- {row.get('entity_value')} · {row.get('module_display_name')} "
                f"({row.get('mode', 'passive')})"
            )

    for row in outcome.get("results") or []:
        item = row["queue_item"]
        print(
            f"- {item.get('entity_value')} · {item.get('module_display_name')} · "
            f"{item.get('status')}: {item.get('summary') or '-'}"
        )

    if outcome.get("exit_code") is not None:
        return int(outcome["exit_code"])
    if outcome.get("selected_count", 0) == 0:
        return 0
    return 0 if outcome.get("failed", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
