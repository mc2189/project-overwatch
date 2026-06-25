#!/usr/bin/env python3
"""Background worker that polls and executes batch queue items."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.batch_queue_runner import resolve_case_ids, run_batch_queue_for_case  # noqa: E402
from utils.operating_context import CLIENT_ENGAGEMENT, PERSONAL_LAB, PASSIVE_RESEARCH  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Poll Project Overwatch batch queues and execute queued items.",
    )
    parser.add_argument(
        "--case-id",
        type=int,
        action="append",
        dest="case_ids",
        help="Case ID to monitor (repeatable). Omit with --all-cases-with-queue.",
    )
    parser.add_argument(
        "--all-cases-with-queue",
        action="store_true",
        help="Process every case that currently has queued batch items.",
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
    )
    parser.add_argument(
        "--authorisation-confirmed",
        action="store_true",
    )
    parser.add_argument(
        "--personal-lab-confirmed",
        action="store_true",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=60.0,
        help="Sleep between polling cycles (default: 60).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one polling cycle and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would run without executing modules.",
    )
    return parser.parse_args()


def _run_cycle(args: argparse.Namespace) -> int:
    case_ids = resolve_case_ids(
        case_ids=args.case_ids,
        all_cases_with_queue=bool(args.all_cases_with_queue),
    )
    if not case_ids:
        print("No cases with queued batch items.")
        return 0

    exit_code = 0
    for case_id in case_ids:
        outcome = run_batch_queue_for_case(
            case_id,
            mode=args.mode,
            operating_context=args.operating_context,
            authorisation_confirmed=args.authorisation_confirmed,
            personal_lab_confirmed=args.personal_lab_confirmed,
            dry_run=args.dry_run,
        )
        print(f"Case #{case_id}: {outcome.get('messages', [''])[-1]}")
        if outcome.get("exit_code") not in (None, 0):
            exit_code = int(outcome["exit_code"])
        elif outcome.get("failed", 0):
            exit_code = 1
    return exit_code


def main() -> int:
    args = _parse_args()
    if not args.case_ids and not args.all_cases_with_queue:
        print(
            "Specify --case-id (repeatable) or --all-cases-with-queue.",
            file=sys.stderr,
        )
        return 2

    exit_code = _run_cycle(args)
    if args.once:
        return exit_code

    while True:
        time.sleep(max(args.interval_seconds, 1.0))
        exit_code = max(exit_code, _run_cycle(args))


if __name__ == "__main__":
    raise SystemExit(main())
