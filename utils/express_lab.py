"""Express Lab helpers — auto-goal and solo workspace defaults."""

from __future__ import annotations

from typing import Any

from utils.assessment_goals import (
    GOAL_CUSTOM,
    GOAL_EVIDENCE_REVIEW,
    GOAL_LIVE_CAPTURE,
    GOAL_QUICK_SAFETY,
    suggested_goals_for_target,
)
from utils.settings_manager import solo_operator_mode

EXPRESS_GOAL_LOCKED_KEY = "express_lab_goal_locked"
EXPRESS_LAST_TARGET_KEY = "express_lab_last_target"

_SKIP_AUTO_GOALS = frozenset({GOAL_LIVE_CAPTURE, GOAL_CUSTOM, GOAL_EVIDENCE_REVIEW})


def express_lab_enabled() -> bool:
    """Express Lab UI is active when solo operator mode is on."""
    return solo_operator_mode()


def default_goal_for_target(target_type: str, target: str = "") -> str:
    """Pick the best default assessment goal for a target type."""
    if not target.strip():
        return GOAL_QUICK_SAFETY
    for goal_id in suggested_goals_for_target(target_type, target):
        if goal_id not in _SKIP_AUTO_GOALS:
            return goal_id
    return GOAL_QUICK_SAFETY


def sync_express_goal(
    session_state: dict[str, Any],
    *,
    target: str,
    target_type: str,
    goal_session_key: str,
    prev_goal_key: str,
) -> str:
    """Auto-update the assessment goal when the target changes unless manually locked."""
    if session_state.get(EXPRESS_GOAL_LOCKED_KEY):
        return str(session_state.get(goal_session_key, GOAL_QUICK_SAFETY))

    cleaned = target.strip()
    last = str(session_state.get(EXPRESS_LAST_TARGET_KEY) or "").strip()
    if cleaned != last:
        session_state[EXPRESS_LAST_TARGET_KEY] = cleaned
        if cleaned:
            new_goal = default_goal_for_target(target_type, target)
            session_state[goal_session_key] = new_goal
            session_state[prev_goal_key] = new_goal

    session_state.setdefault(goal_session_key, GOAL_QUICK_SAFETY)
    return str(session_state[goal_session_key])
