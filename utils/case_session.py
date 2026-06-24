"""Case-scoped Streamlit session state — isolate workspace state per case."""

from __future__ import annotations

import streamlit as st

CASE_SESSION_KEYS: tuple[str, ...] = (
    "operation_target",
    "latest_run_results",
    "latest_run_target",
    "operating_context",
    "personal_lab_confirmed",
    "authorisation_confirmed",
    "pcap_upload",
    "live_capture_last_result",
    "assessment_goal",
    "batch_queue_latest_results",
)

_ACTIVE_CASE_KEY = "_active_case_session_id"


def _bucket_key(case_id: int, key: str) -> str:
    return f"_case_{case_id}__{key}"


def persist_case_session(case_id: int) -> None:
    """Save current global session keys into the case bucket."""
    for key in CASE_SESSION_KEYS:
        if key in st.session_state:
            st.session_state[_bucket_key(case_id, key)] = st.session_state[key]


def load_case_session(case_id: int) -> None:
    """Restore global session keys from the case bucket (clearing missing keys)."""
    for key in CASE_SESSION_KEYS:
        bucket = _bucket_key(case_id, key)
        if bucket in st.session_state:
            st.session_state[key] = st.session_state[bucket]
        elif key in st.session_state:
            del st.session_state[key]


def switch_case_session(previous_case_id: int | None, new_case_id: int) -> None:
    """Persist the previous case and load session state for the new case."""
    if previous_case_id is not None and previous_case_id != new_case_id:
        persist_case_session(previous_case_id)
    load_case_session(new_case_id)
    st.session_state[_ACTIVE_CASE_KEY] = new_case_id


def _case_has_buckets(case_id: int) -> bool:
    return any(_bucket_key(case_id, key) in st.session_state for key in CASE_SESSION_KEYS)


def ensure_case_session(case_id: int) -> None:
    """On first load, bind session state to the active case without persisting."""
    active = st.session_state.get(_ACTIVE_CASE_KEY)
    if active is None:
        st.session_state[_ACTIVE_CASE_KEY] = case_id
        if _case_has_buckets(case_id):
            load_case_session(case_id)
        else:
            # Upgrade path: keep in-flight workspace state, seed the case bucket.
            persist_case_session(case_id)
    elif active != case_id:
        switch_case_session(active, case_id)
