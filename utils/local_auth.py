"""Optional local app password gate (single-user)."""

from __future__ import annotations

import os

import streamlit as st


def configured_app_password() -> str | None:
    """Return the configured password, or None if the app is unlocked by default."""
    env_password = os.environ.get("OVERWATCH_APP_PASSWORD", "").strip()
    if env_password:
        return env_password
    try:
        secret_password = str(st.secrets.get("app_password", "")).strip()
    except Exception:
        secret_password = ""
    return secret_password or None


def local_auth_enabled() -> bool:
    return configured_app_password() is not None


def render_local_auth_gate() -> None:
    """Block the app until the correct local password is entered, if configured."""
    password = configured_app_password()
    if not password:
        return

    if st.session_state.get("local_auth_ok"):
        return

    st.title("Project Overwatch")
    st.info("This local instance is protected. Enter the app password to continue.")
    entered = st.text_input("App password", type="password", key="local_auth_password")
    if st.button("Unlock", type="primary"):
        if entered == password:
            st.session_state.local_auth_ok = True
            st.rerun()
        else:
            st.error("Incorrect password.")
    st.caption(
        "Set `OVERWATCH_APP_PASSWORD` in your environment or `app_password` in `.streamlit/secrets.toml`. "
        "Leave unset for an open local dashboard."
    )
    st.stop()
