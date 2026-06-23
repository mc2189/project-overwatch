"""Settings and API key status page for Project Overwatch."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from ui.metrics import render_compact_metrics
from utils.runtime_health import collect_health_checks, render_runtime_health_panel
from utils.security_posture import collect_security_posture
from utils.settings_manager import (
    ENV_EXAMPLE_PATH,
    general_settings_summary,
    list_api_provider_status,
    list_module_config_status,
    missing_optional_api_providers_count,
)


def render_settings_page(metrics: dict) -> None:
    st.title("Settings")
    render_compact_metrics(metrics)
    st.caption(
        "Local configuration and API key status. Secrets are loaded from `.env` on your machine only — "
        "they are never stored in the database, reports, or Git."
    )
    st.divider()

    st.subheader("Runtime health")
    render_runtime_health_panel(collect_health_checks())
    st.divider()

    st.subheader("Security posture")
    for item in collect_security_posture():
        if item.ok is True:
            icon = "✅"
        elif item.ok is False:
            icon = "❌"
        else:
            icon = "ℹ️"
        st.write(f"{icon} **{item.label}:** {item.value}")
        if item.detail:
            st.caption(item.detail)
    st.divider()

    st.subheader("General settings")
    summary = general_settings_summary()
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Rate limit (seconds)", summary["rate_limit_seconds"])
        st.metric("Default timeout (seconds)", summary["default_timeout_seconds"])
    with col2:
        st.metric("Max batch queue items", summary["max_batch_items"])
        st.metric(
            "Active modules enabled",
            "Yes" if summary["active_modules_enabled"] else "No",
        )
    st.caption(
        "Set via environment variables or `config/overwatch.defaults.json`. "
        "See `.env.example` for variable names."
    )
    st.divider()

    st.subheader("API keys")
    st.info(
        f"Copy `{ENV_EXAMPLE_PATH.name}` to `.env` in the project root and add your keys locally. "
        "Only masked values are shown here."
    )

    providers = list_api_provider_status()
    provider_rows = []
    for provider in providers:
        masked_parts = [
            f"{item['env_key']}: {item['masked']}" for item in provider["key_status"]
        ]
        provider_rows.append(
            {
                "Provider": provider["display_name"],
                "Configured": "Yes" if provider["configured"] else "No",
                "Masked value(s)": " · ".join(masked_parts),
                "Future module(s)": ", ".join(provider["future_modules"]),
                "Status": "In use" if provider["in_use"] else "Future-ready",
            }
        )
    st.dataframe(pd.DataFrame(provider_rows), width="stretch", hide_index=True)

    for provider in providers:
        st.caption(f"**{provider['display_name']}:** {provider['notes']}")

    st.caption(
        f"Configured providers: {len(providers) - missing_optional_api_providers_count()} · "
        f"Missing optional providers: {missing_optional_api_providers_count()}"
    )
    st.divider()

    st.subheader("Module configuration status")
    module_rows = []
    for row in list_module_config_status():
        if row["implemented"]:
            readiness = "Ready" if row["ready"] else "Blocked by settings"
        elif row.get("status") == "disabled":
            readiness = "Disabled"
        else:
            readiness = "Planned"
        api_keys = (
            "None required"
            if not row["requires_api_key"]
            else ("Configured" if row["api_keys_configured"] else f"Missing: {', '.join(row['missing_keys'])}")
        )
        implemented_label = "Yes" if row["implemented"] else ("Disabled" if row.get("status") == "disabled" else "Planned")
        module_rows.append(
            {
                "Module": row["display_name"],
                "Implemented": implemented_label,
                "API keys": api_keys,
                "Readiness": readiness,
            }
        )
    st.dataframe(pd.DataFrame(module_rows), width="stretch", hide_index=True)

    with st.expander("Module configuration notes", expanded=False):
        for row in list_module_config_status():
            if not row.get("config_notes") and not row.get("rate_limit_notes"):
                continue
            st.markdown(f"**{row['display_name']}** (`{row['module_id']}`)")
            if row.get("config_notes"):
                st.caption(row["config_notes"])
            if row.get("rate_limit_notes"):
                st.caption(f"Rate limit: {row['rate_limit_notes']}")
