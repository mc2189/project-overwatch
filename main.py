import sqlite3

import pandas as pd
import streamlit as st

from database.db_setup import get_db_conn
from modules.executor import execute_module, get_runtime_error, is_runtime_ready
from modules.module_registry import (
    CATEGORIES,
    get_module,
    get_modules_by_category,
    is_executable,
    module_ui_label,
)

modules_by_category = get_modules_by_category()
selected_modules: dict[str, bool] = {}
nmap_fast = False
nmap_scripts = False
authorisation_confirmed = False

nmap_runtime_ready = is_runtime_ready("infra_nmap")
nmap_module_error = get_runtime_error("infra_nmap")


def module_selectable(module) -> bool:
    """A module can be selected in the UI only if it is executable and runtime-ready."""
    if not is_executable(module):
        return False
    if module.module_id == "infra_nmap":
        return nmap_runtime_ready
    return True


def selected_module_ids() -> list[str]:
    return [module_id for module_id, enabled in selected_modules.items() if enabled]


def selection_requires_authorisation(module_ids: list[str]) -> bool:
    return any(
        (module := get_module(module_id)) is not None and module.requires_authorisation
        for module_id in module_ids
    )


def render_execution_result(result: dict) -> None:
    """Display a structured executor result in the main panel."""
    module = get_module(result["module_id"])
    display_name = module.display_name if module else result["module_id"]

    if result["status"] == "blocked":
        st.warning(f"**{display_name}:** {result['summary']}")
        for error in result["errors"]:
            st.caption(error)
        return

    if result["status"] == "error" or not result["success"]:
        st.error(f"**{display_name}:** {result['summary']}")
        if result["raw_output"]:
            st.code(result["raw_output"], language="bash")
        return

    st.write(f"🛰️ **{display_name}:** {result['summary']}")

    if result["raw_output"]:
        st.write("### 📜 Live Console: Nmap Output")
        st.code(result["raw_output"], language="bash")

    if result["findings"]:
        st.error(f"🚨 {len(result['findings'])} Critical Problems Found!")
        for finding in result["findings"]:
            st.warning(f"**Finding:** {finding}")


# --- Sidebar ---
with st.sidebar:
    st.title("🛡️ Arsenal Control")

    nmap_entry = get_module("infra_nmap")
    if nmap_entry and is_executable(nmap_entry) and nmap_module_error:
        st.error("Nmap module unavailable")
        st.caption(nmap_module_error)

    target_ip = st.text_input("Target IP/Domain:", placeholder="e.g. 192.168.1.1")

    if st.button("Acquire Target", width="stretch"):
        conn = get_db_conn()
        try:
            conn.execute("INSERT INTO targets (domain_or_ip) VALUES (?)", (target_ip,))
            conn.commit()
            st.success("Target Locked.")
        except sqlite3.IntegrityError:
            st.warning("Target exists in database.")
        finally:
            conn.close()

    st.divider()
    st.subheader("Select Modules")

    for category in CATEGORIES:
        category_key = str(category["key"])
        category_label = str(category["label"])
        default_expanded = bool(category.get("default_expanded", False))
        category_modules = modules_by_category.get(category_key, [])

        with st.expander(category_label, expanded=default_expanded):
            if not category_modules:
                st.caption("No modules registered.")
                continue

            for module in category_modules:
                selectable = module_selectable(module)
                default_checked = module.module_id == "infra_nmap" and selectable

                selected_modules[module.module_id] = st.checkbox(
                    module_ui_label(module),
                    value=default_checked,
                    disabled=not selectable,
                    help=module.description,
                )

                if not selectable and not is_executable(module):
                    st.caption(f"{module.mode.title()} · {module.risk_level.title()} risk · planned")

                if module.module_id == "infra_nmap" and selectable:
                    nmap_fast = st.checkbox("Fast Scan (-F)", disabled=not selectable)
                    nmap_scripts = st.checkbox("Vuln Scripts (--script vuln)", disabled=not selectable)

    selected_ids = selected_module_ids()
    auth_required = selection_requires_authorisation(selected_ids)

    if auth_required:
        st.divider()
        st.subheader("Authorisation")
        authorisation_confirmed = st.checkbox(
            "I confirm I am authorised to run active checks against this target.",
            value=False,
        )
        st.caption(
            "Required for active modules such as Nmap. "
            "Use only on systems you own, lab environments, or targets with written permission."
        )

    if nmap_scripts and selected_modules.get("infra_nmap"):
        st.warning(
            "**High-risk option selected:** `--script vuln` runs intrusive vulnerability checks. "
            "Use only on systems you own or have explicit written permission to test. "
            "This option will not run without the authorisation confirmation above."
        )

    st.divider()
    execute_btn = st.button("LAUNCH OPERATION", type="primary", width="stretch")

# --- Main Dashboard ---
st.title("Project Overwatch")
st.caption("Intelligence Command Centre")

conn = get_db_conn()
t_count = conn.execute("SELECT count(*) FROM targets").fetchone()[0]
s_count = conn.execute("SELECT count(*) FROM recon_data").fetchone()[0]
conn.close()

m1, m2, m3 = st.columns(3)
m1.metric("Targets", t_count)
m2.metric("Logs", s_count)
m3.metric("System", "Operational")

st.divider()

if execute_btn:
    if not target_ip:
        st.error("No target specified.")
    else:
        selected_ids = selected_module_ids()

        with st.status("Executing Active Intelligence Stack...", expanded=True) as status:
            if not selected_ids:
                st.warning("No executable modules selected.")
            elif auth_required and not authorisation_confirmed:
                st.error(
                    "Authorisation confirmation is required before running the selected active modules."
                )
            else:
                conn = get_db_conn()
                try:
                    for module_id in selected_ids:
                        module = get_module(module_id)
                        if module is None or not is_executable(module):
                            if module:
                                st.warning(f"{module.display_name} is planned and cannot be run yet.")
                            continue

                        options = {}
                        if module_id == "infra_nmap":
                            options = {
                                "nmap_fast": nmap_fast,
                                "nmap_scripts": nmap_scripts,
                            }

                        result = execute_module(
                            module_id,
                            target_ip,
                            options=options,
                            db_context=conn,
                            authorisation_confirmed=authorisation_confirmed,
                        )
                        render_execution_result(result)
                finally:
                    conn.close()

            status.update(label="Operation Complete", state="complete")

# --- Archive ---
st.header("📂 Archive")
tab1, tab2 = st.tabs(["Manifest", "History"])
with tab1:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM targets", conn), width="stretch")
    conn.close()
with tab2:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM recon_data", conn), width="stretch")
    conn.close()
