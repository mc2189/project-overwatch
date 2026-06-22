import importlib.util
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

from database.db_setup import get_db_conn
from modules.module_registry import (
    CATEGORIES,
    get_module,
    get_modules_by_category,
    is_executable,
    module_ui_label,
)

PROJECT_ROOT = Path(__file__).resolve().parent
NMAP_MODULE_PATH = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_nmap.py"

run_nmap_scan = None
parse_nmap_problems = None
nmap_module_error = None

if not NMAP_MODULE_PATH.is_file():
    nmap_module_error = f"Module file not found: {NMAP_MODULE_PATH}"
else:
    try:
        spec = importlib.util.spec_from_file_location("infra_nmap", NMAP_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {NMAP_MODULE_PATH}")
        infra_nmap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_nmap)
        run_nmap_scan = infra_nmap.run_nmap_scan
        parse_nmap_problems = infra_nmap.parse_nmap_problems
    except Exception as exc:
        nmap_module_error = str(exc)

nmap_runtime_ready = run_nmap_scan is not None and parse_nmap_problems is not None

modules_by_category = get_modules_by_category()
selected_modules: dict[str, bool] = {}
nmap_fast = False
nmap_scripts = False


def module_selectable(module) -> bool:
    """A module can be selected in the UI only if it is executable and runtime-ready."""
    if not is_executable(module):
        return False
    if module.module_id == "infra_nmap":
        return nmap_runtime_ready
    return True


def run_registered_module(module_id: str, target: str) -> None:
    """Execute an implemented active module. Only Nmap is wired in v0.2."""
    module = get_module(module_id)
    if module is None or not is_executable(module):
        st.warning(f"Module `{module_id}` is not available for execution.")
        return

    if module_id == "infra_nmap":
        if not nmap_runtime_ready:
            st.error("Nmap module is not available. Check the sidebar for details.")
            return

        st.write(f"🛰️ Engaging Nmap on **{target}**...")

        flags = ["-sV"]
        if nmap_fast:
            flags.append("-F")
        if nmap_scripts:
            flags.append("--script vuln")

        raw_output, problems = run_nmap_scan(target, flags)

        st.write("### 📜 Live Console: Nmap Output")
        st.code(raw_output, language="bash")

        if problems:
            st.error(f"🚨 {len(problems)} Critical Problems Found!")
            for problem in problems:
                st.warning(f"**Finding:** {problem}")

        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM targets WHERE domain_or_ip = ?", (target,))
        t_id = cursor.fetchone()
        if t_id:
            cursor.execute(
                "INSERT INTO recon_data (target_id, open_ports) VALUES (?, ?)",
                (t_id[0], raw_output),
            )
            conn.commit()
        conn.close()
        return

    st.info(f"{module.display_name} is registered but not wired for execution yet.")


# --- Sidebar ---
with st.sidebar:
    st.title("🛡️ Arsenal Control")

    nmap_entry = get_module("infra_nmap")
    if nmap_entry and is_executable(nmap_entry) and nmap_module_error:
        st.error("Nmap module unavailable")
        st.caption(nmap_module_error)

    target_ip = st.text_input("Target IP/Domain:", placeholder="e.g. 192.168.1.1")

    if st.button("Acquire Target", use_container_width=True):
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

    st.divider()
    execute_btn = st.button("LAUNCH OPERATION", type="primary", use_container_width=True)

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
        selected_ids = [module_id for module_id, enabled in selected_modules.items() if enabled]

        with st.status("Executing Active Intelligence Stack...", expanded=True) as status:
            if not selected_ids:
                st.warning("No executable modules selected.")
            else:
                for module_id in selected_ids:
                    module = get_module(module_id)
                    if module is None:
                        continue
                    if not is_executable(module):
                        st.warning(f"{module.display_name} is planned and cannot be run yet.")
                        continue
                    run_registered_module(module_id, target_ip)

            status.update(label="Operation Complete", state="complete")

# --- Archive ---
st.header("📂 Archive")
tab1, tab2 = st.tabs(["Manifest", "History"])
with tab1:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM targets", conn), use_container_width=True)
    conn.close()
with tab2:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM recon_data", conn), use_container_width=True)
    conn.close()
