import importlib.util
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

from database.db_setup import get_db_conn

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

nmap_available = run_nmap_scan is not None and parse_nmap_problems is not None

# --- Sidebar: Full 12-Module Control ---
with st.sidebar:
    st.title("🛡️ Arsenal Control")

    if nmap_module_error:
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

    with st.expander("1. Identity", expanded=False):
        st.checkbox("Sherlock (Username Search)")

    with st.expander("2. Infrastructure", expanded=True):
        run_nmap = st.checkbox(
            "Nmap (Port Scan)",
            value=nmap_available,
            disabled=not nmap_available,
        )
        l_fast = st.checkbox("Fast Scan (-F)", disabled=not nmap_available)
        l_scripts = st.checkbox("Vuln Scripts (--script vuln)", disabled=not nmap_available)

    with st.expander("3. Vulnerability"):
        st.caption("Nuclei / SQLmap (Planned)")

    with st.expander("4. Threat Intel"):
        st.caption("VirusTotal / Pulsedive (Planned)")

    st.divider()
    execute_btn = st.button("LAUNCH OPERATION", type="primary", use_container_width=True)

# --- Main Dashboard UI ---
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

# --- Display Engine (runs only when user clicks LAUNCH OPERATION) ---
if execute_btn:
    if not target_ip:
        st.error("No target specified.")
    else:
        with st.status("Executing Active Intelligence Stack...", expanded=True) as status:
            if run_nmap:
                if not nmap_available:
                    st.error("Nmap module is not available. Check the sidebar for details.")
                else:
                    st.write(f"🛰️ Engaging Nmap on **{target_ip}**...")

                    flags = ["-sV"]
                    if l_fast:
                        flags.append("-F")
                    if l_scripts:
                        flags.append("--script vuln")

                    raw_output, problems = run_nmap_scan(target_ip, flags)

                    st.write("### 📜 Live Console: Nmap Output")
                    st.code(raw_output, language="bash")

                    if problems:
                        st.error(f"🚨 {len(problems)} Critical Problems Found!")
                        for problem in problems:
                            st.warning(f"**Finding:** {problem}")

                    conn = get_db_conn()
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM targets WHERE domain_or_ip = ?", (target_ip,))
                    t_id = cursor.fetchone()
                    if t_id:
                        cursor.execute(
                            "INSERT INTO recon_data (target_id, open_ports) VALUES (?, ?)",
                            (t_id[0], raw_output),
                        )
                        conn.commit()
                    conn.close()

            status.update(label="Operation Complete", state="complete")

# --- Archive View ---
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
