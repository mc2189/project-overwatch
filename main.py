import streamlit as st
import sys
import os
import sqlite3
import importlib.util
import pandas as pd
from pathlib import Path

# --- 1. THE ARSENAL BRIDGE (macOS Fail-Safe) ---
# Ensures Python finds modules/2_infrastructure/infra_nmap.py
ABS_PROJECT_ROOT = "/Users/mikecurrie/project_overwatch"
ABS_MODULE_PATH = os.path.join(ABS_PROJECT_ROOT, "modules", "2_infrastructure", "infra_nmap.py")

try:
    spec = importlib.util.spec_from_file_location("infra_nmap", ABS_MODULE_PATH)
    infra_nmap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(infra_nmap)
    run_nmap_scan = infra_nmap.run_nmap_scan
    parse_nmap_problems = infra_nmap.parse_nmap_problems
except Exception as e:
    st.error(f"### ❌ Overwatch Module Link Failure")
    st.write(f"Looking for Nmap at: `{ABS_MODULE_PATH}`")
    st.stop()

# --- 2. Self-Healing Database Configuration ---
DB_PATH = Path(ABS_PROJECT_ROOT) / "database" / "overwatch.db"

def get_db_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    # Create tables if they are missing
    conn.execute('CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, domain_or_ip TEXT UNIQUE, date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
    conn.execute('CREATE TABLE IF NOT EXISTS recon_data (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER, open_ports TEXT, date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(target_id) REFERENCES targets(id))')
    return conn

# --- 3. Sidebar: Full 12-Module Control ---
with st.sidebar:
    st.title("🛡️ Arsenal Control")
    target_ip = st.text_input("Target IP/Domain:", placeholder="e.g. 192.168.1.1")
    
    if st.button("Acquire Target", use_container_width=True):
        conn = get_db_conn()
        try:
            conn.execute("INSERT INTO targets (domain_or_ip) VALUES (?)", (target_ip,))
            conn.commit()
            st.success("Target Locked.")
        except:
            st.warning("Target exists in database.")
        conn.close()

    st.divider()
    st.subheader("Select Modules")
    
    # Placeholders for your 12-module roadmap
    with st.expander("1. Identity", expanded=False):
        run_sherlock = st.checkbox("Sherlock (Username Search)")
    with st.expander("2. Infrastructure", expanded=True):
        run_nmap = st.checkbox("Nmap (Port Scan)", value=True)
        l_fast = st.checkbox("Fast Scan (-F)")
        l_scripts = st.checkbox("Vuln Scripts (--script vuln)")
    with st.expander("3. Vulnerability"):
        st.caption("Nuclei / SQLmap (Planned)")
    with st.expander("4. Threat Intel"):
        st.caption("VirusTotal / Pulsedive (Planned)")
    # (Remaining placeholders truncated for brevity - add as needed)

    st.divider()
    execute_btn = st.button("LAUNCH OPERATION", type="primary", use_container_width=True)

# --- 4. Main Dashboard UI ---
st.title("Project Overwatch")
st.caption("Intelligence Command Centre")

# Metrics display
conn = get_db_conn()
t_count = conn.execute("SELECT count(*) FROM targets").fetchone()[0]
s_count = conn.execute("SELECT count(*) FROM recon_data").fetchone()[0]
conn.close()

m1, m2, m3 = st.columns(3)
m1.metric("Targets", t_count)
m2.metric("Logs", s_count)
m3.metric("System", "Operational")

st.divider()

# --- 5. THE DISPLAY ENGINE ---
if execute_btn:
    if not target_ip:
        st.error("No target specified.")
    else:
        with st.status("Executing Active Intelligence Stack...", expanded=True) as status:
            if run_nmap:
                st.write(f"🛰️ Engaging Nmap on **{target_ip}**...")
                
                flags = ["-sV"]
                if l_fast: flags.append("-F")
                if l_scripts: flags.append("--script vuln")
                
                # Execute the scan via the sub-module
                raw_output, problems = run_nmap_scan(target_ip, flags)
                
                # THIS SECTION PRINTS RESULTS TO THE SCREEN
                st.write("### 📜 Live Console: Nmap Output")
                st.code(raw_output, language="bash")
                
                if problems:
                    st.error(f"🚨 {len(problems)} Critical Problems Found!")
                    for p in problems:
                        st.warning(f"**Finding:** {p}")

                # Save Intelligence to Database
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM targets WHERE domain_or_ip = ?", (target_ip,))
                t_id = cursor.fetchone()
                if t_id:
                    cursor.execute("INSERT INTO recon_data (target_id, open_ports) VALUES (?, ?)", (t_id[0], raw_output))
                    conn.commit()
                conn.close()
            
            status.update(label="Operation Complete", state="complete")

# --- 6. Archive View ---
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