"""SQLite database setup and connection helpers for Project Overwatch."""

import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "overwatch.db"

TARGETS_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_or_ip TEXT UNIQUE,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

RECON_DATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    open_ports TEXT,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id)
)
"""


def get_db_conn() -> sqlite3.Connection:
    """Open the Overwatch database, creating the folder and tables if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(TARGETS_SCHEMA)
    conn.execute(RECON_DATA_SCHEMA)
    return conn
