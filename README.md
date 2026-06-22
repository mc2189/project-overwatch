# Project Overwatch

Defensive security intelligence dashboard built with Python and Streamlit. Project Overwatch v0.2 provides target tracking, reconnaissance logging, a central module registry, and manual Nmap integration for authorised assessments only.

## Requirements

- Python 3.11 or later
- [Nmap](https://nmap.org/download.html) installed and available on your `PATH` (required only when running port scans)

## Setup

1. Clone or copy this repository to your machine.

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # macOS/Linux
   # .venv\Scripts\activate    # Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

The `database/` folder and `overwatch.db` SQLite file are created automatically on first run if they do not already exist.

## Run

From the project root (the directory containing `main.py`):

```bash
streamlit run main.py
```

Streamlit opens the dashboard in your browser, typically at `http://localhost:8501`.

## Usage

1. Enter a target IP or domain in the sidebar and click **Acquire Target** to add it to the archive.
2. Select modules under **Select Modules**. The sidebar is generated from `modules/module_registry.py`.
3. Click **LAUNCH OPERATION** to run selected modules. Scans are never started automatically.
4. Review results in the main panel and browse stored data under **Archive** (Manifest / History tabs).

Only modules marked **active** and **implemented** in the registry can be executed. Planned modules appear in the UI but are disabled.

If the Nmap Python module or the `nmap` binary is missing, the dashboard still loads and shows a clear error in the sidebar.

## Module registry

`modules/module_registry.py` is the single source of truth for module metadata. Each entry defines:

| Field | Purpose |
|-------|---------|
| `module_id` | Stable identifier used in code and UI state |
| `display_name` | Sidebar label |
| `category` | Grouping (Identity, Infrastructure, Threat Intel, etc.) |
| `description` | Tooltip / help text |
| `status` | `active`, `planned`, or `disabled` |
| `mode` | `passive`, `active`, or `analysis` |
| `risk_level` | `low`, `medium`, or `high` |
| `requires_authorisation` | Whether explicit permission is expected |
| `requires_api_key` | Whether an API key will be needed when implemented |
| `implemented` | Whether backend code is wired for execution |

Helper functions:

- `get_modules_by_category()` — modules grouped for the sidebar
- `get_module(module_id)` — lookup a single entry
- `is_executable(module)` — returns `True` only when `implemented` and `status == "active"`

To add a module later: register it in `module_registry.py`, implement its backend file, then wire execution in `main.py` (or a future dispatcher). Do not hard-code sidebar entries in `main.py`.

Current executable module: **Nmap** (`infra_nmap`) under Infrastructure.

## Project layout

```
main.py                          Streamlit entry point
database/
  db_setup.py                    SQLite connection and schema setup
  overwatch.db                   Local target and recon data (auto-created)
modules/
  module_registry.py           Module metadata and helpers
  2_infrastructure/
    infra_nmap.py                Nmap subprocess wrapper
requirements.txt                 Python dependencies
```

Paths are resolved relative to `main.py`, so the project can be moved without editing source code.

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess. Unauthorised scanning or reconnaissance may be illegal in your jurisdiction.
