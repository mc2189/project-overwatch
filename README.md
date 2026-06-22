# Project Overwatch

Defensive security intelligence dashboard built with Python and Streamlit. Project Overwatch v0.5 adds entity relationships, service discovery from Nmap, and a basic graph view on top of the investigation case model.

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

1. Select or create a **case** in the sidebar (a container for an investigation).
2. Enter a target IP or domain and click **Acquire Target** to add it to the legacy archive and create an **entity** in the active case.
3. Select modules under **Select Modules**. The sidebar is generated from `modules/module_registry.py`.
4. If you select an **active** module that requires authorisation (such as Nmap), tick the authorisation checkbox in the sidebar.
5. Click **LAUNCH OPERATION** to run selected modules. Scans are never started automatically.
6. Review results in the main panel and browse stored data under **Archive** tabs, including **Relationships** and **Graph**.

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

To add a module later: register it in `module_registry.py`, implement its backend file, then wire execution in `modules/executor.py`. Do not hard-code sidebar entries in `main.py`.

Current executable module: **Nmap** (`infra_nmap`) under Infrastructure.

## Execution dispatcher

`modules/executor.py` routes all module execution. `main.py` calls:

```python
execute_module(module_id, target, options, db_context, authorisation_confirmed)
```

The executor:

1. Looks up the module in `module_registry.py`
2. Blocks unimplemented, inactive, or non-executable modules
3. Enforces authorisation for modules with `requires_authorisation=True`
4. Runs the module backend (Nmap today)
5. Returns a structured result:

```python
{
    "module_id": "...",
    "success": True,
    "status": "completed",  # or "blocked" / "error"
    "summary": "...",
    "raw_output": "...",
    "findings": [],
    "errors": [],
}
```

## Active vs passive modules

| Mode | Description | Authorisation gate |
|------|-------------|-------------------|
| `passive` | Public or read-only lookups | Only if `requires_authorisation=True` |
| `active` | Sends probes or scans to a target | Usually required |
| `analysis` | Local file or capture analysis | Only if `requires_authorisation=True` |

Passive and analysis modules do not show the authorisation checkbox unless their registry entry sets `requires_authorisation=True`.

## Authorisation gating

When any **selected** module has `requires_authorisation=True`, the sidebar shows:

> I confirm I am authorised to run active checks against this target.

**LAUNCH OPERATION** is blocked until this box is ticked. The executor performs the same check and returns `status: "blocked"` if authorisation is missing.

Selecting Nmap **Vuln Scripts** (`--script vuln`) shows an additional high-risk warning. Vuln scripts also require the authorisation checkbox even if other checks pass.

## Investigation data model

Project Overwatch v0.4 stores investigation data in a structured model alongside the legacy `targets` / `recon_data` tables.

| Table | Purpose |
|-------|---------|
| `cases` | Investigation containers (name, description, status) |
| `entities` | Things under investigation: IPs, domains, emails, usernames, companies, documents, etc. |
| `observations` | Module results linked to a case and entity |
| `relationships` | Links between entities (reserved for future graph/network analysis) |
| `operations` | Audit log of module runs (module, target, status, authorisation) |

### Cases

A **case** groups everything related to one investigation. A default case is created automatically on first run if none exists. Select a case in the sidebar or create a new one.

### Entities

An **entity** is a concrete item being investigated within a case. When you acquire a target, Overwatch infers a basic type:

| Input pattern | Entity type |
|---------------|-------------|
| IPv4 address | `ip_address` |
| Domain name | `domain` |
| Email address | `email` |
| Other | `unknown` |
| Discovered open port/service | `service` (created from Nmap output) |

Service entities use values such as `192.168.1.1:5900/tcp` and labels such as `5900/tcp vnc Apple remote desktop vnc`.

### Observations

An **observation** is a structured module result. When Nmap completes, the executor saves:

- `title`: "Nmap scan result"
- `observation_type`: "network_scan"
- `summary`: executor result summary
- `raw_output`: full Nmap text output
- `data_json`: structured metadata including `open_ports`, findings, and scan options

Legacy `recon_data` rows are still written for backwards compatibility.

### Relationships

A **relationship** links two entities within a case. When Nmap completes against an authorised scan, Overwatch:

1. Parses open ports from the stored Nmap output
2. Creates or reuses **service** entities for each open port
3. Creates `exposes_service` relationships from the scanned target entity to each service entity
4. Avoids duplicate relationships if the same scan is run again

Example: scanning `192.168.68.122` and finding port 5900 creates:

- Service entity: `192.168.68.122:5900/tcp`
- Relationship: `192.168.68.122` → `exposes_service` → `192.168.68.122:5900/tcp`

View relationships in the **Relationships** archive tab.

### Entity graph

The **Graph** archive tab renders a simple network view using stored entities and relationships. It uses NetworkX to build the graph and Plotly to display it:

- **Nodes** = entities (label if present, otherwise value)
- **Edges** = relationships (`exposes_service`, etc.)

The graph is read-only and does **not** perform new scanning. It visualises data already collected from modules the user ran.

## Lawful use

Project Overwatch is intended for **lawful OSINT**, **systems you own**, **lab environments**, and **authorised security assessments** only. Do not use it to scan, probe, or investigate targets without permission.

## Project layout

```
main.py                          Streamlit entry point
database/
  db_setup.py                    SQLite schema, cases/entities/observations helpers
  overwatch.db                   Local investigation and legacy data (auto-created)
modules/
  module_registry.py           Module metadata and helpers
  executor.py                  Execution dispatcher and result format
  2_infrastructure/
    infra_nmap.py                Nmap subprocess wrapper
utils/
  nmap_parser.py               Parse open ports from Nmap output
  graph_view.py                NetworkX + Plotly graph rendering
requirements.txt                 Python dependencies
```

Paths are resolved relative to `main.py`, so the project can be moved without editing source code.

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess. Unauthorised scanning or reconnaissance may be illegal in your jurisdiction.
