# Project Overwatch

Defensive security intelligence dashboard built with Python and Streamlit. Project Overwatch v0.7 adds passive Domain Intelligence alongside guided Nmap scanning, XML parsing, and the investigation case model.

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

Selecting Nmap **Vuln Scripts** (`--script=vuln`) shows an additional high-risk warning. Vuln scripts also require the authorisation checkbox even if other checks pass.

## Guided Nmap scan profiles

When Nmap is enabled under **2. Infrastructure**, choose a guided profile:

| Profile | Purpose |
|---------|---------|
| Quick check | Fast scan of common ports with open-only output |
| Standard service scan | Default service/version detection (`-sV`) |
| Detailed authorised scan | Service detection, OS detection, safe scripts, reasons |
| Host discovery only | Ping/discovery only (`-sn`) with no port/script/version checks |
| Custom guided scan | Individual options with compatibility rules |

Each option includes a tooltip/description in the UI. Project Overwatch does **not** accept arbitrary raw Nmap command input.

### Compatibility rules

- **Host discovery only** disables port scanning, version detection, OS detection, and all script options.
- **Fast scan** and **custom ports** cannot be active together.
- **Top ports** and **custom ports** cannot be active together.
- Only **one script category** may be selected: None, Safe, Default, Discovery, or Vuln.
- Only **one timing profile** may be selected: Polite, Normal, or Aggressive.
- **Vuln scripts** remain high-warning and require authorisation.
- **OS detection**, **traceroute**, and **script scanning** require authorisation.

**OS detection (`-O`) and traceroute (`--traceroute`) may require elevated (root) privileges** on macOS and Linux. Project Overwatch does not automatically request `sudo`. If the Streamlit session is not running as root, those options are disabled or skipped and a service/version scan (`-sV`) is used instead. Service/version detection is the recommended default for most authorised assessments.

If Nmap still reports a privilege error at runtime (for example if privileges change mid-session), Overwatch retries the scan without the failing option and records it as skipped in **Analyst Interpretation**.

### Elevated privileges for lab use only

Project Overwatch never prompts for a password or escalates privileges automatically. For **authorised lab testing only**, you may start Streamlit from an elevated shell yourself:

```bash
# macOS / Linux — lab environments only
sudo "$(which python)" -m streamlit run main.py
```

When running elevated, the sidebar shows **Running with elevated privileges**. Only use this in controlled lab environments you own or are explicitly authorised to test. Prefer normal (`streamlit run main.py`) service scans for day-to-day use.

No stealth, evasion, spoofing, decoy, SYN-only, UDP, or proxy-bypass options are exposed in v0.6.

### XML parsing and structured results

Nmap runs capture both human-readable output and XML (`-oX` via a temporary file). XML is preferred because it provides structured port, service, OS, and script data. If XML parsing fails, Overwatch falls back to the existing text parser.

Observations store:

- `raw_output` — human-readable Nmap text
- `data_json` — profile, selected options, parsed ports/services, OS matches, script results, interpreter findings

### Analyst interpretation

After a scan, Overwatch shows an **Analyst Interpretation** section with advisory defensive findings such as:

- Remote desktop, web, SMB, SSH, FTP/Telnet exposure review notes
- OS fingerprint caveats
- NSE script output treated as potential findings requiring validation

The interpreter is **advisory only**. An open port does not automatically mean a vulnerability, missing script results do not mean a host is safe, and NSE vuln output is not proof of compromise.

## Domain Intelligence (passive)

**Domain Intelligence** (`infra_domain_intel`) is an active passive module under **2. Infrastructure**. It does **not** use Nmap and does **not** require the authorisation checkbox.

For a domain or URL, it collects:

- DNS records: A, AAAA, MX, NS, TXT, CNAME
- Basic HTTP/HTTPS response details
- Presence or absence of common security headers
- Basic TLS certificate issuer and validity dates (when HTTPS is reachable)
- Basic Wayback Machine availability via the public CDX API

Results are stored in the case model as:

- **Operation** log entry
- **Observation** with structured JSON and raw text summary
- **Entities** for the domain, resolved IPs, MX hosts, and nameservers
- **Relationships**:
  - `resolves_to` (domain → IP)
  - `uses_mail_server` (domain → MX host)
  - `uses_nameserver` (domain → NS host)

### How to test with example.com

1. Start the app: `streamlit run main.py`
2. Enter `example.com` as the target
3. Under **2. Infrastructure**, enable **Domain Intelligence** only (leave Nmap unchecked if you want a passive-only test)
4. Click **LAUNCH OPERATION**
5. Review the **Domain Intelligence Summary**, then check **Archive → Relationships**, **Observations**, and **Graph**

No authorisation checkbox is required for this module.

## Findings and suggested actions (v0.8)

Project Overwatch stores **findings** as structured analyst aids derived from module results. Findings are **not** final proof of risk, compromise, or misconfiguration. They highlight items worth reviewing and suggest practical next steps.

Each finding includes:

| Field | Purpose |
|-------|---------|
| `title` | Short summary of what was observed |
| `severity` | Relative priority for analyst review (`critical`, `high`, `medium`, `low`, `info`) |
| `confidence` | How strongly the module supports the observation (0–100) |
| `explanation` | Cautious narrative describing what was or was not observed |
| `suggested_actions_json` | Practical follow-up steps for the analyst |
| `status` | Workflow state (`open` by default) |

**Severity** indicates how urgently an analyst may want to review an item. It does not automatically mean a vulnerability exists. For example, an `info` finding may simply record that MX records were observed.

**Confidence** reflects how reliable the underlying observation is given the module and data source. Low confidence findings should be validated before acting on them.

**Suggested actions** are guidance only. Use them to decide what to verify next — for example, confirming whether an exposed service is expected, checking TLS and security headers, reviewing Wayback snapshots, or documenting that a result is benign.

Findings are created when **Nmap** or **Domain Intelligence** completes successfully. The executor links each finding to the active case, entity, and observation where possible. Exact duplicate findings (same case, entity, module, and title) are not created again.

View findings in **Archive → Findings**. The dashboard shows an **Open Findings** metric for the active case.

### Finding workflow (v0.9)

Each finding can move through analyst workflow states:

| Status | Meaning |
|--------|---------|
| `open` | New or awaiting review |
| `reviewed` | Analyst has reviewed; may still need follow-up |
| `closed` | Resolved, accepted risk, or no further action |

Use the controls inside each finding expander to **Reopen**, **Mark reviewed**, or **Close**.

Re-running the same module against the same entity **refreshes** matching findings and **closes** open/reviewed items that are no longer observed (marked as superseded in the explanation).

### Case export (v0.9)

**Archive → Findings** provides **Download Markdown report** and **Download JSON export** for the active case. Exports include findings (with suggested actions), observation summaries, and entity/relationship counts. Use exports for case notes or handoff — they remain advisory, not proof of risk.

### Entity graph severity (v0.9)

The **Graph** tab colours entity nodes by the highest **open** or **reviewed** finding severity linked to that entity. Grey nodes have no open/reviewed findings.

### Adding findings to new modules

Register an interpreter in `utils/findings_registry.py` (`MODULE_FINDING_INTERPRETERS`), wire module execution in `modules/executor.py`, and call `_persist_module_findings()` after creating an observation. The shared `sync_module_findings()` helper handles upsert and superseded closing.

### Domain Intelligence interpretation

The domain interpreter uses cautious language. Missing security headers are described as **not observed**, not as confirmed vulnerabilities. Example finding types:

- Common security headers not observed on HTTPS
- HTTPS unavailable or failed
- TLS certificate expiry approaching
- No A or AAAA records observed
- MX or nameserver records found (informational)
- Wayback snapshots available

## Investigation data model

Project Overwatch v0.4 stores investigation data in a structured model alongside the legacy `targets` / `recon_data` tables.

| Table | Purpose |
|-------|---------|
| `cases` | Investigation containers (name, description, status) |
| `entities` | Things under investigation: IPs, domains, emails, usernames, companies, documents, etc. |
| `observations` | Module results linked to a case and entity |
| `relationships` | Links between entities such as `exposes_service` |
| `operations` | Audit log of module runs (module, target, status, authorisation) |
| `findings` | Analyst findings with severity, confidence, explanation, and suggested actions |

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
- `data_json`: structured metadata including parsed ports, services, OS matches, script results, interpreter findings, and selected scan options

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

The graph is read-only and does **not** perform new scanning. Entity nodes are coloured by the highest open or reviewed finding severity when findings exist (v0.9).

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
    infra_domain_intel.py        Passive DNS/HTTP/TLS/Wayback lookups
utils/
  nmap_options.py              Scan profiles, compatibility rules, flag builder
  nmap_ui.py                   Streamlit Nmap option UI
  nmap_parser.py               Text fallback parser for open ports
  nmap_xml_parser.py           XML parser for structured Nmap results
  nmap_interpreter.py          Advisory defensive result interpreter
  domain_intel_interpreter.py  Domain intelligence findings interpreter
  findings_registry.py       Module interpreter registry for findings pipeline
  findings_sync.py           Upsert and supersede findings on module completion
  case_report.py             Markdown and JSON case export builders
  graph_view.py                NetworkX + Plotly graph rendering
requirements.txt                 Python dependencies
```

Paths are resolved relative to `main.py`, so the project can be moved without editing source code.

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess. Unauthorised scanning or reconnaissance may be illegal in your jurisdiction.
