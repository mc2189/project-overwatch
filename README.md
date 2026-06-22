# Project Overwatch v1.0

Project Overwatch is a **local** Python/Streamlit dashboard for defensive security intelligence. It helps analysts organise investigations into **cases**, collect data with authorised **active** scans and **passive** lookups, interpret results as advisory **findings**, and export **reports** — all stored in a local SQLite database on your machine.

**v1.0 executable modules:** Nmap (active port scan) and Domain Intelligence (passive domain lookup).

Use only on systems you own, lab environments, or targets with **written permission**.

## Quick start

### Requirements

- Python 3.11+
- [Nmap](https://nmap.org/download.html) on your `PATH` (only for port scans)

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS/Linux
pip install -r requirements.txt
```

Optional extras (graph PNG and native PDF):

```bash
pip install -r requirements-optional.txt
```

### Optional local password

Protect the dashboard on shared machines:

```bash
export OVERWATCH_APP_PASSWORD='your-local-password'
streamlit run main.py
```

Or add to `.streamlit/secrets.toml` (gitignored):

```toml
app_password = "your-local-password"
```

Leave unset for an open local instance.

### Run

```bash
streamlit run main.py
```

Open `http://localhost:8501` in your browser.

### Smoke check (no network)

```bash
python scripts/smoke_check.py
```

## Typical workflow

1. **Select or create a case** in the sidebar (investigation container).
2. **Enter a target** (IP or domain) and click **Acquire Target**.
3. **Enable modules** under **Modules**:
   - **Nmap [Active]** — port/service scan; requires authorisation checkbox.
   - **Domain Intelligence [Passive]** — DNS, HTTP, TLS, Wayback; no authorisation needed.
4. Click **Run selected modules**.
5. Review results in the main panel (raw output stays in expanders).
6. Browse **Archive** tabs: Cases (backup/restore), Entities, Relationships, Graph, Observations, Operations, Findings, Report.
7. Legacy v0.1 target tables are under **Legacy (v0.1)**.

Planned modules appear in the sidebar but are **disabled** — they are not available in v1.0.

## Active vs passive modules

| Mode | Behaviour | Authorisation |
|------|-----------|---------------|
| **Active** | Sends probes (e.g. Nmap) | Required |
| **Passive** | Public/read-only lookups | Not required by default |
| **Analysis** | Local file analysis (planned) | If registry requires it |

## Investigation model

| Concept | Description |
|---------|-------------|
| **Case** | Groups one investigation (name, description, status) |
| **Entity** | IP, domain, email, service, etc. linked to a case |
| **Observation** | Structured module result (summary + JSON + optional raw output) |
| **Operation** | Audit log of each module run |
| **Relationship** | Link between entities (`exposes_service`, `resolves_to`, …) |
| **Finding** | Advisory interpretation with severity, confidence, suggested actions |

**Cases → Download case backup (JSON)** exports the full investigation for migration. Import creates a new case with remapped entity IDs.

Findings are **analyst aids**, not proof of vulnerability. Review before acting or sharing.

### Nmap (active)

- Guided profiles: Quick, Standard, Detailed, Host discovery, Custom
- XML parsing with text fallback; service entities and relationships
- Advisory interpreter creates findings (open ports, exposure notes, script output caveats)
- OS detection / traceroute may need elevated privileges in lab environments only

### Domain Intelligence (passive)

- DNS (A, AAAA, MX, NS, TXT, CNAME), HTTP/HTTPS, security headers, TLS, Wayback CDX
- Creates domain/IP/MX/NS entities and relationships
- Cautious findings (missing headers **not observed**, not confirmed vulns)

## Reports

**Archive → Report** generates Markdown previews with optional:

- Full technical or executive template
- Closed findings and raw output appendix (off by default)
- Redaction (IPs, emails, domains, custom terms/regex)
- Organisation branding (`config/report_settings.json`, local only)
- Export: Markdown, HTML, JSON, PDF (WeasyPrint), encrypted (cryptography)
- Batch export and scheduled export (`config/report_schedule.json`)

Saved reports go to `reports/` (gitignored). Encrypted exports go to `exports/`.

## Project layout

```
main.py                    Streamlit entry point
version.py                 PROJECT_VERSION = "1.0.1"
scripts/smoke_check.py     Local sanity checks
requirements-optional.txt  kaleido, weasyprint (optional)
database/db_setup.py       SQLite schema and helpers
modules/
  module_registry.py       Module metadata (single source of truth)
  executor.py                Execution dispatcher
  2_infrastructure/        Nmap and Domain Intelligence backends
utils/                     Parsers, interpreters, graph, reports
reports/                   Generated reports (gitignored)
exports/                   Encrypted exports (gitignored)
config/                    Local report settings (gitignored)
```

## Safe and local usage

- Data stays in `database/overwatch.db` on your machine.
- Scans never start automatically — you must click **Run selected modules**.
- No stealth, evasion, or exploit features.
- Review and redact reports before external sharing.
- Unauthorised scanning may be illegal in your jurisdiction.

## Known limitations

| Area | Status |
|------|--------|
| Collection modules | **Two** implemented (Nmap, Domain Intelligence). Others show as planned in the sidebar. |
| Live lookups | Domain Intelligence and Nmap need network / local `nmap` when you run them. Smoke test does not use the network. |
| PDF / graph PNG | Install `requirements-optional.txt` (WeasyPrint, kaleido). System libraries may be needed for WeasyPrint on some platforms. |
| Scheduled export | Runs when the app starts and when the Report tab opens — not a background OS daemon. |
| Multi-user | Optional single shared password only — not multi-tenant user accounts. |
| Legacy tables | Preserved under **Legacy (v0.1)**; new work uses cases/entities/observations. |

Check **Sidebar → System status** for Nmap, modules, and optional dependency readiness.

## v1.1 roadmap

- Additional passive collection modules wired through the findings pipeline
- Improved report templates and redaction UX
- Finding-driven graph filters and export presets
- Hardening for long-running local deployments

Previously planned case backup is **available now** on the Cases tab (v1.0.1).

## Development

See `CHANGELOG.md` for version history.

```bash
python scripts/smoke_check.py
streamlit run main.py
```

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess.
