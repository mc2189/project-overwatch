# Project Overwatch v1.3

Project Overwatch is a **local** Python/Streamlit dashboard for defensive security intelligence. It helps analysts organise investigations into **cases**, collect data with authorised **active** scans and **passive** lookups, interpret results as advisory **findings**, and export **reports** — all stored in a local SQLite database on your machine.

**v1.3 executable modules:** Nmap (active port scan), Domain Intelligence (passive DNS/HTTP/TLS/Wayback), and Certificate & Subdomain Intelligence (passive certificate transparency lookup). The sidebar guides which modules are compatible with each target type.

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
2. **Enter a target** (IPv4, domain, URL, email, or username) — the app detects the target type.
3. **Enable compatible modules** under **Modules** (incompatible modules are greyed out with a reason):
   - **Nmap [Active]** — port/service scan for IPv4 or domain; requires authorisation checkbox.
   - **Domain Intelligence [Passive]** — DNS, HTTP, TLS, Wayback for domain or URL; no authorisation needed.
   - **Certificate & Subdomain Intelligence [Passive]** — public certificate transparency names for domain or URL; no authorisation needed.
4. Review the **Operation Plan** on the dashboard, then click **Run selected modules**.
5. Review results in the main panel (raw output stays in expanders).
6. Browse **Archive** tabs: Cases (backup/restore), Entities, Relationships, Graph, Observations, Operations, Findings, Report.
7. Legacy v0.1 target tables are under **Legacy (v0.1)**.

Planned modules appear in the sidebar but are **disabled** — they are not available in this release.

## Target types and module compatibility

Project Overwatch detects the target type from your sidebar input:

| Type | Examples |
|------|----------|
| IPv4 address | `192.168.1.10` |
| Domain | `example.com` |
| URL | `https://example.com/path` |
| Email | `analyst@example.com` |
| Username-like | `johndoe` |
| Unknown | Unrecognised input |

Each module declares which target types it accepts. Incompatible modules are **greyed out** in the sidebar with a short reason (for example, Domain Intelligence requires a domain or URL, not a plain IP address).

### Active vs passive modules

| Mode | Behaviour | Authorisation |
|------|-----------|---------------|
| **Active** | Sends probes (e.g. Nmap port scan) | Required — confirm in sidebar |
| **Passive** | Public DNS/HTTP lookups only | Not required by default |
| **Analysis** | Local file analysis (planned) | If registry requires it |

Implemented modules include expandable help in the sidebar: what they collect, example inputs, expected outputs, and caution notes.

### Operation Plan

Before you click **Run selected modules**, the dashboard **Operation Plan** shows:

- Active case and target
- Detected target type
- Selected active/passive modules
- Whether authorisation is required
- Expected outputs
- Compatibility warnings if a selected module cannot run against the target

The executor also blocks incompatible runs as a second safety layer and records a `blocked` operation without creating observations or findings.

## Investigation model

| Concept | Description |
|---------|-------------|
| **Case** | Groups one investigation (name, description, status) |
| **Entity** | IP, domain, email, service, etc. linked to a case |
| **Observation** | Structured module result (summary + JSON + optional raw output) |
| **Operation** | Audit log of each module run |
| **Relationship** | Link between entities (`exposes_service`, `resolves_to`, …) |
| **Finding** | Advisory interpretation with severity, confidence, suggested actions, and analyst workflow fields |

**Cases → Download case backup (JSON)** exports the full investigation for migration. Import creates a new case with remapped entity IDs.

Findings are **analyst aids**, not proof of vulnerability. Review before acting or sharing.

### Finding workflow (v1.1)

Each finding has a **status** that tracks triage through an investigation:

| Status | Meaning |
|--------|---------|
| `open` | New or unreviewed finding from a module |
| `in_review` | Analyst is reviewing the finding |
| `action_required` | Follow-up or remediation is needed |
| `accepted` | Risk acknowledged and accepted |
| `false_positive` | Not a genuine issue for this case |
| `closed` | Finding closed without accepting risk |

Legacy `reviewed` rows are migrated automatically to `in_review`.

**Analyst notes** — free-text field on each finding for review context, decisions, and follow-up.

**Severity override** — optional `user_severity` lets an analyst override the module-assigned severity. Reports and the Findings tab use the effective severity (override when set, otherwise module severity).

**Typical workflow:** module creates an `open` finding → analyst sets `in_review` and adds notes → mark `action_required` if needed → resolve as `accepted`, `false_positive`, or `closed`. Closed or resolved findings can be **reopened** from the Findings tab if the issue resurfaces.

Re-running a module does not automatically reopen closed/accepted/false positive duplicates; a new observation may still be recorded separately.

### Nmap (active)

- Guided profiles: Quick, Standard, Detailed, Host discovery, Custom
- XML parsing with text fallback; service entities and relationships
- Advisory interpreter creates findings (open ports, exposure notes, script output caveats)
- OS detection / traceroute may need elevated privileges in lab environments only

### Domain Intelligence (passive)

- DNS (A, AAAA, MX, NS, TXT, CNAME), HTTP/HTTPS, security headers, TLS, Wayback CDX
- Creates domain/IP/MX/NS entities and relationships
- Cautious findings (missing headers **not observed**, not confirmed vulns)

### Certificate & Subdomain Intelligence (passive)

- Queries public certificate transparency data via [crt.sh](https://crt.sh/) for names related to a domain or URL
- Does **not** run port scans, service checks, or active probing
- Discovered names are **leads for review** — they do not prove a host is live or in scope
- Creates `has_subdomain` relationships from the queried domain to discovered names
- Cautious findings for discovered names, large result sets, wildcard entries, and unavailable source data

**How to test:** against an authorised or public domain such as `example.com`:

1. Enter `example.com` as the target.
2. Enable **Certificate & Subdomain Intelligence [Passive]** (no authorisation checkbox required).
3. Run the module and review the subdomain table, certificate sample, findings, graph links, and report output.

If crt.sh is rate limited or unavailable, the module returns a structured warning instead of crashing.

## Reports

**Archive → Report** generates Markdown previews with optional:

- Full technical or executive template
- Active findings only by default (`open`, `in_review`, `action_required`); optional inclusion of closed, accepted, and false positive findings
- Finding status summary in the executive summary; analyst notes and severity overrides in the findings section
- Redaction (IPs, emails, domains, custom terms/regex)
- Organisation branding (`config/report_settings.json`, local only)
- Export: Markdown, HTML, JSON, PDF (WeasyPrint), encrypted (cryptography)
- Batch export and scheduled export (`config/report_schedule.json`)

Saved reports go to `reports/` (gitignored). Encrypted exports go to `exports/`.

## Project layout

```
main.py                    Streamlit entry point
version.py                 PROJECT_VERSION = "1.3.0"
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

## v1.4 roadmap

- Stale finding handling on re-scan (reopen terminal findings when the same issue is observed again)
- Finding-driven graph filters and export presets
- Additional passive collection modules wired through the findings pipeline
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
