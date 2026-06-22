# Project Overwatch v1.4

Project Overwatch is a **local** Python/Streamlit dashboard for defensive security intelligence. It helps analysts organise investigations into **cases**, collect data with authorised **active** scans and **passive** lookups, interpret results as advisory **findings**, and export **reports** — all stored in a local SQLite database on your machine.

**v1.4** reorganises the interface around an investigation workflow: **Run Operation** for collection, dedicated pages for findings/archive/reporting, and a **Roadmap** page for planned modules.

Use only on systems you own, lab environments, or targets with **written permission**.

## Navigation

The sidebar provides case selection and main navigation:

| Page | Purpose |
|------|---------|
| **Run Operation** | Target entry, module cards, configuration, operation plan, launch |
| **Findings** | Triage advisory findings |
| **Entities / Relationships / Observations / Operations** | Investigation archive |
| **Graph** | Entity relationship view |
| **Report** | Generate and export case reports |
| **Backup** | Case JSON export/import and legacy tables |
| **Roadmap** | Planned modules (not shown in the run workflow) |

## Typical workflow

1. **Select or create a case** in the sidebar.
2. Open **Run Operation**.
3. **Step 1 — Target:** enter IPv4, domain, URL, email, or username. The app shows detected type and normalised host for URLs.
4. **Step 2 — Module Selection:** choose from implemented module cards (compatible first, incompatible below with reasons). Planned modules are on the **Roadmap** page only.
5. **Step 3 — Module Configuration:** configure selected modules (Nmap profile/options in an expander when Nmap is selected).
6. **Step 4 — Operation Plan:** review case, target, modules, authorisation requirement, and expected outputs.
7. Confirm **authorisation** if an active module is selected, then click **Run selected modules**.
8. Review **Latest Results** (summary plus Summary / Interpretation / Output / Raw / Structured tabs).
9. Move to **Findings**, **Graph**, **Report**, or **Backup** as needed.

### Module cards on Run Operation

- **Network Service Check, powered by Nmap** — active; IPv4 or domain only (not URL — enter hostname separately for port scans).
- **Domain Intelligence** — passive DNS/HTTP/TLS/Wayback for domain or URL.
- **Certificate & Subdomain Intelligence** — passive certificate transparency names for domain or URL.

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

## Typical workflow (summary)

See **Navigation** and **Typical workflow** above for the v1.4 Run Operation flow. Archive pages (Findings, Entities, Graph, Report, Backup) are reached from sidebar navigation rather than a single dashboard tab strip.

Planned modules are listed on the **Roadmap** page only.

## Target types and module compatibility (reference)

Project Overwatch detects the target type from your Run Operation input:

| Type | Examples |
|------|----------|
| IPv4 address | `192.168.1.10` |
| Domain | `example.com` |
| URL | `https://example.com/path` |
| Email | `analyst@example.com` |
| Username-like | `johndoe` |
| Unknown | Unrecognised input |

Each module declares which target types it accepts. Incompatible modules appear disabled on **Run Operation** module cards with a short reason.

### Active vs passive modules

| Mode | Behaviour | Authorisation |
|------|-----------|---------------|
| **Active** | Sends probes (e.g. Nmap port scan) | Required — confirm before run on Run Operation |
| **Passive** | Public DNS/HTTP/certificate lookups | Not required by default |
| **Analysis** | Local file analysis (planned) | If registry requires it |

Module cards on Run Operation show mode, risk, compatible target types, expected outputs, and caution notes.

### Operation Plan and Latest Results

The **Operation Plan** on Run Operation summarises case, original and normalised target, detected type, selected modules, authorisation requirement, and expected outputs immediately before launch.

After a run, **Latest Results** shows per-module status, finding counts, highest severity, and tabbed detail (Summary, Analyst Interpretation, Module Output, Raw Output, Structured Data). Raw output is collapsed by default.

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
main.py                    Streamlit entry point and navigation router
ui/                        Run Operation, archive pages, findings, metrics
version.py                 PROJECT_VERSION = "1.4.0"
scripts/smoke_check.py     Local sanity checks
requirements-optional.txt  kaleido, weasyprint (optional)
database/db_setup.py       SQLite schema and helpers
modules/
  module_registry.py       Module metadata (single source of truth)
  executor.py              Execution dispatcher
  2_infrastructure/        Nmap, Domain Intelligence, Certificate & Subdomain backends
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
| Collection modules | **Three** implemented (Nmap, Domain Intelligence, Certificate & Subdomain Intelligence). Others are on **Roadmap**. |
| Live lookups | Domain Intelligence and Nmap need network / local `nmap` when you run them. Smoke test does not use the network. |
| PDF / graph PNG | Install `requirements-optional.txt` (WeasyPrint, kaleido). System libraries may be needed for WeasyPrint on some platforms. |
| Scheduled export | Runs when the app starts and when the **Report** page is opened — not a background OS daemon. |
| Legacy tables | Preserved under **Backup → Legacy (v0.1)**; new work uses cases/entities/observations. |

Check **Sidebar → System status** for Nmap, modules, and optional dependency readiness.

## v1.5 roadmap

- Stale finding handling on re-scan (reopen terminal findings when the same issue is observed again)
- Finding-driven graph filters and export presets
- Additional passive collection modules wired through the findings pipeline
- Hardening for long-running local deployments

Previously planned case backup is **available now** on the **Backup** page.

## Development

See `CHANGELOG.md` for version history.

```bash
python scripts/smoke_check.py
streamlit run main.py
```

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess.
