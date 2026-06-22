# Project Overwatch v1.9

Project Overwatch is a **local** Python/Streamlit dashboard for defensive security intelligence. It helps analysts organise investigations into **cases**, collect data with authorised **active** scans and **passive** lookups, interpret results as advisory **findings**, and export **reports** — all stored in a local SQLite database on your machine.

**v1.4** reorganises the interface around an investigation workflow: **Run Operation** for collection, dedicated pages for findings/archive/reporting, and a **Roadmap** page for planned modules.

Use only on systems you own, lab environments, or targets with **written permission**.

## Navigation

The sidebar provides case selection and main navigation:

| Page | Purpose |
|------|---------|
| **Run Operation** | Target entry, module cards, configuration, operation plan, launch |
| **Findings** | Triage advisory findings |
| **Entity Workspace** | Inspect entities, pivot to compatible modules, edit analyst notes |
| **Relationships / Observations / Operations** | Investigation archive |
| **Graph** | Entity relationship view; open neighbours in Entity Workspace |
| **Report** | Generate and export case reports |
| **Backup** | Case JSON export/import and legacy tables |
| **Roadmap** | Planned modules (not shown in the run workflow) |

## Typical workflow

1. **Select or create a case** in the sidebar.
2. Open **Run Operation**.
3. **Step 1 — Target:** enter IPv4, domain, URL, email, or username. The app shows detected type and normalised host for URLs.
4. **Choose a run mode** (“What do you want to do?”): Quick Check, Website / Domain Footprint, Local Device / IP Check, or Custom Module Selection.
5. **Step 2 — Module Selection:** review recommended modules for your mode and target, or pick modules manually in Custom mode. Planned modules are on the **Roadmap** page only.
6. **Step 3 — Module Configuration:** configure selected modules (Nmap uses a conservative profile by default for IP-focused modes).
7. **Step 4 — Operation Plan:** review case, target, run mode, module recommendations, authorisation requirement, and expected outputs.
8. Confirm **authorisation** if an active module is selected, then click **Run selected modules**.
9. Review **Latest Results** (summary plus Summary / Interpretation / Output / Raw / Structured tabs).
10. Move to **Findings**, **Entity Workspace**, **Graph**, **Report**, or **Backup** as needed.

### Entity Workspace (v1.8)

After collection populates entities, open **Entity Workspace** to pivot between targets:

1. **Select an entity** from the active case (type, value, label, source, confidence, timestamps).
2. Review **Related intelligence** — findings (with status/notes), observations (raw output collapsed), relationships from/to, and matching operations.
3. Use **Pivot actions** — compatible modules are recommended from existing target compatibility rules:
   - **Domain** → Domain Intelligence, Certificate & Subdomain Intelligence, Website Metadata Review
   - **URL** → Domain Intelligence, Website Metadata Review (hostname normalised)
   - **IPv4** → Network Service Check (authorisation required)
   - **Service** → no direct module; review the parent host entity
   - **Email / username** → no implemented modules yet
4. **Run compatible modules** from the workspace using the same executor path as Run Operation. Active modules still require the authorisation checkbox; passive modules do not.
5. **Analyst fields** — edit entity notes, label, and confidence without deleting stored data.
6. **Pivot queue** — persisted per case in the database; add entities from relationships, findings, or the Graph page; batch passive runs on queued items.
7. From **Graph**, click a node or select a focus entity to see neighbours with **Open** / **Queue** actions, or **Open in Entity Workspace**.

Entity notes appear in generated reports where entities are listed.

### Module cards on Run Operation

- **Network Service Check, powered by Nmap** — active; IPv4 or domain only (not URL — enter hostname separately for port scans).
- **Domain Intelligence** — passive DNS/HTTP/TLS/Wayback for domain or URL.
- **Certificate & Subdomain Intelligence** — passive certificate transparency names for domain or URL.
- **Website Metadata Review** — passive homepage title, meta tags, headers, robots.txt, and sitemap hints for domain or URL.

### Guided run modes (v1.5)

After entering a target, choose **What do you want to do?** on Run Operation:

| Run mode | Purpose | Typical recommendations |
|----------|---------|-------------------------|
| **Quick Check** | Simple default | IPv4 → Network Service Check only; domain/URL → Domain Intelligence + Certificate & Subdomain Intelligence + Website Metadata Review; email/username/unknown → none |
| **Website / Domain Footprint** | Passive domain footprint | Domain Intelligence + Certificate & Subdomain Intelligence + Website Metadata Review (no Nmap by default) |
| **Local Device / IP Check** | Conservative active IP scan | Network Service Check with Quick check Nmap profile; authorisation required |
| **Custom Module Selection** | Power-user manual pick | All compatible modules shown; no automatic preselection when you change target |

Recommendations are deterministic and local — they filter by target type and run mode only. **Compatibility checks and the authorisation gate still apply**; passive-only runs do not require authorisation.

Module cards are grouped as **Recommended for this target**, **Available but not recommended by this mode** (in an expander), and **Not available for this target**. The **Module Lab / Advanced** expander shows full metadata without bypassing the normal executor flow.

The **Operation Plan** includes the selected run mode and an explanation of why modules were recommended.

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

See **Navigation** and **Typical workflow** above for the v1.4 Run Operation flow. Archive pages (Findings, Entity Workspace, Graph, Report, Backup) are reached from sidebar navigation rather than a single dashboard tab strip.

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

The **Operation Plan** on Run Operation summarises case, original and normalised target, detected type, **run mode**, **why modules were recommended**, selected modules, active/passive split, authorisation requirement, and expected outputs immediately before launch.

After a run, **Latest Results** shows a combined run summary (modules run, completed, warnings, findings, highest severity) plus per-module status, finding counts, and tabbed detail (Summary, Analyst Interpretation, Module Output, Raw Output, Structured Data). Raw output is collapsed by default.

### Findings, warnings, and errors (v1.7)

| Type | Meaning |
|------|---------|
| **Review findings** | Advisory analyst interpretation items worth triage (stored in Findings when persisted) |
| **Warnings** | Collection or external lookup issues (timeouts, partial data) — informational, not target risk |
| **Errors** | Module could not complete meaningfully (runtime failure, invalid target, blocked active scan) |

Module run **status** values:

- `completed` — collection finished normally
- `completed_with_warnings` — useful data returned, but external lookups had limits
- `partial` — limited data returned (e.g. source unavailable)
- `blocked` — module did not run (compatibility or authorisation)
- `error` — module failed

External sources (crt.sh, Wayback, public HTTP/DNS) may time out or rate limit. These appear as **warnings** or **source notices**, usually at **info** severity — they do not mean the target is risky or that subdomains/records do not exist.

### Graph finding filters (v1.5)

The **Graph** page can filter node colouring by finding status and minimum severity, and optionally hide entities without matching findings.

### Report export presets (v1.5)

The **Report** page includes built-in presets (Executive brief, Full technical, Shareable redacted, Archive complete). Apply a preset, then adjust individual options if needed.

### Stale finding reopen (v1.5)

When a module re-scan observes the same finding again, terminal findings (closed, accepted, false positive) are automatically reopened to `open` with an analyst note explaining the re-observation.

### Run mode persistence (v1.6)

Each case remembers its last-used run mode (`default_run_mode`). Switching cases restores that case's mode on **Run Operation**. The mode is saved when you change it or launch modules.

### Quick Check optional port scan (v1.6)

For domain or URL targets in **Quick Check**, you can optionally enable **Include light port scan** to add Network Service Check with a conservative profile. Authorisation is still required.

### Mode-aware report presets (v1.6)

The **Report** page suggests export presets based on the case's run mode (e.g. Domain footprint summary for Website / Domain Footprint). Presets marked with ★ match the active run mode.

### Operation run mode analytics (v1.6)

Each operation log records `run_mode_id` and `run_mode_label`. The **Operations** page shows counts by run mode and supports filtering. Case reports include an operations-by-run-mode summary.

### Website Metadata Review (v1.6)

Passive module `infra_website_metadata` for **domain** and **URL** targets. It fetches the public homepage and collects:

- Page title, meta description, canonical URL
- Basic response headers (server, CSP, HSTS, etc.)
- Link and form counts from the HTML
- `robots.txt` summary (disallow/allow/sitemap directives)
- Sitemap hints from robots.txt and common paths

Included in **Quick Check** and **Website / Domain Footprint** run modes for domain/URL targets. No authorisation required. Does not submit forms or crawl beyond the homepage, robots.txt, and lightweight sitemap probes.

**Test with example.com:**

1. `python scripts/smoke_check.py` — offline parser/interpreter checks (no live network required).
2. `streamlit run main.py` → **Run Operation**.
3. Target: `example.com` (or `https://example.com`).
4. Run mode: **Quick Check** or **Website / Domain Footprint** — Website Metadata Review should be preselected.
5. Run selected modules (passive only — no authorisation checkbox).
6. Review **Latest Results** → Summary / Module Output tabs for title, robots.txt, sitemap hints.
7. Check **Findings**, **Observations**, **Graph** (`has_canonical_url`, `references_sitemap` relationships), and **Report**.

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
version.py                 PROJECT_VERSION = "1.5.0"
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

## v1.7 roadmap

- Additional passive collection modules wired through the findings pipeline
- Configurable stale-reopen behaviour per finding status
- Scheduled export as a background helper script
- Multi-case dashboard and comparison views

Previously planned case backup is **available now** on the **Backup** page.

## Development

See `CHANGELOG.md` for version history.

```bash
python scripts/smoke_check.py
streamlit run main.py
```

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess.
