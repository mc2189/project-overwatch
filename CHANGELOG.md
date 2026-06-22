# Changelog

All notable changes to Project Overwatch are documented here.

## v1.0.1 — Limitation fixes

- Nmap binary detection on PATH with clear error messages
- Optional local app password (`OVERWATCH_APP_PASSWORD` or Streamlit secrets)
- Scheduled report export runs at app startup (not only Report tab)
- System status panel in sidebar (modules + optional dependencies)
- Case backup JSON export/import on Cases tab
- Legacy v0.1 data moved to dedicated archive tab
- Dashboard metrics focus on current case model
- Domain Intelligence connectivity warnings when network lookups fail
- `requirements-optional.txt` for kaleido and weasyprint
- Extended smoke check with optional dependency warnings

## v1.0.0 — Stability release

- v1.0 local release: stability pass, smoke checks, documentation refresh
- Lean `requirements.txt` with direct dependencies only
- Version marker (`1.0.0`) shown in the Streamlit sidebar
- UI polish: clearer module labels (Active/Passive), dashboard metrics, user-friendly errors
- `scripts/smoke_check.py` for import and database sanity checks (no network)
- `CHANGELOG.md` and refreshed `README.md`

## v0.9 — Case report builder

- Markdown case reports via `utils/report_builder.py`
- Report tab with preview, save, and download
- Executive and full technical templates
- HTML and JSON export; batch export for multiple cases
- Findings workflow UI (open → reviewed → closed)
- Graph node colouring by finding severity
- Findings sync on re-scan (upsert + supersede stale items)
- `findings_registry.py` and `findings_sync.py` for unified findings pipeline

## v0.8 — Findings and suggested actions

- `findings` table with severity, confidence, explanation, and suggested actions
- Nmap interpreter findings persisted to database
- Domain Intelligence interpreter with cautious language
- Findings archive tab with filters and open-findings metric

## v0.7 — Domain Intelligence

- Passive `infra_domain_intel` module (DNS, HTTP/HTTPS, headers, TLS, Wayback)
- Entities and relationships for DNS resolution, mail servers, and nameservers
- No authorisation gate for passive collection

## v0.6 — Nmap profiles and interpretation

- Guided Nmap scan profiles and compatibility rules
- XML parsing with text fallback
- Advisory `nmap_interpreter` for defensive findings
- Privilege-aware OS detection and traceroute handling
- Service entities and `exposes_service` relationships from Nmap output

## v0.5 — Relationships and graph

- `relationships` table and graph view (NetworkX + Plotly)
- Entity graph archive tab

## v0.4 — Case / entity / observation model

- Investigation tables: `cases`, `entities`, `observations`, `operations`
- Case selector in sidebar; default case on first run
- Entity type inference from target input

## v0.3 — Executor and authorisation gate

- `modules/executor.py` dispatcher with structured results
- Authorisation checkbox for active modules
- Blocked/error/completed status handling

## v0.2 — Module registry

- Central `module_registry.py` for module metadata
- Sidebar generated from registry; planned modules shown but disabled

## v0.1 — Stabilisation

- Portable paths via `pathlib`
- SQLite setup in `database/db_setup.py`
- Legacy `targets` and `recon_data` tables preserved
- Initial Streamlit dashboard and README
