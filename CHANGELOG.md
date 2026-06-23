# Changelog

All notable changes to Project Overwatch are documented here.

## v2.16.0 — Workspace UI Polish and Readability Pass

- **Visual hierarchy** — Assessment Workspace sections: Target, Goal, Readiness, Recommended checks, Results, Next steps
- **`ui/styles.py`** — status chips, section headings, empty states, light CSS polish
- **`ui/workspace_cards.py`** — reusable target, goal, module, readiness, and report journey cards
- **Run button placement** — readiness summary and primary run action moved above detailed journey content
- **Condensed preflight** — one-line summary with **Show readiness details** expander
- **Result cards** — status chips, plain-English timeout messaging, collapsed Summary/Findings/Raw expanders
- **Next actions** — top 3 by default with **Show more suggestions**
- **Empty states** — friendly messages for missing target, pivots, and actions
- **Sidebar** — simplified case, mode, and navigation; runtime health stays on Settings
- **Local IP route card** — clear discover → review → findings path for private targets

## v2.15.0 — Local Target Triage and Port-aware HTTP/TLS Planning

- **Local/private IP triage** — Network Service Check recommended first when no service data exists; no blind TLS/HTTP on port 443
- **`utils/service_classifier.py`** — classifies observations as HTTP, HTTPS/TLS, non-web, or unknown
- **`utils/service_discovery.py`** — loads ports from Nmap observations, service entities, and prior runs
- **`utils/web_port_planner.py`** — common web port probe, custom port validation (max 10, no ranges), journey filtering
- **Journey service table** — Port, Detected service, Classification, Recommended check, Reason for discovered services
- **HTTP/TLS timeout handling** — no missing-header or certificate findings when service is unreachable; clear connection outcome
- **Pivot discovery** — no URL pivot from unreachable default-generated HTTPS URLs
- **Next actions** — nmap-first for private IPs; try common web ports; port-specific HTTP/TLS when services discovered
- **Target selection notes** — modules show whether target assumes default 443, uses discovered service, or manual port

## v2.14.0 — Actionable Next Steps and One-click Pivots

- **Standardised next-action schema** — `utils/next_actions.py` actions include id, title, reason, priority, action_type, target, entity/finding/module ids, enabled flag, blocked_reason, and button_label
- **One-click workflow cards** — `ui/action_cards.py` and `ui/workspace_actions.py` wire buttons for run module, add to queue, open entity/finding, review evidence, generate report, lab scope, and analyst notes
- **Guardrail-aware suggestions** — API keys, passive vs active context, Personal Lab confirmation, engagement scope, and module compatibility disable actions with clear reasons
- **Pivot discovery cards** — `utils/pivot_discovery.py` surfaces new entities with queue and entity workspace buttons (display capped)
- **Per-result next steps** — `utils/result_next_actions.py` adds a practical button to each concise result card
- **Session state navigation** — cross-page links for findings focus, report, evidence, and entity workspace without resetting the workspace
- **Batch Queue integration** — add-to-queue actions use existing queue structure, skip duplicates, and do not auto-run active modules
- Smoke check validates next-action schema without live network calls

## v2.13.0 — Personal Lab Guardrail Fix

- **Single Personal Lab confirmation** — one checkbox satisfies lab authorisation for active checks in the workspace run panel
- **Auto-scope on run** — unknown targets are added to Personal Lab scope automatically when confirmed (safe active checks only)
- **`utils/personal_lab_readiness.py`** — centralized readiness logic shared by UI preflight and executor (no UI/executor mismatch)
- **Compact preflight** — shows Lab confirmation, scope (ready / will be added on run), testing level, and result without scary “scope unknown” when auto-scope applies
- **Public/private target hints** — warnings for public targets; friendly wording for private/local lab targets
- **Audit log** — `lab_testing_log.auto_scope_created` records whether scope was auto-created on run
- Client Engagement and Passive Research behaviour unchanged

## v2.12.0 — Guided Assessment Workspace

- **Assessment Workspace** replaces the long Run Operation scroll with a guided layout: target profile → goal → journey → run → results
- **Goal selector** — Quick safety check, website/domain posture, email spoofing review, external exposure, threat reputation, local network, evidence review, full client-style assessment, and custom module selection
- **`utils/target_profile.py`** — compact case history, findings count, compatible families, and suggested goals
- **`utils/journey_planner.py`** — recommended, optional, blocked, and not-relevant check groupings
- **`utils/next_actions.py`** — next-best-action suggestions after runs (run module, queue pivot, report, scope, triage)
- **`utils/pivot_discovery.py`** — surface subdomains, IPs, services, and URLs from latest results
- **Concise result cards** with collapsed raw output, pivot actions, and report journey shortcuts
- **Run status panel** — current and recent session runs in the side column
- **Compact preflight** — active-check status near the run button
- Custom module selection moved behind **Advanced / Custom module selection**

## v2.11.0 — Lab Mode and Guardrail UX Refactor

- **Operating contexts** on Run Operation: Passive Research, Personal Lab, and Client Engagement
- **Personal Lab Mode** — self-owned / lab testing without a formal client engagement; separate `personal_lab_scope` table and confirmation logging
- **Preflight panel** — clear Ready / Needs action / Blocked status with direct fix hints for active modules
- **Quick-scope** — private/local targets can be added to Personal Lab scope in one click; public targets require confirmation first
- **Client Engagement Mode** — unchanged strict checks (draft engagement, out-of-scope, emergency stop, ROE)
- **Batch Queue** — active items require Personal Lab or Client Engagement context and individual confirmation
- **Reports** — operating context section (Passive Research / Personal Lab / Client Engagement)
- Settings: `PROJECT_OVERWATCH_PERSONAL_LAB_ENABLED`, `PROJECT_OVERWATCH_PERSONAL_LAB_PRIVATE_QUICK_SCOPE`
- Module path: `utils/operating_context.py`, `database/personal_lab.py`, `ui/preflight_panel.py`

## v2.10.0 — HTTP Security Header Review

- **`infra_http_security`** — controlled active HTTP response and security header review for domain, URL, or IPv4 targets
- Module path: `modules/2_infrastructure/infra_http_security.py`
- GET/HEAD requests with short timeout and limited redirects — no API key required
- Reviews security headers, cookie flags (names only), server banners, and optional security.txt / robots.txt
- Does not submit forms, interact with login flows, crawl beyond standard well-known paths, or store full page bodies
- Requires authorisation; respects engagement scope, ROE, and emergency stop before connecting
- Web service entities with `exposes_web_service` relationships
- Evidence capture with `controlled_http_header_review` collection method
- Available in Custom Module Selection and Website / Domain Footprint (not selected by default)
- Batch Queue treats HTTP Security Header Review as an active module (not queued by default)

## v2.9.0 — SSL / TLS Configuration Review

- **`infra_tls_review`** — controlled active TLS certificate and configuration review for domain, URL, or IPv4 targets
- Module path: `modules/2_infrastructure/infra_tls_review.py`
- First controlled **active** client-assessment module after the v2.8 engagement framework
- Opens a single TLS connection to host:port (default 443) — no API key required
- Inspects certificate metadata, negotiated protocol/cipher, and optional safe per-version protocol probes
- Requires authorisation; respects engagement scope, ROE, and emergency stop before connecting
- Does not exploit vulnerabilities, fuzz, perform denial-of-service testing, or scan port ranges
- Service, certificate, and issuer entities with `exposes_tls_service`, `presents_certificate`, and `issued_by` relationships
- Evidence capture with `controlled_tls_review` collection method
- Available in Custom Module Selection and Website / Domain Footprint (not selected by default); not in Quick Check by default
- Batch Queue treats TLS Review as an active module (not queued by default)

## v2.8.0 — Client Engagement, Scope and Authorised Testing Framework

- **Client Engagements page** — create/edit engagements with client details, status, contacts, and authorisation references
- **Scope model** — scoped assets with status (in/out/restricted/pending) and permitted testing levels
- **Rules of engagement (ROE)** — conservative defaults; active/intrusive/DoS/credential/social/malware flags
- **Emergency stop** — per-engagement flag blocks active/intrusive modules; passive modules may continue
- **Module testing levels** — `passive_lookup`, `safe_active_check`, `intrusive_active_check`, `high_risk_manual_only`, `prohibited`
- **Executor guardrails** — scope/engagement/ROE checks before active modules; passive workflow preserved
- **Run Operation** — engagement context, scope warnings, standalone authorised testing option
- **Case ↔ engagement linking** — optional `cases.engagement_id` column
- **Reports** — optional engagement/authorisation context section (off by default)
- **Roadmap restructure** — intrusive tools listed as planned authorised assessment modules, not permanently excluded
- Database tables: `engagements`, `engagement_scope`, `engagement_roe`

## v2.7.0 — Domain Email Security Posture

- **`infra_email_security`** — passive DNS-based review of SPF, DMARC, MX, CAA, MTA-STS, TLS-RPT and BIMI for domain/URL targets
- Module path: `modules/2_infrastructure/infra_email_security.py`
- No API key required — passive DNS lookups and optional MTA-STS HTTPS policy fetch only
- Does not send email, connect via SMTP, test inboxes, brute-force selectors, or validate credentials
- Cautious advisory findings — “public DNS record not observed” rather than definitive “not configured”
- MX mail-server entities with `uses_mail_server` relationships
- Evidence capture with `passive_dns_email_security_lookup` collection method
- Run mode recommendations in Quick Check and Website / Domain Footprint for domain/URL targets
- Settings runtime health shows no key required; Batch Queue, Entity Workspace, Evidence Locker, and reports integration

## v2.6.0 — URLhaus Malware URL Intelligence

- **`intel_urlhaus`** — passive abuse.ch URLhaus lookup for URLs, domains, and public IPv4
- Module path: `modules/4_threat_intelligence/intel_urlhaus.py`
- Requires `ABUSECH_AUTH_KEY` in local `.env` (`URLHAUS_AUTH_KEY` optional alias) — blocked cleanly when missing
- URL targets use `POST /v1/url/`; domain/host/public IPv4 use `POST /v1/host/` — lookup-only
- Private/local IPv4 completes with informational result (no API query)
- No URL submission, malware sample download, recent feeds, bulk datasets, or payload endpoints
- Auth-Key sent in HTTP header only — redacted from logs, evidence, reports, and persisted output
- Cautious findings — “reported by URLhaus”, not “confirmed malicious”
- URL/host entities with `hosted_on`, `reported_by`, `has_reported_url`, and optional malware signature links
- Evidence capture with `api_malware_url_lookup`; download links stripped from summaries
- Output caps for large host results (20 displayed, 50 entity max) with usability warning
- Run mode recommendations for URL/domain/public IPv4 in Quick Check, Website Footprint, and Local IP Check
- SecurityTrails remains Roadmap-only (planned, not implemented, likely paid/API access)
- Settings, Batch Queue, Entity Workspace, Evidence Locker, and reports integration

## v2.5.0 — Shodan Internet Exposure Intelligence

- **`intel_shodan`** — passive Shodan host lookup for public IPv4 via `GET /shodan/host/{ip}`
- Module path: `modules/4_threat_intelligence/intel_shodan.py`
- Requires `SHODAN_API_KEY` in local `.env` — blocked cleanly when missing (not a target risk finding)
- Public IPv4 only — domains/URLs incompatible; private/local IPs complete with informational result (no API query)
- Host lookup only — no Shodan scan, search, alert, streaming, or exploit APIs
- HTTP handling for 200/400/401/403/404/429/5xx, timeouts, and connection errors
- Shodan `key=` query parameters redacted from logs, evidence, reports, and persisted output
- Cautious findings interpreter — “reported by Shodan”, not “confirmed open”
- Service, organisation, ASN, and hostname entities with `reported_exposes_service`, `associated_with`, and `has_hostname` relationships
- Evidence capture with `api_exposure_lookup` collection method; vulnerability references stored as count only
- Run mode recommendations for public IPv4 in Quick Check and Local Device / IP Check when key configured
- Settings, Batch Queue, Entity Workspace, Evidence Locker, and reports integration
- UI summary tab for org/ISP/ASN, ports, services, and stale-data caution; raw JSON and service details collapsed

## v2.4.0 — GreyNoise Internet Noise Intelligence

- **`intel_greynoise`** — passive internet-noise and RIOT lookup for public IPv4 via GreyNoise v3 Community API
- Module path: `modules/4_threat_intelligence/intel_greynoise.py`
- `GREYNOISE_API_KEY` optional but recommended — unauthenticated Community lookups may be limited
- Public IPv4 only — domains/URLs incompatible; private/local IPs complete with informational result (no API query)
- Uses v3 Community endpoint only — no deprecated v2 APIs
- HTTP handling for 200/400/401/403/404/429/5xx, timeouts, and connection errors
- Cautious findings interpreter — “reported by GreyNoise”, not “confirmed malicious”
- Organisation entity/relationship when provider/actor name is useful
- Evidence capture with `api_reputation_lookup` collection method; API keys redacted
- Run mode recommendations for public IPv4 in Quick Check and Local Device / IP Check
- Settings, Batch Queue, Entity Workspace, Evidence Locker, and reports integration
- UI summary tab for noise/RIOT/classification; raw API JSON in collapsed expander

## v2.3.0 — AbuseIPDB Reputation Intelligence

- **`intel_abuseipdb`** — passive abuse-confidence lookup for public IPv4 via AbuseIPDB check API
- Module path: `modules/4_threat_intelligence/intel_abuseipdb.py`
- Requires `ABUSEIPDB_API_KEY` in local `.env` — blocked cleanly when missing (not a target risk finding)
- Public IPv4 only — domains/URLs incompatible; private/local IPs complete with informational result (no API query)
- Lookup-only — no AbuseIPDB report/submission endpoints
- HTTP handling for 200/400/401/403/422/429/5xx, timeouts, and connection errors
- Cautious findings interpreter — “reported by AbuseIPDB”, not “confirmed malicious”
- ISP organisation entity/relationship on successful lookups
- Evidence capture with `api_reputation_lookup` collection method; API keys redacted
- Run mode recommendations for public IPv4 in Quick Check and Local Device / IP Check when key configured
- Settings, Batch Queue, Entity Workspace, Evidence Locker, and reports integration
- UI summary tab for abuse score, report counts, ISP/country context; raw API JSON in collapsed expander

## v2.2.0 — VirusTotal Reputation Intelligence, platform scaffold and passive-source polish

### VirusTotal Reputation Intelligence

- **`intel_virustotal`** — passive reputation enrichment for domains, URLs, and public IPv4 via VirusTotal API v3
- Module path: `modules/4_threat_intelligence/intel_virustotal.py`
- Requires `VIRUSTOTAL_API_KEY` in local `.env` — blocked cleanly when missing (not a target risk finding)
- Run Operation Step 3 configuration text explains passive use, key masking, and cautious interpretation
- Private/local IPv4 addresses complete with informational result — no API query
- HTTP handling for 200/400/404/401/403/429/5xx, timeouts, and connection errors
- Cautious findings interpreter — “reported by VirusTotal”, not “confirmed”
- Entities/relationships for ASN/organisation (IP) and registrar (domain/URL)
- Evidence capture with `api_reputation_lookup` collection method; API keys redacted
- Run mode recommendations include VirusTotal when API key is configured
- Settings, Batch Queue, Entity Workspace, Evidence Locker, and reports integration
- UI summary tab for vendor analysis counts, reputation, and warnings; raw API JSON in collapsed expander

### Platform scaffold and CI

- **`utils/api_module_helpers.py`** — shared timeout, User-Agent, HTTP status classification, missing-key blocked results, redaction
- **`modules/TEMPLATE_api_module.py`** — copy-paste skeleton for upcoming API-backed modules (AbuseIPDB, GreyNoise, etc.)
- **RDAP cache management** — Backup page lists/clears per-case cache; export/import includes `rdap_lookup_cache`
- **Optional cache TTL** — `PROJECT_OVERWATCH_RDAP_CACHE_TTL_HOURS` (0 = no expiry)
- **Encryption scaffold** — `PROJECT_OVERWATCH_LOCAL_ENCRYPTION_KEY` + `encryption_available()` helpers (DB encryption not enabled)
- **CI** — `scripts/security_audit.py` runs in GitHub Actions workflow
- Security posture panel shows encryption library/key scaffold status

### Passive-source result wording (v2.2 polish)

- **Wayback** — user-friendly unavailable messages without raw archive.org URLs in summary/findings; technical detail in Raw/Structured output only
- **crt.sh** — softer wording when no certificate transparency rows are returned (including HTTP 404); technical HTTP detail in raw/structured output
- **`utils/display_format.py`** — shared `format_wayback_user_error()` and `format_crt_sh_user_warning()` helpers

## v2.1.0 — Secure-by-design baseline

- **`utils/security.py`** — secret masking, redaction, env parsing, target validation, private IP checks
- **`utils/crypto_utils.py`** — SHA-256 hashing scaffold; optional Fernet helpers when `cryptography` is installed
- **Centralised masking** — Settings/API key display uses `mask_secret()`; no full keys in UI, logs, DB, reports, or evidence
- **Redaction before persistence** — observations, findings, operations, evidence content, and reports
- **`scripts/security_audit.py`** — local scan for embedded secrets and risky patterns (subprocess, TLS, eval/exec)
- **Smoke check** — security baseline assertions (imports, redaction, `.env` hygiene, quarantined modules)
- **Settings → Security posture** — non-secret safety indicators and manual audit command
- **Quarantined placeholders** — SQLMap, FFUF, Nuclei, HIBP, dark-web, and cloud enum marked `disabled` and blocked from execution
- **`SECURITY.md`** — project security principles, secret rules, hashing vs encryption, audit guidance
- **Command safety** — Nmap remains list-based subprocess with allowlisted profiles (reviewed; no `shell=True`)

### WHOIS/RDAP enhancements (also v2.1)

- **IANA bootstrap RDAP** — queries registry-specific RDAP servers before `rdap.org` redirector
- **Retry/backoff** — automatic retry on HTTP 429/503 from RDAP endpoints
- **WHOIS port-43 fallback** — stdlib socket fallback when RDAP is unavailable (no new dependencies)
- **Per-case cache** — `rdap_lookup_cache` table stores RDAP/WHOIS responses per case/query
- **Domain abuse contacts** — `has_abuse_contact` relationships for domain/URL targets, not just IPv4
- WHOIS text parser produces RDAP-compatible summaries for findings and evidence

## v2.0.0 — WHOIS / RDAP Intelligence

- **`infra_whois_rdap`** — passive registration and allocation metadata for domains, URLs, and public IPv4 addresses
- Public RDAP lookups via `rdap.org` redirector (no API key required)
- Private/local IPv4 handling returns informational result without public lookup
- Entities/relationships: nameservers, registrar, network holder, abuse contacts
- Findings interpreter, evidence capture, run mode recommendations, batch queue support
- UI result summaries for registration dates, status, nameservers, and abuse contacts
- TODO noted for WHOIS port-43 fallback when RDAP is unavailable (v2.1)

## v1.15.0 — Evidence hints, binary storage, VirusTotal and CI

- **`capture_result_evidence_hints()`** — module `result["evidence"]` hints are stored automatically after module-specific capture
- **Binary artefact storage** — `content_bytes` support in `create_evidence_item()` with file spill to `database/evidence_files/`
- **`intel_virustotal`** — first API-backed module (IPv4, domain, URL) with interpreter, evidence capture, and executor wiring
- **`utils/virustotal_interpreter.py`** — cautious advisory findings from VirusTotal detection counts
- **CI** — GitHub Actions workflow runs `scripts/smoke_check.py` and `tests/test_module_sdk.py`
- **`tests/test_module_sdk.py`** — unit tests for SDK helpers and registry validation

## v1.14.0 — Module SDK, output contract and test harness

- **`utils/module_sdk.py`** — `build_module_result()`, result normalisation/validation, registry metadata validation
- Standard result contract: `module_id`, `success`, `status`, `summary`, `raw_output`, `findings`, `warnings`, `errors`, `data`, `evidence`
- **`modules/TEMPLATE_module.py`** — non-executed example skeleton for future modules
- Executor `make_result()` delegates to SDK; persistence calls `normalise_result()` / validation warnings
- Runtime health: module registry validation, implemented-module metadata, API-key configuration gaps
- Smoke check: SDK helpers, registry validation, implemented module metadata, evidence locker imports
- README: **Developing new modules** section

## v1.13.0 — Evidence linking, filters and file spill

- **`evidence_finding_links` table** — many-to-many evidence↔finding relationships
- `list_evidence_for_finding()`, `list_evidence_finding_links()`, `entity_ids_with_evidence()`
- All module-run findings link to observation evidence items (not just the first finding)
- **File spill** for artefacts >32 KB to `database/evidence_files/` with DB preview
- **Findings page** filters: evidence type, reliability, linked evidence
- **Graph page** evidence highlight (green border) and hide-without-evidence filter
- Domain Intelligence observation evidence metadata refined per source type
- Backup export/import includes evidence finding links

## v1.12.0 — Evidence Locker and raw source capture

- **`evidence_items` table** — stores text artefacts with provenance, reliability, and SHA-256 hashes
- Helpers: `create_evidence_item`, `list_evidence_items`, `get_evidence_item`, `calculate_content_hash`, linking helpers
- **`utils/evidence_capture.py`** — module-specific evidence capture on run completion (Nmap, Domain Intel, Cert/Subdomain, Website Metadata)
- Findings linked to observation evidence items after sync
- **Evidence Locker** navigation page with filters and content expanders
- Observations and Findings pages show linked evidence counts/summaries
- Reports: **Evidence Summary** section; evidence content in raw appendix when enabled
- Case backup export/import includes `evidence_items`
- TODO noted for future file-based artefact storage

## v1.11.0 — Source reliability, confidence and evidence model

- **`utils/evidence_model.py`** — evidence types, reliability levels, confidence guidance, module defaults
- Database columns on observations, findings, and relationships (`ensure_evidence_columns`, safe ALTER TABLE)
- Helpers: `normalise_evidence_type`, `normalise_reliability`, `default_evidence_for_module`, `attach_evidence_metadata`
- Executor persistence attaches evidence metadata to observations; relationships inherit module/relationship defaults
- Findings sync stores evidence type, source name, and reliability on upsert
- UI: Observations, Findings detail, and Relationships pages show evidence fields
- Reports: evidence on observations/findings/relationships plus **Evidence and Reliability Notes** section
- README documents evidence types, reliability vs confidence, and third-party source handling

## v1.10.0 — Settings, API key manager and module configuration

- **Settings page** — masked API key status, module configuration readiness, general settings summary
- `utils/settings_manager.py` — `.env` loading, masking, validation, provider/module status helpers
- `.env.example` with placeholder values only; `.env` remains gitignored
- `config/overwatch.defaults.json` for non-secret local defaults
- Module registry extended with `api_key_names`, `config_notes`, `rate_limit_notes`
- Planned API modules: VirusTotal, AbuseIPDB, GreyNoise, Shodan, Censys, SecurityTrails, Hunter.io, HIBP
- Runtime health panel: Python/version, API provider counts, active module toggle
- Executor preflight blocks future API-key modules and globally disabled active modules
- Batch queue marks missing API keys / disabled active modules as incompatible before run

## v2.0.0 — Batch queue persistence and reporting

- Batch queue items persisted in SQLite (`batch_queue_items`) — survives refresh and restarts
- Queue item **reordering** (move up / down) via position field
- Batch run history stored in `batch_queue_runs` with per-run summaries
- Reports include a **Batch queue runs** section (full template)
- **Multi-case summary** expander on Batch Queue page for queues in other cases
- Session-state batch queue migrated to database on first load
- Case backup export/import includes batch queue items

## v1.9.0 — Batch Queue and controlled pivot runner

- **Batch Queue** page: select entities, filter by type, queue compatible entity/module pairs, run passively in batch
- Passive-first defaults: Domain Intelligence, Certificate & Subdomain Intelligence, Website Metadata Review
- Nmap shown as active-only — never included in **Run passive queue**; authorisation required if manually queued
- Queue items track status (queued → running → completed / warnings / blocked / error), summary, and timestamps
- One item at a time via `execute_module`; failures do not stop the rest of the queue
- Configurable courtesy delay (0–5 s) between passive external lookups
- Duplicate entity/module pairs blocked; recent-operation warning when the same module ran recently
- Entity Workspace wired to Batch Queue (add passive modules, open Batch Queue, import pivot queue entities)
- Pivot queue persisted per case in SQLite (`pivot_queue_items` table)
- Graph node selection and neighbour queue/open actions
- Fixed Entity Workspace relationship rendering crash (`entity_lookup`)

## v1.8.0 — Entity Workspace and pivot actions

- **Entity Workspace** replaces the basic Entities list — inspect entity details, linked findings, observations, relationships, and operations
- Pivot module recommendations use existing target compatibility logic (domain, URL, IPv4, service, email, username)
- Run compatible modules directly from Entity Workspace via the same `execute_module` path as Run Operation
- Session **pivot queue** for follow-up targets; batch passive runs on queued domain/URL entities
- Analyst fields: edit entity notes, label, and confidence (`update_entity_notes`, `update_entity_label`, `update_entity_confidence`)
- Findings linked to an entity support status and analyst notes from the workspace
- Graph page: focus entity neighbours and **Open in Entity Workspace**
- Reports already include entity notes where entities are listed

## v1.7.0 — Result quality and lookup resilience

- Standard module run statuses: `completed`, `completed_with_warnings`, `partial`, `blocked`, `error`
- Warnings separated from errors in module results and Latest Results UI
- Source lookup timeouts (e.g. crt.sh) downgraded to info/source notices — not medium risk findings
- Empty positive findings suppressed (MX, subdomains, sitemap hints when none returned)
- Wayback timestamps formatted as readable UTC; no raw `None` in display
- Combined Latest Results summary across modules in a run
- Reports include a separate **Lookup and source notices** section

## v1.6.0 — Run mode persistence, analytics, and report presets

- Guided run modes (v1.5): Quick Check, Website / Domain Footprint, Local Device / IP Check, Custom Module Selection
- Case `default_run_mode` persistence — each case remembers its last run mode
- Operation logs record `run_mode_id` and `run_mode_label` for analytics
- Operations page: counts and filter by run mode; reports include operations-by-run-mode summary
- Mode-aware report presets (Domain footprint summary, Local IP technical, Quick Check overview)
- Quick Check optional light port scan for domain/URL targets (conservative Nmap profile, auth required)
- **Website Metadata Review** passive module (`infra_website_metadata`) for domain/URL targets: homepage metadata, robots.txt, sitemap hints

## v1.5.0 — Stale findings, graph filters, report presets

- Terminal findings (closed, accepted, false positive) reopen to `open` when re-observed on module re-scan
- Graph page filters: finding status, minimum severity, hide entities without matching findings
- Report export presets: Executive brief, Full technical, Shareable (redacted), Archive complete
- SQLite WAL mode and busy timeout for long-running local deployments

## v1.4.0 — Investigation workflow UI

- Sidebar simplified to case selection and page navigation
- New **Run Operation** page with step-by-step target, module cards, configuration, operation plan, and launch
- **Latest Results** section with tabbed result detail (raw output collapsed by default)
- Archive split into dedicated pages: Findings, Entities, Relationships, Observations, Operations, Graph, Report, Backup
- **Roadmap** page for planned modules (removed from active run workflow)
- UI code organised under `ui/` package
- Data quality: skip empty MX/NS findings; clearer URL normalisation and Nmap disabled for URL targets

## v1.3.0 — Certificate and subdomain intelligence

- New passive module `infra_cert_subdomain` (Certificate & Subdomain Intelligence)
- Certificate transparency lookup via crt.sh for domain/URL targets
- Subdomain cleaning, deduplication, domain scoping, and 100-name UI limit
- `has_subdomain` entities and relationships; cautious interpreter findings
- Executor, graph, archive, findings, and report integration

## v1.2.0 — Target compatibility and launch planner

- Central target type detection (`ipv4`, `domain`, `url`, `email`, `username`, `unknown`)
- Module registry metadata: accepted target types, help text, examples, outputs, cautions
- Sidebar compatibility: disable incompatible modules with clear reasons and module expanders
- Operation Plan summary on the dashboard before launch
- Executor blocks incompatible module/target pairs and logs a `blocked` operation without observations
- README documentation for target types, active vs passive modules, and greyed-out modules

## v1.1.0 — Findings workflow and triage

- Extended finding statuses: `open`, `in_review`, `action_required`, `accepted`, `false_positive`, `closed`
- Safe SQLite migrations for `analyst_notes`, `user_severity`, `reviewed_at`, `closed_at`, `updated_at`
- DB helpers: `get_finding`, `update_finding`, `close_finding`, `reopen_finding`, `list_findings_by_entity`, `finding_status_counts`
- Improved duplicate handling: no duplicate for active or terminal identical findings; no auto-reopen on re-scan
- Findings tab: status/severity/module filters, severity grouping, detail expanders, review forms
- Dashboard metrics for in review, action required, closed, and accepted/false positive counts
- Reports: finding status summary, analyst notes, severity override, exclude terminal findings by default
- Graph colouring uses active finding severities (`open`, `in_review`, `action_required`)

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
