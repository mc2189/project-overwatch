# Project Overwatch v2.8

Project Overwatch is a **local** Python/Streamlit intelligence, OSINT, security testing and resilience advisory dashboard for **private internal use** supporting future client assessments.

**v2.8** adds client engagements, scoped assets, rules of engagement, and executor guardrails to prepare for authorised active/intrusive testing modules.

**v2.7** added Domain Email Security Posture. **v2.6** added URLhaus. **v2.5** added Shodan. Earlier releases added GreyNoise, AbuseIPDB, VirusTotal, and the secure-by-design baseline.

Use only on systems you own, lab environments, or targets with **written permission**.

See [SECURITY.md](SECURITY.md) for secret handling, active module rules, and audit guidance.

## Navigation

The sidebar provides case selection and main navigation:

| Page | Purpose |
|------|---------|
| **Run Operation** | Target entry, module cards, configuration, operation plan, launch |
| **Client Engagements** | Client engagement records, scope assets, rules of engagement, emergency stop |
| **Findings** | Triage advisory findings |
| **Entity Workspace** | Inspect entities, pivot to compatible modules, edit analyst notes |
| **Batch Queue** | Queue passive follow-up modules for multiple entities; controlled batch runner |
| **Observations** | Investigation archive with evidence metadata |
| **Evidence Locker** | Source artefacts, raw captures, hashes, and provenance |
| **Operations** | Module run history |
| **Graph** | Entity relationship view; open neighbours in Entity Workspace |
| **Report** | Generate and export case reports |
| **Backup** | Case JSON export/import and legacy tables |
| **Settings** | API key status (masked), general settings, runtime health |
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
   - **Domain** → WHOIS/RDAP Intelligence, Domain Intelligence, Domain Email Security Posture, Certificate & Subdomain Intelligence, Website Metadata Review
   - **URL** → WHOIS/RDAP Intelligence, Domain Intelligence, Domain Email Security Posture, Website Metadata Review (hostname normalised)
   - **IPv4** → Network Service Check (authorisation required); public IPs may also use WHOIS/RDAP, AbuseIPDB, VirusTotal, GreyNoise, or Shodan as passive context
   - **Service** → no direct module; review the parent host entity
   - **Email / username** → no implemented modules yet
4. **Run compatible modules** from the workspace using the same executor path as Run Operation. Active modules still require the authorisation checkbox; passive modules do not.
5. **Analyst fields** — edit entity notes, label, and confidence without deleting stored data.
6. **Pivot queue** — persisted per case; stage entities from relationships, findings, or Graph; import into **Batch Queue**.
7. **Batch Queue shortcuts** — **Passive → Batch Queue** or **Add compatible passive modules to Batch Queue**, then **Open Batch Queue**.
8. From **Graph**, click a node or select a focus entity to see neighbours with **Open** / **Queue** actions.

Entity notes appear in generated reports where entities are listed.

### Batch Queue (v1.9)

The **Batch Queue** page runs compatible follow-up modules for multiple entities in a controlled, visible way:

1. **Select entities** (filter by type) and review compatible module suggestions.
2. **Add passive modules for selection** — queues WHOIS/RDAP Intelligence, Domain Intelligence, Domain Email Security Posture, Certificate & Subdomain Intelligence, and Website Metadata Review where compatible.
3. **Duplicate protection** — the same entity/module pair cannot be queued twice while still queued.
4. **Recent-run warning** — warns if the same module ran against that target within 24 hours.
5. **Run passive queue** — one item at a time via the normal executor, with a configurable courtesy delay (default 1.5 s) between passive lookups.
6. **Run selected queue items** — subset runs; **Nmap is never included** in passive batch runs and requires authorisation if manually queued.
7. **Stop after current item**, **Clear completed items**, and per-item status/summary tracking.

Results appear automatically in Operations, Observations, Findings, Relationships, Graph, and Reports.

**v2.0 persistence:** queue items and run summaries are stored in the local database per case. Use **Move up** / **Move down** to reorder before running. Recent runs appear on the Batch Queue page and in generated reports.

### Module cards on Run Operation

- **Network Service Check, powered by Nmap** — active; IPv4 or domain only (not URL — enter hostname separately for port scans).
- **WHOIS / RDAP Intelligence** — passive registration/allocation metadata for domain, URL (host extracted), or public IPv4 via public RDAP.
- **VirusTotal Reputation Intelligence** — passive API reputation enrichment for domain, URL, or public IPv4 (`VIRUSTOTAL_API_KEY` required; private IPs skipped).
- **AbuseIPDB Reputation Intelligence** — passive abuse-confidence lookup for public IPv4 only (`ABUSEIPDB_API_KEY` required; lookup-only, no report submission).
- **GreyNoise Internet Noise Intelligence** — passive internet-noise/RIOT lookup for public IPv4 (`GREYNOISE_API_KEY` optional but recommended).
- **Shodan Internet Exposure Intelligence** — passive Shodan host lookup for public IPv4 (`SHODAN_API_KEY` required; host lookup only, no Shodan scans).
- **URLhaus Malware URL Intelligence** — passive abuse.ch URLhaus lookup for URL, domain, and public IPv4 (`ABUSECH_AUTH_KEY` required; lookup-only, no submission or payload download).
- **Domain Intelligence** — passive DNS/HTTP/TLS/Wayback for domain or URL.
- **Domain Email Security Posture** — passive SPF, DMARC, MX, CAA, MTA-STS, TLS-RPT and BIMI DNS review for domain or URL (no email sent).
- **Certificate & Subdomain Intelligence** — passive certificate transparency names for domain or URL.
- **Website Metadata Review** — passive homepage title, meta tags, headers, robots.txt, and sitemap hints for domain or URL.

### Guided run modes (v1.5)

After entering a target, choose **What do you want to do?** on Run Operation:

| Run mode | Purpose | Typical recommendations |
|----------|---------|-------------------------|
| **Quick Check** | Simple default | IPv4 → Network Service Check (+ WHOIS/RDAP; optional AbuseIPDB/VirusTotal/Shodan/URLhaus when keyed; GreyNoise for public IPv4); domain/URL → passive domain modules (+ optional VirusTotal/URLhaus); email/username/unknown → none |
| **Website / Domain Footprint** | Passive domain footprint | WHOIS/RDAP + Domain Intelligence + Email Security Posture + Certificate & Subdomain + Website Metadata (+ VirusTotal/URLhaus if key configured; no Nmap, AbuseIPDB, GreyNoise or Shodan by default) |
| **Local Device / IP Check** | Conservative active IP scan | Network Service Check; public IPv4 may recommend WHOIS/RDAP, GreyNoise, and optional AbuseIPDB/VirusTotal/Shodan/URLhaus; private/local IPs skip API reputation modules; authorisation required |
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

### Environment and API keys (v1.10+)

Project Overwatch loads local settings from `.env` (never committed) and optional defaults in `config/overwatch.defaults.json`.

1. Copy the placeholder file: `cp .env.example .env`
2. Edit `.env` locally with your API keys and optional general settings.
3. Open **Settings** in the sidebar to see **masked** key status, **Security posture**, and module readiness.
4. **Never commit `.env`** — it is listed in `.gitignore`.

python scripts/smoke_check.py
```

### VirusTotal Reputation Intelligence (v2.2)

Passive third-party reputation enrichment for **domain**, **URL**, and **public IPv4** targets.

1. Add `VIRUSTOTAL_API_KEY=your_key_here` to local `.env` (see `.env.example`).
2. Open **Settings** — VirusTotal provider shows configured yes/no with **masked** key only.
3. Select the module on **Run Operation**, **Entity Workspace**, or **Batch Queue** when compatible.

**Behaviour:**

- **Missing key** — module is blocked with a clear configuration message (operational issue, not a target risk finding).
- **Private/local IPv4** — completes with informational result; no VirusTotal API call.
- **Rate limit (HTTP 429)** — warning/operational notice; batch queue continues safely.
- **Results** — security vendor analysis counts and reputation are *reported by VirusTotal* — treat as leads, not confirmed threats or benign proof.
- **Evidence** — summaries stored in Evidence Locker with redaction; full raw JSON remains collapsed in the UI.

Requires VirusTotal API terms compliance and respects configured courtesy delays in batch runs.

### AbuseIPDB Reputation Intelligence (v2.3)

Passive third-party abuse-confidence lookup for **public IPv4** targets only.

1. Add `ABUSEIPDB_API_KEY=your_key_here` to local `.env` (see `.env.example`).
2. Open **Settings** — AbuseIPDB provider shows configured yes/no with **masked** key only.
3. Select the module on **Run Operation**, **Entity Workspace**, or **Batch Queue** when the target is a compatible public IPv4 address.

**Behaviour:**

- **Missing key** — module is blocked with a clear configuration message (operational issue, not a target risk finding).
- **Private/local IPv4** — completes with informational result; no AbuseIPDB API call.
- **Domain/URL targets** — incompatible in v2.3 (no in-module DNS resolution).
- **Rate limit (HTTP 429)** — warning/operational notice; batch queue continues safely.
- **Lookup-only** — uses the AbuseIPDB check endpoint; never submits abuse reports.
- **Results** — abuse confidence scores and report counts are *reported by AbuseIPDB* — treat as leads, not confirmed malicious activity or benign proof.
- **Evidence** — summaries stored in Evidence Locker with redaction; full raw JSON remains collapsed in the UI.

Requires AbuseIPDB API terms compliance and respects configured courtesy delays in batch runs.

### GreyNoise Internet Noise Intelligence (v2.4)

Passive third-party internet-noise and RIOT context for **public IPv4** targets only.

1. Optionally add `GREYNOISE_API_KEY=your_key_here` to local `.env` (recommended; see `.env.example`).
2. Open **Settings** — GreyNoise provider shows configured yes/no with **masked** key when present.
3. Select the module on **Run Operation**, **Entity Workspace**, or **Batch Queue** for compatible public IPv4 addresses.

**Behaviour:**

- **Missing key** — module may still perform limited unauthenticated Community API lookups with a clear warning (operational notice, not a target risk finding).
- **Private/local IPv4** — completes with informational result; no GreyNoise API call.
- **Domain/URL targets** — incompatible in this version (no in-module DNS resolution).
- **Rate limit (HTTP 429)** — warning/operational notice; batch queue continues safely.
- **v3 Community API only** — uses `https://api.greynoise.io/v3/community/{ip}`; no deprecated v2 endpoints.
- **Rate limiting** — `PROJECT_OVERWATCH_RATE_LIMIT_SECONDS` applies before each live API reputation request (shared with VirusTotal and AbuseIPDB).
- **Results** — noise/RIOT/classification flags are *reported by GreyNoise* — treat as context, not confirmed threats or benign proof.
- **Evidence** — summaries stored in Evidence Locker with redaction; full raw JSON remains collapsed in the UI.

### Shodan Internet Exposure Intelligence (v2.5)

Passive third-party internet-exposure context for **public IPv4** targets only.

1. Add `SHODAN_API_KEY=your_key_here` to local `.env` (see `.env.example`).
2. Open **Settings** — Shodan provider shows configured yes/no with **masked** key only.
3. Select the module on **Run Operation**, **Entity Workspace**, or **Batch Queue** for compatible public IPv4 addresses.

**Behaviour:**

- **Missing key** — module is **blocked** with a clear message (operational notice, not a target risk finding).
- **Private/local IPv4** — completes with informational result; no Shodan API call.
- **Domain/URL targets** — incompatible in v2.5 (no in-module DNS resolution).
- **Rate limit (HTTP 429)** — warning/operational notice; batch queue continues safely.
- **Host lookup only** — uses `GET https://api.shodan.io/shodan/host/{ip}`; does **not** trigger Shodan on-demand scans, search, alerts, streaming, or exploit APIs.
- **API key in URLs** — Shodan `key=` query parameters are redacted before logging, persistence, evidence, or reports.
- **Rate limiting** — `PROJECT_OVERWATCH_RATE_LIMIT_SECONDS` applies before each live API reputation request (shared with VirusTotal, AbuseIPDB, and GreyNoise).
- **Results** — ports and services are *reported by Shodan* — data may be stale or incomplete; not proof services are currently open. Use authorised Nmap for local verification.
- **Evidence** — exposure summaries stored in Evidence Locker with redaction; vulnerability references stored as count only; full raw JSON and service details remain collapsed in the UI.

### URLhaus Malware URL Intelligence (v2.6)

Passive third-party malware URL intelligence for **URL**, **domain**, and **public IPv4** targets.

1. Add `ABUSECH_AUTH_KEY=your_key_here` to local `.env` (`URLHAUS_AUTH_KEY` optional alias; see `.env.example`).
2. Obtain a free Auth-Key from the [abuse.ch Authentication Portal](https://auth.abuse.ch/).
3. Open **Settings** — URLhaus / abuse.ch provider shows configured yes/no with **masked** key only.
4. Select the module on **Run Operation**, **Entity Workspace**, or **Batch Queue** for compatible targets.

**Behaviour:**

- **Missing key** — module is **blocked** with a clear message (operational notice, not a target risk finding).
- **Private/local IPv4** — completes with informational result; no URLhaus API call.
- **URL targets** — `POST https://urlhaus-api.abuse.ch/v1/url/` with form field `url=`
- **Domain/host/public IPv4** — `POST https://urlhaus-api.abuse.ch/v1/host/` with form field `host=`
- **Lookup-only** — does **not** submit URLs, download malware samples/payloads, or use recent/bulk feed endpoints
- **Auth-Key** — sent in `Auth-Key` HTTP header only; never in URLs; redacted before logging, persistence, evidence, or reports
- **Rate limit (HTTP 429)** — warning/operational notice; batch queue continues safely
- **Large host results** — URL lists capped for UI/entities (20 displayed, 50 entity max) with usability warning
- **Results** — malware URL intelligence is *reported by URLhaus* — not independently confirmed by Overwatch; host matches do not mean every path is malicious
- **Evidence** — summaries stored in Evidence Locker; download links stripped; raw JSON collapsed in UI

**SecurityTrails** remains on the **Roadmap** only — planned, not implemented, likely requires paid/API access.

### Developing API-backed modules (v2.2+)

Use the shared scaffold when adding Censys or similar modules:

1. Copy `modules/TEMPLATE_api_module.py` to `modules/4_threat_intelligence/<your_module>.py`
2. Reuse `utils/api_module_helpers.py` for timeout, User-Agent, HTTP status mapping, missing-key blocked results, and redaction
3. Reference `intel_virustotal.py`, `intel_abuseipdb.py`, `intel_greynoise.py`, `intel_shodan.py`, or `intel_urlhaus.py` for complete working examples
4. Register in `module_registry.py`, wire `executor.py`, add interpreter + evidence capture
5. Run `python scripts/smoke_check.py` and `python scripts/security_audit.py`

API keys stay in `.env` only — never hard-code or persist full keys.

### RDAP cache (Backup page)

WHOIS/RDAP responses are cached per case in `rdap_lookup_cache`. On **Backup**:

- View cached query summaries for the active case
- Clear cache for the case
- Export/import cache via case backup JSON (`rdap_lookup_cache` key)

Optional TTL: `PROJECT_OVERWATCH_RDAP_CACHE_TTL_HOURS` (0 = no expiry).

### Secure-by-design baseline (v2.1)

- **`utils/security.py`** — `mask_secret()`, `redact_secrets_from_text()`, target validation, env parsing helpers.
- **Redaction before persistence** — observations, findings, operations, evidence, and reports redact obvious secrets.
- **`scripts/security_audit.py`** — scans source for hard-coded credentials and risky patterns.
- **Settings → Security posture** — Git ignore status, active module toggle, Nmap safety, hashing/redaction status.
- **Quarantined modules** — SQLMap, FFUF, Nuclei, HIBP breach lookup, dark-web, and cloud enum placeholders are `disabled` and not executable.
- **Hashing ≠ encryption** — evidence SHA-256 hashes support integrity only; see [SECURITY.md](SECURITY.md).

Run locally:

```bash
python scripts/security_audit.py
python scripts/smoke_check.py
```

Supported API keys: **VirusTotal** (`intel_virustotal`), **AbuseIPDB** (`intel_abuseipdb`), **Shodan** (`intel_shodan`), **URLhaus** (`intel_urlhaus` via `ABUSECH_AUTH_KEY`), **GreyNoise** (`intel_greynoise`, optional). Optional future keys: Censys (ID + secret), SecurityTrails (Roadmap only), Hunter.io, Have I Been Pwned.

General settings:

| Variable | Purpose | Default |
|----------|---------|---------|
| `PROJECT_OVERWATCH_RATE_LIMIT_SECONDS` | Courtesy delay between passive batch runs **and** consecutive API reputation lookups (VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLhaus) | `1.5` |
| `PROJECT_OVERWATCH_DEFAULT_TIMEOUT` | Default HTTP timeout (seconds) | `30` |
| `PROJECT_OVERWATCH_MAX_BATCH_ITEMS` | Max queued batch items per case | `50` |
| `PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES` | Global active module toggle | `true` |
| `PROJECT_OVERWATCH_RDAP_CACHE_TTL_HOURS` | RDAP/WHOIS cache expiry (0 = never) | `0` |
| `PROJECT_OVERWATCH_LOCAL_ENCRYPTION_KEY` | Optional Fernet key scaffold (not applied to DB yet) | unset |

Future API-backed modules are blocked cleanly when keys are missing. Current passive modules (WHOIS/RDAP Intelligence, Domain Intelligence, Domain Email Security Posture, Certificate & Subdomain Intelligence, Website Metadata Review) and Nmap do **not** require API keys.

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

### Domain Email Security Posture (v2.7)

Passive module `infra_email_security` for **domain** and **URL** targets. It reviews public DNS and well-known email security controls:

- **SPF** — sender policy framework TXT at the apex (`v=spf1`), terminal policy (`-all`, `~all`, `?all`, `+all`), includes and redirect
- **DMARC** — `_dmarc.<domain>` TXT (`p=`, `sp=`, `rua`/`ruf`, `pct`, alignment tags)
- **MX** — mail exchanger priority and hostnames
- **CAA** — certificate authority authorization records
- **MTA-STS** — `_mta-sts.<domain>` TXT and optional HTTPS fetch of `https://mta-sts.<domain>/.well-known/mta-sts.txt` when TXT is present
- **TLS-RPT** — `_smtp._tls.<domain>` reporting TXT
- **BIMI** — `default._bimi.<domain>` branding TXT (logo/VMC locations not fetched in v2.7)

Included in **Quick Check** and **Website / Domain Footprint** for domain/URL targets. No API key or authorisation required.

**Safety boundary:** DNS/public policy review only — does **not** send email, connect via SMTP, test inboxes, brute-force selectors, or validate credentials. Findings are **advisory** and do not prove messages cannot be spoofed.

**Test with example.com:**

1. `python scripts/smoke_check.py` — offline parser/interpreter checks (no live network required).
2. `streamlit run main.py` → **Run Operation** → target `example.com` → **Website / Domain Footprint**.
3. Ensure **Domain Email Security Posture** is selected → run (passive only).
4. Review SPF/DMARC/MX summary in **Latest Results**; expand record details in the Structured tab.
5. Check **Findings**, **Evidence Locker**, and **Report** for advisory email security observations.

### Client engagements and authorised testing (v2.8)

Project Overwatch is intended to support a future **security testing / OSINT / resilience advisory** business. Intrusive modules are on the roadmap but must only run inside a documented **client engagement** with scope and rules of engagement (ROE).

**Client Engagements page:**

- Create engagements (client, type, dates, status, contacts, authorisation/SOW references)
- Record **scope assets** with status: in-scope, out-of-scope, restricted, pending approval
- Set **permitted testing level** per asset: passive only, safe active, intrusive active, manual only
- Configure **ROE** with conservative defaults (no DoS, credentials, social engineering, or malware handling by default)
- **Emergency stop** — blocks active/intrusive modules for that engagement; passive modules may still run

**Run Operation guardrails:**

- Passive OSINT modules continue to work as today (scope warnings shown when an engagement is linked)
- **Nmap** and future active modules require authorisation confirmation **and** engagement/scope checks (or explicit standalone authorised testing when no engagement is linked)
- Out-of-scope and unknown targets block active/intrusive runs

**Module testing levels:** passive lookup · safe active check · intrusive active check · high-risk manual only · prohibited

See **Roadmap** for planned authorised assessment modules (Nuclei, ffuf, etc.) — listed as future capabilities requiring engagement controls, not permanently excluded.

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

### WHOIS / RDAP Intelligence (passive, v2.0)

- Collects public registration and allocation metadata using **RDAP** (Registration Data Access Protocol) via the public `rdap.org` redirector
- Accepts **domain**, **URL** (hostname extracted), and **public IPv4** targets — no API key required
- Parses registrar/registry, status, registration/update/expiry dates, nameservers, entities, and abuse contacts where published
- **Lookup order:** IANA bootstrap RDAP → `rdap.org` redirector → port-43 WHOIS fallback; retries on HTTP 429/503
- **Per-case cache** — repeat lookups for the same target reuse stored RDAP/WHOIS responses within a case
- **Private/local IPv4** addresses (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`, `127.x.x.x`, etc.) return a clean informational result without attempting public RDAP
- Registration data may be **incomplete, redacted, or stale** — treat all fields as contextual metadata, not proof of ownership or risk
- Creates entities/relationships for nameservers, registrar, network holder, and abuse contacts where observed
- Evidence Locker stores RDAP summaries, WHOIS fallback text, and source-unavailable notices

**How to test:**

1. Enter `example.com` or `8.8.8.8` as the target on Run Operation.
2. Enable **WHOIS / RDAP Intelligence [Passive]** (no authorisation required).
3. Review registrar/status/dates/nameservers in the result summary, findings, graph relationships, Evidence Locker, and reports.
4. Test `192.168.1.10` to confirm the private-IP informational path (not treated as an error).

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

## Evidence and reliability (v1.11)

Project Overwatch records **how** information was collected, not just what was found. Each observation, finding, and relationship can carry evidence metadata so analysts can weigh records appropriately.

### Evidence types

| Type | Meaning |
|------|---------|
| `direct_observation` | Directly observed during local module execution (for example Nmap or HTTP requests) |
| `third_party_source` | Retrieved from a public or external lookup (for example crt.sh, DNS resolvers, Wayback) |
| `parser_inferred` | Derived by Overwatch when parsing module output into entities or relationships |
| `analyst_note` | Analyst-entered context on an entity or finding |
| `user_supplied` | Confirmed input from the analyst (target, case notes) |
| `unavailable_source` | A source timed out or was unreachable — **not** proof of absence |
| `system_generated` | Generated by Overwatch from stored data (reports, summaries) |

### Reliability levels

| Level | Typical use |
|-------|-------------|
| `high` | Strong direct observation or confirmed input |
| `medium` | Useful third-party or parser output — review recommended |
| `low` | Partial, weak, or degraded collection |
| `unknown` | Reliability not established (legacy rows or incomplete runs) |

### Confidence vs reliability

- **Confidence** (0–100 on findings) reflects how strongly the module interpreter reads a signal.
- **Reliability** reflects how much trust to place in the *source* of the underlying data.

Guidance bands:

- **90–100:** Strong direct observation or confirmed user input
- **70–89:** Reliable third-party source or strong parser output
- **50–69:** Useful but needs review
- **0–49:** Weak, partial, or unavailable data

### Third-party data

Certificate transparency names, DNS answers, and archive lookups are **leads**. They may reflect historical or mis-issued certificates, not confirmed live hosts. Overwatch uses cautious wording for third-party and inferred records (for example “Observed via certificate transparency data”).

When a lookup is unavailable, Overwatch records a source notice — that indicates a collection limit during the run, not that the target lacks the attribute.

### Evidence Locker (v1.12)

The **Evidence Locker** preserves source artefacts from module runs:

- **What** was collected (raw Nmap output, DNS summaries, homepage metadata, crt.sh results)
- **When** it was captured (`captured_at`)
- **Which module** and **source** produced it
- **SHA-256 content hash** for change detection (empty when content is absent or secret-like)
- **Links** to observations, findings, and entities

**Evidence items** are distinct from:

| Record | Role |
|--------|------|
| **Observation** | Structured module result attached to an entity |
| **Finding** | Advisory interpreter output for analyst triage |
| **Evidence item** | Raw or summary artefact with provenance and hash |

**Current limitation:** text artefacts are stored in the local SQLite database (`content_text`). Content larger than 32 KB spills to `database/evidence_files/` with a preview retained in the database.

- **Evidence Locker** stores text artefacts with provenance, reliability, and SHA-256 hashes; large/binary spill to disk

### Evidence linking and filters (v1.13)

- **Many-to-many links** between evidence items and findings via `evidence_finding_links`
- **Findings page** filters by evidence type, reliability, and linked evidence presence
- **Graph page** can highlight or hide entities based on Evidence Locker items
- **Domain Intelligence** observations use source-aware evidence metadata (DNS vs HTTP/TLS)

## Developing new modules

Before adding additional collectors (Sherlock, expanded WHOIS fallback, etc.), use the **Module SDK** (`utils/module_sdk.py`) and the template skeleton (`modules/TEMPLATE_module.py`).

### Standard result contract

Every module run should return a dictionary normalised by `normalise_result()`:

```python
{
    "module_id": "infra_example",
    "success": True,
    "status": "completed",           # completed | completed_with_warnings | partial | blocked | error
    "summary": "Human-readable summary",
    "raw_output": "...",
    "findings": [],                  # legacy string lines and/or structured items
    "warnings": [],
    "errors": [],
    "data": {},                      # structured parsed payload (legacy alias: parsed_data)
    "evidence": [],                  # optional evidence locker hints
    "interpreter_findings": [],      # optional advisory finding dicts (interpreter pipeline)
}
```

Use `build_module_result()` and helpers `add_warning()`, `add_error()`, `add_finding()`. Validate with `validate_module_result()` during development.

### Registry metadata requirements

Register each module in `modules/module_registry.py` with at least:

- `module_id`, `display_name`, `category`, `status`, `mode`, `risk_level`
- `implemented`, `requires_authorisation`, `requires_api_key`
- `accepted_target_types` (must match `utils/target_detection.get_target_type()` values)
- `short_help` or `description`, plus `example_inputs` for implemented modules

Run `validate_module_registry()` or check **Settings → System status** for metadata warnings.

### Compatibility and evidence expectations

- Declare compatible target types in the registry; the executor blocks incompatible targets.
- Active modules require analyst authorisation confirmation before running.
- API-key modules must list `api_key_names` and pass settings preflight.
- Persisted **observations**, **findings**, and **Evidence Locker** items are created by the executor — module backends should focus on collection and the standard result payload.
- Copy `modules/TEMPLATE_module.py` as a starting point (it is not registered or executed).

### Testing

```bash
python scripts/smoke_check.py
```

Smoke checks verify SDK helpers, registry metadata for implemented modules, executor imports, evidence locker integration, Domain Email Security Posture parser/interpreter checks, and VirusTotal/AbuseIPDB/GreyNoise/Shodan/URLhaus mock lookups — no live network required.

Unit tests live in `tests/test_module_sdk.py`. CI runs both smoke check and unit tests (see `.github/workflows/smoke_check.yml`).

## Development

See `CHANGELOG.md` for version history.

```bash
python scripts/smoke_check.py
streamlit run main.py
```

## Legal notice

Use Project Overwatch only against systems you own or have explicit written permission to assess.
