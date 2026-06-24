# Security

Project Overwatch is a **local-only** defensive intelligence dashboard. This document describes the security baseline for v2.1 and how to handle secrets, active modules, and evidence safely.

## Principles

- **Local-first** — data stays on your machine in a SQLite database unless you explicitly export it.
- **No embedded credentials** — API keys, passwords, and tokens must come from `.env` or OS environment variables only.
- **Fail safely** — missing binaries, disabled modules, and failed authorisation checks block risky actions rather than running silently.
- **Defensive use only** — use Project Overwatch on systems you own, lab environments, or targets with **written permission**.
- **No credential attack tooling** — modules for SQL injection, exploit scanning, breach credential lookup, or dark-web collection are disabled or quarantined unless explicit guardrails exist.

## Secret handling

1. Copy `.env.example` to `.env` in the project root.
2. Add real API keys and settings **only** in `.env`.
3. Never commit `.env` — it is listed in `.gitignore`.
4. `.env.example` contains placeholders only (`your_*_here`).
5. The Settings page shows **masked** values via `utils.security.mask_secret()` — never full keys.
6. Secrets are redacted before persistence in observations, findings, operations, evidence, and reports where practical.

## Active module authorisation

- **Passive** modules perform read-only public lookups and do not require authorisation.
- **Active** modules (e.g. Nmap, SSL / TLS Configuration Review, HTTP Security Header Review) require:
  - global enablement (`PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES=true`), and
  - per-run authorisation confirmation in the UI.
- Disabled/quarantined modules are not importable for execution through the registry and executor.

## Command execution safety

- Subprocess calls use **list arguments** — not `shell=True`.
- Nmap flags come from **allowlisted profiles**, not free-text user input.
- The app does not request `sudo`, store OS passwords, or attempt privileged actions automatically.
- Target strings are validated for shell metacharacters before module execution.

## Evidence hashing vs encryption

- Evidence items store **SHA-256 content hashes** for integrity verification.
- Hashing proves content has not changed; it does **not** provide confidentiality.
- Full database or evidence encryption is a **future item**.
- Optional scaffold: set `PROJECT_OVERWATCH_LOCAL_ENCRYPTION_KEY` and install `cryptography` for Fernet helpers in `utils/crypto_utils.py` (not applied to the database yet).
- Do not treat hashes as encryption.

## Redaction behaviour

`utils.security.redact_secrets_from_text()` masks common patterns including:

- API key / password / token assignments
- Bearer tokens
- AWS-, GitHub-, Slack-, and Stripe-style keys
- Private key blocks
- Long high-entropy standalone tokens where practical

Normal domain names, IPs, and module output are preserved when possible.

## URLhaus / abuse.ch lookup boundary (v2.6)

The **URLhaus Malware URL Intelligence** module (`intel_urlhaus`) is **lookup-only**:

- Allowed: `POST https://urlhaus-api.abuse.ch/v1/url/` and `POST https://urlhaus-api.abuse.ch/v1/host/` with `Auth-Key` header
- **Not allowed** in this module: URL submission, malware sample/payload download, recent feeds, bulk datasets, IDS rules, or tag/signature bulk endpoints
- The module does **not** fetch malicious URLs or download payloads locally
- `ABUSECH_AUTH_KEY` (or `URLHAUS_AUTH_KEY` alias) must remain in `.env` only — never persisted in observations, findings, evidence, or reports
- Malware download links (`urlhaus_download`) are stripped from summaries; raw JSON remains collapsed in the UI

## PCAP Evidence Review boundary (v2.17)

The **PCAP Evidence Review** module (`net_pcap_review`) is **supplied-capture-only**:

- Allowed: local parsing of user-uploaded `.pcap` / `.pcapng` files with bounded metadata extraction
- **Not allowed** in this module: live interface capture, wireless monitor mode, packet injection/sending, decryption/cracking, or password recovery
- **Not displayed by default:** raw packet payloads, passwords, tokens, cookies, authorisation headers, session values, or credential-like strings
- Sensitive-looking material detected during HTTP review is redacted before persistence; a cautious finding may be recorded
- File hashes and summaries may be stored in observations, findings, evidence, and reports — not full payload dumps
- Analysis reflects only the uploaded capture at review time — not proof of current network behaviour
- Optional `pyshark` / `tshark` dependency: when missing, the module returns metadata-only partial results without crashing the app

## Personal Lab Packet Capture boundary (v2.18)

The **Personal Lab Packet Capture** module (`net_live_capture`) is **bounded local capture only**:

- Allowed: short sequential captures on a user-selected interface using tshark or tcpdump with duration and packet caps
- **Not allowed:** wireless monitor mode, packet injection/sending, continuous/background capture, client engagement requirements, or decryption
- Requires a single Personal Lab confirmation checkbox — not formal ROE or scope forms
- Captured files are stored in a controlled case folder; UI/reports show filename and SHA-256 only
- Captured PCAPs are analysed via PCAP Evidence Review — same redaction and no raw payload display by default
- Capture only on systems and networks you own or are authorised to monitor

## Domain Email Security Posture boundary (v2.7)

The **Domain Email Security Posture** module (`infra_email_security`) is **passive DNS/policy review only**:

- Allowed: public DNS lookups (SPF, DMARC, MX, CAA, TLS-RPT, BIMI, MTA-STS TXT) and optional HTTPS fetch of the standard MTA-STS policy file at `/.well-known/mta-sts.txt`
- **Not allowed** in this module: sending email, SMTP connections, inbox testing, selector brute-forcing, credential validation, or breach lookups
- Findings are advisory — absence of a record in this lookup does not prove misconfiguration
- No API keys or secrets are used by this module

## SSL / TLS Configuration Review (v2.9)

- **Module ID:** `infra_tls_review` — controlled active assessment (`safe_active_check`)
- Allowed: single host:port TLS handshake (default 443), certificate metadata inspection, negotiated protocol/cipher, optional one-handshake-per-version protocol probes using Python `ssl`/`socket`
- **Not allowed:** vulnerability exploitation, fuzzing, denial-of-service testing, repeated aggressive handshakes, mass scanning, port ranges, STARTTLS, credential testing, bypass/evasion, intrusive payloads, SSL stripping, or MITM behaviour
- Requires authorisation and the correct operating context (Personal Lab or Client Engagement) with scope/ROE guardrails before connecting
- Uses standard-library networking only — no subprocess, no `shell=True`
- Results are point-in-time observations — not proof of ongoing posture
- No API keys or secrets are used by this module

## HTTP Security Header Review (v2.10)

- **Module ID:** `infra_http_security` — controlled active assessment (`safe_active_check`)
- Allowed: single-target GET/HEAD HTTP(S) request, security header review, cookie flag metadata (no values), optional `security.txt` and `robots.txt` at standard paths
- **Not allowed:** form submission, login interaction, crawling beyond supplied URL and exact well-known paths, full body storage, cookie value persistence
- Requires authorisation and the correct operating context (Personal Lab or Client Engagement) with scope/ROE guardrails before connecting
- Uses `requests` with short timeout and redirect limit — no subprocess, no `shell=True`
- Cookie and token values are redacted and not stored in observations, evidence, or reports

## Web Stack Identifier (v2.27)

- **Module ID:** `infra_web_stack_identifier` — controlled active assessment (`safe_active_check`)
- Allowed: single-target HTTP GET with redirect limit, response header collection, meta/script/stylesheet name extraction, capped page preview (2048 bytes max) for indicator matching
- **Not allowed:** full page body storage, form submission, login interaction, crawling beyond the supplied URL except redirects during the GET
- Requires authorisation and the correct operating context (Personal Lab or Client Engagement) with scope/ROE guardrails before connecting
- Uses `requests` with short timeout — no subprocess, no `shell=True`
- Indicators use cautious language only — they are review prompts, not confirmed fingerprinting

## Authorised assessment model (v2.8+)

Project Overwatch is designed for **authorised client assessments**, not unconstrained scanning.

### Operating contexts (v2.11)

Run Operation uses three operating contexts:

| Context | Purpose | Active modules |
|---------|---------|----------------|
| **Passive Research** | OSINT and passive enrichment | Blocked — use Personal Lab or Client Engagement |
| **Personal Lab** | Self-owned systems, home network, lab devices, learning | Allowed after Personal Lab confirmation and Personal Lab scope |
| **Client Engagement** | Formal client work | Full engagement, scope, ROE, and authorisation checks |

- **Personal Lab** is not a client engagement — it uses a separate scope table and logs confirmation text/version
- **Personal Lab auto-scope** — after ticking the single confirmation checkbox, unknown targets are added to lab scope automatically when you run safe active checks
- **Client Engagement** remains strict: draft engagements, out-of-scope targets, emergency stop, and ROE limits still block active checks
- **Passive modules** run in Passive Research without engagement, ROE, or lab confirmation

### Engagement framework (v2.8)

- **Engagements** document client authorisation, contacts, and assessment type
- **Scope assets** define what may be tested and at what level (passive / safe active / intrusive / manual only)
- **Rules of engagement** define prohibited actions and whether active or intrusive testing is permitted
- **Emergency stop** halts active/intrusive testing immediately while preserving audit records
- **Passive OSINT** modules may run without an engagement but should still respect written permission for real targets
- **Active/intrusive modules** require: correct operating context, authorisation or Personal Lab confirmation, in-scope target, active engagement status (Client Engagement mode), ROE permission, and no emergency stop
- **Prohibited by default:** unauthorised testing, DoS, credential attacks, social engineering automation, malware deployment, evasion/persistence, destructive testing, exfiltration

v2.9 enables **SSL / TLS Configuration Review** and v2.10 enables **HTTP Security Header Review** as controlled active assessment modules under this framework. Intrusive modules (e.g. Nuclei, ffuf) remain planned and disabled.

## Security audit

Run the local audit before releases or after changing configuration handling:

```bash
python scripts/security_audit.py
```

The script scans source files for hard-coded secrets, risky subprocess/TLS patterns, `eval`/`exec`, pickle loading, and machine-specific paths. It exits non-zero only for **high-severity** findings.

## Reporting issues

If you discover a security problem:

1. Do not commit secrets or real credentials in bug reports.
2. Rotate any exposed keys immediately.
3. Document steps to reproduce using sanitised examples.
4. Prefer fixing via `.env` / configuration rather than hard-coding values.

## Safe testing guidance

- Use lab targets or your own infrastructure.
- Keep `.env` local; verify `python scripts/smoke_check.py` passes.
- Run `python scripts/security_audit.py` after security-related changes.
- Export reports with optional IP/email/domain redaction for external sharing — secret redaction is always applied first.

## v2.2 roadmap (security)

- Optional local evidence/database encryption with user-supplied keys
- RDAP cache management in backup UI
- Richer audit integration in CI
