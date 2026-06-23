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
- **Active** modules (e.g. Nmap) require:
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
