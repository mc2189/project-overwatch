# Project Overwatch

Project Overwatch is a personal Python/Streamlit project for exploring **OSINT, threat intelligence, security assessment and investigative workflows** in one local dashboard.

I built it to turn scattered technical and open-source information into something closer to an investigator's working environment: cases, entities, observations, evidence, relationships, findings, follow-up actions and reports.

It is a learning and portfolio project, not a commercial security product. Active checks are deliberately constrained and should only be used on systems you own, lab environments, or targets for which you have written permission.

## What it demonstrates

- **Python application development** using Streamlit and modular service/helper layers
- **SQL / SQLite data handling** for cases, entities, findings, observations, queues, baselines and cached intelligence
- Parameterised SQL queries and schema/migration handling rather than hard-coded data
- **OSINT and threat-intelligence enrichment** using public data and optional APIs
- Nmap-backed network/service assessment for authorised targets
- Domain, DNS, TLS, email-security and web-surface review
- PCAP and evidence-file review with bounded local processing
- Case memory, baselines and change detection
- Entity relationships, pivots and investigation queues
- Report generation and evidence provenance
- Security guardrails, authorisation checks and secret redaction
- AI-assisted development used as a productivity tool, with manual review and testing of generated changes

## Why I built it

My professional background is in investigations, intelligence, communications data and digital evidence rather than software engineering. I wanted a practical project that forced me to work with the technical side of those problems: structured data, APIs, network artefacts, automation, SQL queries, security controls and turning raw results into usable findings.

The project has grown iteratively as I have learned. The emphasis is less on building offensive tooling and more on **collecting, structuring, assessing and explaining information safely**.

## Tech stack

- Python
- Streamlit
- SQLite / SQL
- Nmap
- Requests / public APIs
- DNS, TLS and HTTP tooling
- Optional Wireshark/tshark integration for PCAP review
- Pytest-based tests for selected workflow and guardrail logic

## SQL / data examples

The application uses SQLite as its local case store. Examples include:

- case, entity and finding records
- relationship and evidence metadata
- queue state and run history
- baseline/change-detection records
- cached RDAP/WHOIS-style lookup data
- parameterised `SELECT`, `INSERT` and update operations
- lightweight schema migrations and table checks

Relevant files include:

- [`database/db_setup.py`](database/db_setup.py)
- [`database/personal_lab.py`](database/personal_lab.py)
- [`ui/metrics.py`](ui/metrics.py)
- [`utils/rdap_cache.py`](utils/rdap_cache.py)
- [`utils/case_workflow.py`](utils/case_workflow.py)

## Investigation workflow

A typical workflow is:

1. Create/select a case.
2. Enter a domain, URL, IPv4 address, email address or username.
3. Select a goal or compatible assessment modules.
4. Run passive enrichment, or explicitly authorise a safe active check in Personal Lab / Client Engagement mode.
5. Review structured results, observations and findings.
6. Pivot between related entities and queue follow-up actions.
7. Compare results against previous baselines where relevant.
8. Generate a report with evidence and recommended actions.

## Implemented capability examples

- WHOIS / RDAP intelligence
- VirusTotal, AbuseIPDB, GreyNoise, Shodan and URLhaus enrichment where API access is configured
- Domain intelligence and certificate/subdomain review
- SPF, DMARC, MX, CAA, MTA-STS, TLS-RPT and BIMI posture review
- Website metadata and HTTP security-header review
- TLS and SSH configuration review for authorised targets
- Nmap service discovery using constrained profiles
- Remote-access exposure review
- Controlled common-path review
- PCAP evidence review and bounded Personal Lab packet capture
- Document/image metadata review
- Case baselines, expected-item handling and change detection
- Guided assessment playbooks and controlled follow-up queues

## Security and ethics

The project is intentionally defensive and local-first.

- Real API keys and passwords are loaded from environment variables and are not stored in the repository.
- `.env`, local databases, evidence files, logs and reports are excluded from Git.
- Active modules require explicit authorisation and the correct operating context.
- Commands use constrained arguments rather than free-form shell execution.
- Secret-like material is redacted before display/persistence where practical.
- Broad scanning, credential attacks, exploitation, evasion and destructive testing are not part of the normal execution path.

See [`SECURITY.md`](SECURITY.md) for the detailed security model.

## Running locally

```bash
git clone https://github.com/mc2189/project-overwatch.git
cd project-overwatch
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run main.py
```

Optional integrations require your own API keys in `.env`. The repository contains placeholders only.

## Project status

This is an active personal project and some modules remain experimental or intentionally limited. The detailed development history is kept in [`CHANGELOG.md`](CHANGELOG.md).

The current codebase includes tests, security-audit tooling, configuration examples and a separate [`SECURITY.md`](SECURITY.md) to make the project's limitations and intended use explicit.
