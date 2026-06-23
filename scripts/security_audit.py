#!/usr/bin/env python3
"""Scan Project Overwatch source for embedded secrets and risky security patterns."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCAN_EXTENSIONS = {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".env.example"}
SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    "reports",
    "backups",
    "database",
}
SKIP_FILE_NAMES = {".env"}

PLACEHOLDER_HINTS = (
    "your_",
    "example",
    "placeholder",
    "changeme",
    "replace_me",
    "xxx",
    "not configured",
    "insert_",
    "<your",
    "<api",
    "dummy",
    "sample",
    "test_key",
    "fake",
)

HIGH_SEVERITY = "high"
MEDIUM_SEVERITY = "medium"
LOW_SEVERITY = "low"


@dataclass
class Finding:
    severity: str
    file: Path
    line_no: int
    category: str
    message: str
    suggestion: str
    line_text: str


@dataclass
class AuditResult:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        *,
        severity: str,
        file: Path,
        line_no: int,
        category: str,
        message: str,
        suggestion: str,
        line_text: str,
    ) -> None:
        self.findings.append(
            Finding(
                severity=severity,
                file=file,
                line_no=line_no,
                category=category,
                message=message,
                suggestion=suggestion,
                line_text=line_text.strip(),
            )
        )


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def _should_skip_path(path: Path) -> bool:
    rel = path.relative_to(PROJECT_ROOT)
    if path.name in SKIP_FILE_NAMES and path.name != ".env.example":
        return True
    if path.suffix == ".db":
        return True
    for part in rel.parts:
        if part in SKIP_DIR_NAMES:
            return True
    if rel.parts and rel.parts[0] == "database" and path.suffix == ".db":
        return True
    return False


def iter_source_files() -> list[Path]:
    files: list[Path] = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if _should_skip_path(path):
            continue
        if path.suffix not in SCAN_EXTENSIONS and path.name != ".env.example":
            continue
        files.append(path)
    return sorted(files)


RULES: list[tuple[str, str, re.Pattern[str], str, str, bool]] = [
    (
        HIGH_SEVERITY,
        "hard-coded password",
        re.compile(r"""(?i)(?:password|passwd|pwd)\s*=\s*['"][^'"]{4,}['"]"""),
        "Possible hard-coded password assignment.",
        "Move secrets to `.env` and load via environment variables only.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "hard-coded api key",
        re.compile(r"""(?i)(?:api[_-]?key|apikey|secret_key|access_key)\s*=\s*['"][^'"]{8,}['"]"""),
        "Possible hard-coded API key assignment.",
        "Use `.env` placeholders and `utils.settings_manager.get_env()`.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "hard-coded token",
        re.compile(r"""(?i)(?:token|auth_token|bearer)\s*=\s*['"][^'"]{8,}['"]"""),
        "Possible hard-coded token assignment.",
        "Load tokens from environment variables; never commit real values.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Private key material found in source.",
        "Remove the key from the repo and rotate it immediately.",
        False,
    ),
    (
        HIGH_SEVERITY,
        "github token",
        re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
        "GitHub token pattern detected.",
        "Revoke the token and use `.env` instead.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "aws access key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key ID pattern detected.",
        "Rotate the key and store credentials outside the repository.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "committed .env reference",
        re.compile(r"""(?i)(?:git\s+add|commit\s+['"]?\.env(?!\.example)|push\s+.*\.env(?!\.example))"""),
        "Documentation or script may encourage committing `.env`.",
        "Reference `.env.example` only; keep `.env` local and gitignored.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "absolute user path",
        re.compile(r"/Users/[A-Za-z0-9._\-]+"),
        "Hard-coded absolute user home path.",
        "Use `Path(__file__)` / `PROJECT_ROOT` instead of machine-specific paths.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "shell=True",
        re.compile(r"subprocess\.[a-z_]+\([^)]*shell\s*=\s*True"),
        "Subprocess invoked with shell=True.",
        "Use list arguments and avoid shell interpolation.",
        False,
    ),
    (
        MEDIUM_SEVERITY,
        "verify=False",
        re.compile(r"verify\s*=\s*False"),
        "TLS certificate verification disabled in HTTP client.",
        "Enable TLS verification unless there is a documented lab-only exception.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "disabled TLS warnings",
        re.compile(r"urllib3\.disable_warnings|InsecureRequestWarning"),
        "TLS warnings are being suppressed.",
        "Fix the TLS issue instead of disabling warnings.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "eval usage",
        re.compile(r"\beval\s*\("),
        "Use of eval() detected.",
        "Avoid eval(); parse structured data safely instead.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "exec usage",
        re.compile(r"\bexec\s*\("),
        "Use of exec() detected.",
        "Avoid exec() on untrusted input.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "pickle load",
        re.compile(r"pickle\.load|pickle\.loads"),
        "Pickle deserialization detected.",
        "Avoid unpickling untrusted data.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "shodan api url with key",
        re.compile(r"api\.shodan\.io[^\s\"']*[?&]key=[^&\s\"']+", re.IGNORECASE),
        "Shodan API URL may expose a query-parameter API key.",
        "Never log or persist full Shodan request URLs; redact key= values before storage.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "shodan request url logging",
        re.compile(r"(?i)(?:log|print|debug|info|warning|error).{0,40}(?:response\.url|request\.url).{0,80}shodan"),
        "Code may log Shodan HTTP request/response URLs that can contain API keys.",
        "Log endpoint names and status codes only; never persist URLs with key= query parameters.",
        True,
    ),
    (
        MEDIUM_SEVERITY,
        "auth-key header leak",
        re.compile(r'(?i)Auth-Key\s*[:=]\s*["\'][^"\']{8,}["\']'),
        "Auth-Key header value may be hard-coded or logged.",
        "Load ABUSECH_AUTH_KEY from environment; never log or persist Auth-Key values.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "urlhaus forbidden endpoint",
        re.compile(
            r"urlhaus-api\.abuse\.ch/v1/(?:urls/recent|payloads|tag|signature|download|urls/download|host/urls)"
        ),
        "URLhaus feed/download/submit-style endpoint reference detected.",
        "Use only v1/url/ and v1/host/ lookup endpoints in lookup-only modules.",
        True,
    ),
    (
        HIGH_SEVERITY,
        "urlhaus submit endpoint",
        re.compile(r"urlhaus\.abuse\.ch/api/"),
        "URLhaus submission API endpoint reference detected.",
        "This module must not submit URLs to URLhaus.",
        True,
    ),
    (
        LOW_SEVERITY,
        "suspicious subprocess shell string",
        re.compile(r"""subprocess\.(?:run|Popen|call)\(\s*['"][^'"]*[;&|`$][^'"]*['"]"""),
        "Subprocess may be using a shell command string.",
        "Prefer list-based arguments without shell metacharacters.",
        True,
    ),
]


def _is_safe_env_documentation(line: str) -> bool:
    lowered = line.lower()
    if ".env.example" in lowered:
        return True
    if any(
        phrase in lowered
        for phrase in (
            "never commit",
            "do not commit",
            "not commit",
            "gitignore",
            "copy to .env",
            "cp .env.example",
            "local .env",
            "add them to your local .env",
            "only in `.env`",
            "only in .env",
        )
    ):
        return True
    return False


def _is_test_or_audit_fixture(path: Path, line: str) -> bool:
    rel = str(path.relative_to(PROJECT_ROOT))
    if rel.startswith("tests/") or "test_" in path.name or path.name == "smoke_check.py":
        return True
    if path.name == "security_audit.py" and "re.compile" in line:
        return True
    return False


def scan_file(path: Path, result: AuditResult) -> None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        result.add(
            severity=LOW_SEVERITY,
            file=path,
            line_no=0,
            category="read error",
            message=str(exc),
            suggestion="Ensure the file is readable.",
            line_text="",
        )
        return

    rel = path.relative_to(PROJECT_ROOT)
    is_example_doc = path.name == ".env.example" or rel.parts[0] in {"docs"} or path.suffix == ".md"

    for line_no, line in enumerate(lines, start=1):
        if line.strip().startswith("#") and "noqa" in line.lower():
            continue
        for severity, category, pattern, message, suggestion, check_placeholder in RULES:
            if not pattern.search(line):
                continue
            match = pattern.search(line)
            if match is None:
                continue
            matched_text = match.group(0)
            if check_placeholder and _is_placeholder(matched_text):
                continue
            if category == "committed .env reference" and _is_safe_env_documentation(line):
                continue
            if _is_test_or_audit_fixture(path, line) and category in {
                "github token",
                "hard-coded api key",
                "hard-coded token",
                "hard-coded password",
                "urlhaus forbidden endpoint",
                "urlhaus submit endpoint",
            }:
                continue
            if is_example_doc and category in {
                "hard-coded password",
                "hard-coded api key",
                "hard-coded token",
            }:
                continue
            if path.name == "security_audit.py" and category in {
                "eval usage",
                "exec usage",
                "pickle load",
                "shell=True",
                "verify=False",
                "disabled TLS warnings",
            }:
                continue
            result.add(
                severity=severity,
                file=path,
                line_no=line_no,
                category=category,
                message=message,
                suggestion=suggestion,
                line_text=line,
            )


def run_audit() -> AuditResult:
    result = AuditResult()
    files = iter_source_files()
    result.files_scanned = len(files)
    for path in files:
        scan_file(path, result)
    return result


def print_report(result: AuditResult) -> int:
    grouped: dict[str, list[Finding]] = {HIGH_SEVERITY: [], MEDIUM_SEVERITY: [], LOW_SEVERITY: []}
    for finding in result.findings:
        grouped.setdefault(finding.severity, []).append(finding)

    high_count = len(grouped[HIGH_SEVERITY])
    status = "PASS" if high_count == 0 else "FAIL"
    print(f"Security audit: {status}")
    print(f"Files scanned: {result.files_scanned}")
    print()

    for severity in (HIGH_SEVERITY, MEDIUM_SEVERITY, LOW_SEVERITY):
        items = grouped.get(severity, [])
        print(f"{severity.upper()} ({len(items)})")
        if not items:
            print("  (none)")
            print()
            continue
        for item in items:
            rel = item.file.relative_to(PROJECT_ROOT)
            print(f"  [{item.category}] {rel}:{item.line_no}")
            print(f"    {item.message}")
            print(f"    Suggestion: {item.suggestion}")
            if item.line_text:
                print(f"    Line: {item.line_text[:200]}")
        print()

    if high_count:
        print("Result: FAIL — resolve high-severity findings before release.")
        return 1
    if grouped.get(MEDIUM_SEVERITY):
        print("Result: PASS with medium-severity notes (non-blocking).")
    else:
        print("Result: PASS")
    return 0


def main() -> int:
    return print_report(run_audit())


if __name__ == "__main__":
    sys.exit(main())
