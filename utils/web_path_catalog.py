"""Curated web path list for controlled path review."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

CATEGORY_BASELINE = "baseline"
CATEGORY_POLICY_INFO = "policy/info"
CATEGORY_LOGIN_ADMIN = "login/admin"
CATEGORY_API_DOCS = "API/docs"
CATEGORY_STATUS_HEALTH = "status/health"
CATEGORY_SENSITIVE = "sensitive-name indicator"
CATEGORY_CMS = "CMS-specific"

CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_BASELINE: "Baseline",
    CATEGORY_POLICY_INFO: "Policy / info",
    CATEGORY_LOGIN_ADMIN: "Login / admin",
    CATEGORY_API_DOCS: "API / docs",
    CATEGORY_STATUS_HEALTH: "Status / health",
    CATEGORY_SENSITIVE: "Sensitive-name indicator",
    CATEGORY_CMS: "CMS-specific",
}

MAX_PATHS = 24
MAX_CUSTOM_PATHS = 24

# (path, category, note)
DEFAULT_WEB_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/", CATEGORY_BASELINE, "Homepage baseline response."),
    ("/robots.txt", CATEGORY_POLICY_INFO, "Robots policy file if published."),
    ("/.well-known/security.txt", CATEGORY_POLICY_INFO, "Standard security.txt location."),
    ("/security.txt", CATEGORY_POLICY_INFO, "Alternate security.txt location."),
    ("/sitemap.xml", CATEGORY_POLICY_INFO, "Sitemap index if published."),
    ("/humans.txt", CATEGORY_POLICY_INFO, "Human-readable site credits file."),
    ("/favicon.ico", CATEGORY_BASELINE, "Favicon resource."),
    ("/admin", CATEGORY_LOGIN_ADMIN, "Common admin path name — review access control if observed."),
    ("/login", CATEGORY_LOGIN_ADMIN, "Common login path name."),
    ("/wp-login.php", CATEGORY_CMS, "WordPress login endpoint indicator."),
    ("/wp-admin/", CATEGORY_CMS, "WordPress admin area indicator."),
    ("/api", CATEGORY_API_DOCS, "Common API root path."),
    ("/api/docs", CATEGORY_API_DOCS, "API documentation path."),
    ("/swagger", CATEGORY_API_DOCS, "Swagger UI path indicator."),
    ("/swagger.json", CATEGORY_API_DOCS, "Swagger JSON descriptor indicator."),
    ("/openapi.json", CATEGORY_API_DOCS, "OpenAPI JSON descriptor indicator."),
    ("/docs", CATEGORY_API_DOCS, "Documentation path indicator."),
    ("/status", CATEGORY_STATUS_HEALTH, "Status endpoint indicator."),
    ("/health", CATEGORY_STATUS_HEALTH, "Health check endpoint indicator."),
    ("/server-status", CATEGORY_STATUS_HEALTH, "Server status page indicator."),
    ("/.git/", CATEGORY_SENSITIVE, "Git metadata path name — response existence only, no body stored."),
    ("/.env", CATEGORY_SENSITIVE, "Environment file path name — response existence only, no body stored."),
    ("/backup", CATEGORY_SENSITIVE, "Backup path name — review whether expected."),
    ("/backups", CATEGORY_SENSITIVE, "Backups path name — review whether expected."),
)

_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$")
_FORBIDDEN_PATH_TOKENS = ("..", "//", "\\", "%2e", "%2f")
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE | re.DOTALL)


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category)


def validate_path(path: str) -> tuple[bool, str | None]:
    """Validate a single path segment for controlled review."""
    cleaned = (path or "").strip()
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned.lstrip('/')}"
    lower = cleaned.lower()
    if any(token in lower for token in _FORBIDDEN_PATH_TOKENS):
        return False, "Path traversal or encoded traversal is not allowed."
    if not _PATH_PATTERN.match(cleaned):
        return False, "Path contains unsupported characters."
    if len(cleaned) > 256:
        return False, "Path exceeds maximum length."
    return True, None


def resolve_path_entries(options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return the capped curated path list for review."""
    options = options or {}
    custom_paths = options.get("custom_paths")
    if custom_paths:
        entries: list[dict[str, Any]] = []
        for item in custom_paths[:MAX_CUSTOM_PATHS]:
            if isinstance(item, dict):
                path = str(item.get("path") or "")
                category = str(item.get("category") or CATEGORY_BASELINE)
                note = str(item.get("note") or "Custom path review entry.")
            else:
                path = str(item)
                category = CATEGORY_BASELINE
                note = "Custom path review entry."
            ok, error = validate_path(path)
            if not ok:
                continue
            normalized = path if path.startswith("/") else f"/{path}"
            entries.append(
                {
                    "path": normalized,
                    "category": category,
                    "category_label": category_label(category),
                    "note": note,
                }
            )
        return entries[:MAX_PATHS]

    return [
        {
            "path": path,
            "category": category,
            "category_label": category_label(category),
            "note": note,
        }
        for path, category, note in DEFAULT_WEB_PATHS[:MAX_PATHS]
    ]


def build_base_url(parsed_target: dict[str, Any]) -> str:
    """Build scheme://host[:port] base URL without trailing path."""
    scheme = (parsed_target.get("scheme") or "https").lower()
    host = parsed_target.get("host") or ""
    port = int(parsed_target.get("port") or (443 if scheme == "https" else 80))
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def build_path_url(base_url: str, path: str) -> str:
    """Join base URL and path safely."""
    if path == "/":
        return f"{base_url.rstrip('/')}/"
    return urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))


def is_sensitive_category(category: str) -> bool:
    return category == CATEGORY_SENSITIVE


def extract_title(preview: str | None) -> str | None:
    if not preview:
        return None
    match = _TITLE_RE.search(preview)
    if not match:
        return None
    title = " ".join(match.group(1).split())
    return title[:200] if title else None


def response_note(*, category: str, status_code: int | None, content_type: str | None) -> str:
    if status_code is None:
        return "No HTTP response received."
    if status_code == 404:
        return "Path not found (404) — may be expected."
    if status_code in {401, 403}:
        return "Access denied response — path may exist but is restricted."
    if category == CATEGORY_SENSITIVE:
        return "Sensitive-name path responded — review whether exposure is expected; body not stored."
    if status_code >= 500:
        return "Server error response — operational note only."
    if content_type and "html" in content_type.lower():
        return "HTML response observed — review whether path is expected."
    return "Response observed — review whether this path is expected."


def is_notable_response(row: dict[str, Any]) -> bool:
    """Return True when a path response may warrant analyst attention."""
    status = row.get("status_code")
    if status is None or row.get("error"):
        return False
    category = row.get("category") or ""
    if category == CATEGORY_BASELINE:
        return False
    if status == 404:
        return False
    if category == CATEGORY_SENSITIVE and status in {200, 301, 302, 307, 308}:
        return True
    if status in {200, 201, 204, 301, 302, 307, 308}:
        return True
    if status in {401, 403} and category in {CATEGORY_LOGIN_ADMIN, CATEGORY_CMS, CATEGORY_API_DOCS}:
        return True
    return False


def summarize_notable_categories(rows: list[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not is_notable_response(row):
            continue
        label = row.get("category_label") or row.get("category") or "unknown"
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def redirect_target(final_url: str | None, requested_url: str) -> str | None:
    if not final_url or final_url.rstrip("/") == requested_url.rstrip("/"):
        return None
    parsed = urlparse(final_url)
    if not parsed.scheme:
        return final_url
    return final_url
