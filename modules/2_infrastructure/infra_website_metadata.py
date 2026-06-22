"""Passive website metadata review for Project Overwatch."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value

MODULE_ID = "infra_website_metadata"
USER_AGENT = "ProjectOverwatch/1.6 (passive website metadata review)"
REQUEST_TIMEOUT = 15
MAX_HTML_BYTES = 512_000
MAX_ROBOTS_BYTES = 64_000
INTERESTING_HEADERS = (
    "server",
    "content-type",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
)


class _HomepageMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self.in_title = False
        self.meta_description: str | None = None
        self.canonical_url: str | None = None
        self.link_count = 0
        self.form_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            name = attrs_dict.get("name", "").lower()
            if name == "description" and attrs_dict.get("content"):
                self.meta_description = attrs_dict["content"].strip()
        elif tag == "link":
            rel = attrs_dict.get("rel", "").lower()
            if rel == "canonical" and attrs_dict.get("href"):
                self.canonical_url = attrs_dict["href"].strip()
        elif tag == "a" and attrs_dict.get("href"):
            self.link_count += 1
        elif tag == "form":
            self.form_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def normalize_domain(value: str) -> str:
    return normalize_target_value(value, get_target_type(value))


def is_valid_domain(domain: str) -> bool:
    return bool(domain) and bool(DOMAIN_PATTERN.match(domain))


def _build_homepage_url(original_target: str, domain: str) -> str:
    cleaned = original_target.strip()
    target_type = get_target_type(cleaned)
    if target_type == "url":
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        if parsed.scheme and parsed.netloc:
            return cleaned if "://" in cleaned else f"https://{cleaned.lstrip('/')}"
    return f"https://{domain}/"


def _fetch_url(url: str, *, max_bytes: int = MAX_HTML_BYTES) -> dict[str, Any]:
    result: dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "final_url": url,
        "headers": {},
        "body_text": "",
        "error": None,
    }
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
        result["reachable"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["headers"] = {key.lower(): value for key, value in response.headers.items()}
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        encoding = response.encoding or "utf-8"
        result["body_text"] = b"".join(chunks).decode(encoding, errors="replace")
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def _parse_homepage_metadata(html: str, base_url: str) -> dict[str, Any]:
    parser = _HomepageMetadataParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip() or None
    canonical = parser.canonical_url
    if canonical:
        canonical = urljoin(base_url, canonical)
    return {
        "page_title": title,
        "meta_description": parser.meta_description,
        "canonical_url": canonical,
        "link_count": parser.link_count,
        "form_count": parser.form_count,
    }


def _select_basic_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: headers[name] for name in INTERESTING_HEADERS if name in headers}


def _parse_robots_txt(text: str) -> dict[str, Any]:
    disallow_rules: list[str] = []
    allow_rules: list[str] = []
    sitemap_urls: list[str] = []
    user_agents: list[str] = []
    current_agents: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            current_agents = [value]
            if value not in user_agents:
                user_agents.append(value)
        elif key == "disallow" and value:
            agent = current_agents[0] if current_agents else "*"
            disallow_rules.append(f"{agent}: {value}")
        elif key == "allow" and value:
            agent = current_agents[0] if current_agents else "*"
            allow_rules.append(f"{agent}: {value}")
        elif key == "sitemap" and value:
            if value not in sitemap_urls:
                sitemap_urls.append(value)

    return {
        "available": True,
        "user_agents": user_agents[:10],
        "disallow_rules": disallow_rules[:20],
        "allow_rules": allow_rules[:20],
        "sitemap_urls": sitemap_urls[:10],
        "disallow_count": len(disallow_rules),
        "allow_count": len(allow_rules),
        "summary": _robots_summary(disallow_rules, allow_rules, sitemap_urls),
    }


def _robots_summary(
    disallow_rules: list[str],
    allow_rules: list[str],
    sitemap_urls: list[str],
) -> str:
    parts: list[str] = []
    if disallow_rules:
        parts.append(f"{len(disallow_rules)} disallow rule(s)")
    if allow_rules:
        parts.append(f"{len(allow_rules)} allow rule(s)")
    if sitemap_urls:
        parts.append(f"{len(sitemap_urls)} sitemap reference(s)")
    return "; ".join(parts) if parts else "No disallow/allow/sitemap directives found"


def _collect_robots_txt(domain: str) -> dict[str, Any]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/robots.txt"
        fetched = _fetch_url(url, max_bytes=MAX_ROBOTS_BYTES)
        if fetched.get("error"):
            continue
        if fetched.get("status_code") == 200 and fetched.get("body_text"):
            parsed = _parse_robots_txt(fetched["body_text"])
            parsed["source_url"] = fetched.get("final_url") or url
            return parsed
    return {
        "available": False,
        "user_agents": [],
        "disallow_rules": [],
        "allow_rules": [],
        "sitemap_urls": [],
        "disallow_count": 0,
        "allow_count": 0,
        "summary": "robots.txt not reachable or empty",
        "source_url": None,
    }


def _collect_sitemap_hints(domain: str, robots: dict[str, Any]) -> dict[str, Any]:
    hints: list[dict[str, Any]] = []
    seen: set[str] = set()

    for sitemap_url in robots.get("sitemap_urls") or []:
        if sitemap_url in seen:
            continue
        seen.add(sitemap_url)
        hints.append({"url": sitemap_url, "source": "robots.txt", "reachable": None})

    for candidate in (f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"):
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = requests.head(
                candidate,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
            reachable = probe.status_code < 400
            status_code = probe.status_code
            final_url = probe.url
        except requests.RequestException:
            reachable = False
            status_code = None
            final_url = candidate
        hints.append(
            {
                "url": final_url,
                "source": "common path probe",
                "reachable": reachable,
                "status_code": status_code,
            }
        )

    reachable = [hint for hint in hints if hint.get("reachable") is True]
    return {
        "entries": hints,
        "reachable_count": len(reachable),
        "summary": (
            f"{len(reachable)} reachable sitemap hint(s) from {len(hints)} checked"
            if hints
            else "No sitemap hints discovered"
        ),
    }


def _build_raw_output(data: dict[str, Any]) -> str:
    homepage = data.get("homepage") or {}
    robots = data.get("robots_txt") or {}
    sitemaps = data.get("sitemap_hints") or {}
    lines = [
        f"Website metadata review for {data.get('domain')}",
        f"Homepage URL: {homepage.get('requested_url')}",
        "",
    ]
    if homepage.get("error"):
        lines.extend([f"Homepage error: {homepage['error']}", ""])
    else:
        lines.extend(
            [
                f"Final URL: {homepage.get('final_url')}",
                f"Status: {homepage.get('status_code')}",
                f"Page title: {homepage.get('page_title') or '(none)'}",
                f"Meta description: {homepage.get('meta_description') or '(none)'}",
                f"Canonical URL: {homepage.get('canonical_url') or '(none)'}",
                f"Link count: {homepage.get('link_count', 0)}",
                f"Form count: {homepage.get('form_count', 0)}",
                "",
                "Basic headers:",
            ]
        )
        for key, value in (homepage.get("basic_headers") or {}).items():
            lines.append(f"  {key}: {value}")
        lines.append("")

    lines.extend(
        [
            f"robots.txt: {robots.get('summary')}",
            f"robots.txt source: {robots.get('source_url') or '(not found)'}",
        ]
    )
    for rule in (robots.get("disallow_rules") or [])[:10]:
        lines.append(f"  disallow {rule}")
    lines.append("")
    lines.append(f"Sitemap hints: {sitemaps.get('summary')}")
    for entry in (sitemaps.get("entries") or [])[:10]:
        lines.append(f"  - {entry.get('url')} ({entry.get('source')})")
    return "\n".join(lines)


def _build_module_notes(data: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    homepage = data.get("homepage") or {}
    if homepage.get("page_title"):
        notes.append(f"Page title observed: {homepage['page_title']}")
    if homepage.get("meta_description"):
        notes.append("Meta description tag present.")
    if homepage.get("canonical_url"):
        notes.append(f"Canonical URL declared: {homepage['canonical_url']}")
    if homepage.get("form_count", 0) > 0:
        notes.append(f"{homepage['form_count']} HTML form(s) observed on the homepage.")
    robots = data.get("robots_txt") or {}
    if robots.get("available"):
        notes.append(f"robots.txt reviewed: {robots.get('summary')}")
    sitemaps = data.get("sitemap_hints") or {}
    if sitemaps.get("reachable_count", 0) > 0:
        notes.append(f"{sitemaps['reachable_count']} reachable sitemap hint(s) discovered.")
    if data.get("warning"):
        notes.append(data["warning"])
    return notes


def run_website_metadata_review(target: str) -> dict[str, Any]:
    """Collect passive homepage metadata and return structured data."""
    original_target = target.strip()
    domain = normalize_domain(original_target)

    base_data: dict[str, Any] = {
        "original_target": original_target,
        "domain": domain,
        "homepage": {},
        "robots_txt": {},
        "sitemap_hints": {},
        "warning": None,
    }

    if not is_valid_domain(domain):
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": "error",
            "summary": f"Invalid domain or URL: {original_target}",
            "raw_output": f"Error: invalid domain or URL: {original_target}",
            "findings": [],
            "errors": [f"Invalid domain or URL: {original_target}"],
            "data": base_data,
        }

    homepage_url = _build_homepage_url(original_target, domain)
    fetched = _fetch_url(homepage_url)
    homepage_data: dict[str, Any] = {
        "requested_url": homepage_url,
        "final_url": fetched.get("final_url"),
        "status_code": fetched.get("status_code"),
        "reachable": fetched.get("reachable", False),
        "error": fetched.get("error"),
        "basic_headers": _select_basic_headers(fetched.get("headers") or {}),
        "page_title": None,
        "meta_description": None,
        "canonical_url": None,
        "link_count": 0,
        "form_count": 0,
    }

    if fetched.get("error"):
        base_data["warning"] = f"Homepage fetch failed: {fetched['error']}"
    elif fetched.get("body_text"):
        metadata = _parse_homepage_metadata(fetched["body_text"], fetched.get("final_url") or homepage_url)
        homepage_data.update(metadata)

    if not fetched.get("error") and fetched.get("status_code") and fetched["status_code"] >= 400:
        base_data["warning"] = f"Homepage returned HTTP {fetched['status_code']}."

    base_data["homepage"] = homepage_data
    base_data["robots_txt"] = _collect_robots_txt(domain)
    base_data["sitemap_hints"] = _collect_sitemap_hints(domain, base_data["robots_txt"])

    title = homepage_data.get("page_title") or "(no title)"
    summary = (
        f"Website metadata reviewed for {domain}: title={title!r}, "
        f"{homepage_data.get('link_count', 0)} link(s), {homepage_data.get('form_count', 0)} form(s)."
    )
    if base_data["robots_txt"].get("available"):
        summary += f" robots.txt: {base_data['robots_txt'].get('summary')}."
    if base_data.get("warning"):
        summary += f" {base_data['warning']}"

    return {
        "module_id": MODULE_ID,
        "success": True,
        "status": "completed",
        "summary": summary,
        "raw_output": _build_raw_output(base_data),
        "findings": _build_module_notes(base_data),
        "errors": [base_data["warning"]] if base_data.get("warning") else [],
        "data": base_data,
    }
