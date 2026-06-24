"""Detect visible web stack indicators from HTTP response metadata."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

CATEGORY_WEB_SERVER = "web_server"
CATEGORY_CMS = "cms"
CATEGORY_JS_FRAMEWORK = "javascript_framework"
CATEGORY_FRONTEND_LIBRARY = "frontend_library"
CATEGORY_HOSTING = "hosting_platform"
CATEGORY_CDN = "cdn_platform"
CATEGORY_ANALYTICS = "analytics_tool"

CATEGORY_LABELS = {
    CATEGORY_WEB_SERVER: "Web server",
    CATEGORY_CMS: "CMS",
    CATEGORY_JS_FRAMEWORK: "JavaScript framework",
    CATEGORY_FRONTEND_LIBRARY: "Frontend library",
    CATEGORY_HOSTING: "Hosting platform",
    CATEGORY_CDN: "CDN / edge platform",
    CATEGORY_ANALYTICS: "Analytics tool",
}

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_LINK_HREF_RE = re.compile(r"""<link[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
_META_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)
_VERSION_IN_TEXT_RE = re.compile(r"\b(\d+(?:\.\d+){0,3})\b")

# (name, category, confidence, source, pattern in lowercased haystack, optional version group)
_HEADER_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    ("nginx", CATEGORY_WEB_SERVER, "high", "header", "server: nginx"),
    ("Apache", CATEGORY_WEB_SERVER, "high", "header", "server: apache"),
    ("Microsoft IIS", CATEGORY_WEB_SERVER, "high", "header", "server: microsoft-iis"),
    ("Caddy", CATEGORY_WEB_SERVER, "high", "header", "server: caddy"),
    ("LiteSpeed", CATEGORY_WEB_SERVER, "high", "header", "server: litespeed"),
    ("Cloudflare", CATEGORY_CDN, "high", "header", "server: cloudflare"),
    ("PHP", CATEGORY_WEB_SERVER, "medium", "header", "x-powered-by: php"),
    ("ASP.NET", CATEGORY_WEB_SERVER, "medium", "header", "x-powered-by: asp.net"),
    ("Express", CATEGORY_JS_FRAMEWORK, "medium", "header", "x-powered-by: express"),
    ("Next.js", CATEGORY_JS_FRAMEWORK, "medium", "header", "x-powered-by: next.js"),
    ("Cloudflare", CATEGORY_CDN, "high", "header", "cf-ray:"),
    ("Cloudflare", CATEGORY_CDN, "medium", "header", "cf-cache-status:"),
    ("Fastly", CATEGORY_CDN, "high", "header", "x-fastly-request-id:"),
    ("Akamai", CATEGORY_CDN, "medium", "header", "x-akamai-"),
    ("Azure Front Door", CATEGORY_CDN, "medium", "header", "x-azure-ref:"),
    ("Amazon CloudFront", CATEGORY_CDN, "medium", "header", "x-amz-cf-id:"),
    ("Vercel", CATEGORY_HOSTING, "high", "header", "x-vercel-id:"),
    ("Netlify", CATEGORY_HOSTING, "high", "header", "x-nf-request-id:"),
    ("GitHub Pages", CATEGORY_HOSTING, "medium", "header", "x-github-request-id:"),
)

_CONTENT_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    ("WordPress", CATEGORY_CMS, "high", "script", "/wp-content/"),
    ("WordPress", CATEGORY_CMS, "high", "script", "/wp-includes/"),
    ("WooCommerce", CATEGORY_CMS, "medium", "script", "woocommerce"),
    ("Shopify", CATEGORY_CMS, "high", "script", "cdn.shopify.com"),
    ("Shopify", CATEGORY_CMS, "medium", "script", "shopify"),
    ("Drupal", CATEGORY_CMS, "medium", "script", "/sites/default/files/"),
    ("Joomla", CATEGORY_CMS, "medium", "script", "/media/system/js/"),
    ("Magento", CATEGORY_CMS, "medium", "script", "magento"),
    ("Ghost", CATEGORY_CMS, "medium", "script", "ghost.org"),
    ("Squarespace", CATEGORY_CMS, "medium", "script", "squarespace.com"),
    ("Wix", CATEGORY_CMS, "medium", "script", "wix.com"),
    ("Webflow", CATEGORY_CMS, "medium", "script", "webflow.com"),
    ("React", CATEGORY_JS_FRAMEWORK, "medium", "script", "react.production.min.js"),
    ("React", CATEGORY_JS_FRAMEWORK, "low", "script", "react-dom"),
    ("Next.js", CATEGORY_JS_FRAMEWORK, "medium", "script", "/_next/static/"),
    ("Angular", CATEGORY_JS_FRAMEWORK, "medium", "script", "angular"),
    ("Vue.js", CATEGORY_JS_FRAMEWORK, "medium", "script", "vue"),
    ("Nuxt", CATEGORY_JS_FRAMEWORK, "medium", "script", "/_nuxt/"),
    ("Svelte", CATEGORY_JS_FRAMEWORK, "low", "script", "svelte"),
    ("jQuery", CATEGORY_FRONTEND_LIBRARY, "high", "script", "jquery"),
    ("Bootstrap", CATEGORY_FRONTEND_LIBRARY, "medium", "script", "bootstrap"),
    ("Tailwind CSS", CATEGORY_FRONTEND_LIBRARY, "low", "stylesheet", "tailwind"),
    ("Vite", CATEGORY_JS_FRAMEWORK, "medium", "script", "/@vite/"),
    ("Webpack", CATEGORY_JS_FRAMEWORK, "low", "script", "webpack"),
    ("Google Analytics", CATEGORY_ANALYTICS, "high", "script", "google-analytics.com"),
    ("Google Analytics", CATEGORY_ANALYTICS, "high", "script", "googletagmanager.com/gtag"),
    ("Google Tag Manager", CATEGORY_ANALYTICS, "high", "script", "googletagmanager.com/gtm.js"),
    ("Meta Pixel", CATEGORY_ANALYTICS, "high", "script", "connect.facebook.net"),
    ("Hotjar", CATEGORY_ANALYTICS, "medium", "script", "hotjar.com"),
    ("Microsoft Clarity", CATEGORY_ANALYTICS, "medium", "script", "clarity.ms"),
    ("Firebase Hosting", CATEGORY_HOSTING, "medium", "script", "firebaseapp.com"),
)


def _plain_version(text: str) -> str | None:
    match = _VERSION_IN_TEXT_RE.search(text)
    if not match:
        return None
    version = match.group(1)
    return version if len(version) <= 20 else None


def _indicator(
    *,
    name: str,
    category: str,
    confidence: str,
    source: str,
    reason: str,
    version: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, category),
        "confidence": confidence,
        "source": source,
        "reason": reason,
        "version": version,
    }


def _match_rules(haystack: str, rules: tuple[tuple[str, str, str, str, str], ...]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    lower = haystack.lower()
    for name, category, confidence, source, needle in rules:
        if needle not in lower:
            continue
        key = (name.lower(), category, source)
        if key in seen:
            continue
        seen.add(key)
        version = None
        if source == "header" and name.lower() in {"nginx", "apache", "php"}:
            idx = lower.find(needle)
            version = _plain_version(lower[idx : idx + 80])
        found.append(
            _indicator(
                name=name,
                category=category,
                confidence=confidence,
                source=source,
                reason=f"Indicator observed in {source}: suggests {name} may be in use.",
                version=version,
            )
        )
    return found


def detect_indicators(
    *,
    headers: dict[str, str],
    body_preview: str | None,
    script_sources: list[str],
    stylesheet_links: list[str],
    meta_generator: str | None,
    cookie_names: list[str],
    redirect_urls: list[str],
) -> list[dict[str, Any]]:
    """Return deduplicated stack indicators from response artefacts."""
    indicators: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(item: dict[str, Any]) -> None:
        key = (item["name"].lower(), item["category"])
        if key in seen:
            return
        seen.add(key)
        indicators.append(item)

    header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    for item in _match_rules(header_blob, _HEADER_RULES):
        add(item)

    if meta_generator:
        gen_lower = meta_generator.lower()
        cms_map = (
            ("wordpress", "WordPress"),
            ("drupal", "Drupal"),
            ("joomla", "Joomla"),
            ("ghost", "Ghost"),
            ("shopify", "Shopify"),
        )
        for token, label in cms_map:
            if token in gen_lower:
                add(
                    _indicator(
                        name=label,
                        category=CATEGORY_CMS,
                        confidence="high",
                        source="meta",
                        reason=f'Meta generator "{meta_generator}" suggests {label} may be in use.',
                        version=_plain_version(meta_generator),
                    )
                )
                break

    script_blob = "\n".join(script_sources)
    stylesheet_blob = "\n".join(stylesheet_links)
    for item in _match_rules(script_blob, _CONTENT_RULES):
        add(item)
    for item in _match_rules(stylesheet_blob, _CONTENT_RULES):
        add(item)

    if body_preview:
        for item in _match_rules(body_preview.lower(), _CONTENT_RULES):
            add(item)

    for cookie in cookie_names:
        if cookie.lower().startswith("wordpress"):
            add(
                _indicator(
                    name="WordPress",
                    category=CATEGORY_CMS,
                    confidence="medium",
                    source="cookie name",
                    reason=f"Cookie name {cookie} suggests WordPress may be in use.",
                )
            )

    for url in redirect_urls:
        host = (urlparse(url).netloc or "").lower()
        host_rules = (
            ("shopify.com", "Shopify", CATEGORY_CMS),
            ("myshopify.com", "Shopify", CATEGORY_CMS),
            ("webflow.io", "Webflow", CATEGORY_CMS),
            ("netlify.app", "Netlify", CATEGORY_HOSTING),
            ("vercel.app", "Vercel", CATEGORY_HOSTING),
            ("github.io", "GitHub Pages", CATEGORY_HOSTING),
            ("firebaseapp.com", "Firebase Hosting", CATEGORY_HOSTING),
            ("cloudfront.net", "Amazon CloudFront", CATEGORY_CDN),
        )
        for suffix, label, category in host_rules:
            if host.endswith(suffix) or suffix in host:
                add(
                    _indicator(
                        name=label,
                        category=category,
                        confidence="medium",
                        source="redirect",
                        reason=f"Redirect to {host} suggests {label} hosting/platform use.",
                    )
                )

    indicators.sort(key=lambda row: (row["category"], row["confidence"], row["name"]))
    return indicators


def extract_html_artifacts(body_preview: str | None) -> dict[str, Any]:
    """Extract script, stylesheet, and meta generator hints from capped HTML preview."""
    text = body_preview or ""
    return {
        "script_sources": _SCRIPT_SRC_RE.findall(text)[:40],
        "stylesheet_links": _LINK_HREF_RE.findall(text)[:40],
        "meta_generator": (_META_GENERATOR_RE.search(text).group(1) if _META_GENERATOR_RE.search(text) else None),
    }


def summarize_categories(indicators: list[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for row in indicators:
        label = row.get("category_label") or row.get("category")
        if label and label not in seen:
            seen.add(label)
            labels.append(label)
    return labels
