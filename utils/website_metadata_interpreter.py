"""Advisory interpretation of passive website metadata review results."""

from __future__ import annotations

from typing import Any

FORM_REVIEW_THRESHOLD = 1
LINK_REVIEW_THRESHOLD = 50


def _finding(
    title: str,
    severity: str,
    confidence: int,
    explanation: str,
    suggested_actions: list[str],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "explanation": explanation,
        "suggested_actions": suggested_actions,
    }


def interpret_website_metadata_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from homepage metadata review."""
    findings: list[dict[str, Any]] = []
    domain = parsed_data.get("domain") or "target"
    homepage = parsed_data.get("homepage") or {}
    robots = parsed_data.get("robots_txt") or {}
    sitemaps = parsed_data.get("sitemap_hints") or {}
    warning = parsed_data.get("warning")

    if homepage.get("error") or (homepage.get("status_code") and homepage["status_code"] >= 400):
        detail = homepage.get("error") or f"HTTP {homepage.get('status_code')}"
        findings.append(
            _finding(
                "Homepage metadata unavailable",
                "medium",
                80,
                f"The homepage for {domain} could not be reviewed reliably. {detail} "
                "Page title, meta tags, and link/form counts may be incomplete.",
                [
                    "Retry when the site is reachable or confirm the target URL is correct.",
                    "Review robots.txt and sitemap hints separately if they were collected.",
                    "Document that homepage metadata was not available for this run.",
                ],
            )
        )
    elif homepage.get("page_title"):
        findings.append(
            _finding(
                "Homepage title observed",
                "info",
                85,
                f"Page title for {domain}: {homepage['page_title']!r}. "
                "Titles help confirm site identity during review.",
                [
                    "Compare the title with expected branding for this target.",
                    "Note unexpected titles that may indicate staging, takeover, or misconfiguration.",
                ],
            )
        )

    if homepage.get("meta_description"):
        findings.append(
            _finding(
                "Meta description present",
                "info",
                80,
                f"A meta description tag was observed for {domain}. "
                "Descriptions can reveal marketing language or unintended content exposure.",
                [
                    "Review whether the description matches expected public messaging.",
                    "Check for sensitive project names or internal terminology.",
                ],
            )
        )

    canonical = homepage.get("canonical_url")
    if canonical:
        findings.append(
            _finding(
                "Canonical URL declared",
                "info",
                80,
                f"The homepage declares canonical URL {canonical}. "
                "Canonical tags indicate preferred indexing targets and may differ from the input URL.",
                [
                    "Verify whether the canonical URL is expected for this investigation.",
                    "Follow the canonical target if it points to a related asset worth reviewing.",
                ],
            )
        )

    form_count = int(homepage.get("form_count") or 0)
    if form_count >= FORM_REVIEW_THRESHOLD:
        findings.append(
            _finding(
                "HTML forms observed on homepage",
                "low",
                75,
                f"{form_count} HTML form(s) were counted on the homepage for {domain}. "
                "Forms may indicate login, contact, or submission surfaces worth manual review.",
                [
                    "Identify whether forms are expected (login, newsletter, contact).",
                    "Review exposed forms for missing CSRF or rate-limiting controls during manual testing.",
                    "Do not submit forms without explicit permission.",
                ],
            )
        )

    link_count = int(homepage.get("link_count") or 0)
    if link_count >= LINK_REVIEW_THRESHOLD:
        findings.append(
            _finding(
                "Large number of homepage links",
                "info",
                70,
                f"{link_count} anchor links were counted on the homepage for {domain}. "
                "A large link surface may warrant prioritised follow-up.",
                [
                    "Sample unexpected outbound or subdirectory links for further review.",
                    "Correlate notable links with other passive modules such as certificate intelligence.",
                ],
            )
        )

    if robots.get("available"):
        findings.append(
            _finding(
                "robots.txt reviewed",
                "info",
                85,
                f"robots.txt for {domain} was retrieved. Summary: {robots.get('summary')}. "
                "Disallow rules indicate paths the site owner asks crawlers to avoid — not proof of hidden content.",
                [
                    "Review disallow rules for unexpected sensitive paths worth manual verification.",
                    "Use sitemap references as leads for further passive review.",
                ],
            )
        )
    elif not warning:
        findings.append(
            _finding(
                "robots.txt not available",
                "info",
                65,
                f"robots.txt could not be retrieved for {domain}. "
                "Absence may be normal but removes a common public footprint signal.",
                [
                    "Retry later or check alternate schemes if robots guidance is needed.",
                    "Do not treat missing robots.txt as a security issue by itself.",
                ],
            )
        )

    reachable_sitemaps = sitemaps.get("reachable_count") or 0
    if reachable_sitemaps:
        sample = ", ".join(
            entry.get("url", "")
            for entry in (sitemaps.get("entries") or [])
            if entry.get("reachable")
        )[:200]
        findings.append(
            _finding(
                "Sitemap hints discovered",
                "info",
                80,
                f"{reachable_sitemaps} reachable sitemap hint(s) were observed for {domain}. "
                f"Examples: {sample or 'see module output'}. "
                "Sitemap URLs are leads for content discovery, not confirmed in-scope assets.",
                [
                    "Review sitemap targets for unexpected paths or subdomains.",
                    "Cross-reference sitemap hosts with certificate and DNS observations.",
                ],
            )
        )

    if warning and not findings:
        findings.append(
            _finding(
                "Website metadata collected with warnings",
                "low",
                70,
                f"Metadata review for {domain} completed with warnings: {warning}",
                [
                    "Review partial results in module output.",
                    "Retry when connectivity improves if fuller metadata is required.",
                ],
            )
        )

    return findings
