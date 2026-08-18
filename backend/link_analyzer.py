"""
Link Analyzer.

Looks at the gap between what a link *claims* to point to (its
displayed text) and where it actually goes (its href), plus a couple
of other well-known red flags (raw IPs, URL shorteners).

Repeated occurrences of the same issue are reported as a single
signal (with a count in the reason) rather than one signal per link,
so ten shortened links don't score ten times worse than one.
"""

from domain_utils import extract_url_domain, is_ip_address, looks_like_domain_or_url
from knowledge import URL_SHORTENERS

CATEGORY = "links"


def analyze_links(email: dict) -> list:
    signals = []
    links = email.get("links", []) or []

    mismatches = []
    ip_links = []
    shortened_domains = []

    for link in links:
        text = (link.get("text") or "").strip()
        url = (link.get("url") or "").strip()
        if not url:
            continue

        actual_domain = extract_url_domain(url)

        if is_ip_address(actual_domain):
            ip_links.append(url)

        if actual_domain in URL_SHORTENERS:
            shortened_domains.append(actual_domain)

        if looks_like_domain_or_url(text):
            displayed_domain = extract_url_domain(text)
            if displayed_domain and actual_domain and displayed_domain != actual_domain:
                mismatches.append((displayed_domain, actual_domain))

    if mismatches:
        displayed, actual = mismatches[0]
        extra = f" ({len(mismatches)} links affected)" if len(mismatches) > 1 else ""
        signals.append({
            "code": "link_domain_mismatch",
            "category": CATEGORY,
            "reason": (
                f"Displayed link domain '{displayed}' does not match actual "
                f"destination '{actual}'{extra}"
            ),
            "points": 25,
        })

    if ip_links:
        signals.append({
            "code": "ip_address_link",
            "category": CATEGORY,
            "reason": f"Link destination uses a raw IP address instead of a domain ({len(ip_links)} link(s))",
            "points": 20,
        })

    if shortened_domains:
        signals.append({
            "code": "url_shortener",
            "category": CATEGORY,
            "reason": f"Link uses a URL shortening service ({', '.join(sorted(set(shortened_domains)))})",
            "points": 10,
        })

    return signals
