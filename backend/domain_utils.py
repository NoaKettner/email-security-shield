"""
Domain Utilities.

Small, shared helpers for pulling a comparable "domain" out of a URL
or email address, and for basic domain/IP classification. Centralized
here so every analyzer that needs "what domain does this actually
point to" answers it the same way instead of re-implementing it.

Pure functions, no analyzer logic - this module never decides
whether something is suspicious, only normalizes strings.
"""

import re
from urllib.parse import urlparse

_IPV4_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IPV6_CHARS_PATTERN = re.compile(r"^[0-9a-f:]+$")


def extract_url_domain(url: str) -> str:
    """Return the lowercase host of a URL, without a leading 'www.',
    credentials, or port. Works even if `url` has no scheme."""
    if not url:
        return ""

    # urlparse only fills in .netloc if a scheme is present.
    candidate = url if "://" in url else f"http://{url}"
    netloc = urlparse(candidate).netloc.lower()

    netloc = netloc.rsplit("@", 1)[-1]  # drop "user:pass@"
    if not netloc.startswith("["):      # drop ":port", but keep bracketed IPv6
        netloc = netloc.split(":", 1)[0]

    if netloc.startswith("www."):
        netloc = netloc[4:]

    return netloc


def extract_email_domain(email: str) -> str:
    """Return the lowercase domain portion of an email address."""
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[-1].strip().lower()


def is_ip_address(host: str) -> bool:
    """True if `host` is a raw IPv4 or IPv6 address rather than a domain
    name. Used to flag links that point straight at an IP."""
    if not host:
        return False

    candidate = host.strip("[]")

    ipv4_match = _IPV4_PATTERN.match(candidate)
    if ipv4_match:
        return all(0 <= int(part) <= 255 for part in ipv4_match.groups())

    if ":" in candidate and _IPV6_CHARS_PATTERN.match(candidate):
        return True

    return False


def looks_like_domain_or_url(text: str) -> bool:
    """Heuristic: does this displayed link text look like it's claiming
    to be a domain/URL (e.g. "paypal.com"), as opposed to plain text
    like "Click here"? Used to decide whether it's meaningful to
    compare the displayed text against the link's real destination."""
    if not text:
        return False

    return bool(re.search(r"[a-z0-9-]+\.[a-z]{2,}", text.lower()))
