"""
Sender / Identity Analyzer.

Looks for inconsistencies in *who the email claims to be from*:
brand impersonation via look-alike or brand-keyword domains, and
From / Reply-To mismatches.

This analyzer only reports evidence (signals). It never decides
whether an email is malicious - that's the scoring engine's job.
"""

from difflib import SequenceMatcher

from domain_utils import extract_email_domain
from knowledge import BRAND_DOMAINS

CATEGORY = "identity"

_LOOKALIKE_RATIO_THRESHOLD = 0.75


def _domain_root_tokens(domain: str) -> list:
    # "paypa1-login.com" -> ["paypa1", "login"]
    labels = domain.split(".")
    core = ".".join(labels[:-1]) if len(labels) > 1 else domain
    return [t for t in core.split("-") if t]


def _brands_mentioned_in(*texts: str) -> list:
    mentioned = []
    for brand in BRAND_DOMAINS:
        for text in texts:
            if text and brand in text.lower():
                mentioned.append(brand)
                break
    return mentioned


def _is_lookalike_token(token: str, brand: str) -> bool:
    if token == brand:
        return True
    return SequenceMatcher(None, token, brand).ratio() >= _LOOKALIKE_RATIO_THRESHOLD


def analyze_sender(email: dict) -> list:
    signals = []
    sender = email.get("sender", {}) or {}
    display_name = sender.get("name") or ""
    from_email = sender.get("email") or ""
    reply_to = sender.get("reply_to")

    from_domain = extract_email_domain(from_email)
    subject = email.get("subject", "")
    body = email.get("body", "")

    mentioned_brands = _brands_mentioned_in(display_name, subject, body)

    for brand in mentioned_brands:
        official_domains = BRAND_DOMAINS[brand]
        if from_domain in official_domains:
            continue  # genuinely sent from the brand's own domain

        tokens = _domain_root_tokens(from_domain)
        lookalike = any(_is_lookalike_token(tok, brand) for tok in tokens)

        if lookalike:
            signals.append({
                "code": "lookalike_domain",
                "category": CATEGORY,
                "reason": (
                    f"Sender domain '{from_domain}' impersonates '{brand}' but is not "
                    f"one of its known domains ({', '.join(official_domains)})"
                ),
                "points": 25,
            })
        else:
            signals.append({
                "code": "display_name_brand_mismatch",
                "category": CATEGORY,
                "reason": (
                    f"Email references '{brand}' but sender domain '{from_domain}' is "
                    "unrelated to any known domain for that brand"
                ),
                "points": 10,
            })

    if reply_to:
        reply_domain = extract_email_domain(reply_to)
        if reply_domain and from_domain and reply_domain != from_domain:
            signals.append({
                "code": "sender_reply_to_mismatch",
                "category": CATEGORY,
                "reason": (
                    f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'"
                ),
                "points": 20,
            })

    return signals
