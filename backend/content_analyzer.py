"""
Content Analyzer.

Scans subject + body for the *concepts* commonly used in social
engineering (urgency, threats, credential requests, ...) rather than
matching single hard-coded words. Each concept fires at most once
per email, regardless of how many matching phrases appear.
"""

import re

CATEGORY = "content"

# code -> (points, [regex patterns]). Any one match fires the concept.
_CONCEPTS = [
    ("urgency", 8, [
        r"\burgent\b", r"\bimmediately\b", r"\bright away\b",
        r"\bas soon as possible\b", r"\b(within|in) \d+ (minutes|hours)\b",
    ]),
    ("threat", 10, [
        r"\bsuspend(ed)?\b", r"\bdisabled?\b", r"\bterminat(ed|e)\b",
        r"\block(ed)? (out|your account)\b", r"\blegal action\b",
        r"\bwill be closed\b", r"\baccess will be disabled\b",
    ]),
    ("credential_request", 15, [
        r"\bpassword\b", r"\busername and password\b",
        r"\bverify your (password|account|identity)\b",
        r"\bconfirm your (password|account)\b",
    ]),
    ("payment_request", 12, [
        r"\bwire transfer\b", r"\bprocess payment\b", r"\binvoice\b",
        r"\boutstanding (invoice|balance)\b", r"\bpay(ment)? (today|immediately)\b",
    ]),
    ("password_reset", 8, [
        r"\breset your password\b", r"\bpassword expir(es|ed|ation)\b",
    ]),
    ("account_suspension", 10, [
        r"\baccount (will be|has been) (suspended|disabled|locked)\b",
    ]),
    ("security_alert", 6, [
        r"\bunusual (sign.?in|activity)\b", r"\bsecurity alert\b",
        r"\bsuspicious activity detected\b",
    ]),
]


def analyze_content(email: dict) -> list:
    signals = []
    text = f"{email.get('subject', '')} {email.get('body', '')}".lower()

    for code, points, patterns in _CONCEPTS:
        if any(re.search(pattern, text) for pattern in patterns):
            signals.append({
                "code": code,
                "category": CATEGORY,
                "reason": f"Language matching the '{code}' concept was found in the subject/body",
                "points": points,
            })

    return signals
