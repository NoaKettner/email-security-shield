"""
Authentication Analyzer.

Reports SPF/DKIM/DMARC failures as evidence only.

Important: authentication failure is evidence, not a verdict - a
legitimate sender can be misconfigured. Likewise, passing does not
prove legitimacy - an attacker can correctly configure SPF/DKIM/DMARC
for a domain they own. The scoring engine weighs this alongside
everything else.
"""

CATEGORY = "authentication"

# field -> (signal code, points)
_CHECKS = {
    "spf": ("spf_fail", 8),
    "dkim": ("dkim_fail", 8),
    "dmarc": ("dmarc_fail", 8),
}


def analyze_authentication(email: dict) -> list:
    signals = []
    auth = email.get("authentication", {}) or {}

    failures = 0
    for field, (code, points) in _CHECKS.items():
        if auth.get(field) == "fail":
            failures += 1
            signals.append({
                "code": code,
                "category": CATEGORY,
                "reason": f"{field.upper()} check failed",
                "points": points,
            })

    if failures >= 2:
        signals.append({
            "code": "multiple_authentication_failures",
            "category": CATEGORY,
            "reason": f"{failures} authentication mechanisms failed at once",
            "points": 10,
        })

    return signals
