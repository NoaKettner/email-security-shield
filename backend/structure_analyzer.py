"""
HTML / Structure Analyzer.

Looks at the raw HTML body for structural red flags: embedded
credential-harvesting forms, hidden content, and zero-width
characters sometimes used to break up text and evade filters.
"""

import re

CATEGORY = "structure"

_ZERO_WIDTH_CHARS = "​‌‍﻿"


def analyze_structure(email: dict) -> list:
    signals = []
    html = email.get("html", "") or ""
    lower_html = html.lower()

    has_form = "<form" in lower_html
    has_password_input = bool(re.search(r"<input[^>]*type=['\"]password['\"]", lower_html))

    if has_form and has_password_input:
        signals.append({
            "code": "embedded_credential_form",
            "category": CATEGORY,
            "reason": "HTML contains a form with a password field, typical of credential harvesting pages",
            "points": 25,
        })

    if re.search(r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b)", lower_html):
        signals.append({
            "code": "hidden_content",
            "category": CATEGORY,
            "reason": "HTML contains content hidden via CSS (display:none / visibility:hidden / opacity:0)",
            "points": 12,
        })

    if any(ch in html for ch in _ZERO_WIDTH_CHARS):
        signals.append({
            "code": "zero_width_chars",
            "category": CATEGORY,
            "reason": "HTML/body contains zero-width characters, often used to evade text-based filters",
            "points": 10,
        })

    if "http-equiv" in lower_html and "refresh" in lower_html:
        signals.append({
            "code": "suspicious_meta_refresh",
            "category": CATEGORY,
            "reason": "HTML uses a meta-refresh redirect",
            "points": 10,
        })

    return signals
