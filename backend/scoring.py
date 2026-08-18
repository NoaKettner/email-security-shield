"""
Scoring Module.

Analyzers only produce *evidence* (signals). This module decides how
much that evidence matters, and turns it into the three things a user
actually needs:

    signals -> category scores -> category caps -> base score
            -> combo rules -> risk floors -> final score
            -> verdict -> recommendation

- Category caps stop one noisy category (e.g. several weak content
  signals) from dominating the score on its own.
- Combo rules recognize that certain signals reinforce each other far
  more than their raw points would suggest, because together they
  describe one coherent attack scenario.
- Risk floors guarantee a minimum score for attack patterns that are,
  on their own, essentially unambiguous.
- The recommendation is derived from the verdict *and* which specific
  signals fired, so "High Risk because of a malicious attachment"
  reads differently from "High Risk because of a spoofed sender".

None of these numbers are final - they're starting points meant to be
tuned by running the full sample set and inspecting the results.
"""

CATEGORY_CAPS = {
    "identity": 35,
    "authentication": 20,
    "links": 30,
    "content": 15,
    "attachments": 25,
    # 25, not 20: must be >= the strongest single signal in the category
    # (embedded_credential_form = 25) or that signal gets silently
    # discounted even when it fires alone, with nothing to cap against.
    "structure": 25,
}

# Highest threshold that the score meets or exceeds wins. Three levels by
# design, kept deliberately simple: a low bar for "worth a second look"
# (Suspicious) and a higher bar for "acted-on-together, essentially
# unambiguous" (High Risk) - reached mainly via the combo rules and risk
# floors below, not by any single signal's raw points.
VERDICT_THRESHOLDS = [
    (55, "High Risk"),
    (25, "Suspicious"),
    (0, "Low Risk"),
]

# (name, {signal codes that must ALL be present}, bonus points)
# Each rule captures signals from different analyzers that together
# describe one attack scenario more convincingly than either does alone.
COMBO_RULES = [
    (
        "brand_impersonation_with_credential_request",
        {"lookalike_domain", "credential_request"},
        12,
    ),
    (
        "brand_impersonation_with_link_mismatch",
        {"lookalike_domain", "link_domain_mismatch"},
        12,
    ),
    (
        "payment_request_with_malicious_attachment",
        {"payment_request", "executable_attachment"},
        18,
    ),
    (
        "auth_failure_with_identity_mismatch",
        {"multiple_authentication_failures", "sender_reply_to_mismatch"},
        15,
    ),
    (
        "credential_form_with_credential_request",
        {"embedded_credential_form", "credential_request"},
        10,
    ),
]

# (name, {signal codes that must ALL be present}, minimum final score)
# Only used for combinations with a clear security rationale - patterns
# that are, together, essentially unambiguous.
RISK_FLOORS = [
    (
        "brand_impersonation_credential_link_triad",
        {"lookalike_domain", "credential_request", "link_domain_mismatch"},
        90,
    ),
]

# Signal codes that make a recommendation more specific/urgent than the
# verdict tier alone would suggest. Grouped by the concrete action a
# user should take (or avoid) when they're present.
_ATTACHMENT_DANGER_CODES = {"executable_attachment", "double_extension", "macro_enabled_office"}
_LINK_DANGER_CODES = {"link_domain_mismatch", "ip_address_link", "url_shortener"}
_CREDENTIAL_DANGER_CODES = {"embedded_credential_form", "credential_request"}
_IDENTITY_DANGER_CODES = {"lookalike_domain", "sender_reply_to_mismatch", "display_name_brand_mismatch"}


def _category_scores(signals: list) -> dict:
    raw = {}
    for signal in signals:
        category = signal["category"]
        raw[category] = raw.get(category, 0) + signal["points"]
    return raw


def _apply_caps(raw_scores: dict) -> dict:
    return {
        category: min(score, CATEGORY_CAPS.get(category, score))
        for category, score in raw_scores.items()
    }


def _verdict_for(score: int) -> str:
    for threshold, label in VERDICT_THRESHOLDS:
        if score >= threshold:
            return label
    return VERDICT_THRESHOLDS[-1][1]


def _recommendation_for(verdict: str, codes: set) -> str:
    """Turn a verdict + the specific signals behind it into one clear,
    actionable instruction. The verdict tier picks the overall posture;
    which signal codes fired sharpens the wording so the advice matches
    the actual risk (a bad attachment gets different advice than a
    spoofed sender with no attachment)."""
    has_attachment_danger = bool(codes & _ATTACHMENT_DANGER_CODES)
    has_link_danger = bool(codes & _LINK_DANGER_CODES)
    has_credential_danger = bool(codes & _CREDENTIAL_DANGER_CODES)
    has_identity_danger = bool(codes & _IDENTITY_DANGER_CODES)

    if verdict == "High Risk":
        actions = []
        if has_link_danger or has_credential_danger:
            actions.append("do not click any links or enter credentials")
        if has_attachment_danger:
            actions.append("do not open any attachments")
        if not actions:
            actions.append("do not click links or open attachments")
        instruction = "Do not interact with this email: " + ", ".join(actions) + "."
        return instruction + " Report the email as phishing."

    if verdict == "Suspicious":
        parts = ["Verify the sender through another channel (phone, known contact, etc.) before taking any action."]
        if has_credential_danger or has_link_danger:
            parts.append("Avoid clicking links or entering credentials until the sender is confirmed.")
        if has_attachment_danger:
            parts.append("Avoid opening attachments until the sender is confirmed.")
        if has_identity_danger:
            parts.append("Do not reply directly - the Reply-To or sending domain does not match who this claims to be from.")
        return " ".join(parts)

    return "No significant threats detected. Safe to proceed normally."


def calculate_risk(signals: list) -> dict:
    codes = {s["code"] for s in signals}

    raw_scores = _category_scores(signals)
    capped_scores = _apply_caps(raw_scores)
    base_score = sum(capped_scores.values())

    score = base_score
    applied_combos = []
    for name, required_codes, bonus in COMBO_RULES:
        if required_codes.issubset(codes):
            score += bonus
            applied_combos.append({"name": name, "bonus": bonus})

    applied_floors = []
    for name, required_codes, minimum in RISK_FLOORS:
        if required_codes.issubset(codes) and score < minimum:
            applied_floors.append({"name": name, "minimum": minimum, "raised_from": score})
            score = minimum

    final_score = max(0, min(100, score))
    verdict = _verdict_for(final_score)
    recommendation = _recommendation_for(verdict, codes)

    return {
        "score": final_score,
        "verdict": verdict,
        "recommendation": recommendation,
        "base_score": base_score,
        "category_raw_scores": raw_scores,
        "category_capped_scores": capped_scores,
        "combo_rules_applied": applied_combos,
        "risk_floors_applied": applied_floors,
        "signals": signals,
    }
