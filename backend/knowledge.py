"""
Knowledge Base.

Static reference data used by the analyzers - known URL-shortening
services (link_analyzer) and known official domains for commonly
impersonated brands (identity_analyzer).

Intentionally a plain data file with no logic, so it's easy to extend
(add a brand, add a shortener) without touching any analyzer code.
This is a starting set, not exhaustive - tune freely.
"""

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "rb.gy",
    "tiny.cc", "lnkd.in", "s.id", "v.gd", "tr.im",
}

# brand keyword (as it would appear in text/domain, lowercase) ->
# set of that brand's known official domains.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "chase": {"chase.com"},
}
