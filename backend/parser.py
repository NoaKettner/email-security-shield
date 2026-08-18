"""
parser.py
=========

Responsibility: normalize the raw Gmail-shaped JSON into a
predictable internal structure - fill in defaults for any field
that's missing, so every analyzer downstream can trust the shape of
what it receives instead of guessing.

    Raw JSON
       |
       v
    Normalized email data

This module does NOT perform any phishing detection or scoring, and
it does not flatten nested fields (e.g. "sender") - analyzers each
pull out what they need from the structure below.
"""


def parse_email(data):
    """
    Normalize the raw email JSON, applying safe defaults for any
    optional field that's missing.

    Args:
        data: dict loaded from JSON, shaped like:
            {
                "sender": {"name": str, "email": str, "reply_to": str?},
                "subject": str,
                "body": str,          # plain-text body
                "html": str,          # raw HTML body (optional)
                "links": [{"text": str, "url": str}],
                "authentication": {"spf": str, "dkim": str, "dmarc": str},
                "attachments": [{"filename": str, "mime_type": str}]
            }

    Returns:
        dict with the same shape, with every optional field defaulted
        so downstream code never has to guard against a KeyError.
    """
    return {
        "sender": data.get("sender", {}),
        "subject": data.get("subject", ""),
        "body": data.get("body", ""),
        "html": data.get("html", ""),
        "links": data.get("links", []),
        "authentication": data.get("authentication", {}),
        "attachments": data.get("attachments", []),
    }
