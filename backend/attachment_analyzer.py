"""
Attachment Analyzer.

Inspects attachment *metadata only* (filename, MIME type) - nothing
is opened or executed. Looks for classic malware-delivery patterns:
double extensions, executables, macro-enabled Office files, and
filename/MIME mismatches.
"""

import re

CATEGORY = "attachments"

_EXECUTABLE_EXTS = {"exe", "scr", "bat", "cmd", "com", "js", "vbs", "jar", "msi", "ps1"}
_MACRO_EXTS = {"docm", "xlsm", "pptm"}
_ARCHIVE_EXTS = {"zip", "rar", "7z"}

_DOUBLE_EXTENSION_RE = re.compile(
    r"\.[a-z0-9]{2,5}\.(" + "|".join(_EXECUTABLE_EXTS) + r")$", re.IGNORECASE
)


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def analyze_attachments(email: dict) -> list:
    signals = []
    attachments = email.get("attachments", []) or []

    double_ext_files = []
    executable_files = []
    macro_files = []
    archive_files = []
    mime_mismatch_files = []

    for att in attachments:
        filename = att.get("filename", "") or ""
        mime_type = (att.get("mime_type") or "").lower()
        ext = _extension(filename)

        if _DOUBLE_EXTENSION_RE.search(filename):
            double_ext_files.append(filename)

        if ext in _EXECUTABLE_EXTS:
            executable_files.append(filename)

        if ext in _MACRO_EXTS:
            macro_files.append(filename)

        if ext in _ARCHIVE_EXTS:
            archive_files.append(filename)

        if ext == "pdf" and mime_type and mime_type != "application/pdf":
            mime_mismatch_files.append(filename)

    if double_ext_files:
        signals.append({
            "code": "double_extension",
            "category": CATEGORY,
            "reason": f"Attachment filename hides an executable behind a second extension: {', '.join(double_ext_files)}",
            "points": 25,
        })

    if executable_files:
        signals.append({
            "code": "executable_attachment",
            "category": CATEGORY,
            "reason": f"Executable attachment(s): {', '.join(executable_files)}",
            "points": 20,
        })

    if macro_files:
        signals.append({
            "code": "macro_enabled_office",
            "category": CATEGORY,
            "reason": f"Macro-enabled Office attachment(s): {', '.join(macro_files)}",
            "points": 15,
        })

    if archive_files:
        signals.append({
            "code": "archive_attachment",
            "category": CATEGORY,
            "reason": f"Archive attachment(s) that could conceal malicious content: {', '.join(archive_files)}",
            "points": 8,
        })

    if mime_mismatch_files:
        signals.append({
            "code": "mime_mismatch",
            "category": CATEGORY,
            "reason": f"Attachment extension does not match its declared MIME type: {', '.join(mime_mismatch_files)}",
            "points": 10,
        })

    return signals
