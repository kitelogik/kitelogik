# SPDX-License-Identifier: Apache-2.0
import re
import unicodedata

from .models import SanitizedResponse

# Unicode characters that adversaries may use to bypass \s+ matching.
# Includes zero-width spaces, non-breaking spaces, and other invisible separators.
_UNICODE_WHITESPACE = re.compile(
    "[\u00a0\u200b\u200c\u200d\u2028\u2029\ufeff\u2060\u180e\u202f\u205f\u3000]"
)


def _normalize_for_scan(text: str) -> str:
    """
    Normalise text before injection scanning.

    Converts confusable unicode to ASCII equivalents (NFKC) and replaces
    invisible unicode whitespace/joiners with regular spaces so that
    patterns like ``ignore\\s+previous\\s+instructions`` cannot be bypassed
    with zero-width characters.
    """
    # NFKC normalisation maps full-width and other confusable characters
    # to their standard equivalents (e.g. fullwidth 'A' → 'A').
    text = unicodedata.normalize("NFKC", text)
    # Replace invisible whitespace variants with regular spaces.
    text = _UNICODE_WHITESPACE.sub(" ", text)
    return text


# Ordered list of (regex_pattern, label) pairs.
# Patterns are case-insensitive and anchored to detect injection attempts
# embedded anywhere in tool output content.
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "ignore_previous_instructions"),
    (r"disregard\s+(your\s+)?(previous\s+)?instructions?", "disregard_instructions"),
    # "you are now" followed by something that strips restrictions
    (
        r"you\s+are\s+now\s+(an?\s+)?(?:unrestricted|unfiltered|jailbroken)",
        "you_are_now_unrestricted",
    ),
    (r"new\s+instructions?\s*:", "new_instructions"),
    (r"\[SYSTEM\]", "system_marker"),
    (r"<\s*/?instructions?\s*>", "instructions_tag"),
    (
        r"override\s+(all\s+)?(?:safety|security|policy)\s+(?:rules?|constraints?|measures?)",
        "policy_override",
    ),
    (r"act\s+as\s+if\s+you\s+(?:have\s+no|are\s+without)\s+restrictions?", "act_as_unrestricted"),
    (
        r"(?:print|show|output|reveal|display)\s+(your\s+)?(system\s+)?(?:prompt|instructions?)",
        "prompt_extraction",
    ),
    (
        r"forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions?|training|guidelines?)",
        "forget_instructions",
    ),
]

_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, re.IGNORECASE), label) for pattern, label in _INJECTION_PATTERNS
]


def sanitize_tool_output(content: str) -> SanitizedResponse:
    """Scan tool output for embedded prompt injection payloads and redact them.

    Primary defence against indirect prompt injection — malicious
    instructions embedded in data the agent reads (web pages, documents,
    database records, MCP server responses).

    Parameters
    ----------
    content : str
            Raw tool output to scan.

    Returns
    -------
    SanitizedResponse
            Sanitized content with modification flag and matched patterns.
    """
    if not content:
        return SanitizedResponse(content=content, was_modified=False)

    # Normalise to defeat unicode whitespace / confusable-character bypasses.
    modified = _normalize_for_scan(content)
    patterns_found: list[str] = []

    for compiled_pattern, label in _COMPILED:
        if compiled_pattern.search(modified):
            patterns_found.append(label)
            modified = compiled_pattern.sub("[REDACTED]", modified)

    return SanitizedResponse(
        content=modified,
        was_modified=bool(patterns_found),
        injection_patterns_found=patterns_found,
    )
