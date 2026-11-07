from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"

# Redaction runs over scanner output that the analyzed repository can influence. Every pattern
# therefore uses bounded (and where possible possessive) quantifiers, and a single call never
# processes more than MAX_REDACTION_CHARS, so hostile input cannot trigger catastrophic backtracking.
MAX_REDACTION_CHARS = 32_768

_SENSITIVE_KEY = r"(?:api[_-]?key|secret|token|passwd|password|pwd|credential|private[_-]?key)"

# Patterns with capture groups keep the leading context (such as the key name) and redact the rest.
_PATTERNS = (
    re.compile(
        r"(?is)(-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----).{0,16384}?"
        r"(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)"
    ),
    re.compile(
        r"(?i)(authorization[\"']?\s{0,8}:\s{0,8}[\"']?(?:bearer|basic|token)\s{1,8})[A-Za-z0-9._~+/=-]{1,2048}+"
    ),
    re.compile(r"(?i)(\bbearer\s{1,8})[A-Za-z0-9._~+/=-]{8,2048}+"),
    re.compile(
        rf"(?i)({_SENSITIVE_KEY}[\w.-]{{0,32}}+[\"']?\s{{0,8}}[:=]\s{{0,8}}[\"']?)[^\s\"',;}}\]]{{1,2048}}+"
    ),
    re.compile(r"(?i)(\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@\"']{1,256}+:)[^\s@/\"']{1,256}+(@)"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}+\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}+\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,255}+\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,255}+\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,255}+\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,2048}+\.[A-Za-z0-9_-]{10,2048}+\.[A-Za-z0-9_-]{5,2048}+\b"),
)


def redact_text(value: str) -> str:
    """Best-effort redaction of common credential shapes.

    This is a safety net, not a guarantee: callers must not rely on it to make arbitrary
    untrusted text safe to publish. Input beyond ``MAX_REDACTION_CHARS`` is truncated and marked.
    """
    result = value
    if len(result) > MAX_REDACTION_CHARS:
        result = f"{result[:MAX_REDACTION_CHARS]} {TRUNCATED}"
    for pattern in _PATTERNS:
        if pattern.groups == 1:
            result = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", result)
        elif pattern.groups == 2:
            result = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}{match.group(2)}", result)
        else:
            result = pattern.sub(REDACTED, result)
    return result


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    return value
