from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:api[_-]?key|secret|token|password)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def redact_text(value: str) -> str:
    result = value
    for pattern in _PATTERNS:
        if pattern.groups:
            result = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", result)
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
