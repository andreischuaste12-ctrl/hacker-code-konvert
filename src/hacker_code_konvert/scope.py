from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hacker_code_konvert.inventory import ScopeError


def load_scope(path: Path, root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > 65536:
        raise ScopeError("Authorization file exceeds 64 KiB")
    try:
        scope = json.loads(data)
        for key in ("repository", "responsible", "authorization_reference", "valid_from", "valid_until"):
            if not isinstance(scope[key], str) or not scope[key].strip():
                raise ValueError(f"Missing {key}")
        if Path(scope["repository"]).resolve() != root:
            raise ValueError("Authorization repository does not match selected root")
        begin = datetime.fromisoformat(scope["valid_from"])
        end = datetime.fromisoformat(scope["valid_until"])
        if begin.tzinfo is None or end.tzinfo is None or not begin <= datetime.now(UTC) <= end:
            raise ValueError("Authorization window is inactive or lacks a timezone")
    except (KeyError, TypeError, ValueError) as error:
        raise ScopeError(f"Invalid authorization: {error}") from error
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "responsible": scope["responsible"],
        "authorization_reference": scope["authorization_reference"],
        "valid_until": scope["valid_until"],
        "verification": "record and validity checked; legal authenticity requires human confirmation",
    }
