from __future__ import annotations

import hashlib
import re
from importlib.resources import files
from typing import Any

from hacker_code_konvert.textsafety import has_unsafe_characters


def rules_metadata(scanner: str = "semgrep") -> dict[str, Any]:
    if scanner == "osv-scanner":
        return {"ids": [], "count": 0, "sha256": None, "kind": "offline advisory database"}
    filename = "gitleaks.toml" if scanner == "gitleaks" else "python-security.yml"
    data = files("hacker_code_konvert").joinpath(f"data/{filename}").read_bytes()
    pattern = r'^id = "(.+)"$' if scanner == "gitleaks" else r"^  - id: (.+)$"
    ids = re.findall(pattern, data.decode(), re.MULTILINE)
    return {
        "ids": ids,
        "count": None if scanner == "gitleaks" else len(ids),
        "custom_count": len(ids),
        "extends_vendor_defaults": scanner == "gitleaks",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def translate_paths(findings: list[dict[str, Any]], mapping: dict[str, str]) -> None:
    for finding in findings:
        location = finding["location"]
        neutral = location["path"]
        if neutral not in mapping:
            raise ValueError("Scanner returned a path outside the staged mapping")
        original = mapping[neutral]
        # Stable neutral path satisfies the portable finding contract. Original Linux bytes are
        # preserved as hex and as ASCII escapes, including surrogateescaped invalid UTF-8.
        location["staged_path"] = neutral
        location["original_path"] = original
        location["original_path_bytes_hex"] = original.encode("utf-8", "surrogateescape").hex()
        location["display_path"] = (
            original
            if original.isprintable() and not has_unsafe_characters(original)
            else ascii(original)[1:-1]
        )
        if (
            original.isprintable()
            and "\\" not in original
            and not has_unsafe_characters(original)
            and not re.match(r"^[A-Za-z]:", original)
        ):
            location["path"] = original
        digest = hashlib.sha256(
            f"{finding['sources'][0]['rule_id']}\0{location['original_path_bytes_hex']}\0"
            f"{location['start_line']}\0{location['end_line']}".encode()
        ).hexdigest()
        finding["fingerprint"] = f"sha256:{digest}"
        finding["id"] = f"HCK-{digest[:12].upper()}"
