from __future__ import annotations

from typing import Any
from urllib.parse import quote_from_bytes


def render_sarif(run: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    results = []
    levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
    }
    for finding in findings:
        loc = finding["location"]
        original = loc.get("original_path", loc["path"])
        uri = quote_from_bytes(original.encode("utf-8", "surrogateescape"), safe="/")
        results.append(
            {
                "ruleId": finding["sources"][0].get("rule_id", finding["category"]),
                "level": levels[finding["severity"]],
                "message": {"text": finding["title"]},
                "partialFingerprints": {"hck/v1": finding["fingerprint"]},
                "properties": {"status": finding["status"], "confidence": finding["confidence"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": loc.get("start_line", 1)},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Hacker Code Konvert", "version": "0.2.0"}},
                "invocations": [{"executionSuccessful": bool(run["complete"])}],
                "results": results,
            }
        ],
    }
