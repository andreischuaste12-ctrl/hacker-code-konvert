"""Offline database identity and freshness, checked before scanner execution."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def database_metadata(root: Path, max_age_days: int = 30) -> tuple[dict[str, Any], list[str]]:
    archives = sorted(root.rglob("all.zip"))
    if not archives:
        raise ValueError("Offline database contains no ecosystem archives")
    entries = []
    warnings = []
    for archive in archives:
        if archive.is_symlink():
            raise ValueError("Offline database archive must not be a symbolic link")
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        checksum = digest.hexdigest()
        entry: dict[str, Any] = {"path": archive.relative_to(root).as_posix(), "sha256": checksum}
        record = archive.with_name("provenance.json")
        if record.exists():
            if record.stat().st_size > 65536:
                raise ValueError("Database provenance is oversized")
            provenance = json.loads(record.read_text())
            if provenance.get("sha256") != checksum:
                raise ValueError("Offline database digest does not match provenance")
            retrieved = datetime.fromisoformat(provenance["retrieved_at"])
            if retrieved.tzinfo is None:
                raise ValueError("Database provenance timestamp requires timezone")
            age = (datetime.now(UTC) - retrieved).total_seconds() / 86400
            if age < 0:
                raise ValueError("Database provenance timestamp is in the future")
            entry.update(retrieved_at=retrieved.isoformat(), age_days=round(age, 2))
            if age > max_age_days:
                warnings.append(f"Offline database {entry['path']} exceeds {max_age_days} days of age.")
        else:
            warnings.append(f"Offline database {entry['path']} has no provenance; freshness is unknown.")
        entries.append(entry)
    aggregate = hashlib.sha256(
        json.dumps([{"path": e["path"], "sha256": e["sha256"]} for e in entries], sort_keys=True).encode()
    ).hexdigest()
    return {"archives": entries, "manifest_sha256": aggregate}, warnings


def osv_severity(vulnerability: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    # Prefer numeric CVSS scores; calculate standard CVSS 3.x base vectors when supplied by OSV.
    for item in vulnerability.get("severity", []):
        vector = str(item.get("score", ""))
        try:
            if vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
                import math

                metrics = dict(part.split(":") for part in vector.split("/")[1:])
                changed = metrics["S"] == "C"
                av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
                ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
                pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
                ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
                impacts = [{"N": 0, "L": 0.22, "H": 0.56}[metrics[key]] for key in ("C", "I", "A")]
                iss = 1 - (1 - impacts[0]) * (1 - impacts[1]) * (1 - impacts[2])
                impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
                base = (
                    0
                    if impact <= 0
                    else min((1.08 if changed else 1) * (impact + 8.22 * av * ac * pr * ui), 10)
                )
                score = math.ceil(round(base, 10) * 10) / 10
            else:
                score = float(vector)
            if not 0 <= score <= 10:
                continue
            severity = (
                "critical"
                if score >= 9
                else "high"
                if score >= 7
                else "medium"
                if score >= 4
                else "low"
                if score > 0
                else "informational"
            )
            return severity, {"cvss_score": score, "cvss_vector": vector, "severity_assessed": True}
        except (ValueError, KeyError):
            continue
    label = str(vulnerability.get("database_specific", {}).get("severity", "")).lower()
    if label in ("critical", "high", "medium", "low"):
        return label, {"severity_assessed": True, "source": "database_specific"}
    return "informational", {
        "severity_assessed": False,
        "reason": "No supported CVSS score; human assessment required",
    }
