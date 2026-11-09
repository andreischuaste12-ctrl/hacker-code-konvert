"""Explicit online database preparation. Never invoked by the analyzer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ecosystem", choices=["npm", "PyPI", "Go", "Maven", "Packagist", "RubyGems"], required=True
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    destination = Path(args.output).resolve() / "osv-scalibr" / args.ecosystem
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{quote(args.ecosystem)}/all.zip"
    descriptor, name = tempfile.mkstemp(dir=destination, prefix=".database-")
    temporary = Path(name)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(url, timeout=120) as response:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 4 * 1024**3:
                    raise ValueError("Database exceeds the explicit 4 GiB download limit")
                digest.update(chunk)
                output.write(chunk)
        temporary.replace(destination / "all.zip")
        provenance = {
            "source": url,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "sha256": digest.hexdigest(),
            "bytes": size,
            "transport": "HTTPS certificate verification enabled",
        }
        (destination / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
