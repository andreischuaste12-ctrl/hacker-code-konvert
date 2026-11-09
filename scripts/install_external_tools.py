"""Explicit online installation step for pinned Linux x86_64 scanners; never run during analysis."""

from __future__ import annotations

import argparse
import hashlib
import io
import platform
import tarfile
import urllib.request
import venv
from pathlib import Path

TOOLS = {
    "gitleaks": (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    "osv-scanner": (
        "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64",
        "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8",
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise SystemExit("Pinned artifacts support Linux x86_64 only")
    root = Path(args.environment).resolve()
    venv.EnvBuilder(with_pip=False).create(root)
    for name, (url, digest) in TOOLS.items():
        with urllib.request.urlopen(url, timeout=120) as response:
            content = response.read(100_000_001)
        if len(content) > 100_000_000 or hashlib.sha256(content).hexdigest() != digest:
            raise SystemExit(f"Artifact verification failed: {name}")
        if name == "gitleaks":
            with tarfile.open(fileobj=io.BytesIO(content)) as archive:
                member = archive.extractfile("gitleaks")
                if member is None:
                    raise SystemExit("Gitleaks binary is missing")
                content = member.read()
        destination = root / "bin" / name
        destination.write_bytes(content)
        destination.chmod(0o755)


if __name__ == "__main__":
    main()
