"""Offline SSH signature verification; trust roots always come from the operator."""

from __future__ import annotations

import subprocess
from pathlib import Path


def verify_review(document: Path, signature: Path, allowed_signers: Path, identity: str) -> None:
    if not identity or identity.startswith("-"):
        raise ValueError("An explicit trusted reviewer identity is required")
    with document.open("rb") as stream:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers.resolve()),
                "-I",
                identity,
                "-n",
                "hck-review",
                "-s",
                str(signature.resolve()),
            ],
            stdin=stream,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    if result.returncode:
        raise ValueError("Review signature is invalid or reviewer is not trusted")
