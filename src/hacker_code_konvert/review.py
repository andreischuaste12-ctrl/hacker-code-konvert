"""Offline SSH signature verification; trust roots always come from the operator."""

from __future__ import annotations

import subprocess
from pathlib import Path


def verify_review(document: Path | bytes, signature: Path, allowed_signers: Path, identity: str) -> None:
    """Verify the review signature over the exact bytes the caller goes on to use."""
    if not identity or identity.startswith("-"):
        raise ValueError("An explicit trusted reviewer identity is required")
    data = document if isinstance(document, bytes) else document.read_bytes()
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
        input=data,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    if result.returncode:
        raise ValueError("Review signature is invalid or reviewer is not trusted")
