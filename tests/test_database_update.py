from __future__ import annotations

import hashlib
import io
import json
import runpy
import sys
from pathlib import Path

import pytest


def test_database_update_is_explicit_and_records_provenance(tmp_path: Path, monkeypatch):
    data = b"PK synthetic offline archive"
    requested = []

    def download(url, timeout):
        requested.append(url)
        return io.BytesIO(data)

    monkeypatch.setattr("urllib.request.urlopen", download)
    monkeypatch.setattr(
        sys, "argv", ["update_osv_database.py", "--ecosystem", "npm", "--output", str(tmp_path)]
    )
    runpy.run_path("scripts/update_osv_database.py", run_name="__main__")
    archive = tmp_path / "osv-scalibr/npm/all.zip"
    provenance = json.loads(archive.with_name("provenance.json").read_text())
    assert archive.read_bytes() == data
    assert provenance["sha256"] == hashlib.sha256(data).hexdigest()
    assert requested == ["https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"]


def test_failed_database_update_keeps_previous_archive(tmp_path: Path, monkeypatch):
    root = tmp_path / "osv-scalibr/npm"
    root.mkdir(parents=True)
    (root / "all.zip").write_bytes(b"previous trusted archive")

    def unavailable(*args, **kwargs):
        raise OSError("synthetic network failure")

    monkeypatch.setattr("urllib.request.urlopen", unavailable)
    monkeypatch.setattr(
        sys, "argv", ["update_osv_database.py", "--ecosystem", "npm", "--output", str(tmp_path)]
    )
    with pytest.raises(OSError):
        runpy.run_path("scripts/update_osv_database.py", run_name="__main__")
    assert (root / "all.zip").read_bytes() == b"previous trusted archive"
    assert list(root.iterdir()) == [root / "all.zip"]
