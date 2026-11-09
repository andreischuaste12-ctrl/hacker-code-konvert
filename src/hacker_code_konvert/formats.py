"""Offline dependency input selection shared by capture and adapter."""

from pathlib import Path

LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "go.mod",
    "composer.lock",
    "Gemfile.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "pom.xml",
    "gradle.lockfile",
}


def dependency_file(name: str) -> bool:
    name = Path(name).name
    return name in LOCKFILES or (name.startswith("requirements") and name.endswith(".txt"))
