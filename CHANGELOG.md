# Changelog

All notable project changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use semantic versioning.

## [Unreleased]

### Security: follow-up to the audit of dccd0b2

- Gitleaks no longer honors inline `gitleaks:allow` comments from the analyzed repository.
- A directory containing `.git` makes the run incomplete instead of being skipped with a complete run.
- A Git LFS pointer is recognized only by its complete grammar; a file that imitates one is analyzed.
- Source files are selected by suffix (`.pyw`, `.phtml`, `.inc`, `.php5` and others), by interpreter
  line, or by a leading PHP tag, and are staged under the canonical suffix of their language.
- A Semgrep run with no supported source file is incomplete; unsupported languages are named.
- The sandbox root and `/dev` are read-only, every writable tmpfs has a size cap, host account files
  and `/opt` are no longer mounted, and a per-sandbox process limit applies for non-root users.
- The seccomp filter allows only `AF_UNIX` sockets and can no longer be bypassed through upper
  register bits; denied names unknown to the installed libseccomp are reported.
- `false_positive` requires a recorded review and, in the CLI, a trusted signature. The findings
  document is read once for validation, signature verification and the disclosure draft.

### Changed

- OSV-Scanner: per-file coverage. Oversized, unpinned or unparsable dependency files are coverage gaps
  and no longer fail the whole run; dependency files default to a 32 MiB limit. Findings name the
  package, locked version, advisory aliases and fixed versions.
- Gitleaks: a tool-owned canary credential proves the rules ran; per-file coverage is reported as
  unknown instead of being asserted.
- Rule pack extended from 15 to 33 rules (19 Python, 14 PHP/WordPress) and renamed to
  `semgrep-rules.yml`. `hck.php.wpdb-injection` is now `hck.php.sql-injection`.
- One capture implementation replaces the separate inventory used by tests.
- `scripts/evaluate_fixture_quality.py` supports line-level expectations and documented known gaps;
  CI measures a third corpus written before the rules were extended.
- Report coverage lines state what each scanner measured; `run.json` gains `scanner.files_submitted`
  and `scanner.coverage`.

### Compatibility

- Exit status `3` is now returned for repositories with nested repositories or submodules and for
  Semgrep runs without Python or PHP sources.
- Finding identifiers of dependency findings include the package, so they differ from earlier runs.

### Security audit follow-up

- Extend pinned Gitleaks vendor rules and retain neutral-file extensions; seven-format synthetic corpus.
- Verify offline OSV database hashes/freshness and accept fixed Python requirements and more manifests.
- Use iterative, scanner-specific capture with depth and total-byte limits and incomplete coverage markers.
- Disable nested user namespaces and deny modern mount, io_uring, VSOCK and namespace escape interfaces.
- Separate read-only release builds from privileged attestation/publication; fix single-maintainer ruleset.
- Expand taint sources/sinks, exempt nonsecurity hashes, preserve printable Unicode paths and enrich SARIF.
- Declare ssh-keygen as a tested prerequisite and install openssh-client in CI.

## [0.2.0] - 2026-11-09

### Added

- Twelve original Python rules and three WordPress/PHP candidate patterns with positive and negative fixtures.
- Neutral staging names, original filename byte preservation, rule hashes and selected input hashes.
- Seccomp filters, restricted /etc mounts, root-user notice and descriptor-relative staging.
- Directory-only Gitleaks and offline lockfile-only OSV adapters with verified binary installation.
- SARIF 2.1.0 output tested against the OASIS schema.
- Scope records, SSH-signed review validation and private local disclosure drafts.
- Strict mypy, property tests, 95% branch-coverage gate and Python 3.12/3.13 CI.
- Separate hash-pinned development/scanner locks, CodeQL and Scorecard workflows.
- Manual release pipeline with signed-tag verification, provenance, SBOM and PyPI OIDC.

### Release prerequisites

Versioned package artifacts can be built locally. A signed tag, GitHub release and PyPI publication still
require maintainer signing and administrative configuration; a version entry alone is not publication.


### Security

- A run no longer reports itself complete when Semgrep silently skipped files. Semgrep's built-in default
  ignores (for example `tests/` and `test/`) are disabled with a tool-owned empty `.semgrepignore`, and the
  adapter compares the files the scanner analyzed with the files the inventory selected. Skipped files,
  scanner errors (such as partial parsing), and missing coverage data produce status `partial_coverage`,
  `complete: false`, and exit status `3`.
- The commit id is read from the analyzed repository's `.git` directory defensively: only a 40-character
  hexadecimal id is accepted, symlinks are never followed, reads are bounded, and references cannot leave
  `.git`. Previously a crafted `.git/HEAD` could copy 40 characters of an arbitrary file into `run.json` or
  exhaust memory (for example through a symlink to `/dev/zero`).
- The sandbox drops all capabilities (including when the CLI runs as root) and mounts only the scanner's
  virtual environment instead of the directory above the executable. Unsupported installation layouts fail
  closed.
- The host-side `semgrep --version` probe runs with the version check disabled and outside the repository
  directory. It previously hung without network access and left the version unrecorded.
- Redaction covers JSON and YAML quoted values, AWS secret keys, fine-grained GitHub tokens, Stripe, Slack and
  Google keys, JWTs, private keys, and credentials in URLs. Its patterns are bounded and its input is capped so
  hostile scanner output cannot cause catastrophic backtracking.
- Control, bidirectional, and separator characters are removed from reports and terminal output and rejected in
  finding paths.
- Files are staged from an open descriptor with `O_NOFOLLOW`, closing most path-swap races.
- Dependency lock now carries hashes and is installed with `--require-hashes`. `pytest` is upgraded to 9.0.3
  (CVE-2025-71176). Advisories in packages pinned by Semgrep are documented in `docs/DEPENDENCIES.md`.

### Changed

- **Breaking:** `hck scan` runs Semgrep by default. `--scanner inventory` must be requested explicitly and its
  report states that no vulnerability scan was performed (`vulnerability_scan_performed: false`).
- `--output` must be new, empty, or contain only a previous run's artifacts; the CLI no longer changes the
  permissions of, or overwrites files in, a directory it did not create. `run.json` is written last.
- The recorded scanner command is generated from the arguments that are actually executed.
- `run.json` `controls` describe the isolation that was started rather than fixed text.
- `SKILL.md` requires running the CLI, forbids direct scanner use against the target, documents data handling
  by AI agents, and declares `allowed-tools`.

### Fixed

- Unreadable Python files are reported as skipped; staging failures produce an incomplete run instead of a
  traceback with no report.
- Dependabot no longer proposes updates that Semgrep's pins make unresolvable.
- The sandbox preflight (`bubblewrap_supported`) mounted only `/usr`, so on systems with a merged `/usr` it
  could not start any dynamically linked binary and always reported the sandbox as unsupported. The
  integration tests that depend on it were therefore skipped. It now mounts the same system directories as the
  scanner run, and CI sets `HCK_REQUIRE_INTEGRATION=1` so a missing prerequisite fails instead of skipping. The
  Semgrep integration test now uses the documented 4 GiB limit; the previous 1 GiB made Semgrep crash.
- JSON Schemas now express the human-review invariants for `validated` and `accepted_risk` findings, and CI
  validates real output against them.

## [0.1.0] - 2026-11-06

### Added

- Initial end-to-end MVP for local Python repository analysis.
- Local Python CLI for authorized repository inventory and reporting.
- Optional Semgrep 1.184.0 adapter with bundled Python rules.
- Bubblewrap scanner isolation with network disabled and bounded resources.
- Executable finding validation and JSON schemas.
- Synthetic fixtures for prompt injection, scanner suppression, safe code, redaction, path escape, timeout, and malformed output.
- CI, dependency updates, fixture quality metrics, CODEOWNERS, and reproducibility metadata.
