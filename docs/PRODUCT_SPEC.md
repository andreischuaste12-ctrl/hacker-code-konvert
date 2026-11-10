# MVP Product Specification

## Product Shape

Hacker Code Konvert has two connected surfaces:

1. A skill that defines authorization, triage, validation, and disclosure behavior.
2. A local CLI that inventories repositories, invokes approved scanners, validates normalized findings, and writes reproducible reports.

The CLI is the enforcement layer for the MVP. Prose in `SKILL.md` does not replace operating-system isolation or executable validation.

## Supported Capability

| Capability | Input | Output | Current limits |
| --- | --- | --- | --- |
| Repository inventory | Explicit local directory and authorization confirmation | Relative file inventory, languages, manifests, skipped entries, and limitations | Maximum 10,000 files by default; symlinks and nested repositories are not traversed |
| Python and PHP SAST | Source files selected by suffix, interpreter line or leading PHP tag, staged from the authorized root | Semgrep candidates normalized to the finding contract, with a coverage check | 19 Python and 14 PHP/WordPress rules; candidates are never automatically validated |
| Dependency advisories | Lockfiles and pinned `requirements*.txt`, with an operator-prepared offline database | OSV candidates naming the package, locked version, advisory and fixed version | Per-file coverage; unpinned or unparsable files are coverage gaps |
| Secret detection | Every captured regular file | Gitleaks candidates with the value redacted | Per-file coverage is not reported by the scanner; a canary proves the rules ran |
| Finding validation | JSON finding list | Pass or explicit contract error | Semantic cross-field rules are enforced in Python; JSON Schema is published for interoperability |
| Reporting | Completed or incomplete run | `run.json`, `findings.json`, `report.md`, and `results.sarif` | Markdown, normalized JSON and SARIF 2.1.0 |

## Analysis Mode

The MVP performs local, static analysis. It does not send requests to an analyzed application, execute target code, initialize submodules, download Git LFS objects, run Git filters, or install target dependencies.

The CLI requires `--authorized`. This records the operator's confirmation; it does not independently prove legal authorization.

## Supported Environment

- Python 3.12 or 3.13
- Linux for Semgrep execution
- Bubblewrap with usable user and network namespaces
- Semgrep 1.184.0 for the optional Python SAST profile
- A 4 GiB default address-space limit for the isolated Semgrep process

Inventory and JSON validation remain available without Semgrep. The Semgrep run fails closed when Bubblewrap isolation is unavailable.

## Confirmed Finding Definition

A scanner result is a `candidate`. It becomes `validated` only after Gates 1 through 8 pass, risk and remediation are assessed, and Gate 9 records independent human review. The CLI does not perform that human decision automatically.

## Explicitly Prohibited Without Separate Authorization

- Requests to deployed targets
- Fuzzing, exploitation, persistence, denial of service, or destructive testing
- Executing code from the target repository
- External disclosure or maintainer contact
- Uploading source code or findings to an AI or hosted analysis service
- Autonomous patch publication

## Exit Status

| Code | Meaning |
| --- | --- |
| `0` | Requested checks completed; findings may still be candidates |
| `2` | Invalid input, missing authorization, or scope failure |
| `3` | A selected scanner was unavailable, failed, timed out, exceeded limits, returned invalid output, had nothing to analyze, or coverage was not demonstrated for everything in scope (`partial_coverage`) |

An exit code of `0` never means that the repository is secure.

## Scanner Modes

`hck scan` runs the isolated Semgrep profile by default. `--scanner inventory` lists and counts files only: the report and `run.json` state `vulnerability_scan_performed: false`, and the absence of findings has no meaning in that mode.

## Supported Scanner Installations

A scanner must be installed under `/usr`, in its own directory under `/opt`, in a Python installation prefix, or inside a Python virtual environment, so the sandbox can mount the runtime without exposing unrelated directories (for example `pip install --user` into a home directory is rejected). The sandbox needs about 4 GiB of address space for `semgrep-core`; lower `--memory-mb` values make Semgrep fail.
