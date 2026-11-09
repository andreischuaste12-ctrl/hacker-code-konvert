# Roadmap

The roadmap favors a narrow, verifiable local workflow before adding hosted services or broad automation.

## Phase 0: Operating Contracts

Status: complete for the initial contract set.

- Define authorization and ethical boundaries.
- Define the normalized finding schema.
- Define architecture and scanner responsibilities.
- Establish the project's own vulnerability reporting policy.
- Record primary references, licensing constraints, and formal verification gates.
- Establish contribution, conduct, issue, pull request, and licensing files.

Exit criteria: documentation is internally consistent and every future component has a clear input and output boundary.

## Phase 1: Repository Inventory and CLI Skeleton

Status: implemented in version 0.1.0.

- Select the implementation language from a small scanner-invocation prototype.
- Build a local CLI with explicit repository root and output directory arguments.
- Detect supported manifests and lockfiles without executing project code.
- Record run metadata, tool availability, exclusions, and failures.

Exit criteria: the CLI inventories a fixture repository deterministically and never writes inside the analyzed repository by default.

## Phase 2: Scanner Adapters

Status: Semgrep Python/PHP, directory-only Gitleaks, and offline lockfile OSV profiles implemented in 0.2.0.

- Integrate Semgrep, OSV-Scanner, and Gitleaks.
- Pin or record tool versions and rulesets.
- Preserve exit status and distinguish findings from tool failures.
- Redact secret material before storing results.

Exit criteria: fixture repositories produce reproducible raw results and a failed scanner makes the overall run incomplete.

## Phase 3: Normalization and Triage

Status: executable finding contract and scanner-to-candidate normalization implemented; contextual human triage pending.

- Normalize all scanner results to the finding schema.
- Deduplicate findings without losing source provenance.
- Add contextual checks for reachability, version applicability, and existing mitigations.
- Record analyst confidence and unresolved assumptions.
- Apply the formal verification gates and preserve inconclusive candidates.

Exit criteria: every normalized finding traces back to evidence, and candidates cannot silently become validated findings.

## Phase 4: Differential Review

- Add an explicit baseline and head revision mode.
- Map security-relevant changes, affected callers, and blast radius.
- Inspect removed validation and authorization logic with Git history.
- Report related test coverage and untested security paths.

Exit criteria: a differential report identifies its complete revision range, reviewed changes, coverage limits, and evidence for every finding.

## Phase 5: Reports

Status: Markdown, normalized JSON and SARIF 2.1.0 implemented.

- Generate Markdown reports for human review.
- Generate valid SARIF for compatible platforms.
- Separate validated findings, candidates, false positives, accepted risks, scanner failures, and skipped checks.

Exit criteria: report fixtures pass schema validation and never include raw secrets or absolute local paths.

## Phase 6: Remediation Assistance

- Generate minimal, reviewable remediation proposals.
- Add project-specific verification commands.
- Re-run affected checks after an approved patch.

Exit criteria: the system distinguishes a proposed fix from a verified fix and preserves human approval before publication.

## Later Considerations

- CodeQL integration for supported languages.
- CycloneDX or SPDX SBOM generation.
- OpenSSF Scorecard and supply-chain analysis.
- EPSS, CISA KEV, and SSVC-based prioritization.
- Authorized dynamic testing as a separate operating mode.
- E-commerce profile implementation after generic repository, dependency, and reporting contracts are stable.
- Hosted execution only after isolation, tenancy, retention, and privacy requirements are designed.
