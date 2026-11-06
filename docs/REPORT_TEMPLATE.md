# Security Analysis Report Template

Reports must remain reviewable by both maintainers and technical security reviewers. Remove sections that do not apply, but never hide failed, skipped, or incomplete analysis.

## 1. Report Metadata

- Report identifier and generation time
- Repository and analyzed revision
- Analysis profile
- Baseline and head revisions for differential analysis
- Authorized scope and explicit exclusions
- Analyst and human reviewer
- Tool and ruleset versions

## 2. Executive Summary

State what was analyzed, the most important validated risks, the overall confidence, and the actions that should be prioritized. Avoid claims that a clean scan proves the absence of vulnerabilities.

## 3. Coverage and Run Health

List:

- languages, manifests, lockfiles, and components identified;
- scanners that completed successfully;
- scanners that failed or returned partial results;
- skipped checks and the reasons;
- generated code, vendored code, or paths excluded;
- limitations that affect confidence.

## 4. Results Overview

Report separate counts for:

- validated findings;
- unresolved candidates;
- false positives;
- accepted risks;
- remediated and reverified findings;
- scanner failures and incomplete checks.

Severity totals must never combine candidates with validated findings without labeling them separately.

## 5. Validated Findings

Use this structure for each finding:

### `[ID] Title`

- **Status:** validated
- **Severity:** informational, low, medium, high, or critical
- **Confidence:** low, medium, or high
- **Confidence rationale:** evidence supporting the confidence value
- **Location:** repository-relative file and lines, or dependency coordinates
- **CWE / OWASP:** applicable taxonomy
- **CVSS v4.0:** vector, score source, assumptions, and metric justification
- **Threat model:** attacker, access, conditions, and affected boundary
- **Evidence:** redacted observed facts and source-to-sink or version trace
- **Verification gates:** outcome of every applicable gate
- **Impact:** realistic consequence under stated conditions
- **Safe reproduction:** authorized steps performed, or why execution was not performed
- **Remediation:** smallest practical fix
- **Verification:** checks required to confirm the fix
- **References:** primary sources and originating scanner rule
- **Disclosure:** current private lifecycle state

## 6. Unresolved Candidates

For each candidate, state the available evidence, unresolved gates, missing facts, provisional severity and confidence, and the next safe verification step. Do not present candidates as confirmed vulnerabilities.

## 7. False Positives and Accepted Risks

Preserve enough rationale to prevent repeated work. Accepted risks must identify the authorized owner, rationale, compensating controls, and review date.

## 8. Remediation Plan

Order actions using validated severity, exploit intelligence, asset context, fix availability, and operational constraints. CVSS alone does not determine priority.

## 9. Disclosure Notes

Keep sensitive findings private. Record the approved channel and current lifecycle state. Do not include raw secrets, exploit-ready payloads, or unnecessary sensitive detail.

## 10. Machine-readable Artifacts

When generated, list SARIF, normalized JSON, SBOM, and redacted raw scanner artifacts with checksums and schema versions.
