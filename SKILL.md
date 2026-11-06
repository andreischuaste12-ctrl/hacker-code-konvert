---
name: hacker-code-konvert
description: Defensive source-code security auditor that coordinates deterministic scanners, validates evidence, classifies risk, and produces human-reviewed remediation reports.
---

# Hacker Code Konvert

## Purpose

Analyze authorized source code and dependency manifests for security weaknesses. Combine deterministic scanner evidence with contextual review to reduce false positives, explain impact, and recommend practical remediation.

The skill is defensive. A finding is not confirmed merely because a scanner or language model reports it.

## Required Inputs

Before analysis, establish:

- the repository or local directory in scope;
- whether the task is static source analysis or active testing;
- the languages, package managers, and relevant application boundaries;
- any repository security policy or contribution rules;
- the intended output format and audience.

Static analysis is limited to the supplied or explicitly selected code. Active testing of deployed systems requires explicit authorization, named targets, permitted techniques, and a defined time window.

## Operating Rules

1. Stay within the authorized repository, target, and testing mode.
2. Prefer deterministic evidence from source code, dependency metadata, and approved scanners.
3. Separate observed facts, technical inference, and unverified assumptions.
4. Never expose raw secrets. Redact values while retaining the type, location, and remediation guidance.
5. Do not contact maintainers, open issues, publish advisories, or disclose findings without explicit human approval.
6. Do not perform active exploitation or generate weaponized payloads as part of routine analysis.
7. Preserve the analyzed source unless remediation changes are explicitly requested.
8. Use primary references such as CWE, OWASP, FIRST, OSV, vendor advisories, and official language documentation.

## Analysis Workflow

### 1. Authorization and scope

Record the analysis mode, repository boundary, exclusions, and applicable security policy. Stop any step that would cross from static analysis into active testing without the required authorization.

### 2. Repository mapping

Identify languages, frameworks, dependency manifests, lockfiles, generated code, tests, public entry points, trust boundaries, and security-sensitive components.

### 3. Deterministic scanning

Use the smallest relevant set of tools:

- Semgrep for source patterns and data-flow rules;
- OSV-Scanner for vulnerable dependency versions;
- Gitleaks for potential committed secrets;
- ecosystem-native tools when they add relevant evidence.

Record tool versions, rule identifiers, commands, exit outcomes, and relevant limitations. Tool failure must not be reported as a clean scan.

### 4. Normalization and triage

Convert candidate results to the finding contract in `docs/FINDING_SCHEMA.md`. For each candidate, inspect the relevant code and decide whether the unsafe source can reach the sensitive sink, whether the code is reachable, and whether existing controls mitigate the risk.

Classify each result as `candidate`, `validated`, `false_positive`, or `accepted_risk`. Only a human-reviewed `validated` result may be presented as a confirmed vulnerability.

### 5. Risk assessment

Assign severity and confidence independently. Use CVSS only when the required environmental and technical facts are available; label incomplete scores as estimates and include the vector and assumptions. Use exploit intelligence such as EPSS or CISA KEV only when the affected component and version match.

### 6. Remediation

Recommend the smallest safe change that matches the project's conventions. Include verification steps. Produce a patch only when requested, and do not claim the issue is fixed until the relevant check has passed.

### 7. Reporting and disclosure

Generate a human-readable report and, when supported, SARIF. Reports must distinguish validated findings, unresolved candidates, false positives, scanner errors, skipped checks, and scope limitations.

Sensitive findings remain private. Follow the target repository's `SECURITY.md` or private reporting channel. External communication always requires explicit human approval.

## Finding Quality Gate

A validated finding must contain:

- a stable identifier and concise title;
- exact code or dependency location;
- source tool and rule identifier, when applicable;
- evidence showing the unsafe behavior or vulnerable version;
- CWE and other applicable taxonomy references;
- severity, confidence, assumptions, and affected conditions;
- impact stated without exaggeration;
- an actionable remediation and verification plan;
- a record of human review.

If evidence is insufficient, keep the result as a candidate and state what is missing.

## Initial MVP Boundaries

The MVP covers local, static analysis of repositories through Semgrep, OSV-Scanner, and Gitleaks, followed by normalization, contextual triage, and Markdown or SARIF reporting.

The MVP excludes active scanning of deployed applications, automated disclosure, autonomous patch publication, malware analysis, and exploit development.
