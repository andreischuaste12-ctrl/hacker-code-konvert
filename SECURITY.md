# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue containing exploit details, credentials, personal data, or information that could put users at risk.

Use GitHub Private Vulnerability Reporting when it is enabled for this repository. If that channel is unavailable, contact the repository owner privately through a verified channel listed on the owner's GitHub profile.

For this repository, the preferred channel is [GitHub Private Vulnerability Reporting](https://github.com/andreischuaste12-ctrl/hacker-code-konvert/security/advisories/new).

If that channel is unavailable, open a public issue containing only a request for a private security contact. Do not include the affected component, vulnerability class, evidence, reproduction steps, or impact in that issue.

Include only the information needed to reproduce and assess the issue:

- affected component and version or commit;
- impact and required conditions;
- minimal, non-destructive reproduction steps;
- relevant logs or code locations with secrets and personal data removed;
- a suggested remediation, if available.

## Research Guidelines

- Limit testing to assets for which you have explicit authorization.
- Do not access, modify, retain, or disclose other people's data.
- Avoid denial of service, social engineering, persistence, and destructive actions.
- Stop testing if you encounter sensitive data or signs of impact to other users.
- Allow maintainers reasonable time to investigate and remediate before disclosure.

This policy does not grant authorization to test third-party systems, deployed applications, or repositories analyzed with Hacker Code Konvert.

## Coordinated Disclosure

Reports are handled through a coordinated process: private report, acknowledgement, triage, remediation, validation, and public disclosure when appropriate. Timing depends on severity, downstream exposure, available mitigations, the reporter's expectations, and maintainer capacity. Public disclosure must be coordinated and must not expose users before a practical mitigation is available.

Technical validation and disclosure status are tracked separately. A validated finding is not automatically approved for publication.

Do not send automated or bulk vulnerability reports. Consolidate related findings, remove duplicates, verify evidence, and submit each report through the target project's approved private channel. Record an expected coordination timeline with the maintainer instead of imposing an undisclosed universal deadline.

## Project Scope

The `main` branch (0.2.x) is the currently supported development line. Its security-sensitive surface includes the
CLI, repository staging, Bubblewrap isolation, bundled rules, output normalization, redaction, schemas,
and report generation. Include the affected version or commit in a private report.

Findings about a third-party repository analyzed by Hacker Code Konvert must be reported through that
project's security policy. This repository's policy does not grant permission to test or disclose issues
in those projects.
