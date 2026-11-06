# Contributing to Hacker Code Konvert

Thank you for helping improve Hacker Code Konvert. Contributions should strengthen defensive security analysis, reproducibility, and responsible disclosure.

## Before You Start

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Review the [architecture](docs/ARCHITECTURE.md), [finding schema](docs/FINDING_SCHEMA.md), and [verification gates](docs/VERIFICATION_GATES.md).
- Search existing issues before opening a new one.
- Do not publish suspected vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).

## Ways to Contribute

- Improve documentation and examples.
- Propose scanner adapters or normalized finding fields.
- Add safe test fixtures for known vulnerability classes.
- Improve false-positive triage and evidence validation.
- Improve report formats, redaction, or interoperability.

Offensive payloads, unauthorized testing workflows, real credentials, personal data, and samples copied from private systems are not accepted.

## Development Workflow

The project is currently in its documentation and contract-design phase. Until the first implementation stack is selected:

1. Create a focused branch from `main`.
2. Keep each pull request limited to one coherent change.
3. Explain the problem, security implications, and validation performed.
4. Update related documentation when changing a contract or workflow.
5. Verify Markdown links, examples, and structured data before submitting.

Do not modify an analyzed third-party repository as part of a fixture. Use synthetic examples with no live secrets or sensitive data.

## Security Analysis Requirements

Changes that introduce or modify analysis behavior must:

- preserve the authorization boundary;
- treat repository content and scanner output as untrusted data;
- distinguish evidence from inference;
- keep severity separate from confidence;
- redact secrets before logs, persistence, and reports;
- preserve scanner failures and coverage limitations;
- require human review before disclosure or patch publication.

Broad exclusions such as “ignore every denial-of-service finding” are not accepted. Filtering must depend on the selected analysis profile, threat model, and documented evidence.

## Pull Requests

A pull request should include:

- a clear description of the behavior or documentation changed;
- links to relevant issues or primary references;
- validation commands and results;
- known limitations and follow-up work;
- confirmation that no secrets or sensitive findings are included.

Maintainers may request changes when evidence, scope, licensing, or safe handling is unclear.

## Licensing and Attribution

By submitting a contribution, you agree that it may be distributed under the [Apache License 2.0](LICENSE).

Do not copy text, rules, or source code from third-party projects unless the license is compatible and the required attribution is included. Ideas and methodologies may be referenced, but adapted content must preserve its license obligations.
