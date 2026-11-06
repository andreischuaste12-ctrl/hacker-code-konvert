# Hacker Code Konvert

*Finding vulnerabilities. Building security. Protecting open source.*

Hacker Code Konvert is an ethical cybersecurity project focused on identifying, analyzing, and preventing vulnerabilities in source code and open-source projects, especially those hosted on GitHub, as well as e-commerce applications and projects on other development platforms.

The project aims to contribute to a safer digital ecosystem by helping developers and organizations identify potential security weaknesses before malicious actors exploit them.

The planned approach combines code analysis, security auditing, and automated tools to detect vulnerabilities, insecure configurations, outdated dependencies, and other application risks. An outdated dependency alone does not establish a vulnerability; findings should be assessed in context.

## Project Status

Version 0.1.0 provides a local end-to-end MVP for repository inventory, optional isolated Semgrep analysis of Python files, executable finding validation, and Markdown or JSON reporting. Scanner findings remain candidates until independently reviewed.

The rule pack is intentionally small. A completed run means that the requested checks finished, not that the analyzed repository is secure.

## Planned Capabilities

- **Repository analysis:** Identify potential vulnerabilities in projects hosted on GitHub.
- **Security issue detection:** Analyze source code for security weaknesses and insecure configurations.
- **Intelligent automation:** Use automated tools and artificial intelligence to assist with identifying and classifying risks, with human review of findings.
- **Security reports:** Produce detailed reports describing findings, severity levels, supporting evidence, and recommended fixes.
- **Improvement suggestions:** Provide technical recommendations to remediate vulnerabilities and strengthen project security.
- **Developer collaboration:** Support responsible communication of validated vulnerabilities so maintainers can address them.

## MVP

The initial implementation focuses on:

1. Static inventory of a selected repository and Semgrep analysis of Python source files.
2. Classification of findings by severity, with evidence and relevant context.
3. Security reports containing actionable remediation recommendations.
4. Human review before any findings are communicated to maintainers.

Active security testing, dependency vulnerability analysis, automated outreach, remote AI processing, and autonomous remediation remain outside the implemented scope.

Scanner status:

- **Semgrep 1.184.0:** implemented for Python through bundled local rules and networkless Bubblewrap isolation.
- **OSV-Scanner:** planned for dependency vulnerability analysis.
- **Gitleaks:** planned for secret detection with mandatory redaction and suppression-resistant staging.

Scanner output will be treated as evidence for review, not as a confirmed vulnerability by itself.

## Documentation

- [Operating skill](SKILL.md): authorization, analysis, triage, and reporting rules.
- [Architecture](docs/ARCHITECTURE.md): system boundaries, components, and analysis flow.
- [MVP specification](docs/PRODUCT_SPEC.md): implemented inputs, outputs, limits, and unsupported cases.
- [Scanner isolation](docs/SCANNER_ISOLATION.md): staging, sandbox, network, and resource controls.
- [Privacy](docs/PRIVACY.md): local data flow, retention, and external-service policy.
- [Quality and measurement](docs/QUALITY.md): fixture metrics, thresholds, and interpretation limits.
- [Finding schema](docs/FINDING_SCHEMA.md): normalized contract for security findings.
- [Verification gates](docs/VERIFICATION_GATES.md): evidence requirements and verdict rules.
- [Technical references](docs/REFERENCES.md): primary sources, standards, and licensing notes.
- [Report template](docs/REPORT_TEMPLATE.md): required sections for reviewable security reports.
- [E-commerce profile](docs/ECOMMERCE_PROFILE.md): authorized payment and storefront review guidance.
- [Roadmap](docs/ROADMAP.md): implementation phases and acceptance criteria.
- [Security policy](SECURITY.md): how to report vulnerabilities in this project.

## Quick Start

The Semgrep profile requires Linux, Python 3.12 or newer, and Bubblewrap with namespace support.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[semgrep]'
```

Run a local inventory without an external scanner:

```bash
hck scan /path/to/authorized/repository \
  --output /tmp/hck-report \
  --authorized
```

Run the isolated Python Semgrep profile:

```bash
hck scan /path/to/authorized/repository \
  --output /tmp/hck-report \
  --authorized \
  --scanner semgrep
```

The output directory must remain outside the analyzed repository. It receives `run.json`, `findings.json`, and `report.md`, with private permissions. See the [MVP specification](docs/PRODUCT_SPEC.md) for exit statuses and limitations.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pip install --no-deps -e .
ruff check src scripts tests
pytest -q
```

The lock file records the complete Python 3.12 development dependency graph used by CI. CI repeats the
package build, lint, unit tests, isolated scanner fixture, schema checks, and fixture quality measurement
on every pull request and push to `main`.

## Community

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md) in all project spaces.
- Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Use the provided issue forms and pull request template so scope, validation, and security considerations remain reviewable.

## Ethical Commitment

All activities must respect ethical hacking principles, project security policies, and the limits of the authorization granted.

- Analysis of public source code must comply with applicable licenses and rules.
- Public availability of a repository does not constitute authorization to test deployed systems.
- Active security testing must only take place with explicit authorization and within the agreed scope.
- Sensitive vulnerabilities must be reported privately to the responsible maintainers, following responsible disclosure practices and any published security policy.
- Reports must avoid exposing secrets, personal data, or unnecessary details that could facilitate exploitation.

## Our Mission

Make software development safer, more accessible, and more trustworthy by using cybersecurity knowledge to turn vulnerabilities into opportunities for improvement.

## License

Copyright 2026 Andrei Schuaste.

Licensed under the [Apache License 2.0](LICENSE).
