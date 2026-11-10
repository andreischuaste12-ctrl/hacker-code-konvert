# Hacker Code Konvert

*Finding vulnerabilities. Building security. Protecting open source.*

Hacker Code Konvert is an ethical cybersecurity project focused on identifying, analyzing, and preventing vulnerabilities in source code and open-source projects, especially those hosted on GitHub, as well as e-commerce applications and projects on other development platforms.

The project aims to contribute to a safer digital ecosystem by helping developers and organizations identify potential security weaknesses before malicious actors exploit them.

The planned approach combines code analysis, security auditing, and automated tools to detect vulnerabilities, insecure configurations, outdated dependencies, and other application risks. An outdated dependency alone does not establish a vulnerability; findings should be assessed in context.

## Project Status

The project provides a local end-to-end MVP: repository inventory, isolated Semgrep analysis of Python and PHP files, offline dependency and secret scanning, executable finding validation, and Markdown, JSON and SARIF reporting. Scanner findings remain candidates until independently reviewed.

The rule pack is a small, reviewed set (19 Python and 15 PHP/WordPress rules). A completed run means that the requested checks finished on the selected files, not that the analyzed repository is secure.

## Planned Capabilities

- **Repository analysis:** Identify potential vulnerabilities in projects hosted on GitHub.
- **Security issue detection:** Analyze source code for security weaknesses and insecure configurations.
- **Intelligent automation:** Use automated tools and artificial intelligence to assist with identifying and classifying risks, with human review of findings.
- **Security reports:** Produce detailed reports describing findings, severity levels, supporting evidence, and recommended fixes.
- **Improvement suggestions:** Provide technical recommendations to remediate vulnerabilities and strengthen project security.
- **Developer collaboration:** Support responsible communication of validated vulnerabilities so maintainers can address them.

## MVP

The initial implementation focuses on:

1. Static inventory of a selected repository and Semgrep analysis of Python and PHP source files.
2. Classification of findings by severity, with evidence and relevant context.
3. Security reports containing actionable remediation recommendations.
4. Human review before any findings are communicated to maintainers.

Active security testing, automatic maintainer outreach, remote AI processing, Git-history secret scanning and autonomous remediation remain outside the implemented scope.

Scanner status:

- **Semgrep 1.184.0:** Python and PHP through bundled local rules and networkless Bubblewrap isolation.
- **OSV-Scanner 2.7.1:** isolated lockfile analysis using an explicitly prepared offline database.
- **Gitleaks 8.30.1:** isolated directory-only secret detection with vendor defaults plus a controlled custom rule, empty ignore file, inline allow comments ignored, and redacted output.

Scanner output will be treated as evidence for review, not as a confirmed vulnerability by itself.

## Documentation

- [Operating skill](SKILL.md): authorization, analysis, triage, and reporting rules.
- [Architecture](docs/ARCHITECTURE.md): system boundaries, components, and analysis flow.
- [MVP specification](docs/PRODUCT_SPEC.md): implemented inputs, outputs, limits, and unsupported cases.
- [Scanner isolation](docs/SCANNER_ISOLATION.md): staging, sandbox, network, and resource controls.
- [Privacy](docs/PRIVACY.md): local data flow, retention, and external-service policy.
- [Dependencies](docs/DEPENDENCIES.md): lock generation, supply-chain checks, and accepted advisories.
- [Repository hardening checklist](docs/MAINTAINER_CHECKLIST.md): GitHub settings that files cannot enforce.
- [Quality and measurement](docs/QUALITY.md): fixture metrics, thresholds, and interpretation limits.
- [Finding schema](docs/FINDING_SCHEMA.md): normalized contract for security findings.
- [Verification gates](docs/VERIFICATION_GATES.md): evidence requirements and verdict rules.
- [Technical references](docs/REFERENCES.md): primary sources, standards, and licensing notes.
- [Report template](docs/REPORT_TEMPLATE.md): required sections for reviewable security reports.
- [E-commerce profile](docs/ECOMMERCE_PROFILE.md): authorized payment and storefront review guidance.
- [Roadmap](docs/ROADMAP.md): implementation phases and acceptance criteria.
- [Security policy](SECURITY.md): how to report vulnerabilities in this project.

## Quick Start

The Semgrep profile requires Linux, Python 3.12 or 3.13, and Bubblewrap with namespace support.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m venv /tmp/hck-semgrep
/tmp/hck-semgrep/bin/python -m pip install --require-hashes -r requirements-semgrep.txt
export PATH="/tmp/hck-semgrep/bin:$PATH"
```

Run the isolated Python Semgrep profile (the default scanner):

```bash
hck scan /path/to/authorized/repository \
  --output /tmp/hck-report \
  --authorized
```

`--authorized` records your confirmation that the repository is in scope; the CLI cannot verify it. A run is complete only when coverage was demonstrated: content the scanner could not be shown (a nested repository, an unreadable or oversized file, a missing Git LFS object), a file the scanner skipped, a scanner error, a sandbox failure, or a repository with no supported source file all produce an incomplete run (`complete: false`, exit status `3`) with the gaps listed in the report. Source files are selected by suffix, interpreter line or a leading PHP tag; see [Scanner isolation](docs/SCANNER_ISOLATION.md) for the exact rules.

To list files without scanning for vulnerabilities, pass `--scanner inventory`. That mode is labelled in the report and in `run.json` (`vulnerability_scan_performed: false`) and says nothing about whether the code is safe.

The output directory must be new, empty, or hold only a previous run's artifacts, and it must remain outside the analyzed repository. It receives `run.json`, `findings.json`, `report.md`, and `results.sarif`, with private permissions. See the [MVP specification](docs/PRODUCT_SPEC.md) for exit statuses and limitations. The CLI itself performs no AI processing; an AI agent that reads the analyzed code does (see [Privacy](docs/PRIVACY.md)).

### Using the skill

`SKILL.md` refers to files under `docs/`, so the whole repository is the skill directory. Install it by cloning or symlinking the repository as `~/.claude/skills/hacker-code-konvert/`; copying `SKILL.md` alone breaks those references. The skill directs the agent to run the CLI above instead of invoking scanners directly. Its `allowed-tools` entry only pre-approves tools: add permission deny rules if you need to prevent an agent from running other tools.

## Development

```bash
python -m pip install --require-hashes -r requirements-dev.txt
python -m pip install --no-deps --no-build-isolation -e .
ruff check src scripts tests
pytest -q
```

The lock file records the complete Python 3.12 development dependency graph, with hashes, used by CI. CI
repeats the dependency audit, package build, lint, tests (the sandbox and Semgrep integration tests are
mandatory there), isolated scanner fixture, and fixture quality measurement on every pull request, on every push
to `main`, and weekly. See [Dependencies](docs/DEPENDENCIES.md) for how the lock is generated and which
advisories are accepted, and the [repository hardening checklist](docs/MAINTAINER_CHECKLIST.md) for the GitHub
settings the owner must confirm.

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

## Version 0.2.0 additions

The bundled original rules cover 19 Python classes and 15 PHP/WordPress classes. Rules, hashes,
selected-file hashes, scanner versions, Python version and actual isolation appear in `run.json`.
Coverage completion describes the requested checks only. The synthetic corpora, including one written
before the rules were extended, are not a real-world accuracy estimate (see [Quality](docs/QUALITY.md)). See [the implementation status](docs/IMPROVEMENT_STATUS.md) for external prerequisites.

- [Operational commands](docs/OPERATIONS.md): offline scanners, authorization records, SSH review and disclosure drafts.
- `results.sarif` is generated locally; upload to GitHub code scanning is a separate authorized action.
- Development and Semgrep dependencies use separate hash-pinned universal locks for Python 3.12/3.13.
