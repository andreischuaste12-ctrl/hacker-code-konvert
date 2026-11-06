# Technical References

This document records the primary sources that guide Hacker Code Konvert. References inform the design; they are not copied blindly, and their licenses remain in effect.

Last reviewed: 2026-11-06.

## Standards and Taxonomies

| Reference | Use in the project | Notes |
| --- | --- | --- |
| [CWE](https://cwe.mitre.org/) | Weakness classification | Use the most specific supported CWE and avoid assigning one without evidence. |
| [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document) | Intrinsic vulnerability severity | Store the version, vector, assumptions, and calculator-derived score. CVSS is not a complete risk score. |
| [OWASP ASVS](https://github.com/OWASP/ASVS) | Application security requirements | Pin the referenced version because requirement identifiers can change between releases. |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | High-level awareness categories | Do not use it as a complete test plan. |
| [OWASP API Security Top 10](https://owasp.org/API-Security/) | API threat categories | Apply only to relevant API surfaces. |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) | Authorized testing methodology | Dynamic tests remain outside the static-analysis MVP. |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | Remediation guidance | Prefer technology-specific primary documentation when it is more precise. |
| [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | Interchange format for static-analysis results | Generated SARIF must validate against the supported schema. |

## Deterministic Tools and Data Sources

| Reference | Planned responsibility |
| --- | --- |
| [Semgrep](https://semgrep.dev/docs/) | Static source patterns and data-flow candidates |
| [OSV-Scanner](https://google.github.io/osv-scanner/) and [OSV Schema](https://ossf.github.io/osv-schema/) | Dependency matches and advisory interchange |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Candidate secret detection with mandatory redaction |
| [CodeQL](https://codeql.github.com/docs/) | Deferred language-specific semantic and data-flow analysis |
| [SonarQube](https://docs.sonarsource.com/sonarqube-server/) | Deferred code-quality and security-analysis integration |
| [Trivy](https://trivy.dev/latest/docs/) | Deferred container, filesystem, dependency, and IaC analysis |
| [Dependabot](https://docs.github.com/en/code-security/dependabot) | Repository-native dependency alerts and update proposals |
| [npm audit](https://docs.npmjs.com/cli/commands/npm-audit) and [pip-audit](https://github.com/pypa/pip-audit) | Ecosystem-native dependency evidence when applicable |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Optional second source for candidate secret detection |
| [Syft](https://github.com/anchore/syft) | Deferred SBOM generation and package inventory |
| [CycloneDX](https://cyclonedx.org/docs/1.6/json/) and [SPDX](https://spdx.dev/use/specifications/) | Deferred SBOM generation and interchange |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Deferred repository and supply-chain posture signals |
| [EPSS](https://www.first.org/epss/) | Exploitation probability enrichment, with observation date |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploitation enrichment after exact product and version matching |
| [SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) | Decision-oriented prioritization, separate from severity |

## Review and Verification Methodologies

| Reference | Adopted principle | Adaptation |
| --- | --- | --- |
| [Anthropic Claude Code Security Review](https://github.com/anthropics/claude-code-security-review) | Review changes in repository context and reduce noise | Its broad hard exclusions are not adopted. The project itself warns that the action is not hardened against prompt injection. |
| [Trail of Bits Skills](https://github.com/trailofbits/skills) | Explicit verification gates, differential review, and justified CVSS metrics | Concepts are adapted to the project's authorization model. Executable proof of concept is not mandatory when safe evidence is sufficient. Source material is CC-BY-SA-4.0 and must not be copied without complying with that license. |

## Responsible Disclosure

| Reference | Use in the project |
| --- | --- |
| [OpenSSF OSS Vulnerability Guide](https://github.com/ossf/oss-vulnerability-guide) | Finder guidance, coordinated vulnerability disclosure, and maintainer-aware timelines |
| [ISO/IEC 29147](https://www.iso.org/standard/72311.html) | Vulnerability disclosure process reference |
| [ISO/IEC 30111](https://www.iso.org/standard/69725.html) | Vulnerability handling process reference |
| [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository) | Preferred private channel when enabled by the target repository |
| [GitHub Repository Security Advisories](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories) | Private maintainer collaboration, remediation, and advisory publication |

## Secure Development and Supply Chain

| Reference | Use in the project |
| --- | --- |
| [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) | Secure-development practice framework |
| [OpenSSF SLSA](https://slsa.dev/spec/) | Build provenance and supply-chain maturity |
| [OWASP SAMM](https://owaspsamm.org/model/) | Security-program maturity reference |

## E-commerce and Payment Systems

[PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/) applies only when the assessed system is within payment-data scope. Requirements related to payment-page scripts, change detection, penetration testing, or service-provider responsibilities must be checked against the current official PCI SSC document before use.

Platform-specific assumptions about Shopify, WooCommerce, payment gateways, plugins, pixels, or widgets must be verified through official platform documentation and the target architecture. Magecart-style compromise is not reduced to a single vector such as stored XSS; dependencies, administrative access, plugins, build pipelines, and third-party scripts may also be relevant.

## Discovery-only Material

Community skills, blog posts, aggregators, and vendor articles may reveal useful patterns, but they are not normative sources. The project may evaluate examples such as `utkusen/sast-skills`, general security-review skills, DevSecOps playbooks, or platform audit articles without adopting their claims as facts. Offensive skill collections are never loaded or executed merely because they appear in a reference list.

## Licensing Rule

Reference links and general concepts may be used with attribution. Text, rulesets, code, and templates from another project may only be incorporated after confirming license compatibility and satisfying attribution or share-alike obligations. Secondary articles can help discovery but must not be the sole authority for a security rule.
