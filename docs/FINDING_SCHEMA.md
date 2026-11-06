# Finding Schema

Every scanner result starts as a candidate. This normalized contract connects scanner adapters, contextual triage, verification gates, risk classification, remediation, and reporting.

## Required Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable project identifier, independent of a scanner run |
| `fingerprint` | Deterministic deduplication key that never contains secret material |
| `title` | Concise description of the security issue |
| `status` | `candidate`, `validated`, `false_positive`, or `accepted_risk` |
| `analysis_profile` | `repository`, `differential`, `dependency`, `ecommerce`, or `active` |
| `severity` | `informational`, `low`, `medium`, `high`, or `critical` |
| `confidence` | `low`, `medium`, or `high` |
| `category` | Finding family such as `sast`, `dependency`, `secret`, or `configuration` |
| `location` | Repository-relative path and line or exact dependency coordinates |
| `threat_model` | Attacker, required access, affected boundary, and triggering conditions |
| `evidence` | Redacted observed facts supporting the result |
| `validation` | Outcome and evidence for each applicable verification gate |
| `impact` | Realistic consequence under stated conditions |
| `remediation` | Actionable correction and verification guidance |
| `sources` | Scanner, rule, advisory, standard, or analyst references |
| `review` | Human-review state, reviewer, timestamp, and rationale |
| `disclosure` | Private disclosure lifecycle, kept separate from technical status |

## Optional Enrichment

- CWE identifier and applicable OWASP category;
- CVSS v4.0 vector, metric justifications, score source, and assumptions;
- EPSS probability and observation date;
- CISA KEV membership and observation date;
- SSVC decision and rationale;
- dependency ecosystem, package, installed version, affected range, and fixed version;
- source-to-sink trace and relevant callers;
- differential baseline, head revision, changed lines, and blast radius;
- patch reference and post-remediation verification;
- SARIF rule and result identifiers.

## Disclosure Lifecycle

`disclosure.status` uses one of these values:

- `not_applicable`: no external vulnerability disclosure applies;
- `not_reported`: a validated finding remains private and has not been sent;
- `privately_reported`: sent through an approved private channel;
- `acknowledged`: the maintainer confirmed receipt;
- `triaged`: the maintainer assessed the report;
- `remediation_in_progress`: a private fix is being developed;
- `fixed`: a fix is available but disclosure may still be restricted;
- `coordinated_disclosure`: public disclosure was approved and coordinated.

External communication requires explicit human approval. The lifecycle must not advance merely because a report artifact was generated.

## Example

```json
{
  "id": "HCK-2026-0001",
  "fingerprint": "sha256:<deterministic-value>",
  "title": "Untrusted input reaches a SQL query",
  "status": "candidate",
  "analysis_profile": "repository",
  "severity": "high",
  "confidence": "medium",
  "category": "sast",
  "location": {
    "path": "src/example.ts",
    "start_line": 42,
    "end_line": 42
  },
  "threat_model": {
    "attacker": "unauthenticated remote user",
    "required_access": "HTTP access to the search route",
    "conditions": [
      "The route is enabled",
      "No upstream allowlist rejects the input"
    ]
  },
  "taxonomy": {
    "cwe": "CWE-89",
    "owasp": "A03:2021"
  },
  "evidence": {
    "summary": "A request parameter is concatenated into a query string.",
    "source_to_sink": [
      "request.query.term",
      "buildSearchQuery",
      "database.execute"
    ],
    "redacted": true
  },
  "validation": {
    "authorization_scope": "pass",
    "coherent_claim": "pass",
    "code_applicability": "pass",
    "attacker_control_reachability": "unresolved",
    "vulnerability_mechanism": "pass",
    "realistic_impact": "unresolved",
    "environmental_controls": "unresolved",
    "safe_evidence": "pass",
    "human_review": "pending"
  },
  "impact": "An attacker may alter the query if the route is reachable and no upstream validation applies.",
  "risk": {
    "cvss_version": "4.0",
    "cvss_vector": null,
    "cvss_score": null,
    "assumptions": [
      "Exploitability metrics are incomplete"
    ]
  },
  "remediation": {
    "summary": "Use a parameterized query and validate the expected input shape.",
    "verification": "Run the relevant unit and integration tests and repeat the SAST rule."
  },
  "sources": [
    {
      "type": "scanner",
      "name": "semgrep",
      "version": "<recorded-at-runtime>",
      "rule_id": "example.sql-injection"
    }
  ],
  "review": {
    "human_reviewed": false,
    "reviewer": null,
    "reviewed_at": null,
    "rationale": "Reachability and upstream validation have not yet been confirmed."
  },
  "disclosure": {
    "status": "not_applicable",
    "approved_by": null,
    "updated_at": null
  }
}
```

## Validation Rules

- A `validated` finding requires all applicable gates and independent human review.
- Missing evidence keeps a result as `candidate`; it does not establish `false_positive`.
- `accepted_risk` requires an authorized owner, rationale, and review date.
- Severity and confidence must not be merged into one value.
- A CVSS score must include version 4.0, its vector, metric justifications, assumptions, and a validated score source.
- EPSS and KEV data must include the observation date and exact component match.
- Secret values must never appear in evidence, logs, fingerprints, reports, or test fixtures.
- Repository paths must be relative and must not escape the analyzed root.
- A dependency finding must identify its ecosystem, package, installed version, affected range, and advisory source.
- Differential findings must identify both baseline and head revisions.
- Scanner errors, skipped checks, and incomplete coverage belong in run metadata, not as security findings.
- Technical status and disclosure status must remain independent.
