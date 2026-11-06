# Finding Schema

Every scanner result starts as a candidate. The normalized finding below is the contract between scanner adapters, triage, and report generation.

## Required Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable project identifier, independent of a scanner run |
| `fingerprint` | Deterministic deduplication key based on rule and location |
| `title` | Concise description of the security issue |
| `status` | `candidate`, `validated`, `false_positive`, or `accepted_risk` |
| `severity` | `informational`, `low`, `medium`, `high`, or `critical` |
| `confidence` | `low`, `medium`, or `high` |
| `category` | Finding family such as `sast`, `dependency`, `secret`, or `configuration` |
| `location` | Repository-relative path and line or dependency coordinates |
| `evidence` | Redacted facts supporting the result |
| `impact` | Realistic consequence under stated conditions |
| `remediation` | Actionable correction and verification guidance |
| `sources` | Scanner, rule, advisory, or analyst references |
| `review` | Human-review state and rationale |

## Optional Enrichment

- CWE identifier and OWASP category;
- CVSS version, vector, score, and assumptions;
- EPSS probability and observation date;
- CISA KEV membership and due-date metadata;
- dependency ecosystem, package, installed version, and fixed version;
- source-to-sink trace;
- patch reference;
- SARIF rule and result identifiers.

## Example

```json
{
  "id": "HCK-2026-0001",
  "fingerprint": "sha256:<deterministic-value>",
  "title": "Untrusted input reaches a SQL query",
  "status": "candidate",
  "severity": "high",
  "confidence": "medium",
  "category": "sast",
  "location": {
    "path": "src/example.ts",
    "start_line": 42,
    "end_line": 42
  },
  "taxonomy": {
    "cwe": "CWE-89",
    "owasp": "A03:2021"
  },
  "evidence": {
    "summary": "A request parameter is concatenated into a query string.",
    "redacted": true
  },
  "impact": "An attacker may alter the query if the route is reachable and no upstream validation applies.",
  "remediation": {
    "summary": "Use a parameterized query and validate the expected input shape.",
    "verification": "Run the relevant unit and integration tests and repeat the SAST rule."
  },
  "sources": [
    {
      "type": "scanner",
      "name": "semgrep",
      "rule_id": "example.sql-injection"
    }
  ],
  "review": {
    "human_reviewed": false,
    "rationale": "Reachability and upstream validation have not yet been confirmed."
  }
}
```

## Validation Rules

- A `validated` finding requires human review and sufficient evidence.
- Severity and confidence must not be merged into one value.
- A CVSS score must include its version and vector; an estimated score must say so.
- Secret values must never appear in `evidence`, logs, fingerprints, or reports.
- Repository paths must be relative and must not escape the analyzed root.
- A dependency finding must identify its ecosystem, package, installed version, and advisory source.
- Scanner errors, skipped checks, and incomplete coverage belong in run metadata, not as security findings.
