# Quality and Measurement

Hacker Code Konvert treats a scanner match as a candidate, not as a confirmed vulnerability. Quality
measurement therefore covers both detection and the evidence required for validation.

## Current fixture baseline

The first synthetic fixture exercises the bundled Python `eval` rule. It contains one intentionally
vulnerable file and one safe file using `ast.literal_eval`. The vulnerable line also contains a
`nosemgrep` comment and the fixture contains a `.semgrepignore`; both cases verify that repository
content cannot silently suppress the controlled rule set.

The CI job compares normalized findings with `tests/fixtures/python/expected.json` and publishes a
redacted `quality.json` artifact. For this deliberately small fixture, the required regression baseline
is:

| Metric | Required value |
| --- | ---: |
| Expected findings detected (recall) | 100% |
| Reported findings expected (precision) | 100% |
| Schema-valid normalized findings | 100% |
| Scanner and sandbox failures in CI | 0 |

These values only describe the checked fixture. They are not estimates of performance on arbitrary
repositories and must not be presented as a universal detection rate.

## Adding coverage

Each new supported language or rule category must add at least one intentionally vulnerable fixture,
one nearby safe example, and an expected-result entry. Prefer minimal synthetic code with no real
credentials or third-party source. Record false positives as test cases before changing rules.

Run the same measurement used by CI:

```bash
python scripts/evaluate_fixture_quality.py \
  --findings /tmp/hck-report/findings.json \
  --expected tests/fixtures/python/expected.json \
  --output /tmp/hck-report/quality.json
```

## Operational indicators

For repeated internal runs, track scanner completion rate, sandbox failures, skipped or oversized files,
schema completeness, candidate-to-validated conversion, false-positive rate after review, and median time
to remediation. Compare only runs with the same tool, rule-set, and project revision. Reports include
those versions so that results can be reproduced and differences can be explained.
