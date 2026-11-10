# Quality and Measurement

Hacker Code Konvert treats a scanner match as a candidate, not as a confirmed vulnerability. Quality
measurement therefore covers both detection and the evidence required for validation.

## Corpora

| Corpus | Content | Matching |
| --- | --- | --- |
| `tests/fixtures/python` | One vulnerable and one safe neighbor for each of the 19 Python rules, plus suppression attempts (`nosemgrep`, a target `.semgrepignore`, code under `tests/`) | rule and file |
| `tests/fixtures/php` | One vulnerable and one safe neighbor for each of the 14 PHP rules, with WordPress and WooCommerce sinks and escaping functions | rule and file |
| `tests/fixtures/mixed` | Common vulnerable patterns written during an independent audit, before the rules were extended | rule, file and line |

All content is synthetic. The first two corpora were written together with the rules, so they can only
show regressions. The mixed corpus was not written to fit the rules and is the more honest signal.

## Required baseline

CI scans every corpus through the real sandbox and compares normalized findings with `expected.json`:

| Metric | Required value |
| --- | ---: |
| Expected candidates detected | 100% |
| Reported candidates expected | 100% |
| Schema-valid normalized findings | 100% |
| Scanner and sandbox failures | 0 |

`expected.json` may list `known_gaps`: vulnerable patterns the rules are known to miss. They are not
counted as detected, `quality.json` reports recall with and without them, and the measurement fails if a
known gap starts being detected, so that the corpus and this document change together.

Current known gap (mixed corpus, 28 of 29 patterns detected): a shell command reached through
`__import__("os").system(...)`.

These values describe the checked corpora. They are not estimates of performance on arbitrary
repositories and must not be presented as a detection rate.

## What the rules do not cover

- Languages other than Python and PHP. Their files are counted in the inventory and named in the run
  limitations, and a repository without any supported source file gives an incomplete run.
- Flows across files or through frameworks the rules do not model. Taint rules follow data within a file.
- Business-logic flaws: missing nonce or capability checks are surfaced only as review candidates
  (public AJAX handlers, permissive REST routes, request data written to options or user data).

## Adding coverage

Each new rule adds at least one vulnerable fixture, one nearby safe example, and an expected-result entry.
Prefer minimal synthetic code with no real credentials or third-party source. Record a false positive as
a safe fixture before changing a rule.

```bash
hck scan tests/fixtures/php --output /tmp/hck-report --authorized
python scripts/evaluate_fixture_quality.py \
  --findings /tmp/hck-report/findings.json \
  --expected tests/fixtures/php/expected.json \
  --output /tmp/hck-report/quality.json
```

## Engineering gates

CI runs Python 3.12 and 3.13 with mandatory sandbox and scanner integrations (a missing prerequisite is a
failure, not a skip), strict mypy, lint, dependency audits, and a 95% branch-coverage gate. Only the
child-process resource-limit setter and pre-exec hook are excluded from coverage instrumentation; process
behavior is tested through timeouts, output limits and probes executed inside the real sandbox.

## Operational indicators

For repeated internal runs, track scanner completion rate, sandbox failures, skipped or oversized files,
candidate-to-validated conversion, false-positive rate after review, and median time to remediation.
Compare only runs with the same tool, rule-set, and project revision; reports include those versions.
