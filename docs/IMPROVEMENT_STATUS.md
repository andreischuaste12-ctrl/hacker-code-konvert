# Requested improvements: implementation status

This is an evidence-based status, not a numerical security rating. Version 0.2.0 does not claim exhaustive detection.

| Request | Delivered or remaining dependency |
| --- | --- |
| 1. GitHub hardening | Ruleset JSON and maintainer instructions prepared; administrative API returned Forbidden, settings not applied |
| 2. Close five Dependabot PRs | The latest external review reports the older PRs closed; this agent still lacks administrative API access to verify or change them |
| 3. Version 0.2.0 | Package/changelog updated and wheel/sdist built; signed tag/release requires the maintainer's signing key |
| 4. Rule visibility | IDs, count, SHA256 and explicit limitations in run/Markdown output |
| 5. Filename staging | Neutral names; original path, escaped display and byte-hex roundtrip, including invalid UTF-8 |
| 6. Python coverage | Twelve original classes, expanded framework/environment taint sources and shell sinks, nonsecurity-hash exclusions, positive/negative corpus |
| 7. Gitleaks | Sandboxed directory-only adapter, pinned vendor defaults plus controlled extension/empty ignore, redaction, seven-format corpus |
| 8. OSV | Offline fixed requirements/manifests/lockfiles, archive SHA256 and verified freshness metadata, no resolution, synthetic database tests |
| 9. SARIF | Local SARIF 2.1.0 output, OASIS schema validation |
| 10. Seccomp | Architecture-aware seccomp, nested-userns prevention, modern mount/io_uring and VSOCK/KEY restrictions, real sandbox probes |
| 11. Restrict /etc | Narrow read-only files including required CA bundle; shadow absent in sandbox probe |
| 12. Single-pass staging | CLI inventories and captures file bytes in one descriptor-relative pass; scanners consume that private capture, not the changing repository |
| 13. Root execution | Explicit run limitation when euid=0 |
| 14. Process cgroup | Optional delegated cgroup-v2 pids.max via HCK_CGROUP_PARENT/HCK_TASKS_MAX; fail-closed configuration checks; no writable delegated cgroup available for kernel integration here |
| 15. Strict types | Strict mypy succeeds and runs in CI |
| 16. Error paths/coverage | Process failures, schema failure, FIFO, unreadable directories, validate success, module entry and 95% branch-coverage CI gate |
| 17. Python matrix | Universal hash locks, CI 3.12/3.13 |
| 18. Property tests | Hypothesis tests redaction boundedness/idempotence, paths, Markdown and Git IDs |
| 19. Reproducibility | Rule hash, Python/Bubblewrap/scanner versions and actual staged file hashes |
| 20. Separate Semgrep | Independent hash-pinned scanner and development environments |
| 21. Release pipeline | Read-only builds without persisted credentials; separate privileged attestation/release job and OIDC publishing; external trust/settings remain manual |
| 22. CodeQL/Scorecard | Pinned workflows committed; hosted execution must be confirmed after push |
| 23. Scanner advisory review | Existing five scanner-only exceptions retained; CI audits development separately and scanner weekly |
| 24. Scope file | Explicit root, responsible party, reference, active window and hash; JSON/YAML subset, not legal authentication |
| 25. Signed human review | SSH verification against operator-owned trusted signers; tamper/untrusted-identity tests |
| 26. Skill evaluation | Deny-settings example, evaluation scenarios, executable authorization/injection/partial-coverage regression tests; no skill-creator runtime available here |
| 27. Private draft | Signed validated findings produce a local draft, without sending or overwriting an existing file |
| 28. E-commerce | Three original PHP patterns with positive/negative corpus; public AJAX registration is a review candidate, not proof of missing authorization |

Outstanding infrastructure actions must be completed by an administrator with the relevant access and
signing identity. Concurrent in-place writes and host-dependent delegated PID limits remain explicit technical
limitations. See OPERATIONS.md before enabling release publication or applying repository rules.

## Follow-up to the audit of `dccd0b2`

| Finding | Status |
| --- | --- |
| Inline `gitleaks:allow` suppressed secrets | Fixed: `--ignore-gitleaks-allow`, regression test with the real scanner |
| An empty `.git` file hid a directory with a complete run | Fixed: nested repositories make the run incomplete |
| A PHP file starting with the Git LFS version line was skipped | Fixed: only a file matching the whole pointer grammar is a pointer |
| Source files with other suffixes or no suffix were ignored silently | Fixed: selection by suffix, interpreter line or leading PHP tag; unsupported languages are named; nothing to analyze is incomplete |
| Low recall of the bundled rules | Improved: 33 rules with per-rule fixtures and a line-level corpus written before the rules; one documented gap |
| One oversized or unpinned dependency file failed the whole OSV run | Fixed: per-file gaps, 32 MiB default for dependency files, per-file isolation of parse failures |
| Dependency findings lacked package, version and fix | Fixed |
| Writable tmpfs mounts were limited only by host memory | Fixed: size caps, read-only root and `/dev` |
| No process limit without a delegated cgroup | Fixed for non-root users on Linux 5.14+; recorded as a limitation elsewhere |
| `false_positive` needed no reviewer or signature | Fixed in the validator, the JSON Schema and the CLI |
| Gitleaks and OSV coverage was asserted | OSV coverage is measured per file; Gitleaks coverage is proven by a canary and otherwise reported as unknown |
| Socket filter bypass through upper register bits | Fixed: only `AF_UNIX` is allowed |
| Two inventory implementations | Fixed: one capture implementation, used by the CLI and the tests |
| Unprotected `main`, no signed release | Open: requires the repository administrator and the maintainer's signing key (see OPERATIONS.md) |

## Follow-up to the audit of `e6971e2`

All eight reproduced findings are addressed in the working implementation: context-specific URL
attribute checks and conservative SQL/SSRF sanitizers; invalidation of stale run markers with
serialized report writers; LFS gaps for every secret-scan input; bounded traversal and capture
deadlines; controlled database provenance errors; and verified linked-worktree metadata support.
The rule pack now has 34 rules (19 Python, 15 PHP). Regression fixtures include the audit's escaped
SQL expression, HTML URL attribute and encoded outbound hostname, with safe neighboring inputs.

The copyright notice identifies Andrei Schuaste, including the LICENSE appendix example.
Administrative GitHub settings, release signing identity, accepted scanner dependency advisories,
and the documented limits of static analysis remain operational prerequisites, not properties that
these source changes can certify or eliminate.
