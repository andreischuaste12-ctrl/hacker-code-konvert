# Scanner Isolation Contract

## Threat Model

The analyzed repository, scanner configuration, file names, source code, comments, documentation, and scanner output are untrusted. They may attempt path traversal, resource exhaustion, result suppression, prompt injection, or secret exposure.

## Staging Boundary

The external scanner never receives the original repository root. The CLI creates a controlled temporary tree containing only supported regular files that passed scope and size checks.

- Symlinks are recorded and not followed.
- Nested repositories and submodules are recorded and not traversed.
- Git LFS pointers are reported as unavailable content.
- Git filters are not executed.
- Target `.semgrepignore`, `.gitignore`, scanner configuration, and dependency scripts are not copied.
- The staged root carries a tool-owned, empty `.semgrepignore`. Without it Semgrep applies built-in default ignores (for example `tests/` and `test/`), which would skip code silently.
- Each file is opened with `O_NOFOLLOW`, re-checked as a regular file under the repository root and within the size limit, and copied from the open descriptor, which closes most path-swap races.
- Unreadable files are recorded as skipped in the inventory instead of aborting the run.
- The staged tree is made read-only before scanner execution.

## Process Boundary

Semgrep runs through Bubblewrap with:

- a new user, mount, PID, IPC, UTS, cgroup, and network namespace, with all capabilities dropped (`--cap-drop ALL`), including when the CLI runs as root;
- only the staged target, bundled rule file, scanner runtime, and required system libraries mounted read-only. The scanner must live under `/usr` or `/opt`, or inside a Python virtual environment; any other layout fails closed rather than exposing the surrounding directory (such as a home directory). The host `/etc` is mounted read-only for runtime configuration;
- no stdin;
- a temporary home and temporary directory;
- a fixed argument array without shell interpolation;
- CPU time, address-space, open-file, output-size, and wall-clock limits;
- metrics and version checks disabled, including for the host-side `semgrep --version` probe.

If Bubblewrap or the required namespaces are unavailable, the scanner fails closed. There is no automatic unsandboxed fallback.

The GitHub Actions job runs on a dedicated ephemeral Ubuntu runner. It explicitly enables unprivileged
user namespaces when the runner exposes the relevant kernel controls, then exercises the complete
Bubblewrap path. This runner configuration is limited to CI and does not weaken the CLI's fail-closed
behavior on an operator's machine.

## Suppression Resistance

The adapter supplies bundled rules, stages only a tool-owned empty `.semgrepignore`, disables Git ignore handling, and passes `--disable-nosem`. Tests include a target `.semgrepignore`, an inline `nosemgrep` comment, and vulnerable code under `tests/` directories, and require every synthetic candidate to remain visible.

## Coverage Verification

Suppression resistance is not enough on its own: the run must also prove what was analyzed. After each Semgrep run the adapter compares the files reported in `paths.scanned` with the files the inventory selected, and it surfaces `paths.skipped` and `errors[]` from Semgrep's JSON. Any gap marks the scanner status `partial_coverage`, makes the run incomplete (`complete: false`, exit status `3`), and lists the affected paths in the report. Findings that were produced are still reported. Semgrep error messages can quote source code, so only the error type and the repository-relative path are copied.

Future OSV-Scanner and Gitleaks adapters must use tool-owned configuration and isolated staging. They must prove through fixtures that target-controlled ignore files cannot silently suppress results.

## Network Policy

Network access is disabled for scanner execution. Future scanners that require vulnerability databases must use an explicitly prepared local database or a separate, disclosed update step. Analysis must not silently enable network access.

## Output Handling

Scanner stdout and stderr are written to bounded temporary files. Oversized, timed-out, malformed, or nonzero runs are marked incomplete. Raw output is discarded after normalization. Error text is reduced to a bounded excerpt, redacted, and stripped of control and bidirectional characters before reporting. Redaction is a best-effort safety net: it bounds its own input (32 KiB per call) and uses bounded patterns so hostile output cannot cause catastrophic backtracking, but it cannot recognize every secret format.

## Known Limits

- Files can still change concurrently between inventory and staging; each file is reopened without following symlinks and rechecked, but the MVP does not snapshot the filesystem.
- No seccomp filter is applied, and no process-count limit is set (a per-user `RLIMIT_NPROC` could break unrelated processes). Isolation relies on namespaces, dropped capabilities, read-only mounts, and the resource limits above.
- The `controls` recorded in `run.json` describe the isolation that was actually started (`scanner_isolation`); runs that never started a sandbox record `not_used` or `not_applicable`.
- Bubblewrap depends on Linux kernel namespace support and local security policy.
- The initial rule pack is intentionally small and does not provide comprehensive Python coverage.
