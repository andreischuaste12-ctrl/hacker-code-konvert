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
- Files are checked again immediately before copying to reduce path-swap risk.
- The staged tree is made read-only before scanner execution.

## Process Boundary

Semgrep runs through Bubblewrap with:

- a new user, mount, PID, IPC, UTS, cgroup, and network namespace;
- only the staged target, bundled rule file, scanner runtime, and required system libraries mounted read-only;
- no stdin;
- a temporary home and temporary directory;
- a fixed argument array without shell interpolation;
- CPU time, address-space, open-file, output-size, and wall-clock limits;
- metrics and version checks disabled.

If Bubblewrap or the required namespaces are unavailable, the scanner fails closed. There is no automatic unsandboxed fallback.

The GitHub Actions job runs on a dedicated ephemeral Ubuntu runner. It explicitly enables unprivileged
user namespaces when the runner exposes the relevant kernel controls, then exercises the complete
Bubblewrap path. This runner configuration is limited to CI and does not weaken the CLI's fail-closed
behavior on an operator's machine.

## Suppression Resistance

The adapter supplies bundled rules, stages no `.semgrepignore`, disables Git ignore handling, and passes `--disable-nosem`. Tests include both a target `.semgrepignore` and an inline `nosemgrep` comment and require the synthetic candidate to remain visible.

Future OSV-Scanner and Gitleaks adapters must use tool-owned configuration and isolated staging. They must prove through fixtures that target-controlled ignore files cannot silently suppress results.

## Network Policy

Network access is disabled for scanner execution. Future scanners that require vulnerability databases must use an explicitly prepared local database or a separate, disclosed update step. Analysis must not silently enable network access.

## Output Handling

Scanner stdout and stderr are written to bounded temporary files. Oversized, timed-out, malformed, or nonzero runs are marked incomplete. Raw output is discarded after normalization, and error text is redacted before reporting.

## Known Limits

- Files can still change concurrently between inventory and staging; type, root, and size are rechecked, but the MVP does not snapshot the filesystem.
- Bubblewrap depends on Linux kernel namespace support and local security policy.
- The initial rule pack is intentionally small and does not provide comprehensive Python coverage.
