# Scanner Isolation Contract

## Threat Model

The analyzed repository, scanner configuration, file names, source code, comments, documentation, and scanner output are untrusted. They may attempt path traversal, resource exhaustion, result suppression, prompt injection, or secret exposure.

## Capture and Selection

The CLI inventories the repository and captures the selected files in one descriptor-relative pass. Each directory is opened relative to its parent with `O_NOFOLLOW`, and file bytes are read through the descriptor used for classification. Scanners only ever read that private capture, staged under neutral names (`f000001.py`); the original path is preserved in the finding as text, escaped display form and byte hex.

Selection is part of the coverage contract, because a file that is not selected is not analyzed:

- **Source files (Semgrep).** A file is Python or PHP when its suffix says so (`.py`, `.pyw`, `.php`, `.phtml`, `.pht`, `.phps`, `.php3`–`.php8`, `.inc`), when it starts with a `python` or `php` interpreter line, or when it starts with a PHP opening tag. Each is staged under the canonical suffix of its language so the scanner cannot disagree with the selection. Code kept in any other file is not analyzed, and every Semgrep run states that limitation.
- **Dependency files (OSV-Scanner).** Supported lockfiles and `requirements*.txt`.
- **Secrets (Gitleaks).** Every captured regular file.

Anything the scanner will not see is recorded in `inventory.skipped`. Entries that hide content the scanner needed make the run incomplete (`complete: false`, exit status `3`):

| Situation | Recorded | Run incomplete |
| --- | --- | --- |
| Directory containing `.git` (nested repository, submodule, or a planted marker) | yes | yes |
| Unreadable file or directory, depth/count limit, per-file or total size limit | yes | yes |
| Git LFS pointer in place of a source or dependency file | yes | yes |
| Git LFS pointer in place of any other file | yes | yes for Gitleaks; no for source/dependency-only scans |
| Symbolic link, FIFO, socket or device | yes | no |
| Semgrep selected, but no supported source file found | error | yes |

A Git LFS pointer is recognized only when the whole file matches the pointer grammar. A file that merely starts with the pointer version line is ordinary content and is analyzed.

Other rules of the capture:

- Git filters are not executed; `.git` is never read by a scanner.
- Target `.semgrepignore`, `.gitignore`, `.gitleaksignore`, scanner configuration, and dependency scripts are never used.
- This is a file-level capture, not an atomic multi-file snapshot: a writer can still modify a file in place while it is being read. Use an immutable checkout for reproducible analyses.
- Defaults: 10,000 files, depth 64, 256 MiB captured in total, 1 MB per file (32 MiB per dependency file with OSV-Scanner). All are configurable.

## Process Boundary

Every scanner runs through Bubblewrap with:

- new user, mount, PID, IPC, UTS, cgroup, and network namespaces, with all capabilities dropped and nested user namespaces disabled;
- a read-only filesystem: the staged target, the bundled rule file, `/usr`, `/bin`, `/lib`, `/lib64`, the loader cache, the time zone and the CA bundle are mounted read-only, and the sandbox root and `/dev` are remounted read-only. `/etc/passwd`, `/etc/group`, `/etc/shadow` and the rest of `/etc` are absent;
- writable space only on size-capped tmpfs mounts: `/tmp` (256 MiB), `/home` (16 MiB) and `/dev/shm` (64 MiB). These caps bound the memory a scanner can consume through files;
- only the runtime the scanner needs: a Python virtual environment, a Python installation prefix, or the scanner's own directory under `/opt`. `/opt` is never mounted as a whole, and any other layout fails closed rather than exposing the surrounding directory (such as a home directory);
- a seccomp filter generated with libseccomp. It denies every socket family except `AF_UNIX` (the comparison covers the full register, so setting upper bits does not bypass it), namespace creation and entry, the classic and modern mount APIs, `io_uring`, kernel module and kexec interfaces, `ptrace`, cross-process memory access, `bpf`, `userfaultfd`, key management and `perf_event_open`. It remains a denylist for everything else. Names the installed libseccomp cannot express are listed in `run.json` and as a limitation;
- a process and thread limit (`RLIMIT_NPROC`, 256) applied by `prlimit` after the user namespace exists, where the kernel counts only the sandbox. It requires Linux 5.14 or later, a non-root user and `prlimit`; otherwise the run records that no process limit was enforced. A delegated cgroup (`HCK_CGROUP_PARENT`, `HCK_TASKS_MAX`) adds a `pids.max` limit that also applies to root;
- no stdin, a fixed argument array without shell interpolation, and CPU time, address-space, open-file, output-size, and wall-clock limits;
- metrics and version checks disabled, including for the host-side version probe.

If Bubblewrap, libseccomp or the required namespaces are unavailable, the scanner fails closed. There is no unsandboxed fallback. `controls` and `scanner.sandbox` in `run.json` describe the isolation that was actually started.

The GitHub Actions job runs on an ephemeral Ubuntu runner and explicitly enables unprivileged user namespaces there so the complete sandbox is exercised. That runner configuration does not weaken the fail-closed behavior on an operator's machine.

## Suppression Resistance

Content of the analyzed repository cannot suppress results:

- **Semgrep:** bundled rules only, a tool-owned empty `.semgrepignore`, `--no-git-ignore`, and `--disable-nosem`.
- **Gitleaks:** tool-owned configuration, a tool-owned empty ignore file, and `--ignore-gitleaks-allow`, so inline `gitleaks:allow` comments are not honored. Directory mode only: Git history, textconv and external diff drivers are never invoked.
- **OSV-Scanner:** only the staged dependency files and the operator's read-only offline database.

Tests place a target `.semgrepignore`, inline `nosemgrep` and `gitleaks:allow` comments, target scanner configuration, and vulnerable code under `tests/` directories, and require every synthetic candidate to remain visible.

## Coverage Verification

A run is complete only when coverage was demonstrated, not assumed.

- **Semgrep** reports the files it analyzed. The adapter compares `paths.scanned` with the staged files and surfaces `paths.skipped` and `errors[]`. Any gap gives `partial_coverage`.
- **OSV-Scanner** lists every package it extracted (`--all-packages`). A dependency file from which no package was extracted, a file the scanner could not parse, a file that was not captured, and a requirements file with unpinned entries are each a gap. One unreadable lockfile does not discard the others: the adapter re-runs the remaining files individually and keeps their results.
- **Gitleaks** does not report per-file coverage, so `files_scanned` is `null` and the report says so. The adapter stages a tool-owned canary credential and requires the bundled rule to report it; a run without the canary fails. This proves that the rules ran on the staged tree, not that every file type was inspected: vendor allowlists for file types and placeholder values still apply.

Findings produced by a partially covered run are still reported.

## Network Policy

Network access is disabled for scanner execution. OSV-Scanner uses an explicitly prepared local database; preparing it is a separate, disclosed step that the analyzer never performs.

## Output Handling

Scanner stdout and stderr are written to bounded temporary files. Oversized, timed-out, malformed, or nonzero runs are marked incomplete. Raw output is discarded after normalization. Text taken from scanner output or from an advisory database is redacted, reduced to one bounded line, and stripped of control and bidirectional characters. Redaction is a best-effort safety net: it bounds its own input and uses bounded patterns so hostile output cannot cause catastrophic backtracking, but it cannot recognize every secret format.

## Known Limits

- Total memory is bounded per process (address space) and for files (tmpfs caps), not as a sum across processes. Without a process limit or a delegated cgroup, a scanner can still exhaust memory or the process table for the duration of the timeout.
- Seccomp denies specific interfaces; it is not an exhaustive system-call allowlist.
- The read-only system directories (`/usr`, `/bin`, `/lib`, `/lib64`) are visible to the scanner.
- Bubblewrap depends on Linux kernel namespace support and local security policy.
- The bundled rules are a small, reviewed set. A completed run means the requested checks finished on the selected files, not that the repository is secure.

## Capture and report publication limits

Capture has its own wall-clock deadline, using `--timeout`, before scanner execution starts.
The traversal budget is twice `--max-files` and counts every directory entry, including links,
special files and ignored directories. Directory enumeration is bounded before sorting. Exceeding
this budget or deadline aborts capture with an explicit scope error; no complete scan is reported.
As with ordinary filesystem I/O, a stalled kernel/filesystem read cannot be interrupted by a
cooperative deadline; scan local immutable checkouts for predictable behavior.

Report writers lock the output directory and remove the previous `run.json` before replacing
artifacts. `run.json` is published last. A failed overwrite leaves no completion marker. Consumers
must require that marker and must not read while a writer is active; readers needing a stable set
should take a shared flock on the output directory or use a separate output directory per run.
