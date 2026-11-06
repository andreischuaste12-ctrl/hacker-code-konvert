# Privacy and Data Flow

## Default Data Flow

The MVP is local-first:

- repository inventory runs in the CLI process;
- selected Python files are copied to a temporary, read-only staging directory;
- Semgrep runs in a Bubblewrap sandbox with a separate network namespace;
- source files and raw scanner output are not retained;
- normalized reports are written only to the operator-selected output directory;
- AI processing, telemetry, and external uploads are disabled.

Semgrep receives bundled local rules, `--metrics=off`, and `SEMGREP_SEND_METRICS=off`. A run fails when the required networkless sandbox cannot be created.

## Stored Data

The output contains relative paths, scanner rule identifiers, redacted messages, tool versions, run configuration, limitations, and normalized findings. It does not intentionally contain source snippets, absolute repository paths, raw secrets, or raw scanner artifacts.

Output directories use mode `0700`; generated artifacts use mode `0600`. Operators remain responsible for storage, backups, access control, retention, and secure sharing after generation.

## Temporary Data

The CLI creates a temporary staging directory containing supported regular files only. It excludes target scanner configuration such as `.semgrepignore`. Temporary files are removed when the scanner finishes or fails.

Process termination or operating-system failure can leave temporary data subject to the host's temporary-file cleanup policy. Do not run the analyzer on a host whose administrators are not authorized to access the source.

## External Services

The MVP does not use an AI provider or hosted analysis service. Installing packages can contact the configured Python package index, but analysis itself is offline.

Any future remote mode must be opt-in and disclose the provider, destination, data classes, retention, telemetry, authentication, and deletion controls before execution. It must never silently fall back from local to remote processing.

## Sensitive Reports

Treat findings as confidential until reviewed and approved for disclosure. Share only through an authorized private channel. Delete obsolete raw or derived artifacts according to the applicable retention policy.
