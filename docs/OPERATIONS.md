# Operating version 0.2.0

Use Linux, Bubblewrap, libseccomp2 and Python 3.12/3.13. Keep the analyzer and scanner environments separate:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m venv /tmp/hck-semgrep
/tmp/hck-semgrep/bin/python -m pip install --require-hashes -r requirements-semgrep.txt
export PATH="/tmp/hck-semgrep/bin:$PATH"
```

The explicit online step `python scripts/install_external_tools.py --environment /tmp/hck-external`
installs Gitleaks 8.30.1 and OSV-Scanner 2.7.1 for Linux x86_64 after SHA256 verification. Add that
`bin` directory to PATH. No download happens during `hck scan`.

```bash
hck scan /authorized/repo --scope-file /private/scope.json --output /tmp/hck-report
hck scan /authorized/repo --authorized --scanner gitleaks --output /tmp/hck-secrets
hck scan /authorized/repo --authorized --scanner osv-scanner \
  --offline-database /private/osv-database --output /tmp/hck-dependencies
```

The authorization file is JSON (a valid YAML subset); see `examples/scope.json`. The CLI checks the exact
root, responsible party, reference, timezone-aware validity interval and records the file hash. It cannot
independently authenticate a contract or grant permission. `--authorized` remains available for local work.

Gitleaks scans bounded regular files from the inventory, without Git history or target ignore/config files.
OSV accepts supported lockfiles only, disables resolution and call analysis, and mounts the database
read-only. Prepare the database in a separate explicit online step:

```bash
python scripts/update_osv_database.py --ecosystem npm --output /private/osv-database
```

This downloads the official ecosystem archive over verified HTTPS and writes a timestamped SHA256
provenance record; no repository dependencies are sent. It is never called by the analyzer. You may also
prepare `<database>/osv-scalibr/<ecosystem>/all.zip` using
OSV's official database distribution. Preserve its source, retrieval time and checksums. Do not use
`--download-offline-databases` in analysis. Without offline mode, OSV would disclose dependency names;
this adapter never enables that mode. An unsupported or absent database makes the scan fail.

The Go scanners default to a 16 GiB virtual-address-space ceiling to accommodate runtime/WASM reservation;
GOMEMLIMIT=512MiB and GOMAXPROCS=1 reduce runtime memory and concurrency. Address space is not resident RAM.
The Python/Semgrep default remains 4 GiB; override with `--memory-mb` when needed.

## Signed review and disclosure draft

A human reviewer must inspect all gates, risk and remediation before signing. Use an existing trusted SSH
key; keep its private component outside this repository. The allowed-signers file is an operator-owned
trust root and must never come from the analyzed repository or finding document.

```bash
ssh-keygen -Y sign -f /private/reviewer-key -n hck-review /private/findings.json
hck validate /private/findings.json --signature /private/findings.json.sig \
  --allowed-signers /private/allowed-signers --reviewer reviewer@example.org
hck report draft /private/findings.json --signature /private/findings.json.sig \
  --allowed-signers /private/allowed-signers --reviewer reviewer@example.org \
  --output /private/new-advisory-draft.md
```

The allowed-signers line has the form `reviewer@example.org ssh-ed25519 AAAA...`. Verification covers the
exact document bytes, namespace and identity. Schema-valid `validated`/`accepted_risk` findings require a
valid signature through the CLI. Signatures establish provenance, not the correctness of human reasoning.
Draft generation never sends a message and requires a new output filename.

## Release and repository configuration

`examples/main-ruleset.json` is a reviewable GitHub ruleset requiring PR review, both matrix checks, signatures
and no force-push/deletion. Apply it with repository administrator access after validating workflow context
names. Enable private vulnerability reports, secret scanning/push protection (subject to account support),
read-only Actions tokens and external contributor workflow approval in GitHub settings.

A host may delegate a cgroup-v2 directory and set `HCK_CGROUP_PARENT=/sys/fs/cgroup/...` plus
`HCK_TASKS_MAX=64`. The per-run child limit is applied before scanner execution and removed afterward.
Without a delegation, the report explicitly says the PID limit was not enforced. Do not point this
setting at a parent used by unrelated tasks.

The release workflow is manual. Configure environments `release` and `pypi`, PyPI Trusted Publishing for
this repository/workflow/environment, and the public-key-only variable `HCK_RELEASE_ALLOWED_SIGNERS`.
Create and push `v0.2.0` with the maintainer's trusted SSH signing key, then dispatch Release on that tag.
The job verifies the tag, builds wheel/sdist, creates SBOM documents and provenance, attaches release
artifacts and publishes through OIDC. No signing key or PyPI credential is embedded in this repository.

CodeQL and Scorecard workflows are committed. Their execution and security-event upload still depend on
repository plan, permissions and settings. Scorecard publishes repository security metadata to OpenSSF.

## Audit follow-up controls

Gitleaks extends the vendor's default rules in the pinned binary plus the project rule. The configuration
hash identifies the extension, and the binary version identifies vendor defaults; the report does not
pretend the one custom rule is the complete vendor rule count. Neutral filenames preserve extensions.
Filename-dependent vendor rules may still differ from scanning an original directory layout; tests cover
seven synthetic formats and cannot prove universal secret detection.

OSV accepts `requirements*.txt` with fixed `==` versions, `go.mod`, `pom.xml`, `gradle.lockfile` and the
supported lockfiles. A requirements file with includes, options or version ranges cannot be matched
offline: it is reported as a coverage gap (`partial_coverage`, exit status `3`) and the other dependency
files are still analyzed. Dependency files may be up to 32 MiB by default (`--max-file-bytes`).
Archive SHA256 values, an aggregate identity, retrieval timestamps and database age are recorded. Missing
provenance produces an explicit freshness limitation, a digest mismatch fails the scan, and the default
staleness warning threshold is configurable with `--max-database-age-days` (30). These metadata records
are audit evidence, not independently authenticated signatures on the upstream database.

CVSS 3.x vectors and numeric scores determine OSV severity; database-specific severity labels are a
fallback. Unsupported/missing scores are marked unassessed and require human assessment, rather than
silently receiving medium severity. SARIF uses the package version and includes rule descriptions.

The release build job has only read access and checkout credentials are not persisted. Artifact
attestation/release creation uses a separate privileged job which does not install project dependencies
or execute downloaded artifacts. Configure the public allowed-signers variable at repository level for
read-only tag verification in the build job.

The sample main ruleset permits administrators to bypass requirements **only through pull requests**.
This prevents the sole maintainer from being locked out by an impossible self-approval requirement while
keeping direct-push/force-push restrictions. Review that tradeoff before applying the template.
