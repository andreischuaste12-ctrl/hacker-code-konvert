# Dependencies and Supply Chain

## Runtime and development

The `hck` package has no runtime dependencies. Semgrep is an optional extra (`.[semgrep]`) that runs as a
separate process inside the sandbox. `requirements-dev.txt` is the complete development lock for Python 3.12.
It is generated, not edited by hand:

```bash
uv pip compile pyproject.toml --extra semgrep --extra dev --python-version 3.12 \
  --generate-hashes --output-file requirements-dev.txt
```

CI installs it with `pip install --require-hashes`, builds without network access to a build backend
(`--no-build-isolation`, `setuptools` is part of the lock), and runs `pip-audit` on every push, pull request,
and weekly. To upgrade one package, add `--upgrade-package <name>` to the command above and review the diff.

## Accepted advisories

`semgrep==1.184.0` (the newest release when this was written) pins `mcp==1.29.0` and
`opentelemetry-api~=1.37.0`. Fixed versions of those packages cannot be installed until Semgrep publishes a
release that allows them; the resolver rejects every combination. The advisories below are therefore accepted,
explicitly listed in `.github/workflows/ci.yml`, and limited to the conditions stated here.

| Advisory | Package | Affected behavior | Why it is not reachable here |
| --- | --- | --- | --- |
| CVE-2026-59951 | `mcp` 1.29.0 | Unbounded session state in an MCP Streamable HTTP *server* | `hck` never starts an MCP server; Semgrep runs once as a CLI process with no network |
| CVE-2026-116684 | `mcp` 1.29.0 | MCP server bearer-token audience not checked | No MCP server or authentication is used |
| CVE-2026-116685 | `mcp` 1.29.0 | MCP *client* follows cross-origin redirects with custom headers | No MCP client connection is made |
| CVE-2026-116686 | `mcp` 1.29.0 | MCP *client* resolves remote `$ref` in tool output schemas | No MCP client connection is made |
| CVE-2026-114603 | `opentelemetry-api` 1.37.0 | Quadratic parsing of an inbound W3C `tracestate` header | No HTTP server receives trace headers; metrics and telemetry are disabled, and the scanner has no network |

These packages are present only as transitive dependencies of Semgrep. The assessment is the maintainers'
reading of the advisory descriptions and of how the CLI invokes Semgrep, not a guarantee.

Review date: 2026-11-07. Remove an entry (and its `--ignore-vuln` flag) as soon as a Semgrep release allows the
fixed version, or earlier if Semgrep starts using the affected feature. Re-run `pip-audit` without the ignore
flags when upgrading Semgrep.

## Automatic update pull requests

Dependabot is configured not to open version-update pull requests for packages that Semgrep pins
(`mcp`, `opentelemetry-*`, `jsonschema`, `peewee`, `wcmatch`, `wrapt`): such a pull request cannot pass until
Semgrep is upgraded. Security updates are unaffected by that list. Pull requests that were opened before this
configuration existed can be closed once this change is merged.

## Actions

Workflow actions are pinned by commit SHA. Dependabot proposes SHA updates; review the upstream release notes
before merging.
