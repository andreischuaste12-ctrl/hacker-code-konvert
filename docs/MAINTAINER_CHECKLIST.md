# Repository Hardening Checklist

These controls are configured in GitHub settings and cannot be enforced by files in the repository. They are
listed so the owner can verify them. Last reviewed in the repository: 2026-11-07. The settings themselves were
not inspected when this file was written; confirm each one.

## Required before inviting contributors or publishing a release

- [ ] **Branch protection or ruleset on `main`:** require a pull request, require the `CI` check to pass,
      block force pushes and deletion. `.github/CODEOWNERS` only has an effect once code-owner review is
      required.
- [ ] **Signed commits** required on `main`, with a signing key registered for the maintainer account.
- [ ] **Private vulnerability reporting** enabled (Settings, Code security). `SECURITY.md` links to it as the
      preferred channel; the link does not work for reporters while it is disabled.
- [ ] **Secret scanning and push protection** enabled.
- [ ] **Two-factor authentication** (preferably a hardware key or passkey) on every account with write access.
- [ ] **Actions permissions:** default workflow token set to read-only; require approval for workflows from
      outside collaborators and for first-time contributors.
- [ ] **Dependabot alerts** enabled, so advisories surface even without a pull request.

## Contact points

- [ ] Publish a monitored contact for conduct reports (see `CODE_OF_CONDUCT.md`) and a backup contact, so a
      report about the sole maintainer has somewhere to go.
- [ ] Consider using the GitHub `noreply` commit address if the personal address should not appear in public
      history.
