# MCPPerm Orchestration

## Local Flow

1. Install dependencies with `npm ci`.
2. Run `npm run check` during implementation.
3. Run `npm test` before committing behavioral changes.
4. Run `npm run release:check` before opening or updating a pull request.
5. Run `bash scripts/validate.sh` for repository-level checks.

## ReleaseBox Flow

ReleaseBox is configured in `releasebox.config.json` for a reviewed Node CLI release:

- package manager: `npm`
- smoke checks: `npm test`, `npm pack --dry-run`
- GitHub release creation: enabled
- npm publish: disabled

Pull requests that affect release metadata run `.github/workflows/release-dry-run.yml`, which installs ReleaseBox, checks readiness, runs release checks, and previews generated release notes.

## Review Expectations

Each pull request should include:

- user-visible CLI or policy behavior changed
- fixtures or tests covering the change
- verification commands run locally
- risk level and rollback notes

High-risk permission classification changes need explicit maintainer review because they can alter CI pass/fail behavior for downstream users.
