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
- npm publish: enabled with public access and provenance

Pull requests that affect release metadata run `.github/workflows/release-dry-run.yml`, which installs npm 11.5.1 and ReleaseBox, checks readiness and the publication configuration, runs release checks plus `npm publish --dry-run`, and previews generated release notes.

For tag releases, the tag must exactly equal `v` plus the `version` from
`package.json`. The release job validates this relationship before packaging;
the dry-run workflow exercises the same check with the current package version.

Before pushing a version tag, configure npm trusted publishing for package
`mcpperm` with repository `rogerchappel/mcpperm` and workflow
`.github/workflows/release.yml`. No `NPM_TOKEN` is used. The tag workflow grants
only `contents: write` and `id-token: write`, validates the tag and release
configuration, runs the release checks, packs and publishes the package with
provenance, generates notes, and creates the GitHub release last. This ordering
prevents a GitHub release from advertising a package that was not published.

## Review Expectations

Each pull request should include:

- user-visible CLI or policy behavior changed
- fixtures or tests covering the change
- verification commands run locally
- risk level and rollback notes

High-risk permission classification changes need explicit maintainer review because they can alter CI pass/fail behavior for downstream users.
