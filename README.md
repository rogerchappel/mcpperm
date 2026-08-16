# mcpperm

Local-first MCP manifest permission profiler and policy generator.

`mcpperm` reads MCP-style server manifests, infers likely tool permissions from names, descriptions, schemas, and annotations, then emits a reviewable deny-by-default policy. It is designed as a deterministic preflight before wiring an MCP server into an agent client.

## Install

```sh
npm install
npm run build
```

For local CLI use from this checkout:

```sh
npm link
mcpperm --help
```

## Commands

Inspect a manifest:

```sh
mcpperm inspect fixtures/filesystem-server.json
```

Emit machine-readable JSON:

```sh
mcpperm inspect fixtures/messaging-server.json --json
```

Generate a least-privilege policy:

```sh
mcpperm policy fixtures/shell-server.json --output mcpperm.policy.json
```

The output path must be distinct from the input manifest; `mcpperm` rejects
equivalent resolved paths before writing so the source manifest is preserved.

Compare two generated policies:

```sh
mcpperm diff old.policy.json new.policy.json
```

Policy diffs report tool changes, permission additions/removals, and risk
changes for permissions that remain allowed. Risk increases retain their new
risk level, so `diff --fail-on-high` exits 2 for a medium-to-high escalation;
use `--json` for deterministic structured output. Changes to explanatory
`reasons` alone are not treated as permission drift.

A complete local policy-diff walkthrough is available in
[`examples/policy-diff.md`](examples/policy-diff.md). It generates policies
from the packaged `docs-server` and `messaging-server` fixtures, then shows the
permission expansion reviewers should inspect before enabling messaging tools.

Fail CI when high-risk permissions are detected:

```sh
mcpperm inspect fixtures/shell-server.json --fail-on-high
```

Each command validates its documented positional argument count and rejects
unknown options with a non-zero exit status. Supported options may appear
before or after positional arguments.

## Risk Categories

`mcpperm` currently profiles these categories:

- `filesystem`: local path, file, directory, read, write, or delete behavior.
- `shell`: command, process, shell, terminal, or subprocess execution.
- `network`: HTTP, API, webhook, upload, download, host, or endpoint behavior.
- `browser`: browser, page, DOM, click, screenshot, Playwright, or Puppeteer behavior.
- `credentials`: token, secret, API key, OAuth, password, session, cookie, or auth behavior.
- `messaging`: email, Slack, Discord, Teams, SMS, publish, post, reply, inbox, or channel behavior.

The profiler is intentionally conservative. It can flag false positives, and it cannot prove a manifest is truthful.
Every entry in a manifest `tools` array must be a JSON object; malformed entries
are rejected with their original array indexes instead of being silently omitted.

## Manifest Tool Identity

Every tool must define a non-empty `name` or `id`, and the resolved values must
be unique within the manifest. `name` takes precedence when both fields are
present. The `inspect` and `policy` commands reject missing or duplicate tool
identities instead of silently merging tools into one policy entry; the library
applies the same validation during normalization and policy generation.

## Example Output

```text
Manifest: filesystem-server
Overall risk: high

Permission categories:
- filesystem: high
- shell: none
- network: none
- browser: none
- credentials: none
- messaging: none

Tools:
- read_workspace_file: medium
  - filesystem: medium (reads local filesystem paths)
- write_workspace_file: high
  - filesystem: high (mutates files or directories; reads local filesystem paths)
```

## Policy Model

Generated policies use schema version `mcpperm.policy.v1`. They default to deny,
mark high-risk tools as review-required, and keep per-category permission reasons
so reviewers can decide whether to allow or reject each capability.

The `diff` command accepts complete generated v1 policies. Each policy must
include a string `generatedAt`, a manifest with a non-empty string `name`,
`defaultAction: "deny"`, a boolean `reviewRequired`, and a `tools` object. Every
tool requires boolean `allowed` and `reviewRequired` fields, a `risk` of `low`,
`medium`, or `high`, and a `permissions` object containing all six risk
categories. Each permission requires a boolean `allowed`, a `risk` of `none`,
`low`, `medium`, or `high`, and a string array `reasons`. An optional manifest
`description` must be a string. Malformed old or new policies are rejected with
a field-specific validation error before diffing.

```json
{
  "schemaVersion": "mcpperm.policy.v1",
  "generatedAt": "2026-05-31T00:00:00.000Z",
  "manifest": { "name": "shell-server" },
  "defaultAction": "deny",
  "reviewRequired": true,
  "tools": {
    "exec_command": {
      "allowed": true,
      "risk": "high",
      "reviewRequired": true,
      "permissions": {
        "filesystem": { "allowed": false, "risk": "none", "reasons": [] },
        "shell": { "allowed": true, "risk": "high", "reasons": ["executes commands"] },
        "network": { "allowed": false, "risk": "none", "reasons": [] },
        "browser": { "allowed": false, "risk": "none", "reasons": [] },
        "credentials": { "allowed": false, "risk": "none", "reasons": [] },
        "messaging": { "allowed": false, "risk": "none", "reasons": [] }
      }
    }
  }
}
```

## Verify

Run the full local release check:

```sh
npm run release:check
```

Release tags must exactly equal `v` followed by the `version` in
`package.json` (for example, package version `0.1.0` requires tag `v0.1.0`).
The release workflow checks this invariant before packing the package or
creating the GitHub release. You can exercise the same guard locally:

```sh
node scripts/check-release-tag.mjs --tag v0.1.0 --version 0.1.0
```

Run repository validation:

```sh
bash scripts/validate.sh
```

`scripts/validate.sh` runs the repository's standard local checks when they are defined and also runs `agent-qc ready` when `agent-qc` is installed. Missing `agent-qc` is treated as a skip.

## Package contents

The npm package allowlist includes the runtime files plus the public support
documents needed for release review: `README.md`, `LICENSE`, `SECURITY.md`,
`CHANGELOG.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`. It also includes
the fixtures and `examples/policy-diff.md` so package users can reproduce the
core permission-review workflow.

Run `npm run package:smoke` before publishing. The package smoke builds the
project, runs `npm pack --dry-run --json`, and fails if the CLI entrypoint,
library entrypoint, fixtures, example, or support docs are missing from the
tarball.

## Security

`mcpperm` is a static heuristic tool. It does not execute MCP servers and should be used alongside code review, dependency review, and sandboxing. Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## License

MIT

## Verification

Run the release-readiness checks before publishing or cutting a PR:

```bash
npm run check
npm run build
npm run test
npm run smoke
npm run package:smoke
npm run release:check
```

Use `npm run package:smoke` or `npm pack --dry-run` to confirm the published tarball includes the support docs and runnable package contents.

## Limitations

mcpperm works from local MCP configuration and fixture data. It does not contact live MCP servers or verify provider-side permissions, so treat its output as a preflight review aid rather than an authorization decision.
