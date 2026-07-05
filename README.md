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

Compare two generated policies:

```sh
mcpperm diff old.policy.json new.policy.json
```

A complete local policy-diff walkthrough is available in
[`examples/policy-diff.md`](examples/policy-diff.md). It generates policies
from the packaged `docs-server` and `messaging-server` fixtures, then shows the
permission expansion reviewers should inspect before enabling messaging tools.

Fail CI when high-risk permissions are detected:

```sh
mcpperm inspect fixtures/shell-server.json --fail-on-high
```

## Risk Categories

`mcpperm` currently profiles these categories:

- `filesystem`: local path, file, directory, read, write, or delete behavior.
- `shell`: command, process, shell, terminal, or subprocess execution.
- `network`: HTTP, API, webhook, upload, download, host, or endpoint behavior.
- `browser`: browser, page, DOM, click, screenshot, Playwright, or Puppeteer behavior.
- `credentials`: token, secret, API key, OAuth, password, session, cookie, or auth behavior.
- `messaging`: email, Slack, Discord, Teams, SMS, publish, post, reply, inbox, or channel behavior.

The profiler is intentionally conservative. It can flag false positives, and it cannot prove a manifest is truthful.

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

Generated policies use schema version `mcpperm.policy.v1`. They default to deny, mark high-risk tools as review-required, and keep per-category permission reasons so reviewers can decide whether to allow or reject each capability.

```json
{
  "schemaVersion": "mcpperm.policy.v1",
  "defaultAction": "deny",
  "reviewRequired": true,
  "tools": {
    "exec_command": {
      "allowed": true,
      "risk": "high",
      "reviewRequired": true
    }
  }
}
```

## Verify

Run the full local release check:

```sh
npm run release:check
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
