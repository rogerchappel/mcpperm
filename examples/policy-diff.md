# Policy Diff Example

This example shows a local permission-review workflow using the packaged
fixtures.

```sh
npm run build
node dist/src/cli.js policy fixtures/docs-server.json --output /tmp/mcpperm-docs-policy.json
node dist/src/cli.js policy fixtures/messaging-server.json --output /tmp/mcpperm-messaging-policy.json
node dist/src/cli.js diff /tmp/mcpperm-docs-policy.json /tmp/mcpperm-messaging-policy.json
```

Expected drift includes adding the high-risk `send_slack_message` tool and
removing the low-risk `search_docs` tool. Reviewers should treat that as a
permission expansion that needs an explicit approval decision before the
messaging server is wired into an agent client.

The diff also detects category-level risk changes when a permission remains
allowed, even if the tool's aggregate risk is unchanged. For example, an
allowed `filesystem` permission changing from `medium` to `high` is emitted as:

```text
- [high] Permission risk changed: workspace filesystem medium -> high
```

Pass `--json` for the same drift as structured output, or `--fail-on-high` to
exit 2 when the diff contains this escalation. Risk downgrades are reported as
low-risk drift. A change only to a permission's explanatory `reasons` is
ignored because it does not alter the effective permission category or risk.
