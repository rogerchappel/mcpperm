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
