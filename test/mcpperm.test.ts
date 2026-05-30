import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import assert from "node:assert/strict";
import {
  diffPolicies,
  generatePolicy,
  inspectManifest,
  normalizeManifest,
  readJsonInput
} from "../src/index.js";

const execFileAsync = promisify(execFile);

async function loadFixture(name: string) {
  const { raw, sourceName } = await readJsonInput(join("fixtures", name));
  return normalizeManifest(raw, sourceName);
}

test("inspectManifest profiles filesystem and shell risk", async () => {
  const filesystemSummary = inspectManifest(await loadFixture("filesystem-server.json"));
  const shellSummary = inspectManifest(await loadFixture("shell-server.json"));

  assert.equal(filesystemSummary.manifest.name, "filesystem-server");
  assert.equal(filesystemSummary.categories.filesystem, "high");
  assert.equal(filesystemSummary.tools.find((tool) => tool.name === "read_workspace_file")?.risk, "medium");
  assert.equal(filesystemSummary.tools.find((tool) => tool.name === "write_workspace_file")?.risk, "high");
  assert.equal(shellSummary.risk, "high");
  assert.equal(shellSummary.categories.shell, "high");
});

test("generatePolicy emits deny-by-default tool permissions", async () => {
  const summary = inspectManifest(await loadFixture("messaging-server.json"));
  const policy = generatePolicy(summary, "2026-05-31T00:00:00.000Z");

  assert.equal(policy.schemaVersion, "mcpperm.policy.v1");
  assert.equal(policy.defaultAction, "deny");
  assert.equal(policy.reviewRequired, true);
  assert.equal(policy.tools.send_slack_message?.reviewRequired, true);
  assert.equal(policy.tools.send_slack_message?.permissions.messaging.allowed, true);
  assert.equal(policy.tools.send_slack_message?.permissions.filesystem.allowed, false);
  assert.equal(policy.tools.read_mentions?.permissions.messaging.risk, "medium");
});

test("diffPolicies reports added tools and permission expansion", async () => {
  const docsPolicy = generatePolicy(inspectManifest(await loadFixture("docs-server.json")), "2026-05-31T00:00:00.000Z");
  const messagingPolicy = generatePolicy(
    inspectManifest(await loadFixture("messaging-server.json")),
    "2026-05-31T00:00:00.000Z"
  );

  const drifts = diffPolicies(docsPolicy, messagingPolicy);

  assert.deepEqual(
    drifts.map((drift) => drift.type),
    ["tool-added", "tool-removed", "tool-added"]
  );
  assert.ok(drifts.some((drift) => drift.message === "Tool added: send_slack_message (high)"));
});

test("CLI writes policies and fails on high risk when requested", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "mcpperm-test-"));
  const policyPath = join(workspace, "policy.json");

  try {
    await execFileAsync("node", ["dist/src/cli.js", "policy", "fixtures/messaging-server.json", "--output", policyPath]);
    const policy = JSON.parse(await readFile(policyPath, "utf8")) as { reviewRequired: boolean };
    assert.equal(policy.reviewRequired, true);

    await assert.rejects(
      execFileAsync("node", ["dist/src/cli.js", "inspect", "fixtures/shell-server.json", "--fail-on-high"]),
      (error: unknown) => {
        assert.equal((error as { code?: number }).code, 2);
        return true;
      }
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("CLI prints policy drift", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "mcpperm-diff-"));
  const oldPath = join(workspace, "old.json");
  const newPath = join(workspace, "new.json");

  try {
    const oldPolicy = generatePolicy(inspectManifest(await loadFixture("docs-server.json")), "2026-05-31T00:00:00.000Z");
    const newPolicy = generatePolicy(inspectManifest(await loadFixture("shell-server.json")), "2026-05-31T00:00:00.000Z");
    await writeFile(oldPath, `${JSON.stringify(oldPolicy, null, 2)}\n`);
    await writeFile(newPath, `${JSON.stringify(newPolicy, null, 2)}\n`);

    const { stdout } = await execFileAsync("node", ["dist/src/cli.js", "diff", oldPath, newPath]);

    assert.match(stdout, /\[high\] Tool added: exec_command \(high\)/);
    assert.match(stdout, /\[low\] Tool removed: search_docs/);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
