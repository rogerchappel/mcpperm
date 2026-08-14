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

test("normalizeManifest rejects duplicate and ambiguous tool identities", () => {
  assert.throws(
    () => normalizeManifest({ tools: [{ name: "same" }, { id: "same" }] }),
    /Manifest tool names must be unique; duplicate name "same"/
  );

  assert.throws(
    () => normalizeManifest({ tools: [{ description: "first" }, { description: "second" }] }),
    /Manifest tools must define a non-empty name or id; invalid tools at indexes 0, 1/
  );
});

test("normalizeManifest rejects non-object tools at their original indexes", () => {
  assert.throws(
    () => normalizeManifest({ tools: [null, { name: "valid" }, "invalid", 7] }),
    /Manifest tools must be JSON objects; invalid tools at indexes 0, 2, 3/
  );

  assert.throws(
    () => normalizeManifest({ tools: [null, false] }),
    /Manifest tools must be JSON objects; invalid tools at indexes 0, 1/
  );

  assert.throws(
    () => normalizeManifest({ tools: [{ name: "valid" }, null, { description: "missing identity" }] }),
    /Manifest tools must be JSON objects; invalid tools at indexes 1/
  );

  assert.deepEqual(
    normalizeManifest({ tools: [{ name: "valid" }] }).tools.map((tool) => tool.name),
    ["valid"]
  );
});

test("normalizeManifest preserves original indexes for invalid tool identities", () => {
  assert.throws(
    () => normalizeManifest({ tools: [{ name: "valid" }, { description: "missing identity" }] }),
    /Manifest tools must define a non-empty name or id; invalid tools at indexes 1/
  );
});

test("CLI rejects manifests containing non-object tools", async () => {
  const cases = [
    ['{"tools":[null,{"name":"valid"}]}', /invalid tools at indexes 0/],
    ['{"tools":[null]}', /invalid tools at indexes 0/]
  ] as const;

  for (const [manifest, expected] of cases) {
    await assert.rejects(execFileAsync("node", ["dist/src/cli.js", "inspect", manifest]), (error: unknown) => {
      assert.equal((error as { code?: number }).code, 1);
      assert.match((error as { stderr: string }).stderr, expected);
      return true;
    });
  }
});

test("generatePolicy refuses duplicate tool identities in library summaries", () => {
  const summary = inspectManifest(normalizeManifest({ tools: [{ name: "same" }] }));
  summary.tools.push({ ...summary.tools[0]! });

  assert.throws(() => generatePolicy(summary), /Permission summary tool names must be unique; duplicate name "same"/);
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

test("diffPolicies reports permission risk changes without duplicating allowed-state drift", () => {
  const basePermission = { allowed: false, risk: "none" as const, reasons: [] };
  const policy = (filesystem: { allowed: boolean; risk: "low" | "medium" | "high" | "none"; reasons: string[] }) => ({
    schemaVersion: "mcpperm.policy.v1" as const,
    generatedAt: "2026-05-31T00:00:00.000Z",
    manifest: { name: "risk-diff" },
    defaultAction: "deny" as const,
    reviewRequired: true,
    tools: {
      workspace: {
        allowed: true,
        risk: "high" as const,
        reviewRequired: true,
        permissions: {
          filesystem,
          shell: { allowed: true, risk: "high" as const, reasons: ["executes commands"] },
          network: basePermission,
          browser: basePermission,
          credentials: basePermission,
          messaging: basePermission
        }
      }
    }
  });

  const medium = policy({ allowed: true, risk: "medium", reasons: ["reads files"] });
  const high = policy({ allowed: true, risk: "high", reasons: ["writes files"] });

  assert.deepEqual(diffPolicies(medium, high), [
    {
      type: "permission-risk-changed",
      risk: "high",
      message: "Permission risk changed: workspace filesystem medium -> high"
    }
  ]);
  assert.deepEqual(diffPolicies(high, medium), [
    {
      type: "permission-risk-changed",
      risk: "low",
      message: "Permission risk changed: workspace filesystem high -> medium"
    }
  ]);
  assert.deepEqual(
    diffPolicies(medium, policy({ allowed: true, risk: "medium", reasons: ["reads workspace files"] })),
    []
  );
  assert.deepEqual(diffPolicies(medium, medium), []);
});

test("diffPolicies rejects malformed nested policy fields with context", () => {
  const valid = generatePolicy(
    inspectManifest(normalizeManifest({ name: "valid", tools: [{ name: "read_file", description: "Read a file" }] })),
    "2026-05-31T00:00:00.000Z"
  );
  const malformedCases: Array<[string, unknown, RegExp]> = [
    ["missing permissions", { ...valid, tools: { read_file: { allowed: true, risk: "medium", reviewRequired: false } } }, /Old policy tools\.read_file\.permissions must be a JSON object/],
    ["invalid tool risk", { ...valid, tools: { read_file: { ...valid.tools.read_file, risk: "critical" } } }, /Old policy tools\.read_file\.risk must be one of low, medium, high/],
    ["invalid permission reasons", { ...valid, tools: { read_file: { ...valid.tools.read_file, permissions: { ...valid.tools.read_file!.permissions, filesystem: { allowed: true, risk: "medium", reasons: [7] } } } } }, /Old policy tools\.read_file\.permissions\.filesystem\.reasons must be an array of strings/],
    ["invalid manifest", { ...valid, manifest: { name: 42 } }, /Old policy manifest\.name must be a non-empty string/]
  ];

  for (const [name, malformed, expected] of malformedCases) {
    assert.throws(() => diffPolicies(malformed, valid), expected, name);
  }

  assert.throws(
    () => diffPolicies(valid, { ...valid, defaultAction: "allow" }),
    /New policy defaultAction must be "deny"/
  );
});

test("CLI diff reports malformed policies as contextual validation errors", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "mcpperm-malformed-policy-"));
  const oldPath = join(workspace, "old.json");
  const newPath = join(workspace, "new.json");
  const malformed = { schemaVersion: "mcpperm.policy.v1", tools: { read_file: { risk: "low" } } };

  try {
    await writeFile(oldPath, JSON.stringify(malformed));
    await writeFile(newPath, JSON.stringify(malformed));
    await assert.rejects(execFileAsync("node", ["dist/src/cli.js", "diff", oldPath, newPath]), (error: unknown) => {
      const stderr = (error as { stderr: string }).stderr;
      assert.match(stderr, /mcpperm: Old policy generatedAt must be a string/);
      assert.doesNotMatch(stderr, /TypeError|Cannot read properties/);
      return true;
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
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

test("CLI rejects an output path that aliases its policy input without modifying it", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "mcpperm-alias-"));
  const inputPath = join(workspace, "manifest.json");
  const original = await readFile("fixtures/filesystem-server.json", "utf8");

  try {
    await writeFile(inputPath, original);
    await assert.rejects(
      execFileAsync("node", ["dist/src/cli.js", "policy", inputPath, "--output", join(workspace, ".", "manifest.json")]),
      (error: unknown) => {
        assert.match((error as { stderr: string }).stderr, /--output must not resolve to the policy input file/);
        return true;
      }
    );
    assert.equal(await readFile(inputPath, "utf8"), original);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("CLI rejects unknown options and surplus command arguments", async () => {
  const cases = [
    ["inspect", "fixtures/filesystem-server.json", "--bogus"],
    ["policy", "fixtures/filesystem-server.json", "extra.json"],
    ["diff", "old.json", "new.json", "extra.json"]
  ];

  for (const args of cases) {
    await assert.rejects(execFileAsync("node", ["dist/src/cli.js", ...args]), (error: unknown) => {
      assert.equal((error as { code?: number }).code, 1);
      assert.match((error as { stderr: string }).stderr, /Unknown option|accepts exactly/);
      return true;
    });
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

test("CLI emits permission risk drift as text and JSON and fails on high risk", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "mcpperm-risk-diff-"));
  const oldPath = join(workspace, "old.json");
  const newPath = join(workspace, "new.json");
  const policy = generatePolicy(inspectManifest(await loadFixture("filesystem-server.json")), "2026-05-31T00:00:00.000Z");
  const tool = Object.values(policy.tools).find((candidate) => candidate.permissions.filesystem.allowed)!;
  tool.risk = "high";
  tool.reviewRequired = true;
  tool.permissions.filesystem = { allowed: true, risk: "medium", reasons: ["reads files"] };

  try {
    await writeFile(oldPath, `${JSON.stringify(policy, null, 2)}\n`);
    tool.permissions.filesystem = { allowed: true, risk: "high", reasons: ["writes files"] };
    await writeFile(newPath, `${JSON.stringify(policy, null, 2)}\n`);

    const { stdout } = await execFileAsync("node", ["dist/src/cli.js", "diff", oldPath, newPath]);
    assert.match(stdout, /\[high\] Permission risk changed: .* filesystem medium -> high/);

    const json = await execFileAsync("node", ["dist/src/cli.js", "diff", oldPath, newPath, "--json"]);
    assert.equal(JSON.parse(json.stdout)[0].type, "permission-risk-changed");

    await assert.rejects(
      execFileAsync("node", ["dist/src/cli.js", "diff", oldPath, newPath, "--fail-on-high"]),
      (error: unknown) => {
        assert.equal((error as { code?: number }).code, 2);
        return true;
      }
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
