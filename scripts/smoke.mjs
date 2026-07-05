import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const cli = resolve("dist/src/cli.js");
const workspace = mkdtempSync(join(tmpdir(), "mcpperm-smoke-"));

function run(args, options = {}) {
  return execFileSync(process.execPath, [cli, ...args], {
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit"
  });
}

try {
  run(["inspect", "fixtures/filesystem-server.json"]);

  const oldPolicy = join(workspace, "docs-policy.json");
  const newPolicy = join(workspace, "messaging-policy.json");
  run(["policy", "fixtures/docs-server.json", "--output", oldPolicy]);
  run(["policy", "fixtures/messaging-server.json", "--output", newPolicy]);

  const driftJson = run(["diff", oldPolicy, newPolicy, "--json"], { capture: true });
  const drift = JSON.parse(driftJson);
  if (!drift.some((entry) => entry.type === "tool-added" && entry.message === "Tool added: send_slack_message (high)")) {
    throw new Error("expected messaging policy drift to add send_slack_message");
  }

  const generatedPolicy = JSON.parse(readFileSync(newPolicy, "utf8"));
  if (generatedPolicy.defaultAction !== "deny" || generatedPolicy.reviewRequired !== true) {
    throw new Error("expected generated messaging policy to require review and deny by default");
  }

  console.log("Smoke passed: inspect, policy generation, and policy diff all worked.");
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
