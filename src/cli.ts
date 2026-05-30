#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { diffPolicies, formatPolicyDiff, generatePolicy } from "./policy.js";
import { formatSummary, inspectManifest } from "./risk.js";
import { normalizeManifest, readJsonInput } from "./manifest.js";

interface CliOptions {
  json: boolean;
  failOnHigh: boolean;
  output?: string;
}

function usage(): string {
  return `mcpperm <command> [options]

Commands:
  inspect <manifest-or-json>        Print a permission summary
  policy <manifest-or-json>         Generate a least-privilege JSON policy
  diff <old-policy> <new-policy>    Explain permission drift between policies

Options:
  --json             Emit JSON where supported
  --output <file>    Write policy JSON to a file
  --fail-on-high     Exit 2 when high-risk permissions are detected
  -h, --help         Show help
`;
}

function parseArgs(argv: string[]): { command?: string; positional: string[]; options: CliOptions } {
  const positional: string[] = [];
  const options: CliOptions = {
    json: false,
    failOnHigh: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg) {
      continue;
    }

    if (arg === "--json") {
      options.json = true;
      continue;
    }

    if (arg === "--fail-on-high") {
      options.failOnHigh = true;
      continue;
    }

    if (arg === "--output" || arg === "-o") {
      const output = argv[index + 1];
      if (!output) {
        throw new Error("--output requires a file path.");
      }
      options.output = output;
      index += 1;
      continue;
    }

    if (arg === "--help" || arg === "-h") {
      return { positional: ["help"], options };
    }

    positional.push(arg);
  }

  return {
    command: positional[0],
    positional: positional.slice(1),
    options
  };
}

async function loadManifestSummary(input: string) {
  const { raw, sourceName } = await readJsonInput(input);
  return inspectManifest(normalizeManifest(raw, sourceName));
}

async function run(argv: string[]): Promise<number> {
  const { command, positional, options } = parseArgs(argv);

  if (!command || command === "help") {
    process.stdout.write(usage());
    return 0;
  }

  if (command === "inspect") {
    const input = positional[0];
    if (!input) {
      throw new Error("inspect requires <manifest-or-json>.");
    }

    const summary = await loadManifestSummary(input);
    process.stdout.write(options.json ? `${JSON.stringify(summary, null, 2)}\n` : formatSummary(summary));
    return options.failOnHigh && summary.risk === "high" ? 2 : 0;
  }

  if (command === "policy") {
    const input = positional[0];
    if (!input) {
      throw new Error("policy requires <manifest-or-json>.");
    }

    const summary = await loadManifestSummary(input);
    const policy = generatePolicy(summary);
    const output = `${JSON.stringify(policy, null, 2)}\n`;

    if (options.output) {
      await writeFile(options.output, output);
    } else {
      process.stdout.write(output);
    }

    return options.failOnHigh && policy.reviewRequired ? 2 : 0;
  }

  if (command === "diff") {
    const [oldPath, newPath] = positional;
    if (!oldPath || !newPath) {
      throw new Error("diff requires <old-policy> <new-policy>.");
    }

    const [oldPolicy, newPolicy] = await Promise.all([readJsonInput(oldPath), readJsonInput(newPath)]);
    const drifts = diffPolicies(oldPolicy.raw, newPolicy.raw);
    process.stdout.write(options.json ? `${JSON.stringify(drifts, null, 2)}\n` : formatPolicyDiff(drifts));
    return options.failOnHigh && drifts.some((drift) => drift.risk === "high") ? 2 : 0;
  }

  throw new Error(`Unknown command: ${command}`);
}

run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`mcpperm: ${message}\n\n${usage()}`);
    process.exitCode = 1;
  });
