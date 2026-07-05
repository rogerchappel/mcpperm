import { execFileSync } from "node:child_process";

const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
  encoding: "utf8"
});
const [pack] = JSON.parse(output);
const files = new Set(pack.files.map((file) => file.path));

const required = [
  "README.md",
  "LICENSE",
  "SECURITY.md",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "CODE_OF_CONDUCT.md",
  "dist/src/cli.js",
  "dist/src/index.js",
  "fixtures/docs-server.json",
  "fixtures/filesystem-server.json",
  "fixtures/messaging-server.json",
  "fixtures/shell-server.json",
  "examples/policy-diff.md"
];

const missing = required.filter((file) => !files.has(file));
if (missing.length > 0) {
  console.error("Package smoke failed; missing expected files:");
  for (const file of missing) console.error(`- ${file}`);
  process.exit(1);
}

console.log(`Package smoke passed with ${pack.files.length} packed files.`);
