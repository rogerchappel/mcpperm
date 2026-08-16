import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { checkReleaseConfig } from "./check-release-config.mjs";

const root = new URL("../", import.meta.url);
const files = ["package.json", "releasebox.config.json", ".github/workflows/release.yml", ".github/workflows/release-dry-run.yml"];

async function fixture(replacements = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mcpperm-release-config-"));
  for (const file of files) {
    const target = join(directory, file);
    await mkdir(join(target, ".."), { recursive: true });
    let content = await readFile(new URL(file, root), "utf8");
    if (replacements[file]) content = replacements[file](content);
    await writeFile(target, content);
  }
  return new URL(`file://${directory}/`);
}

test("accepts the repository release configuration", async () => {
  await checkReleaseConfig(root);
});

for (const [name, file, mutate, message] of [
  ["requires public package access", "package.json", (s) => s.replace('"access": "public"', '"access": "restricted"'), /access must be public/],
  ["requires package provenance", "package.json", (s) => s.replace('"provenance": true', '"provenance": false'), /provenance must be true/],
  ["requires ReleaseBox npm publication", "releasebox.config.json", (s) => s.replace('"publishNpm": true', '"publishNpm": false'), /publication must be enabled/],
  ["requires OIDC permission", ".github/workflows/release.yml", (s) => s.replace("id-token: write", "id-token: none"), /must grant id-token: write/],
  ["requires an npm version with trusted publishing", ".github/workflows/release.yml", (s) => s.replace("npm@11.5.1", "npm@10.9.0"), /must install npm 11.5.1/],
  ["requires publish before GitHub release", ".github/workflows/release.yml", (s) => s.replace(/      - name: Publish package to npm\n        run: npm publish --provenance --access public\n/, "") + "\n      # npm publish --provenance --access public\n", /GitHub release must be created after npm publication/],
  ["requires the publish command in dry runs", ".github/workflows/release-dry-run.yml", (s) => s.replace("npm publish --dry-run", "npm pack --dry-run"), /must exercise npm publish --dry-run/],
]) {
  test(name, async () => {
    await assert.rejects(checkReleaseConfig(await fixture({ [file]: mutate })), message);
  });
}
