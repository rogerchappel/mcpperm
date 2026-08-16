import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function orderedIndex(source, needle, after, message) {
  const index = source.indexOf(needle, after);
  requireCondition(index !== -1, message);
  return index;
}

export async function checkReleaseConfig(root = new URL("../", import.meta.url)) {
  const read = (path) => readFile(new URL(path, root), "utf8");
  const packageJson = JSON.parse(await read("package.json"));
  const releasebox = JSON.parse(await read("releasebox.config.json"));
  const releaseWorkflow = await read(".github/workflows/release.yml");
  const dryRunWorkflow = await read(".github/workflows/release-dry-run.yml");

  requireCondition(packageJson.publishConfig?.access === "public", "package publishConfig.access must be public");
  requireCondition(packageJson.publishConfig?.provenance === true, "package publishConfig.provenance must be true");
  requireCondition(releasebox.release?.publishNpm === true, "ReleaseBox npm publication must be enabled");
  requireCondition(/^\s*id-token:\s*write\s*$/m.test(releaseWorkflow), "release workflow must grant id-token: write");

  const npmInstall = orderedIndex(releaseWorkflow, "npm install --global npm@11.5.1", 0, "release workflow must install npm 11.5.1 for trusted publishing");
  const publish = orderedIndex(releaseWorkflow, "npm publish --provenance --access public", npmInstall, "release workflow must publish publicly with provenance after installing npm 11.5.1");
  orderedIndex(releaseWorkflow, "gh release create", publish, "GitHub release must be created after npm publication");
  requireCondition(dryRunWorkflow.includes("npm run release:config:test"), "release dry run must execute the configuration guard");
  requireCondition(dryRunWorkflow.includes("npm publish --dry-run"), "release dry run must exercise npm publish --dry-run");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  checkReleaseConfig().then(
    () => console.log("Release publication configuration is valid."),
    (error) => { console.error(error.message); process.exitCode = 1; },
  );
}
