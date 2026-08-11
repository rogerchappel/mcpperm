import process from "node:process";

export function expectedReleaseTag(version) {
  if (typeof version !== "string" || version.length === 0) {
    throw new Error("A package version is required.");
  }

  return `v${version}`;
}

export function checkReleaseTag(tag, version) {
  const expected = expectedReleaseTag(version);

  if (tag !== expected) {
    throw new Error(`Release tag ${JSON.stringify(tag)} must exactly match ${JSON.stringify(expected)}.`);
  }
}

function readArgument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], "file:").href) {
  try {
    const tag = readArgument("--tag");
    const version = readArgument("--version");
    checkReleaseTag(tag, version);
    console.log(`Release tag ${tag} matches package version ${version}.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
