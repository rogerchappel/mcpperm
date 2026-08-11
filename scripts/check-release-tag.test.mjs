import assert from "node:assert/strict";
import test from "node:test";

import { checkReleaseTag, expectedReleaseTag } from "./check-release-tag.mjs";

test("accepts a tag that exactly matches the package version", () => {
  assert.doesNotThrow(() => checkReleaseTag("v0.1.0", "0.1.0"));
});

test("rejects a tag for a different package version", () => {
  assert.throws(
    () => checkReleaseTag("v9.9.9", "0.1.0"),
    /Release tag "v9\.9\.9" must exactly match "v0\.1\.0"/,
  );
});

test("requires the lowercase v prefix", () => {
  assert.throws(() => checkReleaseTag("0.1.0", "0.1.0"), /must exactly match "v0\.1\.0"/);
});

test("requires an explicit package version", () => {
  assert.throws(() => expectedReleaseTag(), /package version is required/);
});
