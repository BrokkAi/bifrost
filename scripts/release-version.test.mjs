import assert from "node:assert/strict";
import test from "node:test";

import {
  confirmReleaseVersion,
  normalizeReleaseTag,
  readCargoVersion,
  validatePyprojectVersionInheritance,
} from "./release-version.mjs";

test("reads only the root package version from Cargo.toml", () => {
  const manifest = [
    '[workspace.package]',
    'version = "9.9.9"',
    '',
    '[package]',
    'name = "brokk-bifrost"',
    'version = "0.8.8"',
    '',
    '[dependencies.example]',
    'version = "1.0.0"',
  ].join("\n");
  assert.equal(readCargoVersion(manifest), "0.8.8");
});

test("rejects Cargo.toml without exactly one package version", () => {
  assert.throws(
    () => readCargoVersion('[package]\nname = "brokk-bifrost"\n'),
    /Expected exactly one package version/u,
  );
});

test("normalizes short and fully qualified release tags", () => {
  assert.deepEqual(normalizeReleaseTag("v1.2.3"), { tag: "v1.2.3", version: "1.2.3" });
  assert.deepEqual(normalizeReleaseTag("refs/tags/v1.2.3-rc.1+build.7"), {
    tag: "v1.2.3-rc.1+build.7",
    version: "1.2.3-rc.1+build.7",
  });
});

test("rejects unprefixed and malformed release tags", () => {
  assert.throws(() => normalizeReleaseTag("1.2.3"), /must start with v/u);
  assert.throws(() => normalizeReleaseTag("v1.2"), /valid semver/u);
  assert.throws(() => normalizeReleaseTag("v01.2.3"), /valid semver/u);
  assert.throws(() => normalizeReleaseTag("v1.2.3-01"), /valid semver/u);
});

test("requires the release tag to match the Cargo package version", () => {
  assert.deepEqual(
    confirmReleaseVersion("v0.8.8", '[package]\nversion = "0.8.8"\n'),
    { tag: "v0.8.8", version: "0.8.8" },
  );
  assert.throws(
    () => confirmReleaseVersion("v0.8.7", '[package]\nversion = "0.8.8"\n'),
    /does not match Cargo\.toml package version/u,
  );
});

test("accepts pyproject dynamic version inheritance", () => {
  assert.doesNotThrow(() =>
    validatePyprojectVersionInheritance(
      '[project]\nname = "brokk-bifrost-searchtools"\ndynamic = [\n  "readme",\n  "version",\n]\n',
    ));
});

test("rejects static or missing pyproject version inheritance", () => {
  assert.throws(
    () =>
      validatePyprojectVersionInheritance(
        '[project]\nversion = "0.8.8"\ndynamic = ["readme"]\n',
      ),
    /declares project\.version/u,
  );
  assert.throws(
    () => validatePyprojectVersionInheritance('[project]\ndynamic = ["readme"]\n'),
    /must include "version"/u,
  );
  assert.throws(
    () => validatePyprojectVersionInheritance('[project]\nname = "example"\n'),
    /must declare project\.dynamic/u,
  );
});
