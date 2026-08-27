import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  confirmReleaseVersion,
  normalizeReleaseTag,
  THIRD_PARTY_SEMANTIC_PACK_SPECS,
  readCargoVersion,
  syncBifrostDependencyVersions,
  syncCitationVersion,
  validatePyprojectVersionInheritance,
  validateWorkspaceVersionInheritance,
} from "./release-version.mjs";

test("release inputs include every pinned third-party semantic-pack ecosystem", () => {
  assert.deepEqual(THIRD_PARTY_SEMANTIC_PACK_SPECS, [
    "semantic-packs/jvm/temurin-jdk-21.0.8+9.json",
    "semantic-packs/jvm/kotlin-stdlib-2.2.20.json",
    "semantic-packs/jvm/scala-library-2.13.16.json",
    "semantic-packs/python/typeshed-stdlib-2026.8.8.json",
    "semantic-packs/typescript/typescript-7.0.2.json",
    "semantic-packs/rust/rust-stdlib-nightly-2026-08-24.json",
  ]);
});

test("synchronizes exact internal Bifrost dependency versions", () => {
  const manifest = [
    '[dependencies]',
    'brokk-bifrost-core = { path = "../bifrost-core", version = "=0.8.21" }',
    'brokk-bifrost-policy = { path = "../bifrost-policy", version = "=0.8.21", optional = true }',
    'tree-sitter-java = "0.23.5"',
  ].join("\n");

  assert.equal(
    syncBifrostDependencyVersions(manifest, "0.8.22"),
    [
      '[dependencies]',
      'brokk-bifrost-core = { path = "../bifrost-core", version = "=0.8.22" }',
      'brokk-bifrost-policy = { path = "../bifrost-policy", version = "=0.8.22", optional = true }',
      'tree-sitter-java = "0.23.5"',
    ].join("\n"),
  );
});

test("synchronizes only the top-level citation version", () => {
  const citation = [
    "cff-version: 1.2.0",
    'version: "0.9.5" # release version',
    'date-released: "2026-08-13"',
    "references:",
    '  - version: "7.8.9"',
    "",
  ].join("\r\n");

  assert.equal(
    syncCitationVersion(citation, "0.10.0"),
    [
      "cff-version: 1.2.0",
      'version: "0.10.0" # release version',
      'date-released: "2026-08-13"',
      "references:",
      '  - version: "7.8.9"',
      "",
    ].join("\r\n"),
  );
});

test("rejects missing or duplicate top-level citation versions", () => {
  assert.throws(
    () => syncCitationVersion('date-released: "2026-08-13"\n', "0.10.0"),
    /found 0/u,
  );
  assert.throws(
    () => syncCitationVersion('version: "0.9.5"\nversion: "0.9.6"\n', "0.10.0"),
    /found 2/u,
  );
});

test("reads only the workspace package version from Cargo.toml", () => {
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
  assert.equal(readCargoVersion(manifest), "9.9.9");
});

test("rejects Cargo.toml without exactly one workspace package version", () => {
  assert.throws(
    () => readCargoVersion('[package]\nname = "brokk-bifrost"\n'),
    /does not contain \[workspace\.package\]/u,
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
    confirmReleaseVersion("v0.8.8", '[workspace.package]\nversion = "0.8.8"\n'),
    { tag: "v0.8.8", version: "0.8.8" },
  );
  assert.throws(
    () => confirmReleaseVersion("v0.8.7", '[workspace.package]\nversion = "0.8.8"\n'),
    /does not match Cargo\.toml workspace package version/u,
  );
});

test("requires every released package to inherit the workspace version", (context) => {
  const originalCwd = process.cwd();
  context.after(() => process.chdir(originalCwd));
  assert.doesNotThrow(() => validateWorkspaceVersionInheritance(originalCwd));
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

// The policy-scan action reached v0.10.5 still defaulting to v0.10.4, because
// nothing projected the release version into it. The subdirectory form
// `BrokkAi/bifrost/.github/actions/policy-scan@vX.Y.Z` serves this file
// verbatim, so that default is what a consumer pinning an exact tag installs.
// Asserted against the real files rather than a fixture: the defect is drift
// between two checked-in files, which a fixture cannot reproduce.
test("the policy-scan action default tracks the workspace version", () => {
  const version = readCargoVersion(fs.readFileSync("Cargo.toml", "utf8"));
  const action = fs.readFileSync(".github/actions/policy-scan/action.yml", "utf8");
  const defaults = action.match(/^    default: v\d+\.\d+\.\d+$/gmu) ?? [];
  assert.equal(defaults.length, 1, "expected exactly one version default in the policy-scan action");
  assert.equal(defaults[0].trim(), `default: v${version}`);
});
