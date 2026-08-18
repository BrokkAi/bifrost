import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { checkNpmTrustedPublishing } from "./check-npm-trusted-publishing.mjs";

const realPublishNpm = readFileSync(
  new URL("../.github/workflows/publish-npm.yml", import.meta.url),
  "utf8",
);
const realRelease = readFileSync(
  new URL("../.github/workflows/release.yml", import.meta.url),
  "utf8",
);

test("the repository workflows satisfy the npm trusted-publishing contract", () => {
  assert.deepEqual(
    checkNpmTrustedPublishing({ publishNpm: realPublishNpm, release: realRelease }),
    [],
  );
});

test("a classic-token registry-url configuration is rejected", () => {
  const broken = realPublishNpm.replace(
    "node-version: 24",
    "node-version: 24\n          registry-url: https://registry.npmjs.org",
  );
  assert.notEqual(broken, realPublishNpm);
  const violations = checkNpmTrustedPublishing({ publishNpm: broken, release: realRelease });
  assert.equal(violations.length, 1);
  assert.match(violations[0], /registry-url/u);
});

test("an npm client older than the minimum is rejected", () => {
  const broken = realPublishNpm.replace(
    /npm install --global npm@[0-9]+\.[0-9]+\.[0-9]+/u,
    "npm install --global npm@11.15.0",
  );
  assert.notEqual(broken, realPublishNpm);
  const violations = checkNpmTrustedPublishing({ publishNpm: broken, release: realRelease });
  assert.equal(violations.length, 1);
  assert.match(violations[0], /at least npm@11\.19\.0/u);
});

test("a missing NODE_AUTH_TOKEN clearing is rejected", () => {
  const broken = realPublishNpm.replace("unset NODE_AUTH_TOKEN", "true");
  assert.notEqual(broken, realPublishNpm);
  const violations = checkNpmTrustedPublishing({ publishNpm: broken, release: realRelease });
  assert.equal(violations.length, 1);
  assert.match(violations[0], /NODE_AUTH_TOKEN/u);
});

test("a missing provenance flag is rejected", () => {
  const broken = realPublishNpm.replace('NPM_CONFIG_PROVENANCE: "true"', "");
  assert.notEqual(broken, realPublishNpm);
  const violations = checkNpmTrustedPublishing({ publishNpm: broken, release: realRelease });
  assert.equal(violations.length, 1);
  assert.match(violations[0], /NPM_CONFIG_PROVENANCE/u);
});

test("a release dispatch that abandons the master workflow ref is rejected", () => {
  const broken = realRelease.replace("--ref master", "--ref v0.0.0");
  assert.notEqual(broken, realRelease);
  const violations = checkNpmTrustedPublishing({ publishNpm: realPublishNpm, release: broken });
  assert.equal(violations.length, 1);
  assert.match(violations[0], /--ref master/u);
});
