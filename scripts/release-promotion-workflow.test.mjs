import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const release = readFileSync(
  new URL("../.github/workflows/release.yml", import.meta.url),
  "utf8",
);
const releaseContext = readFileSync(
  new URL("../.github/workflows/release-context.yml", import.meta.url),
  "utf8",
);
const cratePublisher = readFileSync(
  new URL("../.github/workflows/publish-crate.yml", import.meta.url),
  "utf8",
);
const wheelBuilder = readFileSync(
  new URL("../.github/workflows/build-wheels.yml", import.meta.url),
  "utf8",
);
const wheelPublisher = readFileSync(
  new URL("../.github/workflows/publish-wheels.yml", import.meta.url),
  "utf8",
);
const tagVerifier = readFileSync(
  new URL("./verify-release-tag-commit.sh", import.meta.url),
  "utf8",
);

function jobBlock(workflow, job) {
  const jobStart = new RegExp(`^  ${job}:\\n`, "mu");
  const start = workflow.search(jobStart);
  assert.notEqual(start, -1, `expected ${job} job`);
  const afterStart = workflow.slice(start + workflow.slice(start).indexOf("\n") + 1);
  const nextJob = afterStart.search(/^  [a-z][a-z0-9-]*:\n/mu);
  return nextJob === -1 ? afterStart : afterStart.slice(0, nextJob);
}

function jobNeedsPromotionEvidence(job) {
  assert.match(
    jobBlock(release, job),
    /^    needs: \[[^\]]*promotion-evidence[^\]]*\]$/mu,
  );
}

test("release is the only tag and manual-dispatch entrypoint for package publication", () => {
  assert.match(release, /^  push:\n    tags:/mu);
  assert.match(release, /^  workflow_dispatch:/mu);
  for (const publisher of [cratePublisher, wheelPublisher, wheelBuilder]) {
    assert.match(publisher, /^  workflow_call:/mu);
    assert.doesNotMatch(publisher, /^  push:/mu);
    assert.doesNotMatch(publisher, /^  workflow_dispatch:/mu);
  }
});

test("release context captures a commit and every called workflow receives it", () => {
  assert.match(releaseContext, /^      commit:/mu);
  assert.match(releaseContext, /git rev-parse HEAD/u);
  assert.match(releaseContext, /ref: refs\/tags\/\$\{\{ inputs\.tag \}\}/u);
  assert.match(releaseContext, /refs\/tags\/\$\{RELEASE_TAG\}\^\{commit\}/u);
  assert.doesNotMatch(release, /validation_ref/u);
  assert.doesNotMatch(
    release,
    /ref: \$\{\{ needs\.release-context\.outputs\.tag \}\}/u,
  );
  for (const workflow of [cratePublisher, wheelBuilder, wheelPublisher]) {
    assert.match(workflow, /^      commit:/mu);
  }
  assert.match(release, /commit: \$\{\{ needs\.release-context\.outputs\.commit \}\}/u);
});

test("publish actions fail closed if the remote tag no longer selects the validated commit", () => {
  assert.match(tagVerifier, /git ls-remote --tags origin/u);
  assert.match(tagVerifier, /refs\/tags\/\$\{release_tag\}/u);
  assert.match(tagVerifier, /test "\$actual_commit" = "\$expected_commit"/u);
  assert.ok(
    (release.match(/scripts\/verify-release-tag-commit\.sh/gu) ?? []).length >= 6,
  );
  assert.match(cratePublisher, /scripts\/verify-release-tag-commit\.sh/u);
  assert.match(wheelPublisher, /scripts\/verify-release-tag-commit\.sh/u);
});

test("reusable workflow inputs are environment-bound before shell execution", () => {
  for (const publisher of [cratePublisher, wheelPublisher]) {
    assert.match(publisher, /RELEASE_TAG: \$\{\{ inputs\.tag \}\}/u);
    assert.match(publisher, /RELEASE_VERSION: \$\{\{ inputs\.version \}\}/u);
    assert.match(publisher, /RELEASE_COMMIT: \$\{\{ inputs\.commit \}\}/u);
    assert.doesNotMatch(publisher, /(?:bash|echo).*\$\{\{ inputs\./u);
  }
});

test("promotion evidence covers validation before every external publisher", () => {
  const evidence = jobBlock(release, "promotion-evidence");
  for (const prerequisite of [
    "crate-package",
    "build-wheels",
    "build",
    "agent-plugin-package",
    "agent-plugin-prepublish-smoke",
    "agent-plugin-release-smoke",
    "pi-package",
    "vscode-package",
  ]) {
    assert.ok(evidence.includes(`      - ${prerequisite}\n`));
  }
  for (const job of [
    "release",
    "publish-crate",
    "publish-wheels",
    "publish-agent-plugin",
    "publish-pi-package",
    "attach-vscode",
    "publish-vscode",
  ]) {
    jobNeedsPromotionEvidence(job);
  }
});

test("publishers preserve their platform, environment, and OIDC protections", () => {
  for (const target of [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-linux-android",
    "universal-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
  ]) {
    assert.ok(release.includes(`target: ${target}`));
  }
  for (const target of [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
  ]) {
    assert.ok(wheelBuilder.includes(`target: ${target}`));
  }
  for (const publisher of [cratePublisher, wheelPublisher]) {
    assert.match(publisher, /^    environment: release$/mu);
    assert.match(publisher, /^      id-token: write$/mu);
  }
  assert.match(cratePublisher, /crates-io-auth-action/u);
  assert.match(wheelPublisher, /gh-action-pypi-publish/u);
});

test("an always-run summary names targets and safe retry guidance", () => {
  assert.match(release, /^  release-summary:/mu);
  assert.match(release, /^    if: \$\{\{ always\(\) \}\}$/mu);
  assert.match(release, /Safe recovery/u);
  assert.match(release, /Re-run failed jobs/u);
  assert.match(release, /different tag, branch, or commit/u);
  for (const target of [
    "CLI archives and checksums built",
    "Crate package contents verified",
    "Wheels and sdist built and version-verified",
    "Agent plugin prepublication smoke",
    "VS Code extension built and tested",
    "crates.io",
    "PyPI",
    "VS Code release asset attachment",
    "VS Code Marketplace",
  ]) {
    assert.ok(release.includes(target));
  }
});
