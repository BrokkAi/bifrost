import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import {
  classifyArtifact,
  generateManifest,
  normalizeManifestPath,
  qualificationArtifactName,
  selectQualificationRun,
  validateIdentity,
  verifyManifest,
} from "./release-qualification.mjs";

const execFileAsync = promisify(execFile);
const script = path.resolve("scripts/public/release-qualification.mjs");
const commit = "a".repeat(40);
const otherCommit = "b".repeat(40);
const repository = "BrokkAi/bifrost";
const version = "0.10.3";
const identity = {
  release: { version, tag: `v${version}` },
  source: { repository, publicCommit: commit },
  qualification: {
    workflow: "release-readiness.yml",
    runId: 123,
    runAttempt: 2,
  },
};

test("manifest output is deterministic and sorted independent of creation order", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-qualification-"));
  const bundle = path.join(temp, "bundle");
  await fs.mkdir(path.join(bundle, "z"), { recursive: true });
  await fs.mkdir(path.join(bundle, "a"));
  await fs.writeFile(path.join(bundle, "z", "program.tar.gz"), "program");
  await fs.writeFile(path.join(bundle, "a", "package.whl"), "wheel");

  const output = path.join(bundle, "release-qualification.json");
  const first = generateManifest({ bundleDir: bundle, identity, outputPath: output });
  const firstBytes = await fs.readFile(output);
  await fs.rm(output);
  await fs.rm(path.join(bundle, "a", "package.whl"));
  await fs.writeFile(path.join(bundle, "a", "package.whl"), "wheel");
  const second = generateManifest({ bundleDir: bundle, identity, outputPath: output });

  assert.deepEqual(first, second);
  assert.deepEqual(second.files.map((entry) => entry.path), [
    "a/package.whl",
    "z/program.tar.gz",
  ]);
  assert.deepEqual(second.files.map((entry) => entry.kind), ["wheel", "cli"]);
  assert.deepEqual(second.qualification, {
    workflow: "release-readiness.yml",
    runId: 123,
    runAttempt: 2,
  });
  assert.equal(classifyArtifact("pi/package.tgz"), "pi");
  assert.equal(classifyArtifact("agent-plugin/package.tar.gz"), "agent-plugin");
  assert.deepEqual(await fs.readFile(output), firstBytes);
});

test("CLI manifest and verify commands complete a local smoke", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-qualification-cli-"));
  const bundle = path.join(temp, "bundle");
  const output = path.join(bundle, "release-qualification.json");
  const identityPath = path.join(temp, "identity.json");
  const runsPath = path.join(temp, "runs.json");
  const artifactsPath = path.join(temp, "artifacts.json");
  await fs.mkdir(bundle);
  await fs.writeFile(path.join(bundle, "cli.tar.gz"), "release");
  await fs.writeFile(identityPath, `${JSON.stringify(identity)}\n`);
  await fs.writeFile(runsPath, JSON.stringify({ workflow_runs: [readinessRun(123)] }));
  await fs.writeFile(artifactsPath, JSON.stringify({
    artifacts: [qualificationArtifact(123, { expires_at: "2099-01-01T00:00:00Z" })],
  }));

  await execFileAsync(process.execPath, [
    script,
    "manifest",
    "--bundle",
    bundle,
    "--identity",
    identityPath,
    "--output",
    output,
  ]);
  const { stdout } = await execFileAsync(process.execPath, [
    script,
    "verify",
    "--bundle",
    bundle,
    "--manifest",
    output,
    "--repository",
    "BrokkAi/bifrost",
    "--commit",
    commit,
    "--version",
    version,
    "--run-id",
    "123",
  ]);
  assert.match(stdout, /"schemaVersion": 1/u);

  const selected = await execFileAsync(process.execPath, [
    script,
    "select-run",
    "--runs",
    runsPath,
    "--artifacts",
    artifactsPath,
    "--repository",
    repository,
    "--commit",
    commit,
    "--version",
    version,
    "--run-id",
    "123",
  ]);
  assert.match(selected.stdout, /"runId": 123/u);
});

test("manifest generation refuses to overwrite an existing output", async () => {
  const { bundle, output } = await preparedBundle();
  const before = await fs.readFile(output);
  assert.throws(
    () => generateManifest({ bundleDir: bundle, identity, outputPath: output }),
    /Manifest output already exists/u,
  );
  assert.deepEqual(await fs.readFile(output), before);
});

test("verify detects one-byte tampering", async () => {
  const { bundle, output } = await preparedBundle();
  await fs.writeFile(path.join(bundle, "cli.tar.gz"), "tampered");
  assert.throws(
    () => verifyManifest({ bundleDir: bundle, manifestPath: output }),
    /Tampered qualification files: cli\.tar\.gz/u,
  );
});

test("verify detects missing and extra files", async () => {
  const missing = await preparedBundle();
  await fs.rm(path.join(missing.bundle, "cli.tar.gz"));
  assert.throws(
    () => verifyManifest({ bundleDir: missing.bundle, manifestPath: missing.output }),
    /missing=.*cli\.tar\.gz/u,
  );

  const extra = await preparedBundle();
  await fs.writeFile(path.join(extra.bundle, "unexpected.txt"), "extra");
  assert.throws(
    () => verifyManifest({ bundleDir: extra.bundle, manifestPath: extra.output }),
    /extra=.*unexpected\.txt/u,
  );
});

test("unsafe manifest paths and symlinks are rejected", async () => {
  assert.throws(
    () => normalizeManifestPath("../outside.tar.gz"),
    /Unsafe manifest path/u,
  );

  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-qualification-"));
  const bundle = path.join(temp, "bundle");
  await fs.mkdir(bundle);
  await fs.writeFile(path.join(temp, "outside"), "outside");
  await fs.symlink(path.join(temp, "outside"), path.join(bundle, "link"));
  assert.throws(
    () => generateManifest({ bundleDir: bundle, identity }),
    /Symbolic links are not allowed/u,
  );
});

test("identity validation and verification reject wrong release identity", async () => {
  assert.throws(
    () => validateIdentity({
      ...identity,
      qualification: { ...identity.qualification, artifactId: 456 },
    }),
    /unexpected fields: artifactId/u,
  );
  assert.throws(
    () => validateIdentity({
      ...identity,
      release: { version, tag: "v0.10.2" },
    }),
    /does not match version/u,
  );
  const { bundle, output } = await preparedBundle();
  assert.throws(
    () => verifyManifest({
      bundleDir: bundle,
      manifestPath: output,
      expected: {
        release: { version },
        source: { repository: "BrokkAi/bifrost", publicCommit: otherCommit },
      },
    }),
    /manifest commit mismatch/u,
  );
  assert.throws(
    () => verifyManifest({
      bundleDir: bundle,
      manifestPath: output,
      expected: {
        release: { version: "0.10.2" },
        source: { repository: "BrokkAi/bifrost", publicCommit: commit },
      },
    }),
    /manifest version mismatch/u,
  );
});

test("selection rejects expired or absent qualification artifacts", () => {
  const run = readinessRun(1);
  assert.throws(
    () => selectQualificationRun({
      runs: { workflow_runs: [run] },
      artifacts: { artifacts: [qualificationArtifact(1, { expired: true })] },
      repository,
      commit,
      version,
      now: Date.parse("2026-08-17T12:00:00Z"),
    }),
    /No successful, unexpired/u,
  );
  assert.throws(
    () => selectQualificationRun({
      runs: { workflow_runs: [run] },
      artifacts: { artifacts: [] },
      repository,
      commit,
      version,
      now: Date.parse("2026-08-17T12:00:00Z"),
    }),
    /No successful, unexpired/u,
  );
});

test("selection rejects ambiguity and supports explicit run selection", () => {
  const runs = [readinessRun(1), readinessRun(2)];
  const artifacts = [qualificationArtifact(1), qualificationArtifact(2)];
  const now = Date.parse("2026-08-17T12:00:00Z");
  assert.throws(
    () => selectQualificationRun({
      runs: { workflow_runs: runs },
      artifacts: { artifacts },
      repository,
      commit,
      version,
      now,
    }),
    /Ambiguous release qualification runs: 1, 2/u,
  );
  const selected = selectQualificationRun({
    runs: { workflow_runs: runs },
    artifacts: { artifacts },
    repository,
    commit,
    version,
    runId: "2",
    now,
  });
  assert.equal(selected.run.id, 2);
  assert.equal(selected.artifact.id, 1002);
});

test("selection requires the exact commit, version, workflow, and successful conclusion", () => {
  const validRun = readinessRun(1);
  const invalidRuns = [
    { ...validRun, head_sha: otherCommit },
    { ...validRun, id: 2, inputs: { version: "0.10.2" } },
    { ...validRun, id: 3, path: "release.yml" },
    { ...validRun, id: 4, conclusion: "failure" },
  ];
  const artifacts = invalidRuns.map((run) => qualificationArtifact(run.id));
  assert.throws(
    () => selectQualificationRun({
      runs: { workflow_runs: invalidRuns },
      artifacts: { artifacts },
      repository,
      commit,
      version,
      now: Date.parse("2026-08-17T12:00:00Z"),
    }),
    /No successful, unexpired/u,
  );
});

test("selection accepts the official workflow-run shape without dispatch inputs", () => {
  const run = readinessRun(1);
  delete run.inputs;
  const selected = selectQualificationRun({
    runs: { workflow_runs: [run] },
    artifacts: { artifacts: [qualificationArtifact(1)] },
    repository,
    commit,
    version,
    now: Date.parse("2026-08-17T12:00:00Z"),
  });
  assert.equal(selected.run.id, 1);
});

test("selection rejects qualification artifacts with near-miss commit or version names", () => {
  const run = readinessRun(1);
  const now = Date.parse("2026-08-17T12:00:00Z");
  for (const name of [
    `release-qualification-${commit}-v0.10.2`,
    `release-qualification-${otherCommit}-v${version}`,
    `release-qualification-${commit}-v${version}-retry`,
  ]) {
    assert.throws(
      () => selectQualificationRun({
        runs: { workflow_runs: [run] },
        artifacts: { artifacts: [qualificationArtifact(1, { name })] },
        repository,
        commit,
        version,
        now,
      }),
      /No successful, unexpired/u,
    );
  }
});

test("selection rejects a successful run from another repository", () => {
  const run = {
    ...readinessRun(1),
    repository: { full_name: "other-owner/other-repository" },
  };
  assert.throws(
    () => selectQualificationRun({
      runs: { workflow_runs: [run] },
      artifacts: { artifacts: [qualificationArtifact(1)] },
      repository,
      commit,
      version,
      now: Date.parse("2026-08-17T12:00:00Z"),
    }),
    /No successful, unexpired/u,
  );
});

async function preparedBundle() {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-qualification-"));
  const bundle = path.join(temp, "bundle");
  await fs.mkdir(bundle);
  await fs.writeFile(path.join(bundle, "cli.tar.gz"), "release");
  const output = path.join(bundle, "release-qualification.json");
  generateManifest({ bundleDir: bundle, identity, outputPath: output });
  return { bundle, output };
}

function readinessRun(id) {
  return {
    id,
    path: ".github/workflows/release-readiness.yml",
    status: "completed",
    conclusion: "success",
    head_sha: commit,
    repository: { full_name: "BrokkAi/bifrost" },
    inputs: { version },
    run_attempt: 1,
  };
}

function qualificationArtifact(runId, overrides = {}) {
  return {
    id: 1000 + runId,
    name: qualificationArtifactName(commit, version),
    workflow_run: { id: runId },
    expired: false,
    expires_at: "2026-08-20T12:00:00Z",
    ...overrides,
  };
}
