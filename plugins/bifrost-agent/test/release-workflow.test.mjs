import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { SUPPORTED_TARGETS } from "../bin/bifrost-launcher.mjs";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDirectory, "../../..");
const prepareScript = path.join(repoRoot, "scripts", "prepare-vscode-extension-manifest.mjs");

test("agent release preparation projects future checksums into both host manifests", async () => {
  const workflow = await readFile(path.join(repoRoot, ".github", "workflows", "release.yml"), "utf8");
  const agentJobStart = workflow.indexOf("  agent-package:");
  const agentJob = workflow.slice(
    agentJobStart,
    workflow.indexOf("  release:", agentJobStart),
  );
  const prepareStepStart = agentJob.indexOf("      - name: Prepare plugin release metadata");
  const projectionCheckStart = agentJob.indexOf("      - name: Check release version projections");
  assert.ok(prepareStepStart >= 0, "agent package job has no checksum preparation step");
  assert.ok(
    projectionCheckStart > prepareStepStart,
    "release version projections must be checked after both checksum projections are prepared",
  );
  const prepareStep = agentJob.slice(prepareStepStart, projectionCheckStart);
  assert.match(prepareStep, /--manifest editors\/vscode\/package\.json/);
  assert.match(prepareStep, /--plugin-release plugins\/bifrost-agent\/bifrost-release\.json/);

  const release = JSON.parse(await readFile(
    path.join(repoRoot, "plugins", "bifrost-agent", "bifrost-release.json"),
    "utf8",
  ));
  const temp = await mkdtemp(path.join(os.tmpdir(), "bifrost-release-projection-test-"));
  try {
    const dist = path.join(temp, "dist");
    const manifestPath = path.join(temp, "package.json");
    const pluginReleasePath = path.join(temp, "bifrost-release.json");
    await mkdir(dist);

    const futureHashes = {};
    for (const [index, target] of SUPPORTED_TARGETS.entries()) {
      const hash = (index + 10).toString(16).repeat(64).slice(0, 64);
      futureHashes[target] = hash;
      await writeFile(
        path.join(dist, `bifrost-v${release.binaryVersion}-${target}.tar.gz.sha256`),
        `${hash}  archive\n`,
      );
    }
    assert.notDeepEqual(futureHashes, release.archiveSha256);

    await writeFile(manifestPath, JSON.stringify({
      version: release.binaryVersion,
      bifrost: { binaryVersion: release.binaryVersion, archiveSha256: release.archiveSha256 },
    }));
    await writeFile(pluginReleasePath, JSON.stringify(release));

    const prepared = spawnSync(process.execPath, [
      prepareScript,
      "--version", release.binaryVersion,
      "--manifest", manifestPath,
      "--plugin-release", pluginReleasePath,
      "--dist", dist,
    ], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    assert.equal(prepared.status, 0, prepared.stderr);

    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    const pluginRelease = JSON.parse(await readFile(pluginReleasePath, "utf8"));
    assert.deepEqual(manifest.bifrost.archiveSha256, futureHashes);
    assert.deepEqual(pluginRelease.archiveSha256, futureHashes);
    assert.deepEqual(manifest.bifrost.archiveSha256, pluginRelease.archiveSha256);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
