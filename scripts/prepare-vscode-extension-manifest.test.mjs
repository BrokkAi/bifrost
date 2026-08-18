import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { SUPPORTED_TARGETS } from "../plugins/bifrost-agent/bin/bifrost-launcher.mjs";

const execFileAsync = promisify(execFile);
const script = path.resolve("scripts/prepare-vscode-extension-manifest.mjs");

test("projects one compatibility range into agent and VSIX release metadata", async () => {
  const temp = await fs.mkdtemp(
    path.join(os.tmpdir(), "bifrost-vscode-manifest-test-"),
  );
  const dist = path.join(temp, "dist");
  const manifest = path.join(temp, "package.json");
  const pluginRelease = path.join(temp, "bifrost-release.json");
  await fs.mkdir(dist);
  await fs.writeFile(
    manifest,
    `${JSON.stringify({ bifrost: { binaryVersion: "0.9.3" } }, null, 2)}\n`,
  );
  await fs.writeFile(
    pluginRelease,
    `${JSON.stringify(
      {
        binaryVersion: "0.9.3",
        minimumBinaryVersion: "0.9.0",
        allowPrerelease: false,
        archiveSha256: {},
      },
      null,
      2,
    )}\n`,
  );
  for (const target of SUPPORTED_TARGETS) {
    const archive = `bifrost-v0.9.4-${target}${target.includes("windows") ? ".zip" : ".tar.gz"}`;
    await fs.writeFile(
      path.join(dist, `${archive}.sha256`),
      `${"a".repeat(64)}  ${archive}\n`,
    );
  }

  await execFileAsync(process.execPath, [
    script,
    "--version",
    "0.9.4",
    "--dist",
    dist,
    "--manifest",
    manifest,
    "--plugin-release",
    pluginRelease,
  ]);

  const projectedManifest = JSON.parse(await fs.readFile(manifest, "utf8"));
  const projectedPlugin = JSON.parse(await fs.readFile(pluginRelease, "utf8"));
  for (const projected of [projectedManifest.bifrost, projectedPlugin]) {
    assert.equal(projected.binaryVersion, "0.9.4");
    assert.equal(projected.minimumBinaryVersion, "0.9.0");
    assert.equal(projected.allowPrerelease, false);
    assert.deepEqual(
      Object.keys(projected.archiveSha256).sort(),
      [...SUPPORTED_TARGETS].sort(),
    );
  }
});

test("replaces stale release checksums with the exact staged archive sidecars", async () => {
  const temp = await fs.mkdtemp(
    path.join(os.tmpdir(), "bifrost-vscode-manifest-test-"),
  );
  const dist = path.join(temp, "dist");
  const manifest = path.join(temp, "package.json");
  const pluginRelease = path.join(temp, "bifrost-release.json");
  await fs.mkdir(dist);
  const staleHash = "e5a2fdd5c11dd3d4fce6b06f580cadca56439178345402bf565fb3551d86ee85";
  const stagedHash = "4ebd001ba0c34a28ff0dee84a0df810e1caeb131dbdab6ccefa11e8a7b64a0fd";
  await fs.writeFile(
    manifest,
    `${JSON.stringify({
      bifrost: {
        binaryVersion: "0.10.3",
        archiveSha256: { "universal-apple-darwin": staleHash },
      },
    }, null, 2)}\n`,
  );
  await fs.writeFile(
    pluginRelease,
    `${JSON.stringify({
      binaryVersion: "0.10.3",
      minimumBinaryVersion: "0.10.3",
      allowPrerelease: false,
      archiveSha256: { "universal-apple-darwin": staleHash },
    }, null, 2)}\n`,
  );
  for (const target of SUPPORTED_TARGETS) {
    const archive = `bifrost-v0.10.3-${target}${target.includes("windows") ? ".zip" : ".tar.gz"}`;
    const hash = target === "universal-apple-darwin" ? stagedHash : "b".repeat(64);
    await fs.writeFile(
      path.join(dist, `${archive}.sha256`),
      `${hash}  ${archive}\n`,
    );
  }

  await execFileAsync(process.execPath, [
    script,
    "--version",
    "0.10.3",
    "--dist",
    dist,
    "--manifest",
    manifest,
    "--plugin-release",
    pluginRelease,
  ]);

  const projectedManifest = JSON.parse(await fs.readFile(manifest, "utf8"));
  const projectedPlugin = JSON.parse(await fs.readFile(pluginRelease, "utf8"));
  assert.equal(
    projectedManifest.bifrost.archiveSha256["universal-apple-darwin"],
    stagedHash,
  );
  assert.equal(
    projectedPlugin.archiveSha256["universal-apple-darwin"],
    stagedHash,
  );
  assert.notEqual(
    projectedPlugin.archiveSha256["universal-apple-darwin"],
    staleHash,
  );
});

test("resets both projections when a release starts a new minor series", async () => {
  const temp = await fs.mkdtemp(
    path.join(os.tmpdir(), "bifrost-vscode-manifest-test-"),
  );
  const dist = path.join(temp, "dist");
  const manifest = path.join(temp, "package.json");
  const pluginRelease = path.join(temp, "bifrost-release.json");
  await fs.mkdir(dist);
  await fs.writeFile(manifest, `${JSON.stringify({ bifrost: {} })}\n`);
  await fs.writeFile(
    pluginRelease,
    `${JSON.stringify({
      binaryVersion: "0.9.4",
      minimumBinaryVersion: "0.9.0",
      allowPrerelease: false,
    })}\n`,
  );
  for (const target of SUPPORTED_TARGETS) {
    const archive = `bifrost-v0.10.0-${target}${target.includes("windows") ? ".zip" : ".tar.gz"}`;
    await fs.writeFile(
      path.join(dist, `${archive}.sha256`),
      `${"b".repeat(64)}  ${archive}\n`,
    );
  }

  await execFileAsync(process.execPath, [
    script,
    "--version",
    "0.10.0",
    "--dist",
    dist,
    "--manifest",
    manifest,
    "--plugin-release",
    pluginRelease,
  ]);

  const projectedManifest = JSON.parse(await fs.readFile(manifest, "utf8"));
  const projectedPlugin = JSON.parse(await fs.readFile(pluginRelease, "utf8"));
  assert.equal(projectedManifest.bifrost.minimumBinaryVersion, "0.10.0");
  assert.equal(projectedPlugin.minimumBinaryVersion, "0.10.0");
});
