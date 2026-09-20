import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { SUPPORTED_TARGETS } from "../../plugins/bifrost-agent/bin/bifrost-launcher.mjs";

const execFileAsync = promisify(execFile);
const script = path.resolve("scripts/public/prepare-launcher-release-metadata.mjs");

test("projects one compatibility range into launcher release metadata", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-metadata-test-"));
  const { dist, pluginRelease } = await stagedRelease(temp, "0.9.4", "a");
  await fs.writeFile(
    pluginRelease,
    `${JSON.stringify({
      binaryVersion: "0.9.3",
      minimumBinaryVersion: "0.9.0",
      allowPrerelease: false,
      archiveSha256: {},
    }, null, 2)}\n`,
  );

  await prepare(dist, pluginRelease, "0.9.4");

  const projected = JSON.parse(await fs.readFile(pluginRelease, "utf8"));
  assert.equal(projected.binaryVersion, "0.9.4");
  assert.equal(projected.minimumBinaryVersion, "0.9.0");
  assert.equal(projected.allowPrerelease, false);
  assert.deepEqual(
    Object.keys(projected.archiveSha256).sort(),
    [...SUPPORTED_TARGETS].sort(),
  );
});

test("replaces stale release checksums with exact staged archive sidecars", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-metadata-test-"));
  const staleHash = "e5a2fdd5c11dd3d4fce6b06f580cadca56439178345402bf565fb3551d86ee85";
  const stagedHash = "4ebd001ba0c34a28ff0dee84a0df810e1caeb131dbdab6ccefa11e8a7b64a0fd";
  const { dist, pluginRelease } = await stagedRelease(temp, "0.10.3", (target) => (
    target === "universal-apple-darwin" ? stagedHash : "b"
  ));
  await fs.writeFile(
    pluginRelease,
    `${JSON.stringify({
      binaryVersion: "0.10.3",
      minimumBinaryVersion: "0.10.3",
      allowPrerelease: false,
      archiveSha256: { "universal-apple-darwin": staleHash },
    }, null, 2)}\n`,
  );

  await prepare(dist, pluginRelease, "0.10.3");

  const projected = JSON.parse(await fs.readFile(pluginRelease, "utf8"));
  assert.equal(projected.archiveSha256["universal-apple-darwin"], stagedHash);
});

test("resets compatibility when a release starts a new minor series", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-metadata-test-"));
  const { dist, pluginRelease } = await stagedRelease(temp, "0.10.0", "b");
  await fs.writeFile(
    pluginRelease,
    `${JSON.stringify({
      binaryVersion: "0.9.4",
      minimumBinaryVersion: "0.9.0",
      allowPrerelease: false,
    })}\n`,
  );

  await prepare(dist, pluginRelease, "0.10.0");

  const projected = JSON.parse(await fs.readFile(pluginRelease, "utf8"));
  assert.equal(projected.minimumBinaryVersion, "0.10.0");
});

test("requires a launcher release metadata destination", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-metadata-test-"));
  const { dist, pluginRelease } = await stagedRelease(temp, "0.10.0", "b");
  await assert.rejects(
    execFileAsync(process.execPath, [script, "--version", "0.10.0", "--dist", dist]),
    /Missing required --plugin-release/u,
  );
  await assert.rejects(fs.readFile(pluginRelease), /ENOENT/u);
});

async function stagedRelease(temp, version, hashSource) {
  const dist = path.join(temp, "dist");
  const pluginRelease = path.join(temp, "bifrost-release.json");
  await fs.mkdir(dist);
  for (const target of SUPPORTED_TARGETS) {
    const archive = `bifrost-v${version}-${target}${target.includes("windows") ? ".zip" : ".tar.gz"}`;
    const seed = typeof hashSource === "function" ? hashSource(target) : hashSource;
    await fs.writeFile(path.join(dist, `${archive}.sha256`), `${seed.repeat(64).slice(0, 64)}  ${archive}\n`);
  }
  return { dist, pluginRelease };
}

function prepare(dist, pluginRelease, version) {
  return execFileAsync(process.execPath, [
    script,
    "--version",
    version,
    "--dist",
    dist,
    "--plugin-release",
    pluginRelease,
  ]);
}
