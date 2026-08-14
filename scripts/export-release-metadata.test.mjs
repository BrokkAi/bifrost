import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const script = path.resolve("scripts/export-release-metadata.mjs");
const exportedFiles = [
  "editors/vscode/package.json",
  "plugins/bifrost-agent/bifrost-release.json",
];

test("exports only release metadata with identity and content hashes", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-release-export-"));
  const sourceRoot = path.join(temp, "source");
  const outputDir = path.join(temp, "output");
  const contentsByPath = new Map([
    [exportedFiles[0], '{"name":"bifrost-vscode"}\n'],
    [exportedFiles[1], '{"binaryVersion":"0.10.0"}\n'],
  ]);
  for (const [relativePath, contents] of contentsByPath) {
    const filePath = path.join(sourceRoot, relativePath);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, contents);
  }

  const publicCommit = "a".repeat(40);
  await execFileAsync(process.execPath, [
    script,
    "--tag",
    "v0.10.0",
    "--version",
    "0.10.0",
    "--public-commit",
    publicCommit,
    "--output-dir",
    outputDir,
    "--source-root",
    sourceRoot,
  ]);

  assert.deepEqual(await listFiles(outputDir), [
    "editors/vscode/package.json",
    "plugins/bifrost-agent/bifrost-release.json",
    "release-metadata-export.json",
  ]);
  const manifest = JSON.parse(
    await fs.readFile(path.join(outputDir, "release-metadata-export.json"), "utf8"),
  );
  assert.deepEqual(manifest.release, {
    tag: "v0.10.0",
    version: "0.10.0",
    publicCommit,
  });
  assert.deepEqual(
    manifest.files,
    exportedFiles.map((relativePath) => ({
      path: relativePath,
      sha256: createHash("sha256")
        .update(contentsByPath.get(relativePath))
        .digest("hex"),
    })),
  );
  for (const [relativePath, contents] of contentsByPath) {
    assert.equal(await fs.readFile(path.join(outputDir, relativePath), "utf8"), contents);
  }
});

test("rejects mismatched release identity", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-release-export-"));
  await assert.rejects(
    execFileAsync(process.execPath, [
      script,
      "--tag",
      "v0.10.1",
      "--version",
      "0.10.0",
      "--public-commit",
      "a".repeat(40),
      "--output-dir",
      path.join(temp, "output"),
      "--source-root",
      temp,
    ]),
    /does not match version/u,
  );
});

test("refuses an existing export directory", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-release-export-"));
  const outputDir = path.join(temp, "output");
  await fs.mkdir(outputDir);
  await assert.rejects(
    execFileAsync(process.execPath, [
      script,
      "--tag",
      "v0.10.0",
      "--version",
      "0.10.0",
      "--public-commit",
      "a".repeat(40),
      "--output-dir",
      outputDir,
      "--source-root",
      temp,
    ]),
    /EEXIST/u,
  );
});

async function listFiles(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(absolutePath);
      } else {
        files.push(path.relative(root, absolutePath));
      }
    }
  }
  return files.sort();
}
