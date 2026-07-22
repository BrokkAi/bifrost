import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const testDir = path.dirname(fileURLToPath(import.meta.url));
const releaseVersionScript = path.resolve(testDir, "../../../scripts/release-version.mjs");

const jsonProjections = [
  "plugins/bifrost-agent/.codex-plugin/plugin.json",
  "plugins/bifrost-agent/.claude-plugin/plugin.json",
  "plugins/bifrost-agent/.cursor-plugin/plugin.json",
  ".cursor-plugin/marketplace.json",
  "plugins/bifrost-agent/bifrost-release.json",
  "plugins/bifrost-agent/package.json",
  "plugins/bifrost-agent/package-lock.json",
  "plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json",
  "editors/vscode/package.json",
  "editors/vscode/package-lock.json",
];

const allProjections = [
  ...jsonProjections,
  "plugins/bifrost-agent/README.md",
  "docs/src/content/docs/rust-library.md",
];

test("release version check accepts synced CRLF projections", async () => {
  const root = await createFixture("1.2.3", "1.2.3", "\r\n");
  try {
    await execFileAsync(process.execPath, [releaseVersionScript, "check"], { cwd: root });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release version update preserves CRLF projections", async () => {
  const root = await createFixture("1.2.4", "1.2.3", "\r\n");
  try {
    await execFileAsync(process.execPath, [releaseVersionScript, "sync"], { cwd: root });
    await execFileAsync(process.execPath, [releaseVersionScript, "check"], { cwd: root });

    for (const relativePath of allProjections) {
      const source = await readFile(path.join(root, relativePath), "utf8");
      assert.equal(/(^|[^\r])\n/u.test(source), false, `${relativePath} contains a bare LF`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release version check rejects projection drift", async () => {
  const root = await createFixture("1.2.4", "1.2.3", "\n");
  try {
    await assert.rejects(
      execFileAsync(process.execPath, [releaseVersionScript, "check"], { cwd: root }),
      /Release metadata is not synced to Cargo\.toml version 1\.2\.4/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("GitHub outputs are emitted only after successful release validation", async () => {
  const root = await createFixture("1.2.3", "1.2.3", "\n");
  const outputPath = path.join(root, "github-output.txt");
  try {
    await writeFile(outputPath, "");
    await execFileAsync(
      process.execPath,
      [releaseVersionScript, "check", "--tag", "refs/tags/v1.2.3", "--github-output", outputPath],
      { cwd: root },
    );
    assert.equal(await readFile(outputPath, "utf8"), "tag=v1.2.3\nversion=1.2.3\n");

    await writeFile(outputPath, "");
    await assert.rejects(
      execFileAsync(
        process.execPath,
        [releaseVersionScript, "check", "--tag", "v1.2.4", "--github-output", outputPath],
        { cwd: root },
      ),
      /does not match Cargo\.toml package version/u,
    );
    assert.equal(await readFile(outputPath, "utf8"), "");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function createFixture(cargoVersion, projectionVersion, lineEnding) {
  const root = await mkdtemp(path.join(tmpdir(), "bifrost-release-version-"));
  await writeFixtureFile(
    root,
    "Cargo.toml",
    `[package]${lineEnding}version = "${cargoVersion}"${lineEnding}`,
  );
  await writeFixtureFile(
    root,
    "pyproject.toml",
    `[project]${lineEnding}dynamic = ["version"]${lineEnding}`,
  );

  const basicPlugin = { version: projectionVersion };
  const marketplace = {
    metadata: { version: projectionVersion },
    plugins: [{ version: projectionVersion }],
  };
  const release = {
    binaryVersion: projectionVersion,
    archiveSha256: { test: "checksum" },
  };
  const packageLock = {
    version: projectionVersion,
    packages: { "": { version: projectionVersion } },
  };
  const vscodePackage = {
    version: projectionVersion,
    bifrost: {
      binaryVersion: projectionVersion,
      archiveSha256: { test: "checksum" },
    },
  };

  const values = new Map([
    ["plugins/bifrost-agent/.codex-plugin/plugin.json", basicPlugin],
    ["plugins/bifrost-agent/.claude-plugin/plugin.json", basicPlugin],
    ["plugins/bifrost-agent/.cursor-plugin/plugin.json", basicPlugin],
    [".cursor-plugin/marketplace.json", marketplace],
    ["plugins/bifrost-agent/bifrost-release.json", release],
    ["plugins/bifrost-agent/package.json", basicPlugin],
    ["plugins/bifrost-agent/package-lock.json", packageLock],
    ["plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json", release],
    ["editors/vscode/package.json", vscodePackage],
    ["editors/vscode/package-lock.json", packageLock],
  ]);

  for (const relativePath of jsonProjections) {
    const json = JSON.stringify(values.get(relativePath), null, 2).replaceAll("\n", lineEnding);
    await writeFixtureFile(root, relativePath, `${json}${lineEnding}`);
  }
  await writeFixtureFile(
    root,
    "plugins/bifrost-agent/README.md",
    `Install:${lineEnding}${lineEnding}pi install npm:@brokk/bifrost-agent@${projectionVersion}${lineEnding}`,
  );
  await writeFixtureFile(
    root,
    "docs/src/content/docs/rust-library.md",
    `Install:${lineEnding}${lineEnding}brokk-bifrost = "${projectionVersion}"${lineEnding}`,
  );
  return root;
}

async function writeFixtureFile(root, relativePath, contents) {
  const absolutePath = path.join(root, relativePath);
  await mkdir(path.dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, contents);
}
