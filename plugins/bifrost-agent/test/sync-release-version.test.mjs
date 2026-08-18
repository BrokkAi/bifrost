import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES,
  BIFROST_OWNED_SEMANTIC_PACK_SPECS,
  RELEASE_BUNDLE_SPECS,
  RELEASED_CARGO_MANIFESTS,
  THIRD_PARTY_SEMANTIC_PACK_SPECS,
} from "../../../scripts/release-version.mjs";

const execFileAsync = promisify(execFile);
const testDir = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDir, "../../..");
const releaseVersionScript = path.resolve(testDir, "../../../scripts/release-version.mjs");

const jsonProjections = [
  "plugins/bifrost-agent/.claude-plugin/plugin.json",
  "plugins/bifrost-agent/.codex-plugin/plugin.json",
  "plugins/bifrost-agent/.cursor-plugin/plugin.json",
  "plugins/bifrost-agent/plugin.json",
  ".cursor-plugin/marketplace.json",
  "plugins/bifrost-agent/bifrost-release.json",
  "plugins/bifrost-dsh/bifrost-release.json",
  "plugins/bifrost-agent/package.json",
  "plugins/bifrost-dsh/package.json",
  "plugins/bifrost-agent/package-lock.json",
  "editors/vscode/package.json",
  "editors/vscode/package-lock.json",
];

const allProjections = [
  ...jsonProjections,
  ...RELEASE_BUNDLE_SPECS,
  ...BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES,
  "CITATION.cff",
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

test("release version update synchronizes RQL internal dependencies", async () => {
  const root = await createFixture("1.2.4", "1.2.3", "\n");
  const manifest = path.join(root, "crates/bifrost-rql/Cargo.toml");
  try {
    await writeFile(
      manifest,
      '[package]\nname = "brokk-bifrost-rql"\nversion.workspace = true\n\n[dependencies]\nbrokk-bifrost-core = { path = "../bifrost-core", version = "=1.2.3" }\n',
    );

    await execFileAsync(process.execPath, [releaseVersionScript, "sync"], { cwd: root });

    assert.match(await readFile(manifest, "utf8"), /version = "=1\.2\.4"/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release version update includes the current version in release bundle compatibility", async () => {
  const root = await createFixture("2.0.0", "1.2.3", "\n");
  try {
    await execFileAsync(process.execPath, [releaseVersionScript, "sync"], { cwd: root });

    for (const relativePath of RELEASE_BUNDLE_SPECS) {
      const spec = JSON.parse(await readFile(path.join(root, relativePath), "utf8"));
      assert.equal(spec.compatibility.bifrost, ">=0.8.0, <3.0.0");
    }
    for (const relativePath of BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES) {
      assert.match(
        await readFile(path.join(root, relativePath), "utf8"),
        /const BIFROST_REQUIREMENT: &str = ">=0\.8\.0, <3\.0\.0";/u,
      );
    }
    assert.match(
      await readFile(path.join(root, "CITATION.cff"), "utf8"),
      /^version: "2\.0\.0"$/mu,
    );
    assert.match(
      await readFile(path.join(root, "CITATION.cff"), "utf8"),
      /^date-released: "2026-08-13"$/mu,
    );
    const release = JSON.parse(
      await readFile(path.join(root, "plugins/bifrost-agent/bifrost-release.json"), "utf8"),
    );
    assert.equal(release.binaryVersion, "2.0.0");
    assert.equal(release.minimumBinaryVersion, "2.0.0");
    assert.equal(release.allowPrerelease, false);
    const vscode = JSON.parse(
      await readFile(path.join(root, "editors/vscode/package.json"), "utf8"),
    );
    assert.equal(vscode.bifrost.binaryVersion, "2.0.0");
    assert.equal(vscode.bifrost.minimumBinaryVersion, "2.0.0");
    assert.equal(vscode.bifrost.allowPrerelease, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release version update preserves third-party semantic pack metadata", async () => {
  const root = await createFixture("2.0.0", "1.2.3", "\n");
  try {
    const before = new Map();
    for (const relativePath of THIRD_PARTY_SEMANTIC_PACK_SPECS) {
      before.set(
        relativePath,
        JSON.parse(await readFile(path.join(root, relativePath), "utf8")),
      );
    }

    await execFileAsync(process.execPath, [releaseVersionScript, "sync"], { cwd: root });

    for (const relativePath of THIRD_PARTY_SEMANTIC_PACK_SPECS) {
      const original = before.get(relativePath);
      const updated = JSON.parse(await readFile(path.join(root, relativePath), "utf8"));
      updated.compatibility.bifrost = original.compatibility.bifrost;
      assert.deepEqual(updated, original, `${relativePath} changed non-Bifrost metadata`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release metadata inventory covers every owned foundry compatibility surface", async () => {
  const discoveredSpecs = [];
  for (const relativeRoot of [
    "semantic-packs/framework-decls",
    "semantic-packs/golden-core",
    "semantic-packs/sanitizers",
  ]) {
    for (const relativePath of await listFilesRecursively(repositoryRoot, relativeRoot)) {
      if (!relativePath.endsWith(".json")) {
        continue;
      }
      const json = JSON.parse(await readFile(path.join(repositoryRoot, relativePath), "utf8"));
      if (typeof json.compatibility?.bifrost === "string") {
        discoveredSpecs.push(relativePath);
      }
    }
  }
  assert.deepEqual(
    discoveredSpecs.sort(),
    [...BIFROST_OWNED_SEMANTIC_PACK_SPECS].sort(),
  );

  const discoveredSources = [];
  for (const relativePath of await listFilesRecursively(
    repositoryRoot,
    "crates/bifrost-semantic-packs/src/summary_foundry",
  )) {
    if (
      relativePath.endsWith(".rs")
      && (await readFile(path.join(repositoryRoot, relativePath), "utf8")).includes(
        "const BIFROST_REQUIREMENT: &str",
      )
    ) {
      discoveredSources.push(relativePath);
    }
  }
  assert.deepEqual(
    discoveredSources.sort(),
    [...BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES].sort(),
  );
});

test("release version update resets launcher compatibility on a new minor series", async () => {
  const root = await createFixture("1.3.0", "1.2.9", "\n");
  try {
    await execFileAsync(process.execPath, [releaseVersionScript, "sync"], { cwd: root });
    const release = JSON.parse(
      await readFile(path.join(root, "plugins/bifrost-agent/bifrost-release.json"), "utf8"),
    );
    assert.equal(release.binaryVersion, "1.3.0");
    assert.equal(release.minimumBinaryVersion, "1.3.0");
    const vscode = JSON.parse(
      await readFile(path.join(root, "editors/vscode/package.json"), "utf8"),
    );
    assert.equal(vscode.bifrost.minimumBinaryVersion, "1.3.0");
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
      /does not match Cargo\.toml workspace package version/u,
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
    `[workspace.package]${lineEnding}version = "${cargoVersion}"${lineEnding}${lineEnding}[package]${lineEnding}name = "fixture"${lineEnding}version.workspace = true${lineEnding}`,
  );
  for (const relativePath of RELEASED_CARGO_MANIFESTS.slice(1)) {
    await writeFixtureFile(
      root,
      relativePath,
      `[package]${lineEnding}name = "fixture"${lineEnding}version.workspace = true${lineEnding}`,
    );
  }
  for (const relativePath of RELEASE_BUNDLE_SPECS) {
    const upperBound = compatibilityUpperBound(projectionVersion);
    const spec = JSON.stringify(
      {
        pack_id: `fixture.${path.basename(relativePath, ".json")}`,
        version: "7.8.9",
        producer: { name: "fixture-producer", version: "6.5.4" },
        compatibility: {
          bifrost: `>=0.8.0, <${upperBound}`,
          toolchains: [{ name: "fixture-toolchain", requirement: ">=3.2.1" }],
        },
        provenance: { source: "fixture-source", revision: "fixture-revision" },
        license: "Fixture-License",
      },
      null,
      2,
    ).replaceAll("\n", lineEnding);
    await writeFixtureFile(
      root,
      relativePath,
      `${spec}${lineEnding}`,
    );
  }
  for (const relativePath of BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES) {
    const upperBound = compatibilityUpperBound(projectionVersion);
    await writeFixtureFile(
      root,
      relativePath,
      `const BIFROST_REQUIREMENT: &str = ">=0.8.0, <${upperBound}";${lineEnding}`,
    );
  }
  await writeFixtureFile(
    root,
    "CITATION.cff",
    `cff-version: 1.2.0${lineEnding}version: "${projectionVersion}"${lineEnding}date-released: "2026-08-13"${lineEnding}references:${lineEnding}  - version: "7.8.9"${lineEnding}`,
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
    minimumBinaryVersion: projectionVersion,
    allowPrerelease: false,
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
      minimumBinaryVersion: projectionVersion,
      allowPrerelease: false,
      archiveSha256: { test: "checksum" },
    },
  };

  const values = new Map([
    ["plugins/bifrost-agent/.claude-plugin/plugin.json", basicPlugin],
    ["plugins/bifrost-agent/.codex-plugin/plugin.json", basicPlugin],
    ["plugins/bifrost-agent/.cursor-plugin/plugin.json", basicPlugin],
    ["plugins/bifrost-agent/plugin.json", basicPlugin],
    [".cursor-plugin/marketplace.json", marketplace],
    ["plugins/bifrost-agent/bifrost-release.json", release],
    ["plugins/bifrost-dsh/bifrost-release.json", release],
    ["plugins/bifrost-agent/package.json", basicPlugin],
    ["plugins/bifrost-dsh/package.json", basicPlugin],
    ["plugins/bifrost-agent/package-lock.json", packageLock],
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

async function listFilesRecursively(root, relativeDirectory) {
  const files = [];
  const entries = await readdir(path.join(root, relativeDirectory), { withFileTypes: true });
  for (const entry of entries) {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listFilesRecursively(root, relativePath));
    } else if (entry.isFile()) {
      files.push(relativePath.split(path.sep).join("/"));
    }
  }
  return files;
}

function compatibilityUpperBound(version) {
  const [major, minor] = version.split(".").map(Number);
  return major === 0 ? `0.${minor + 1}.0` : `${major + 1}.0.0`;
}
