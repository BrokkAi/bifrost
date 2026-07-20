#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const args = new Set(process.argv.slice(2));
const checkOnly = args.has("--check");
if ([...args].some((arg) => arg !== "--check")) {
  throw new Error("Usage: node scripts/sync-release-version.mjs [--check]");
}

const repoRoot = process.cwd();
const version = readCargoVersion(path.join(repoRoot, "Cargo.toml"));
const existingReleaseMetadata = readJson("plugins/bifrost-agent/bifrost-release.json");
const canCopyReleaseChecksums = existingReleaseMetadata.binaryVersion === version;

const updates = [
  updateJson("plugins/bifrost-agent/.codex-plugin/plugin.json", (json) => {
    json.version = version;
  }),
  updateJson("plugins/bifrost-agent/.claude-plugin/plugin.json", (json) => {
    json.version = version;
  }),
  updateJson("plugins/bifrost-agent/.cursor-plugin/plugin.json", (json) => {
    json.version = version;
  }),
  updateJson(".cursor-plugin/marketplace.json", (json) => {
    json.metadata ??= {};
    json.metadata.version = version;
    for (const plugin of json.plugins ?? []) {
      if (plugin.version !== undefined) {
        plugin.version = version;
      }
    }
  }),
  updateJson("plugins/bifrost-agent/bifrost-release.json", (json) => {
    json.binaryVersion = version;
  }),
  updateJson("plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json", (json) => {
    json.binaryVersion = version;
  }),
  updateJson("editors/vscode/package.json", (json) => {
    json.version = version;
    json.bifrost ??= {};
    json.bifrost.binaryVersion = version;
    if (canCopyReleaseChecksums) {
      json.bifrost.archiveSha256 = existingReleaseMetadata.archiveSha256;
    }
  }),
  updateJson("editors/vscode/package-lock.json", (json) => {
    json.version = version;
    json.packages ??= {};
    json.packages[""] ??= {};
    json.packages[""].version = version;
  }),
  updateText("docs/src/content/docs/rust-library.md", (contents) => {
    const pattern = /^brokk-bifrost = "[^"]+"$/gm;
    const matches = contents.match(pattern) ?? [];
    if (matches.length !== 1) {
      throw new Error(
        `Expected exactly one brokk-bifrost dependency example, found ${matches.length}`,
      );
    }
    return contents.replace(pattern, `brokk-bifrost = "${version}"`);
  }),
].filter(Boolean);

if (checkOnly && updates.length > 0) {
  for (const file of updates) {
    console.error(`${file} is not synced to Cargo.toml version ${version}`);
  }
  process.exit(1);
}

if (updates.length === 0) {
  console.log(`Release metadata is already synced to ${version}.`);
} else if (checkOnly) {
  console.log(`Release metadata is synced to ${version}.`);
} else {
  console.log(`Synced release metadata to ${version}:`);
  for (const file of updates) {
    console.log(`- ${file}`);
  }
  if (!canCopyReleaseChecksums) {
    console.log(
      "Note: editors/vscode/package.json archiveSha256 was left unchanged because plugins/bifrost-agent/bifrost-release.json does not yet match this version.",
    );
  }
}

function readCargoVersion(cargoTomlPath) {
  const cargoToml = fs.readFileSync(cargoTomlPath, "utf8");
  const versionMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"$/m);
  if (!versionMatch) {
    throw new Error("Could not read package version from Cargo.toml");
  }
  return versionMatch[1];
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));
}

function updateJson(relativePath, mutate) {
  const absolutePath = path.join(repoRoot, relativePath);
  const original = fs.readFileSync(absolutePath, "utf8");
  const json = JSON.parse(original);
  mutate(json);
  const next = `${JSON.stringify(json, null, 2)}\n`;
  if (next === original) {
    return null;
  }
  if (!checkOnly) {
    fs.writeFileSync(absolutePath, next);
  }
  return relativePath;
}

function updateText(relativePath, mutate) {
  const absolutePath = path.join(repoRoot, relativePath);
  const original = fs.readFileSync(absolutePath, "utf8");
  const next = mutate(original);
  if (next === original) {
    return null;
  }
  if (!checkOnly) {
    fs.writeFileSync(absolutePath, next);
  }
  return relativePath;
}
