#!/usr/bin/env node

import fs from "node:fs";
import assert from "node:assert/strict";
import { constants as fsConstants } from "node:fs";
import { SUPPORTED_TARGETS } from "../plugins/bifrost-agent/bin/bifrost-launcher.mjs";

const cargoToml = fs.readFileSync("Cargo.toml", "utf8");
const cargoVersion = cargoToml.match(/^version = "([^"]+)"$/m)?.[1];
if (!cargoVersion) {
  throw new Error("Could not read package version from Cargo.toml");
}

const codexManifestPath = "plugins/bifrost-agent/.codex-plugin/plugin.json";
const codexManifest = JSON.parse(fs.readFileSync(codexManifestPath, "utf8"));
if (codexManifest.version !== cargoVersion) {
  throw new Error(
    `${codexManifestPath} version ${codexManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}

const claudeManifestPath = "plugins/bifrost-agent/.claude-plugin/plugin.json";
const claudeManifest = JSON.parse(fs.readFileSync(claudeManifestPath, "utf8"));
if (claudeManifest.version !== cargoVersion) {
  throw new Error(
    `${claudeManifestPath} version ${claudeManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}

const sharedManifestFields = [
  "name",
  "description",
  "author",
  "homepage",
  "repository",
  "license",
  "keywords",
  "mcpServers",
];
for (const field of sharedManifestFields) {
  assert.deepStrictEqual(
    claudeManifest[field],
    codexManifest[field],
    `${claudeManifestPath} field ${field} does not match ${codexManifestPath}`,
  );
}

const mcpPath = "plugins/bifrost-agent/.mcp.json";
const mcpConfig = JSON.parse(fs.readFileSync(mcpPath, "utf8"));
assert.deepStrictEqual(
  mcpConfig.mcpServers?.bifrost?.command,
  "./bin/bifrost-launcher.mjs",
  `${mcpPath} should launch the package-local Bifrost launcher`,
);
assert.deepStrictEqual(
  mcpConfig.mcpServers?.bifrost?.args?.slice(0, 2),
  ["--mcp", "symbol|extended"],
  `${mcpPath} should use the default Bifrost MCP toolset`,
);
fs.accessSync("plugins/bifrost-agent/bin/bifrost-launcher.mjs", fsConstants.X_OK);

const releaseMetadataPath = "plugins/bifrost-agent/bifrost-release.json";
const releaseMetadata = JSON.parse(fs.readFileSync(releaseMetadataPath, "utf8"));
if (releaseMetadata.binaryVersion !== cargoVersion) {
  throw new Error(
    `${releaseMetadataPath} binaryVersion ${releaseMetadata.binaryVersion} does not match Cargo.toml version ${cargoVersion}`,
  );
}
for (const target of SUPPORTED_TARGETS) {
  const hash = releaseMetadata.archiveSha256?.[target];
  if (!/^[a-f0-9]{64}$/.test(hash ?? "")) {
    throw new Error(`${releaseMetadataPath} is missing a valid archiveSha256.${target}`);
  }
}

const marketplacePath = ".agents/plugins/marketplace.json";
JSON.parse(fs.readFileSync(marketplacePath, "utf8"));

const claudeMarketplacePath = ".claude-plugin/marketplace.json";
JSON.parse(fs.readFileSync(claudeMarketplacePath, "utf8"));

console.log(`Agent plugin manifests are valid for Bifrost ${cargoVersion}.`);
