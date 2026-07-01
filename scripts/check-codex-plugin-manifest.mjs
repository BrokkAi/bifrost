#!/usr/bin/env node

import fs from "node:fs";

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

const mcpPath = "plugins/bifrost-agent/.mcp.json";
JSON.parse(fs.readFileSync(mcpPath, "utf8"));

const marketplacePath = ".agents/plugins/marketplace.json";
JSON.parse(fs.readFileSync(marketplacePath, "utf8"));

const claudeMarketplacePath = ".claude-plugin/marketplace.json";
JSON.parse(fs.readFileSync(claudeMarketplacePath, "utf8"));

console.log(`Agent plugin manifests are valid for Bifrost ${cargoVersion}.`);
