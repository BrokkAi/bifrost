#!/usr/bin/env node

import fs from "node:fs";

const cargoToml = fs.readFileSync("Cargo.toml", "utf8");
const cargoVersion = cargoToml.match(/^version = "([^"]+)"$/m)?.[1];
if (!cargoVersion) {
  throw new Error("Could not read package version from Cargo.toml");
}

const manifestPath = "plugins/bifrost-agent/.codex-plugin/plugin.json";
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
if (manifest.version !== cargoVersion) {
  throw new Error(
    `${manifestPath} version ${manifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}

const mcpPath = "plugins/bifrost-agent/.mcp.json";
JSON.parse(fs.readFileSync(mcpPath, "utf8"));

const marketplacePath = ".agents/plugins/marketplace.json";
JSON.parse(fs.readFileSync(marketplacePath, "utf8"));

console.log(`Codex plugin manifest is valid for Bifrost ${cargoVersion}.`);
