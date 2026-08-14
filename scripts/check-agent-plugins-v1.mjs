#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readCargoVersion } from "./release-version.mjs";

const PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const PLUGIN_FIELDS = [
  "$schema",
  "name",
  "version",
  "description",
  "author",
  "homepage",
  "repository",
  "license",
  "keywords",
];
const MCP_FIELDS = ["$schema", "mcpServers"];
const SERVER_FIELDS = ["type", "command", "args"];

export function validateAgentPluginDirectory(pluginDir, expectedVersion) {
  const resolvedPluginDir = path.resolve(pluginDir);
  const pluginPath = path.join(resolvedPluginDir, "plugin.json");
  const mcpPath = path.join(resolvedPluginDir, "mcp.json");
  const plugin = readJson(pluginPath);
  const mcp = readJson(mcpPath);

  assert.deepEqual(
    Object.keys(plugin).sort(),
    [...PLUGIN_FIELDS].sort(),
    `${pluginPath} must contain only portable Agent Plugins v1 fields`,
  );
  assert.equal(plugin.$schema, PLUGIN_SCHEMA, `${pluginPath} must use the Agent Plugins v1 plugin schema`);
  assert.equal(plugin.name, "bifrost", `${pluginPath} must use the portable bifrost name`);
  assert.equal(plugin.version, expectedVersion, `${pluginPath} version must match Cargo.toml`);
  assert.equal(typeof plugin.description, "string", `${pluginPath} must describe the plugin`);
  assert.deepEqual(plugin.author, { name: "Brokk", url: "https://brokk.ai" }, `${pluginPath} must identify Brokk`);
  assert.equal(typeof plugin.homepage, "string", `${pluginPath} must include the homepage`);
  assert.equal(typeof plugin.repository, "string", `${pluginPath} must include the repository`);
  assert.equal(typeof plugin.license, "string", `${pluginPath} must include the license`);
  assert.ok(Array.isArray(plugin.keywords) && plugin.keywords.length > 0, `${pluginPath} must include keywords`);

  assert.deepEqual(
    Object.keys(mcp).sort(),
    [...MCP_FIELDS].sort(),
    `${mcpPath} must contain only portable Agent Plugins v1 fields`,
  );
  assert.equal(mcp.$schema, MCP_SCHEMA, `${mcpPath} must use the Agent Plugins v1 MCP schema`);
  assert.deepEqual(Object.keys(mcp.mcpServers ?? {}), ["bifrost"], `${mcpPath} must define only the bifrost MCP server`);
  const server = mcp.mcpServers?.bifrost;
  assert.deepEqual(
    Object.keys(server ?? {}).sort(),
    [...SERVER_FIELDS].sort(),
    `${mcpPath} must not contain host-specific MCP settings`,
  );
  assert.equal(server?.type, "stdio", `${mcpPath} must declare a stdio MCP server`);
  assert.equal(server?.command, "./bin/bifrost-launcher.mjs", `${mcpPath} must use the portable relative launcher`);
  assert.deepEqual(server?.args, ["--mcp", "symbol|extended"], `${mcpPath} must use the default Bifrost MCP toolset`);
  assert.ok(!server.command.includes("${"), `${mcpPath} must not use a client-specific environment variable`);

  const skillsRoot = path.join(resolvedPluginDir, "skills");
  const skillDirectories = fs.existsSync(skillsRoot)
    ? fs.readdirSync(skillsRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort()
    : [];
  for (const skillDirectory of skillDirectories) {
    const skillRoot = path.join(skillsRoot, skillDirectory);
    fs.accessSync(path.join(skillRoot, "SKILL.md"), fs.constants.R_OK);
    assert.equal(
      findNestedSkillFiles(skillRoot).length,
      0,
      `${skillRoot} must not contain nested portable skills`,
    );
  }

  const cursorManifestPath = path.join(resolvedPluginDir, ".cursor-plugin", "plugin.json");
  const cursorManifest = readJson(cursorManifestPath);
  assert.equal(
    cursorManifest.mcpServers,
    "./cursor-mcp.json",
    `${cursorManifestPath} must keep Cursor-specific configuration in an adapter`,
  );
  const cursorMcpPath = path.join(resolvedPluginDir, "cursor-mcp.json");
  const cursorMcp = readJson(cursorMcpPath);
  assert.equal(
    cursorMcp.mcpServers?.bifrost?.command,
    "${CURSOR_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
    `${cursorMcpPath} must retain Cursor's package-root adapter`,
  );

  return { name: plugin.name, version: plugin.version, skills: skillDirectories };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function findNestedSkillFiles(skillRoot) {
  const nestedSkillFiles = [];
  const pending = fs.readdirSync(skillRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(skillRoot, entry.name));
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(entryPath);
      } else if (entry.isFile() && entry.name === "SKILL.md") {
        nestedSkillFiles.push(entryPath);
      }
    }
  }
  return nestedSkillFiles;
}

function parseArgs(args) {
  if (args.length === 0) {
    return { pluginDir: "plugins/bifrost-agent" };
  }
  if (args.length !== 2 || args[0] !== "--plugin-dir") {
    throw new Error("Usage: check-agent-plugins-v1.mjs [--plugin-dir <dir>]");
  }
  return { pluginDir: args[1] };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { pluginDir } = parseArgs(process.argv.slice(2));
  const cargoVersion = readCargoVersion(fs.readFileSync("Cargo.toml", "utf8"));
  const result = validateAgentPluginDirectory(pluginDir, cargoVersion);
  console.log(`Validated Agent Plugins v1 package ${result.name} ${result.version} with ${result.skills.length} portable skills.`);
}
