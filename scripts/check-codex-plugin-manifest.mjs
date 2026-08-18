#!/usr/bin/env node

import fs from "node:fs";
import assert from "node:assert/strict";
import { constants as fsConstants } from "node:fs";
import {
  MINIMUM_MCP_STARTUP_TIMEOUT_MS,
  SUPPORTED_TARGETS,
} from "../plugins/bifrost-agent/bin/bifrost-launcher.mjs";
import { validateAgentPluginDirectory } from "./check-agent-plugins-v1.mjs";
import { readCargoVersion } from "./release-version.mjs";

const cargoToml = fs.readFileSync("Cargo.toml", "utf8");
const cargoVersion = readCargoVersion(cargoToml);
validateAgentPluginDirectory("plugins/bifrost-agent", cargoVersion);

const claudeManifestPath = "plugins/bifrost-agent/.claude-plugin/plugin.json";
const claudeManifest = JSON.parse(fs.readFileSync(claudeManifestPath, "utf8"));
if (claudeManifest.version !== cargoVersion) {
  throw new Error(
    `${claudeManifestPath} version ${claudeManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}

const cursorManifestPath = "plugins/bifrost-agent/.cursor-plugin/plugin.json";
const cursorManifest = JSON.parse(fs.readFileSync(cursorManifestPath, "utf8"));
if (cursorManifest.version !== cargoVersion) {
  throw new Error(
    `${cursorManifestPath} version ${cursorManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}

const piManifestPath = "plugins/bifrost-agent/package.json";
const piManifest = JSON.parse(fs.readFileSync(piManifestPath, "utf8"));
if (piManifest.version !== cargoVersion) {
  throw new Error(
    `${piManifestPath} version ${piManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}
assert.deepStrictEqual(
  piManifest.pi?.extensions,
  ["./extensions/bifrost.ts"],
  `${piManifestPath} should expose the native Bifrost Pi extension`,
);
assert.deepStrictEqual(
  piManifest.dependencies?.["@modelcontextprotocol/sdk"],
  "1.29.0",
  `${piManifestPath} should pin the reviewed MCP SDK`,
);
assert.deepStrictEqual(
  piManifest.peerDependencies?.["@earendil-works/pi-tui"],
  "*",
  `${piManifestPath} should use Pi's host-provided TUI`,
);
for (const packageFile of [
  "plugins/bifrost-agent/extensions/bifrost.ts",
  "plugins/bifrost-agent/extensions/bifrost-capabilities.ts",
  "plugins/bifrost-agent/extensions/bifrost-session.ts",
  "plugins/bifrost-agent/extensions/bifrost-settings.ts",
  "plugins/bifrost-agent/extensions/mcp-adapter.ts",
  "plugins/bifrost-agent/package-lock.json",
]) {
  fs.accessSync(packageFile, fsConstants.R_OK);
}

const sharedManifestFields = [
  "homepage",
  "repository",
  "license",
  "keywords",
  "agents",
];
for (const field of sharedManifestFields) {
  assert.deepStrictEqual(
    claudeManifest[field],
    cursorManifest[field],
    `${claudeManifestPath} field ${field} does not match ${cursorManifestPath}`,
  );
}
assert.deepStrictEqual(
  cursorManifest.name,
  "bifrost",
  `${cursorManifestPath} should use Bifrost as the Cursor-facing plugin name`,
);
assert.deepStrictEqual(
  cursorManifest.description,
  "Bifrost by Brokk: multi-language code intelligence and MCP workflows.",
  `${cursorManifestPath} should use Bifrost-facing display text`,
);
assert.deepStrictEqual(
  claudeManifest.author?.name,
  cursorManifest.author?.name,
  `${claudeManifestPath} author name does not match ${cursorManifestPath}`,
);
assert.deepStrictEqual(
  cursorManifest.logo,
  "assets/icon.png",
  `${cursorManifestPath} should reference the package icon`,
);
fs.accessSync("plugins/bifrost-agent/assets/icon.png", fsConstants.R_OK);
assert.deepStrictEqual(
  claudeManifest.mcpServers,
  "./claude-mcp.json",
  `${claudeManifestPath} should select Claude Code's host-specific MCP config`,
);
assert.deepStrictEqual(
  claudeManifest.lspServers,
  "./.lsp.json",
  `${claudeManifestPath} should select Claude Code's packaged LSP config`,
);
assert.deepStrictEqual(
  cursorManifest.mcpServers,
  "./cursor-mcp.json",
  `${cursorManifestPath} should select Cursor's host-specific MCP config`,
);
fs.accessSync("plugins/bifrost-agent/assets/icon.png", fsConstants.R_OK);

const cursorPluginNamePattern = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
if (!cursorPluginNamePattern.test(cursorManifest.name)) {
  throw new Error(`${cursorManifestPath} name must be lowercase kebab-case`);
}

const claudeMcpPath = "plugins/bifrost-agent/claude-mcp.json";
const claudeMcpConfig = JSON.parse(fs.readFileSync(claudeMcpPath, "utf8"));
const claudeLspPath = "plugins/bifrost-agent/.lsp.json";
const claudeLspConfig = JSON.parse(fs.readFileSync(claudeLspPath, "utf8"));
const cursorMcpPath = "plugins/bifrost-agent/cursor-mcp.json";
const cursorMcpConfig = JSON.parse(fs.readFileSync(cursorMcpPath, "utf8"));
assert.deepStrictEqual(
  claudeMcpConfig.mcpServers?.bifrost?.command,
  "${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
  `${claudeMcpPath} should resolve the launcher from Claude Code's installed plugin directory`,
);
const claudeLspServer = claudeLspConfig.bifrost;
assert.deepStrictEqual(
  claudeLspServer?.command,
  "${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
  `${claudeLspPath} should resolve the launcher from Claude Code's installed plugin directory`,
);
assert.deepStrictEqual(
  claudeLspServer?.args,
  ["--root", "${CLAUDE_PROJECT_DIR}", "--lsp"],
  `${claudeLspPath} should launch LSP against Claude Code's active project`,
);
assert.deepStrictEqual(
  claudeLspServer?.transport,
  "stdio",
  `${claudeLspPath} should use the Bifrost LSP stdio transport`,
);
assert.deepStrictEqual(
  claudeLspServer?.workspaceFolder,
  "${CLAUDE_PROJECT_DIR}",
  `${claudeLspPath} should initialize against Claude Code's active project`,
);
assert.deepStrictEqual(
  claudeLspServer?.startupTimeout,
  MINIMUM_MCP_STARTUP_TIMEOUT_MS,
  `${claudeLspPath} should cover managed binary provisioning before LSP startup`,
);
assert.equal(
  typeof claudeLspServer?.extensionToLanguage,
  "object",
  `${claudeLspPath} should declare an extension-to-language map`,
);
assert.deepStrictEqual(
  claudeMcpConfig.mcpServers?.bifrost?.cwd,
  undefined,
  `${claudeMcpPath} should not infer a workspace from Claude Code's process directory`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.command,
  "${CURSOR_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
  `${cursorMcpPath} should resolve the launcher from Cursor's installed plugin directory`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.type,
  "stdio",
  `${cursorMcpPath} should use Cursor's documented stdio MCP type`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.cwd,
  undefined,
  `${cursorMcpPath} should not infer a workspace from Cursor's process directory`,
);
assert.deepStrictEqual(
  claudeMcpConfig.mcpServers?.bifrost?.args,
  ["--mcp", "symbol|extended"],
  `${claudeMcpPath} should start rootless with the default Bifrost MCP toolset`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.args,
  ["--mcp", "symbol|extended"],
  `${cursorMcpPath} should start rootless with the default Bifrost MCP toolset`,
);
const claudeMcpServer = claudeMcpConfig.mcpServers?.bifrost;
const cursorMcpServer = cursorMcpConfig.mcpServers?.bifrost;
assert.deepStrictEqual(
  claudeMcpServer?.startup_timeout_sec,
  undefined,
  `${claudeMcpPath} should not use Codex's unsupported startup_timeout_sec field`,
);
assert.deepStrictEqual(
  claudeMcpServer?.tool_timeout_sec,
  undefined,
  `${claudeMcpPath} should not use Codex's unsupported tool_timeout_sec field`,
);
assert.deepStrictEqual(
  cursorMcpServer?.startup_timeout_sec,
  180,
  `${cursorMcpPath} should retain the 180-second startup timeout`,
);
assert.deepStrictEqual(
  cursorMcpServer?.tool_timeout_sec,
  300,
  `${cursorMcpPath} should retain the 300-second tool timeout`,
);
const minimumStartupTimeoutSec = Math.ceil(MINIMUM_MCP_STARTUP_TIMEOUT_MS / 1000);
if ((cursorMcpServer?.startup_timeout_sec ?? 0) < minimumStartupTimeoutSec) {
  throw new Error(
    `${cursorMcpPath} startup_timeout_sec must be at least ${minimumStartupTimeoutSec} seconds ` +
    "to cover download, extraction, version probing, and startup margin",
  );
}
fs.accessSync("plugins/bifrost-agent/bin/bifrost-launcher.mjs", fsConstants.X_OK);
const piSessionSource = fs.readFileSync(
  "plugins/bifrost-agent/extensions/bifrost-session.ts",
  "utf8",
);
assert.match(
  piSessionSource,
  /from "\.\.\/bin\/bifrost-launcher\.mjs"/u,
  "Pi must resolve Bifrost through the shared launcher module",
);
const pluginReadme = fs.readFileSync("plugins/bifrost-agent/README.md", "utf8");
assert.match(
  pluginReadme,
  /"command": "\/absolute\/path\/to\/plugin\/bin\/bifrost-launcher\.mjs"/u,
  "Amp instructions must invoke the shared launcher",
);

const expectedAgents = [
  "./agents/architect-reviewer.md",
  "./agents/devops-reviewer.md",
  "./agents/dry-reviewer.md",
  "./agents/issue-diagnostician.md",
  "./agents/issue-enhancer.md",
  "./agents/issue-planner.md",
  "./agents/security-reviewer.md",
  "./agents/senior-dev-reviewer.md",
];
assert.deepStrictEqual(
  claudeManifest.agents,
  expectedAgents,
  `${claudeManifestPath} should expose workflow specialist agents`,
);
assert.deepStrictEqual(
  cursorManifest.agents,
  expectedAgents,
  `${cursorManifestPath} should expose workflow specialist agents`,
);
for (const agentPath of expectedAgents) {
  fs.accessSync(`plugins/bifrost-agent/${agentPath.slice("./".length)}`, fsConstants.R_OK);
}

const releaseMetadataPath = "plugins/bifrost-agent/bifrost-release.json";
const releaseMetadata = JSON.parse(fs.readFileSync(releaseMetadataPath, "utf8"));
if (releaseMetadata.binaryVersion !== cargoVersion) {
  throw new Error(
    `${releaseMetadataPath} binaryVersion ${releaseMetadata.binaryVersion} does not match Cargo.toml version ${cargoVersion}`,
  );
}
const preferredParts = releaseMetadata.binaryVersion.split(".");
const minimumParts = String(releaseMetadata.minimumBinaryVersion ?? "").split(".");
if (
  minimumParts.length !== 3 ||
  minimumParts[0] !== preferredParts[0] ||
  minimumParts[1] !== preferredParts[1]
) {
  throw new Error(
    `${releaseMetadataPath} minimumBinaryVersion must be in the preferred binary's minor series`,
  );
}
if (Number(minimumParts[2]) > Number(preferredParts[2])) {
  throw new Error(
    `${releaseMetadataPath} minimumBinaryVersion cannot exceed binaryVersion`,
  );
}
assert.equal(
  releaseMetadata.allowPrerelease,
  false,
  `${releaseMetadataPath} must explicitly reject prerelease fallback binaries`,
);
const vscodeManifestPath = "editors/vscode/package.json";
const vscodeManifest = JSON.parse(fs.readFileSync(vscodeManifestPath, "utf8"));
assert.deepStrictEqual(
  {
    binaryVersion: vscodeManifest.bifrost?.binaryVersion,
    minimumBinaryVersion: vscodeManifest.bifrost?.minimumBinaryVersion,
    allowPrerelease: vscodeManifest.bifrost?.allowPrerelease,
  },
  {
    binaryVersion: releaseMetadata.binaryVersion,
    minimumBinaryVersion: releaseMetadata.minimumBinaryVersion,
    allowPrerelease: releaseMetadata.allowPrerelease,
  },
  `${vscodeManifestPath} must use the agent launcher's binary compatibility range`,
);
for (const target of SUPPORTED_TARGETS) {
  const hash = releaseMetadata.archiveSha256?.[target];
  if (!/^[a-f0-9]{64}$/.test(hash ?? "")) {
    throw new Error(`${releaseMetadataPath} is missing a valid archiveSha256.${target}`);
  }
}

const marketplacePath = ".agents/plugins/marketplace.json";
// This marketplace is private-only and is absent from the public projection.
// When present in the canonical checkout, it remains part of validation.
if (fs.existsSync(marketplacePath)) {
  JSON.parse(fs.readFileSync(marketplacePath, "utf8"));
}

const claudeMarketplacePath = ".claude-plugin/marketplace.json";
JSON.parse(fs.readFileSync(claudeMarketplacePath, "utf8"));

const cursorMarketplacePath = ".cursor-plugin/marketplace.json";
const cursorMarketplace = JSON.parse(fs.readFileSync(cursorMarketplacePath, "utf8"));
if (cursorMarketplace.metadata?.version !== cargoVersion) {
  throw new Error(
    `${cursorMarketplacePath} metadata.version ${cursorMarketplace.metadata?.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}
assert.deepStrictEqual(cursorMarketplace.name, "bifrost", `${cursorMarketplacePath} should use the public namespace`);
assert.deepStrictEqual(cursorMarketplace.owner?.name, "Brokk", `${cursorMarketplacePath} should publish as Brokk`);
const cursorMarketplacePlugin = cursorMarketplace.plugins?.find((plugin) => plugin.name === cursorManifest.name);
if (!cursorMarketplacePlugin) {
  throw new Error(`${cursorMarketplacePath} should list the ${cursorManifest.name} plugin`);
}
assert.deepStrictEqual(
  cursorMarketplacePlugin.source,
  "plugins/bifrost-agent",
  `${cursorMarketplacePath} should point at the shared plugin package`,
);
assert.deepStrictEqual(
  cursorMarketplacePlugin.description,
  cursorManifest.description,
  `${cursorMarketplacePath} plugin description should match ${cursorManifestPath}`,
);
assert.deepStrictEqual(
  cursorMarketplacePlugin.logo,
  "plugins/bifrost-agent/assets/icon.png",
  `${cursorMarketplacePath} plugin logo should be relative to the repository root`,
);
fs.accessSync(cursorMarketplacePlugin.logo, fsConstants.R_OK);
assert.deepStrictEqual(
  cursorMarketplacePlugin.version,
  cargoVersion,
  `${cursorMarketplacePath} plugin version should match Cargo.toml`,
);

const dshManifestPath = "plugins/bifrost-dsh/package.json";
const dshManifest = JSON.parse(fs.readFileSync(dshManifestPath, "utf8"));
if (dshManifest.version !== cargoVersion) {
  throw new Error(
    `${dshManifestPath} version ${dshManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}
assert.deepStrictEqual(
  dshManifest.name,
  "@brokkai/dsh-plugin-bifrost",
  `${dshManifestPath} should keep the published dsh bundle name`,
);
assert.deepStrictEqual(
  dshManifest.dsh,
  { bundle: { patch: "./cordis.patch.yml" } },
  `${dshManifestPath} should declare the dsh bundle patch`,
);
assert.ok(
  dshManifest.keywords?.includes("dsh-plugin"),
  `${dshManifestPath} should carry the dsh-plugin discovery keyword`,
);
assert.equal(
  typeof dshManifest.engines?.dsh,
  "string",
  `${dshManifestPath} should pin a dsh compatibility floor in engines.dsh`,
);
assert.equal(
  typeof dshManifest.peerDependencies?.["@deepseek-ai/dsh-mcp-client"],
  "string",
  `${dshManifestPath} should declare the harness-provided MCP client as a peer dependency`,
);
const dshPatch = fs.readFileSync("plugins/bifrost-dsh/cordis.patch.yml", "utf8");
assert.match(
  dshPatch,
  /^- insert:\n {4}- id: bifrost\n {6}name: '@brokkai\/dsh-plugin-bifrost'\n$/mu,
  "plugins/bifrost-dsh/cordis.patch.yml should insert exactly the Bifrost bundle row",
);
// The dsh bundle vendors the shared launcher; the canonical files stay in
// plugins/bifrost-agent and the copies must not drift.
for (const [canonical, vendored] of [
  ["plugins/bifrost-agent/bin/bifrost-launcher.mjs", "plugins/bifrost-dsh/bin/bifrost-launcher.mjs"],
  ["plugins/bifrost-agent/bifrost-release.json", "plugins/bifrost-dsh/bifrost-release.json"],
]) {
  if (!fs.readFileSync(canonical).equals(fs.readFileSync(vendored))) {
    throw new Error(
      `${vendored} is out of sync with ${canonical}; run node plugins/bifrost-dsh/scripts/sync-launcher.mjs`,
    );
  }
}
fs.accessSync("plugins/bifrost-dsh/bin/bifrost-launcher.mjs", fsConstants.X_OK);

console.log(`Agent plugin manifests are valid for Bifrost ${cargoVersion}.`);
