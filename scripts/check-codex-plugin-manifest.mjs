#!/usr/bin/env node

import fs from "node:fs";
import assert from "node:assert/strict";
import { constants as fsConstants } from "node:fs";
import { SUPPORTED_TARGETS } from "../plugins/bifrost-agent/bin/bifrost-launcher.mjs";
import {
  AMP_SKILL_BUNDLE_ROOT,
  AMP_SKILL_NAME,
  buildAmpSkillBundleFiles,
} from "./generate-amp-skill-bundle.mjs";

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

const cursorManifestPath = "plugins/bifrost-agent/.cursor-plugin/plugin.json";
const cursorManifest = JSON.parse(fs.readFileSync(cursorManifestPath, "utf8"));
if (cursorManifest.version !== cargoVersion) {
  throw new Error(
    `${cursorManifestPath} version ${cursorManifest.version} does not match Cargo.toml version ${cargoVersion}`,
  );
}

const sharedManifestFields = [
  "homepage",
  "repository",
  "license",
  "keywords",
  "skills",
  "agents",
];
for (const field of sharedManifestFields) {
  assert.deepStrictEqual(
    claudeManifest[field],
    codexManifest[field],
    `${claudeManifestPath} field ${field} does not match ${codexManifestPath}`,
  );
  assert.deepStrictEqual(
    cursorManifest[field],
    codexManifest[field],
    `${cursorManifestPath} field ${field} does not match ${codexManifestPath}`,
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
  claudeManifest.author,
  codexManifest.author,
  `${claudeManifestPath} author does not match ${codexManifestPath}`,
);
assert.deepStrictEqual(
  cursorManifest.author?.name,
  codexManifest.author?.name,
  `${cursorManifestPath} author name does not match ${codexManifestPath}`,
);
assert.deepStrictEqual(
  cursorManifest.logo,
  "assets/icon.png",
  `${cursorManifestPath} should reference the package icon`,
);
fs.accessSync("plugins/bifrost-agent/assets/icon.png", fsConstants.R_OK);
assert.deepStrictEqual(
  codexManifest.mcpServers,
  "./.mcp.json",
  `${codexManifestPath} should keep using the Claude/Codex MCP config`,
);
assert.deepStrictEqual(
  claudeManifest.mcpServers,
  "./.mcp.json",
  `${claudeManifestPath} should keep using the Claude/Codex MCP config`,
);
assert.deepStrictEqual(
  cursorManifest.mcpServers,
  undefined,
  `${cursorManifestPath} should let Cursor discover root mcp.json automatically`,
);
fs.accessSync("plugins/bifrost-agent/assets/icon.png", fsConstants.R_OK);

const cursorPluginNamePattern = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
if (!cursorPluginNamePattern.test(cursorManifest.name)) {
  throw new Error(`${cursorManifestPath} name must be lowercase kebab-case`);
}

const mcpPath = "plugins/bifrost-agent/.mcp.json";
const mcpConfig = JSON.parse(fs.readFileSync(mcpPath, "utf8"));
const cursorMcpPath = "plugins/bifrost-agent/mcp.json";
const cursorMcpConfig = JSON.parse(fs.readFileSync(cursorMcpPath, "utf8"));
assert.deepStrictEqual(
  mcpConfig.mcpServers?.bifrost?.command,
  "./bin/bifrost-launcher.mjs",
  `${mcpPath} should launch the package-local Bifrost launcher`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.command,
  "./bin/bifrost-launcher.mjs",
  `${cursorMcpPath} should launch the package-local Bifrost launcher`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.type,
  "stdio",
  `${cursorMcpPath} should use Cursor's documented stdio MCP type`,
);
assert.deepStrictEqual(
  mcpConfig.mcpServers?.bifrost?.args?.slice(0, 2),
  ["--mcp", "symbol|extended"],
  `${mcpPath} should use the default Bifrost MCP toolset`,
);
assert.deepStrictEqual(
  cursorMcpConfig.mcpServers?.bifrost?.args?.slice(0, 2),
  ["--mcp", "symbol|extended"],
  `${cursorMcpPath} should use the default Bifrost MCP toolset`,
);
fs.accessSync("plugins/bifrost-agent/bin/bifrost-launcher.mjs", fsConstants.X_OK);

const skillsRoot = "plugins/bifrost-agent/skills";
const expectedSkills = [
  ["bifrost-code-navigation", "bifrost-code-navigation", "search_symbols", "scan_usages", "get_symbol_locations"],
  ["bifrost-code-reading", "bifrost-code-reading", "get_summaries", "get_symbol_sources"],
  ["bifrost-codebase-search", "bifrost-codebase-search", "search_symbols", "find_filenames", "list_files"],
  ["git-exploration", "brokk-git-exploration", "git log", "git diff", "gh pr view"],
  ["guided-issue", "brokk-guided-issue", "Guided Issue Resolution", "brokk:issue-diagnostician"],
  ["guided-review", "brokk-guided-review", "Guided Code Review", "brokk:security-reviewer"],
  ["review-pr", "brokk-review-pr", "Adversarial PR Review", "brokk:architect-reviewer"],
  ["review", "review", "expert code reviewer", "Output format", "Issues"],
  ["today", "brokk-today", "Slack-ready summary", "gh issue"],
  ["write-issue", "brokk-write-issue", "Draft a new GitHub issue", "brokk:issue-enhancer"],
];
assert.deepStrictEqual(
  codexManifest.skills,
  "./skills/",
  `${codexManifestPath} should expose Bifrost skills`,
);
assert.deepStrictEqual(
  claudeManifest.skills,
  "./skills/",
  `${claudeManifestPath} should expose Bifrost skills`,
);
assert.deepStrictEqual(
  cursorManifest.skills,
  "./skills/",
  `${cursorManifestPath} should expose Bifrost skills`,
);
for (const [skillDir, skillName, ...requiredTerms] of expectedSkills) {
  const skillPath = `${skillsRoot}/${skillDir}/SKILL.md`;
  const skill = fs.readFileSync(skillPath, "utf8");
  if (!skill.includes(`name: ${skillName}`)) {
    throw new Error(`${skillPath} should declare name: ${skillName}`);
  }
  for (const term of requiredTerms) {
    if (!skill.includes(term)) {
      throw new Error(`${skillPath} should mention ${term}`);
    }
  }
}

for (const [relativePath, expected] of buildAmpSkillBundleFiles()) {
  const bundlePath = `${AMP_SKILL_BUNDLE_ROOT}/${relativePath}`;
  const actual = fs.readFileSync(bundlePath, "utf8");
  assert.equal(
    actual,
    expected,
    `${bundlePath} is stale; run node scripts/generate-amp-skill-bundle.mjs`,
  );
}
fs.accessSync(`${AMP_SKILL_BUNDLE_ROOT}/bin/bifrost-launcher.mjs`, fsConstants.X_OK);
const ampSkill = fs.readFileSync(`${AMP_SKILL_BUNDLE_ROOT}/SKILL.md`, "utf8");
if (!ampSkill.includes(`name: ${AMP_SKILL_NAME}`)) {
  throw new Error(`${AMP_SKILL_BUNDLE_ROOT}/SKILL.md should declare name: ${AMP_SKILL_NAME}`);
}
const ampMcpConfig = JSON.parse(fs.readFileSync(`${AMP_SKILL_BUNDLE_ROOT}/mcp.json`, "utf8"));
assert.deepStrictEqual(
  Object.keys(ampMcpConfig),
  ["bifrost"],
  `${AMP_SKILL_BUNDLE_ROOT}/mcp.json should use Amp's direct server-name map`,
);
assert.deepStrictEqual(
  ampMcpConfig.bifrost.command,
  "sh",
  `${AMP_SKILL_BUNDLE_ROOT}/mcp.json should use the portable launcher search shim`,
);
assert.deepStrictEqual(
  ampMcpConfig.bifrost.args?.slice(3, 7),
  ["--root", ".", "--mcp", "symbol|extended"],
  `${AMP_SKILL_BUNDLE_ROOT}/mcp.json should launch Bifrost against Amp's current workspace`,
);
for (const tool of ["search_symbols", "get_summaries", "scan_usages", "find_filenames"]) {
  if (!ampMcpConfig.bifrost.includeTools?.includes(tool)) {
    throw new Error(`${AMP_SKILL_BUNDLE_ROOT}/mcp.json should include ${tool}`);
  }
}

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
  codexManifest.agents,
  expectedAgents,
  `${codexManifestPath} should expose workflow specialist agents`,
);
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

console.log(`Agent plugin manifests are valid for Bifrost ${cargoVersion}.`);
