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
  "skills",
  "agents",
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

console.log(`Agent plugin manifests are valid for Bifrost ${cargoVersion}.`);
