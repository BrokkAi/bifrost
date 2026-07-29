import { appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SCHEMA_VERSION = "1";

export const COMPONENTS = Object.freeze([
  "dependency_licenses",
  "crate_package",
  "agent_plugin",
  "external_fixture",
  "vscode",
  "pi_package",
  "rust",
  "python",
  "rql_runtime",
  "mcp_contract",
  "lsp_contract",
  "policy_pack",
]);

const FULL_COMPONENTS = new Set(COMPONENTS);
const RQL_COMPONENTS = new Set([
  "rql_runtime",
  "mcp_contract",
  "lsp_contract",
  "policy_pack",
  "vscode",
]);
const MCP_COMPONENTS = new Set(["rql_runtime", "mcp_contract"]);
const LSP_COMPONENTS = new Set(["rql_runtime", "lsp_contract"]);
const RUNTIME_COMPONENTS = new Set(["rql_runtime", "mcp_contract", "lsp_contract"]);
const EDITOR_COMPONENTS = new Set(["vscode"]);
const PLUGIN_COMPONENTS = new Set(["pi_package", "agent_plugin"]);

function startsWithAny(path, prefixes) {
  return prefixes.some((prefix) => path.startsWith(prefix));
}

function isRqlPath(path) {
  return (
    startsWithAny(path, ["src/analyzer/structural/", "src/analyzer/policy/", "policy-packs/"]) ||
    path === "tests/code_intelligence_runtime.rs" ||
    /^(tests\/(structural_search_|policy_|builtin_policy_pack\.rs|bifrost_policy_cli\.rs)|editors\/vscode\/(src\/rql|test\/rql|syntaxes\/bifrost-rql))/u.test(
      path,
    )
  );
}

function isMcpPath(path) {
  return (
    startsWithAny(path, ["src/mcp_", "src/searchtools/"]) ||
    [
      "src/mcp_cli.rs",
      "src/mcp_common.rs",
      "src/mcp_core.rs",
      "src/mcp_extended.rs",
      "src/mcp_nlp.rs",
      "src/mcp_registry.rs",
      "src/mcp_slopcop.rs",
      "src/mcp_text.rs",
      "src/searchtools_service.rs",
      "tests/bifrost_mcp_server.rs",
    ].includes(path)
  );
}

function isLspPath(path) {
  return startsWithAny(path, ["src/lsp/"]) || path === "tests/bifrost_lsp_server.rs";
}

function isPluginPath(path) {
  return (
    startsWithAny(path, ["plugins/bifrost-agent/", ".claude-plugin/", ".cursor-plugin/"]) ||
    [
      "scripts/check-codex-plugin-manifest.mjs",
      "scripts/generate-amp-skill-bundle.mjs",
      "scripts/smoke-agent-plugin-release.mjs",
    ].includes(path)
  );
}

function classifyPath(path) {
  if (isRqlPath(path)) {
    return { components: RQL_COMPONENTS, reason: "RQL, structural-query, or policy surface" };
  }
  if (path === "src/code_intelligence.rs") {
    return { components: RUNTIME_COMPONENTS, reason: "shared code-intelligence runtime" };
  }
  if (isMcpPath(path)) {
    return { components: MCP_COMPONENTS, reason: "MCP host contract" };
  }
  if (isLspPath(path)) {
    return { components: LSP_COMPONENTS, reason: "LSP host contract" };
  }
  if (startsWithAny(path, ["editors/vscode/", "editors/zed/"])) {
    return { components: EDITOR_COMPONENTS, reason: "editor-only surface" };
  }
  if (isPluginPath(path)) {
    return { components: PLUGIN_COMPONENTS, reason: "agent-plugin surface" };
  }
  return null;
}

function fullDecision(reason, changedPaths) {
  return {
    schemaVersion: SCHEMA_VERSION,
    mode: "full",
    changedPaths,
    reasons: [reason],
    selected: FULL_COMPONENTS,
  };
}

export function classifyChangeSet({ eventName, ref = "", changedPaths = [], diffFailed = false }) {
  if (eventName === "merge_group") {
    return fullDecision("merge queue requires the full matrix", changedPaths);
  }
  if (eventName === "push" && ref === "refs/heads/master") {
    return fullDecision("master push requires the full matrix", changedPaths);
  }
  if (eventName !== "pull_request") {
    return fullDecision(`unsupported event ${eventName || "<missing>"}`, changedPaths);
  }
  if (diffFailed) {
    return fullDecision("unable to compute the pull-request change set", changedPaths);
  }

  const selected = new Set();
  const reasons = [];
  for (const path of changedPaths) {
    const decision = classifyPath(path);
    if (!decision) {
      return fullDecision(`unmapped or safety-critical path: ${path}`, changedPaths);
    }
    for (const component of decision.components) {
      selected.add(component);
    }
    reasons.push(`${path}: ${decision.reason}`);
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    mode: "impact",
    changedPaths,
    reasons: reasons.length === 0 ? ["no changed paths; run the always-on baseline"] : reasons,
    selected,
  };
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("Usage: ci-impact.mjs --event EVENT --ref REF --base SHA --head SHA --output FILE --summary FILE");
    }
    options[key.slice(2)] = value;
  }
  return options;
}

function changedPathsFromGit(base, head) {
  const result = spawnSync("git", ["diff", "--name-only", "--diff-filter=ACMRD", base, head], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    return { changedPaths: [], diffFailed: true };
  }
  return {
    changedPaths: result.stdout.split(/\r?\n/u).filter(Boolean),
    diffFailed: false,
  };
}

function writeOutputs(outputPath, decision) {
  const lines = [
    `schema_version=${decision.schemaVersion}`,
    `mode=${decision.mode}`,
    `selected=${[...decision.selected].sort().join(",")}`,
  ];
  for (const component of COMPONENTS) {
    lines.push(`${component}=${decision.selected.has(component)}`);
  }
  appendFileSync(outputPath, `${lines.join("\n")}\n`);
}

function markdownCell(value) {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}

function writeSummary(summaryPath, decision) {
  const selected = [...decision.selected].sort();
  const paths = decision.changedPaths.length === 0 ? ["(none)"] : decision.changedPaths;
  const lines = [
    "## CI impact selection",
    "",
    `Schema version: \`${decision.schemaVersion}\`  `,
    `Mode: \`${decision.mode}\`  `,
    `Selected checks: ${selected.length === 0 ? "always-on baseline only" : selected.map((name) => `\`${name}\``).join(", ")}`,
    "",
    "| Changed path | Decision |",
    "| --- | --- |",
    ...paths.map((path) => `| ${markdownCell(path)} | ${markdownCell(decision.reasons.find((reason) => reason.startsWith(`${path}:`)) ?? decision.reasons[0])} |`),
    "",
  ];
  appendFileSync(summaryPath, `${lines.join("\n")}\n`);
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  let changedPaths = [];
  let diffFailed = false;
  if (options.event === "pull_request") {
    ({ changedPaths, diffFailed } = changedPathsFromGit(options.base, options.head));
  }
  const decision = classifyChangeSet({
    eventName: options.event,
    ref: options.ref,
    changedPaths,
    diffFailed,
  });
  writeOutputs(options.output, decision);
  writeSummary(options.summary, decision);
  process.stdout.write(`CI impact selection: ${decision.mode}; ${[...decision.selected].sort().join(",") || "baseline only"}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
