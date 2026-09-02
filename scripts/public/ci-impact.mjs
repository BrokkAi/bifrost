import { appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SCHEMA_VERSION = "3";

export const COMPONENTS = Object.freeze([
  "dependency_licenses",
  "crate_package",
  "agent_plugin",
  "external_fixture",
  "vscode",
  "pi_package",
  "csmi",
  "rust",
  "python",
  "semantic_pack_jvm",
  "semantic_pack_python",
  "semantic_pack_typescript",
  "semantic_pack_rust",
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
const FLOW_COMPONENTS = new Set([...RQL_COMPONENTS, "rust"]);
const MCP_COMPONENTS = new Set(["rql_runtime", "mcp_contract"]);
const LSP_COMPONENTS = new Set(["rql_runtime", "lsp_contract"]);
const RUNTIME_COMPONENTS = new Set(["rql_runtime", "mcp_contract", "lsp_contract"]);
const EDITOR_COMPONENTS = new Set(["vscode"]);
const PLUGIN_COMPONENTS = new Set(["pi_package", "agent_plugin"]);
const RUST_COMPONENTS = new Set(["rust"]);
const PYTHON_COMPONENTS = new Set(["python"]);
const JVM_LANGUAGE_COMPONENTS = new Set(["rust", "semantic_pack_jvm"]);
const JS_TS_LANGUAGE_COMPONENTS = new Set(["rust", "semantic_pack_typescript"]);
const PYTHON_LANGUAGE_COMPONENTS = new Set(["rust", "semantic_pack_python"]);
const RUST_LANGUAGE_COMPONENTS = new Set(["rust", "semantic_pack_rust"]);
const SEMANTIC_PACK_SOURCE_COMPONENTS = new Set([
  "rust",
  "semantic_pack_jvm",
  "semantic_pack_python",
  "semantic_pack_typescript",
  "semantic_pack_rust",
]);
const CSMI_COMPONENTS = new Set(["csmi"]);
const CSMI_RUST_COMPONENTS = new Set(["csmi", "rust"]);
const CSMI_SEMANTIC_PACK_SOURCE_COMPONENTS = new Set([
  ...SEMANTIC_PACK_SOURCE_COMPONENTS,
  "csmi",
]);
const PINNED_SEMANTIC_PACK_PATHS = [
  {
    prefixes: ["semantic-packs/jvm/"],
    paths: ["scripts/public/build-pinned-jvm-semantic-packs.sh"],
    components: new Set(["semantic_pack_jvm"]),
    reason: "pinned JVM semantic-pack input or builder",
  },
  {
    prefixes: ["semantic-packs/python/"],
    paths: ["scripts/public/build-pinned-python-semantic-packs.sh"],
    components: new Set(["semantic_pack_python"]),
    reason: "pinned Python semantic-pack input or builder",
  },
  {
    prefixes: ["semantic-packs/typescript/"],
    paths: ["scripts/public/build-pinned-typescript-semantic-packs.sh"],
    components: new Set(["semantic_pack_typescript"]),
    reason: "pinned TypeScript semantic-pack input or builder",
  },
  {
    prefixes: ["semantic-packs/rust/"],
    paths: ["scripts/public/build-pinned-rust-semantic-packs.sh"],
    components: new Set(["semantic_pack_rust"]),
    reason: "pinned Rust semantic-pack input or builder",
  },
];
const EXTRACTED_LANGUAGE_PATHS = [
  {
    prefixes: [
      "crates/bifrost-jvm/src/",
      "crates/bifrost-jvm/resources/",
      "crates/bifrost-analysis/src/analyzer/jvm/",
    ],
    components: JVM_LANGUAGE_COMPONENTS,
    reason: "JVM language crate source or resources",
  },
  {
    prefixes: [
      "crates/bifrost-js-ts/src/",
      "crates/bifrost-js-ts/resources/",
      "crates/bifrost-analysis/src/analyzer/js_ts/",
    ],
    components: JS_TS_LANGUAGE_COMPONENTS,
    reason: "JavaScript/TypeScript language crate source or resources",
  },
  {
    prefixes: [
      "crates/bifrost-python/src/",
      "crates/bifrost-python/resources/",
      "crates/bifrost-analysis/src/analyzer/python/",
    ],
    components: PYTHON_LANGUAGE_COMPONENTS,
    reason: "Python language crate source or resources",
  },
  {
    prefixes: [
      "crates/bifrost-rust/src/",
      "crates/bifrost-rust/resources/",
      "crates/bifrost-analysis/src/analyzer/rust/",
    ],
    components: RUST_LANGUAGE_COMPONENTS,
    reason: "Rust language crate source or resources",
  },
  {
    prefixes: [
      "crates/bifrost-cpp/src/",
      "crates/bifrost-cpp/resources/",
      "crates/bifrost-csharp/src/",
      "crates/bifrost-csharp/resources/",
      "crates/bifrost-go/src/",
      "crates/bifrost-go/resources/",
      "crates/bifrost-php/src/",
      "crates/bifrost-php/resources/",
      "crates/bifrost-ruby/src/",
      "crates/bifrost-ruby/resources/",
    ],
    components: RUST_COMPONENTS,
    reason: "extracted language crate source or resources",
  },
  {
    prefixes: ["crates/bifrost-analysis/src/analyzer/semantic_model/"],
    components: SEMANTIC_PACK_SOURCE_COMPONENTS,
    reason: "shared semantic-pack producer source",
  },
];
const PYTHON_BINDING_COMPONENTS = new Set(["python", "rust"]);
const RQL_TEST_COMPONENTS = new Set([...RQL_COMPONENTS, "rust"]);
const MCP_TEST_COMPONENTS = new Set([...MCP_COMPONENTS, "rust"]);
const EXTERNAL_FIXTURE_COMPONENTS = new Set(["external_fixture", "rust"]);
const MCP_AGENT_PLUGIN_FIXTURE_COMPONENTS = new Set([...MCP_TEST_COMPONENTS, "agent_plugin"]);
const NO_COMPONENTS = new Set();

function startsWithAny(path, prefixes) {
  return prefixes.some((prefix) => path.startsWith(prefix));
}

function isRqlPath(path) {
  return (
    startsWithAny(path, [
      "crates/bifrost-analysis/src/analyzer/structural/",
      "crates/bifrost-core/src/analyzer/structural/",
      "crates/bifrost-policy/src/",
      "crates/bifrost-rql/src/",
      "crates/bifrost-policy/policy-packs/",
    ]) ||
    path === "crates/bifrost-runtime/tests/code_intelligence_runtime.rs" ||
    /^(tests\/(structural_search_|policy_|builtin_policy_pack\.rs|bifrost_policy_cli\.rs)|editors\/vscode\/(src\/rql|test\/rql|syntaxes\/bifrost-rql))/u.test(
      path,
    )
  );
}

function isFlowPath(path) {
  return startsWithAny(path, ["crates/bifrost-flow/src/"]);
}

function isRqlTestPath(path) {
  return (
    startsWithAny(path, [
      "tests/fixtures/policies/",
      "tests/fixtures/policy-cli/",
      "scripts/fixtures/policy-report/",
      "tests/suite_bench_policy/",
    ]) ||
    path === "tests/suite_cross_language/code_query_docs.rs"
  );
}

function isMcpPath(path) {
  return (
    startsWithAny(path, ["crates/bifrost-mcp/", "crates/bifrost-analysis/src/searchtools/"])
  );
}

function isExternalFixturePath(path) {
  return (
    startsWithAny(path, [
      "tests/fixtures/csharp-external/",
      "tests/fixtures/testcode-java/",
    ]) ||
    [
      "scripts/public/java-class-fixture-lib.sh",
      "scripts/regenerate-csharp-external-fixture.sh",
      "scripts/public/regenerate-java-class-fixture.sh",
      "scripts/verify-csharp-external-fixture.sh",
      "scripts/public/verify-java-class-fixture.sh",
    ].includes(path)
  );
}

function isLspPath(path) {
  return startsWithAny(path, ["crates/bifrost-lsp/"]);
}

function isPluginPath(path) {
  return (
    startsWithAny(path, [
      "plugins/bifrost-agent/",
      "plugins/bifrost-dsh/",
      ".claude-plugin/",
      ".cursor-plugin/",
    ]) ||
    [
      "scripts/public/check-codex-plugin-manifest.mjs",
      "scripts/public/check-codex-plugin-manifest.test.mjs",
      "scripts/public/smoke-agent-plugin-release.mjs",
    ].includes(path)
  );
}

function isPythonPath(path) {
  return (
    startsWithAny(path, ["bifrost_searchtools/", "python_tests/"]) ||
    path === "scripts/public/test_python.sh"
  );
}

function isRustPath(path) {
  return startsWithAny(path, [
    "src/",
    "crates/bifrost-analysis/src/",
    "crates/bifrost-core/src/",
    "crates/bifrost-flow/src/",
    "crates/bifrost-policy/src/",
    "crates/bifrost-rql/src/",
    "crates/bifrost-semantic-packs/src/",
    "crates/bifrost-semantic-packs/tests/",
    "tests/",
    "examples/",
  ]);
}

function classifyPinnedSemanticPackPath(path) {
  return PINNED_SEMANTIC_PACK_PATHS.find(
    ({ prefixes = [], paths = [] }) => paths.includes(path) || startsWithAny(path, prefixes),
  );
}

function classifyExtractedLanguagePath(path) {
  return EXTRACTED_LANGUAGE_PATHS.find(({ prefixes }) => startsWithAny(path, prefixes));
}

function isDocumentationPath(path) {
  return (
    startsWithAny(path, [".agents/docs/", ".agents/plans/", "docs/"]) ||
    [
      ".agents/PLANS.md",
      "AGENTS.md",
      "CODE_OF_CONDUCT.md",
      "CONTRIBUTING.md",
      "README.md",
      "SECURITY.md",
      "plugins/bifrost-agent/README.md",
    ].includes(path)
  );
}

function classifyPath(path) {
  if (isDocumentationPath(path)) {
    return {
      components: NO_COMPONENTS,
      documentation: true,
      reason: "documentation-only surface",
    };
  }
  if (
    path.startsWith("crates/bifrost-analysis/src/analyzer/semantic_model/csmi/") ||
    path === "crates/bifrost-semantic-packs/src/bin/bifrost-semantic-pack.rs"
  ) {
    return {
      components: CSMI_SEMANTIC_PACK_SOURCE_COMPONENTS,
      reason: "CSMI implementation or CLI source",
    };
  }
  if (path.startsWith("schemas/csmi/")) {
    return { components: CSMI_COMPONENTS, reason: "CSMI schema or fixture" };
  }
  if (path === "crates/bifrost-semantic-packs/tests/authoring_cli.rs") {
    return { components: CSMI_RUST_COMPONENTS, reason: "CSMI authoring CLI test surface" };
  }
  if (path.startsWith("crates/bifrost-semantic-packs/src/")) {
    return {
      components: SEMANTIC_PACK_SOURCE_COMPONENTS,
      reason: "semantic-pack compiler or runtime source",
    };
  }
  const pinnedSemanticPack = classifyPinnedSemanticPackPath(path);
  if (pinnedSemanticPack) {
    return {
      components: pinnedSemanticPack.components,
      reason: pinnedSemanticPack.reason,
    };
  }
  const extractedLanguage = classifyExtractedLanguagePath(path);
  if (extractedLanguage) {
    return {
      components: extractedLanguage.components,
      reason: extractedLanguage.reason,
    };
  }
  if (path === "scripts/fixtures/mcp/codex-sandbox-state-handshake.json") {
    return {
      components: MCP_AGENT_PLUGIN_FIXTURE_COMPONENTS,
      reason: "shared MCP and agent-plugin contract fixture",
    };
  }
  if (isRqlTestPath(path)) {
    return {
      components: RQL_TEST_COMPONENTS,
      reason: "RQL or policy integration test surface",
    };
  }
  if (isFlowPath(path)) {
    return { components: FLOW_COMPONENTS, reason: "flow engine and query execution surface" };
  }
  if (isRqlPath(path)) {
    return { components: RQL_COMPONENTS, reason: "RQL, structural-query, or policy surface" };
  }
  if (path === "crates/bifrost-runtime/src/code_intelligence.rs") {
    return { components: RUNTIME_COMPONENTS, reason: "shared code-intelligence runtime" };
  }
  if (isMcpPath(path)) {
    return { components: MCP_COMPONENTS, reason: "MCP host contract" };
  }
  if (path === "tests/suite_mcp_cli/bifrost_tool_cli.rs") {
    return { components: MCP_TEST_COMPONENTS, reason: "MCP integration test surface" };
  }
  if (isLspPath(path)) {
    return { components: LSP_COMPONENTS, reason: "LSP host contract" };
  }
  if (isExternalFixturePath(path)) {
    return {
      components: EXTERNAL_FIXTURE_COMPONENTS,
      reason: "external fixture provenance surface",
    };
  }
  if (startsWithAny(path, ["editors/vscode/", "editors/zed/"])) {
    return { components: EDITOR_COMPONENTS, reason: "editor-only surface" };
  }
  if (isPluginPath(path)) {
    return { components: PLUGIN_COMPONENTS, reason: "agent-plugin surface" };
  }
  if (path === "src/python_module.rs") {
    return {
      components: PYTHON_BINDING_COMPONENTS,
      reason: "Rust-backed Python binding surface",
    };
  }
  if (isPythonPath(path)) {
    return { components: PYTHON_COMPONENTS, reason: "Python package or test surface" };
  }
  if (isRustPath(path)) {
    return { components: RUST_COMPONENTS, reason: "Rust analyzer or test surface" };
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

export function classifyChangeSet(input) {
  return classifyComponents(input);
}

function classifyComponents({ eventName, ref = "", changedPaths = [], diffFailed = false }) {
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
  let documentationOnly = changedPaths.length > 0;
  for (const path of changedPaths) {
    const decision = classifyPath(path);
    if (!decision) {
      return fullDecision(`unmapped or safety-critical path: ${path}`, changedPaths);
    }
    documentationOnly &&= decision.documentation === true;
    for (const component of decision.components) {
      selected.add(component);
    }
    reasons.push(`${path}: ${decision.reason}`);
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    mode: documentationOnly ? "docs" : "impact",
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
  // Pull requests select their component matrix from the diff. For a push,
  // --base is the prior commit (github.event.before).
  if (options.event === "pull_request" || options.event === "push") {
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
