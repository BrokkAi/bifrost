import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { COMPONENTS, SCHEMA_VERSION, classifyChangeSet } from "./ci-impact.mjs";

function fixture(name) {
  return readFileSync(new URL(`../fixtures/ci-impact/${name}.txt`, import.meta.url), "utf8")
    .split(/\r?\n/u)
    .filter(Boolean);
}

function selected(decision) {
  return [...decision.selected].sort();
}

test("unmapped paths conservatively select the full matrix", () => {
  const decision = classifyChangeSet({ eventName: "pull_request", changedPaths: fixture("unknown") });
  assert.equal(decision.mode, "full");
  assert.deepEqual(selected(decision), [...COMPONENTS].sort());
});

test("build, packaging, dependency, and workflow changes conservatively select the full matrix", () => {
  for (const changedPaths of [
    fixture("cargo"),
    ["crates/bifrost-analysis/Cargo.toml"],
    ["crates/bifrost-flow/Cargo.toml"],
    ["crates/bifrost-analysis/resources/treesitter/java/definitions.scm"],
    ["schemas/semantic-model-pack-v1.schema.json"],
    ["pyproject.toml"],
    ["uv.lock"],
    ["build.rs"],
    [".github/workflows/ci.yml"],
  ]) {
    const decision = classifyChangeSet({ eventName: "pull_request", changedPaths });
    assert.equal(decision.mode, "full");
  }
});

test("documentation-only changes select the docs baseline", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [
      ".agents/plans/1387-antigravity-dynamic-workspace-plugin.md",
      "docs/src/content/docs/antigravity.md",
      "plugins/bifrost-agent/README.md",
    ],
  });
  assert.equal(decision.mode, "docs");
  assert.deepEqual(selected(decision), []);
});

test("documentation mixed with component changes retains component validation", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: ["docs/src/content/docs/antigravity.md", "plugins/bifrost-agent/package.json"],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), ["agent_plugin", "pi_package"]);
});

test("RQL changes select runtime, host, policy-pack, and editor coverage", () => {
  const decision = classifyChangeSet({ eventName: "pull_request", changedPaths: fixture("rql") });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), [
    "lsp_contract",
    "mcp_contract",
    "policy_pack",
    "rql_runtime",
    "rust",
    "vscode",
  ]);
});

test("flow changes select query, host, policy, editor, and Rust coverage", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: ["crates/bifrost-flow/src/value_flow/client.rs"],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), [
    "lsp_contract",
    "mcp_contract",
    "policy_pack",
    "rql_runtime",
    "rust",
    "vscode",
  ]);
});

test("runtime and individual host paths select their contracts", () => {
  assert.deepEqual(
    selected(classifyChangeSet({ eventName: "pull_request", changedPaths: fixture("runtime") })),
    ["lsp_contract", "mcp_contract", "rql_runtime"],
  );
  assert.deepEqual(
    selected(
      classifyChangeSet({
        eventName: "pull_request",
        changedPaths: ["crates/bifrost-mcp/src/mcp_extended.rs"],
      }),
    ),
    ["mcp_contract", "rql_runtime"],
  );
  assert.deepEqual(
    selected(
      classifyChangeSet({
        eventName: "pull_request",
        changedPaths: ["crates/bifrost-lsp/src/lsp/server.rs"],
      }),
    ),
    ["lsp_contract", "rql_runtime"],
  );
});

test("ordinary analyzer and test changes select the Rust matrix only", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [
      "crates/bifrost-analysis/src/analyzer/javascript/semantic.rs",
      "crates/bifrost-semantic-packs/src/lib.rs",
      "tests/fixtures/testcode-js/FeaturesTest.jsx",
      "tests/suite_analyzers/language_behavior.rs",
    ],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), ["rust"]);
});

test("Python package changes select Python validation without unrelated lanes", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [
      "bifrost_searchtools/client.py",
      "bifrost_searchtools/models.py",
      "python_tests/test_searchtools_client.py",
    ],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), ["python"]);

  assert.deepEqual(
    selected(
      classifyChangeSet({
        eventName: "pull_request",
        changedPaths: ["src/python_module.rs"],
      }),
    ),
    ["python", "rust"],
  );
});

test("external fixture changes retain provenance and Rust validation", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [
      "scripts/public/verify-java-class-fixture.sh",
      "tests/fixtures/testcode-java/A.java",
    ],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), ["external_fixture", "rust"]);
});

test("broad analyzer PRs avoid unrelated packaging and plugin lanes", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [
      ".agents/plans/issue-1364-standalone-taint-codequery.md",
      "bifrost_searchtools/client.py",
      "crates/bifrost-flow/src/taint/client.rs",
      "crates/bifrost-policy/src/taint_policy.rs",
      "crates/bifrost-mcp/src/mcp_extended.rs",
      "crates/bifrost-runtime/src/code_intelligence.rs",
      "docs/src/content/docs/code-querying.md",
      "editors/vscode/syntaxes/bifrost-rql.tmLanguage.json",
      "tests/fixtures/policies/dynamic-eval.normalized.json",
      "tests/suite_bench_policy/taint_policy_adapter.rs",
      "tests/suite_cross_language/code_query_docs.rs",
      "tests/suite_mcp_cli/bifrost_tool_cli.rs",
    ],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), [
    "lsp_contract",
    "mcp_contract",
    "policy_pack",
    "python",
    "rql_runtime",
    "rust",
    "vscode",
  ]);
});

test("editor-only and plugin-only changes select only their Node checks", () => {
  assert.deepEqual(
    selected(classifyChangeSet({ eventName: "pull_request", changedPaths: fixture("editor") })),
    ["vscode"],
  );
  assert.deepEqual(
    selected(classifyChangeSet({ eventName: "pull_request", changedPaths: fixture("plugin") })),
    ["agent_plugin", "pi_package"],
  );
});

test("public release contract fixtures retain their host and package checks", () => {
  assert.deepEqual(
    selected(
      classifyChangeSet({
        eventName: "pull_request",
        changedPaths: ["scripts/fixtures/policy-report/v5-one-finding.json"],
      }),
    ),
    ["lsp_contract", "mcp_contract", "policy_pack", "rql_runtime", "rust", "vscode"],
  );
  assert.deepEqual(
    selected(
      classifyChangeSet({
        eventName: "pull_request",
        changedPaths: ["scripts/fixtures/mcp/codex-sandbox-state-handshake.json"],
      }),
    ),
    ["agent_plugin", "mcp_contract", "rql_runtime", "rust"],
  );
});

test("combined paths union selected checks", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [...fixture("editor"), ...fixture("plugin")],
  });
  assert.deepEqual(selected(decision), ["agent_plugin", "pi_package", "vscode"]);
});

test("deleted paths use the same conservative mapping as changed paths", () => {
  const decision = classifyChangeSet({
    eventName: "pull_request",
    changedPaths: [
      "crates/bifrost-policy/policy-packs/bifrost.code-smells/policies/removed-rule.rqlp",
    ],
  });
  assert.deepEqual(selected(decision), ["lsp_contract", "mcp_contract", "policy_pack", "rql_runtime", "vscode"]);
});

test("failed diffs select the full matrix rather than skipping validation", () => {
  const decision = classifyChangeSet({ eventName: "pull_request", diffFailed: true });
  assert.equal(decision.mode, "full");
  assert.deepEqual(selected(decision), [...COMPONENTS].sort());
});

test("merge groups and master pushes always select the full matrix", () => {
  for (const context of [
    { eventName: "merge_group", ref: "refs/heads/gh-readonly-queue/master/pr-1" },
    { eventName: "push", ref: "refs/heads/master" },
  ]) {
    const decision = classifyChangeSet(context);
    assert.equal(decision.schemaVersion, SCHEMA_VERSION);
    assert.equal(decision.mode, "full");
    assert.deepEqual(selected(decision), [...COMPONENTS].sort());
  }
});

test("an empty pull request retains the always-on baseline", () => {
  const decision = classifyChangeSet({ eventName: "pull_request" });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), []);
});

test("the nlp build gate follows the nlp compile surface, not the full Rust surface", () => {
  const nlpPaths = [
    ["crates/bifrost-nlp/src/indexer.rs"],
    ["crates/bifrost-mcp/src/mcp_nlp.rs"],
    ["crates/bifrost-mcp/src/searchtools_service.rs"],
    ["src/lib.rs"],
    ["src/bin/embed_probe.rs"],
    ["tests/suite_semantic/semantic_search.rs"],
    ["tests/suite_persistence/main.rs"],
    ["tests/nlp_semantic_search_models.rs"],
    ["Cargo.toml"],
    ["Cargo.lock"],
  ];
  for (const changedPaths of nlpPaths) {
    assert.equal(
      classifyChangeSet({ eventName: "push", ref: "refs/heads/master", changedPaths }).nlp,
      true,
      `expected nlp build for ${changedPaths[0]}`,
    );
  }

  const nonNlpPaths = [
    ["crates/bifrost-analysis/src/analyzer/javascript/semantic.rs"],
    ["crates/bifrost-core/src/analyzer/capabilities.rs"],
    ["tests/suite_analyzers/language_behavior.rs"],
    ["editors/vscode/src/rql/index.ts"],
  ];
  for (const changedPaths of nonNlpPaths) {
    assert.equal(
      classifyChangeSet({ eventName: "push", ref: "refs/heads/master", changedPaths }).nlp,
      false,
      `expected no nlp build for ${changedPaths[0]}`,
    );
  }
});

test("the nlp build gate stays conservative when the change set is untrusted", () => {
  // Merge queue, a failed diff, and events we do not diff all force the build.
  assert.equal(classifyChangeSet({ eventName: "merge_group" }).nlp, true);
  assert.equal(classifyChangeSet({ eventName: "pull_request", diffFailed: true }).nlp, true);
  assert.equal(classifyChangeSet({ eventName: "workflow_dispatch" }).nlp, true);
  // A push touching a non-nlp path alongside an nlp path still builds nlp.
  assert.equal(
    classifyChangeSet({
      eventName: "push",
      ref: "refs/heads/master",
      changedPaths: [
        "crates/bifrost-analysis/src/analyzer/rust/semantic.rs",
        "crates/bifrost-nlp/src/engine.rs",
      ],
    }).nlp,
    true,
  );
});
