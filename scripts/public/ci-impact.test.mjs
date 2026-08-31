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

test("impact schema version tracks the exported component contract", () => {
  assert.equal(SCHEMA_VERSION, "2");
});

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
    ["crates/bifrost-jvm/Cargo.toml"],
    ["crates/bifrost-js-ts/Cargo.toml"],
    ["crates/bifrost-python/Cargo.toml"],
    ["crates/bifrost-rust/Cargo.toml"],
    ["crates/bifrost-semantic-packs/Cargo.toml"],
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
      "tests/fixtures/testcode-js/FeaturesTest.jsx",
      "tests/suite_analyzers/language_behavior.rs",
    ],
  });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), ["rust"]);
});

test("pinned semantic-pack inputs and builders select only their matching lanes", () => {
  for (const [changedPath, component] of [
    ["semantic-packs/jvm/temurin-jdk-21.0.8+9.json", "semantic_pack_jvm"],
    ["semantic-packs/python/typeshed-stdlib-2026.8.31.json", "semantic_pack_python"],
    ["semantic-packs/typescript/typescript-7.0.2.json", "semantic_pack_typescript"],
    ["semantic-packs/rust/rust-stdlib-nightly-2026-08-24.json", "semantic_pack_rust"],
    ["scripts/public/build-pinned-jvm-semantic-packs.sh", "semantic_pack_jvm"],
    ["scripts/public/build-pinned-python-semantic-packs.sh", "semantic_pack_python"],
    ["scripts/public/build-pinned-typescript-semantic-packs.sh", "semantic_pack_typescript"],
    ["scripts/public/build-pinned-rust-semantic-packs.sh", "semantic_pack_rust"],
  ]) {
    assert.deepEqual(
      selected(classifyChangeSet({ eventName: "pull_request", changedPaths: [changedPath] })),
      [component],
      changedPath,
    );
  }

  assert.deepEqual(
    selected(
      classifyChangeSet({
        eventName: "pull_request",
        changedPaths: ["crates/bifrost-semantic-packs/src/release_bundle.rs"],
      }),
    ),
    ["rust", "semantic_pack_jvm", "semantic_pack_python", "semantic_pack_rust", "semantic_pack_typescript"],
  );
});

test("extracted language crates select Rust and their matching pinned pack lane", () => {
  for (const [changedPath, components] of [
    ["crates/bifrost-jvm/src/java/declarations.rs", ["rust", "semantic_pack_jvm"]],
    ["crates/bifrost-jvm/resources/treesitter/java/definitions.scm", ["rust", "semantic_pack_jvm"]],
    ["crates/bifrost-js-ts/src/typescript.rs", ["rust", "semantic_pack_typescript"]],
    ["crates/bifrost-js-ts/resources/treesitter/typescript/definitions.scm", ["rust", "semantic_pack_typescript"]],
    ["crates/bifrost-python/src/declarations.rs", ["rust", "semantic_pack_python"]],
    ["crates/bifrost-python/resources/treesitter/python/definitions.scm", ["rust", "semantic_pack_python"]],
    ["crates/bifrost-rust/src/declarations.rs", ["rust", "semantic_pack_rust"]],
    ["crates/bifrost-rust/resources/treesitter/rust/definitions.scm", ["rust", "semantic_pack_rust"]],
  ]) {
    assert.deepEqual(
      selected(classifyChangeSet({ eventName: "pull_request", changedPaths: [changedPath] })),
      components,
      changedPath,
    );
  }

  for (const language of ["cpp", "csharp", "go", "php", "ruby"]) {
    assert.deepEqual(
      selected(
        classifyChangeSet({
          eventName: "pull_request",
          changedPaths: [`crates/bifrost-${language}/src/lib.rs`],
        }),
      ),
      ["rust"],
      language,
    );
  }
});

test("legacy analyzer producer paths select their matching pinned pack lanes", () => {
  for (const [changedPath, components] of [
    [
      "crates/bifrost-analysis/src/analyzer/semantic_model/catalog/mod.rs",
      ["rust", "semantic_pack_jvm", "semantic_pack_python", "semantic_pack_rust", "semantic_pack_typescript"],
    ],
    ["crates/bifrost-analysis/src/analyzer/jvm/jmod_artifact.rs", ["rust", "semantic_pack_jvm"]],
    ["crates/bifrost-analysis/src/analyzer/js_ts/external.rs", ["rust", "semantic_pack_typescript"]],
    ["crates/bifrost-analysis/src/analyzer/python/external.rs", ["rust", "semantic_pack_python"]],
    ["crates/bifrost-analysis/src/analyzer/rust/rustdoc_artifact.rs", ["rust", "semantic_pack_rust"]],
  ]) {
    assert.deepEqual(
      selected(classifyChangeSet({ eventName: "pull_request", changedPaths: [changedPath] })),
      components,
      changedPath,
    );
  }
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
