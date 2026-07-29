import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { COMPONENTS, SCHEMA_VERSION, classifyChangeSet } from "./ci-impact.mjs";

function fixture(name) {
  return readFileSync(new URL(`./fixtures/ci-impact/${name}.txt`, import.meta.url), "utf8")
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

test("Cargo and workflow changes conservatively select the full matrix", () => {
  for (const changedPaths of [fixture("cargo"), [".github/workflows/ci.yml"]]) {
    const decision = classifyChangeSet({ eventName: "pull_request", changedPaths });
    assert.equal(decision.mode, "full");
  }
});

test("RQL changes select runtime, host, policy-pack, and editor coverage", () => {
  const decision = classifyChangeSet({ eventName: "pull_request", changedPaths: fixture("rql") });
  assert.equal(decision.mode, "impact");
  assert.deepEqual(selected(decision), ["lsp_contract", "mcp_contract", "policy_pack", "rql_runtime", "vscode"]);
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
      "crates/bifrost-analysis/policy-packs/bifrost.code-smells/policies/removed-rule.rqlp",
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
