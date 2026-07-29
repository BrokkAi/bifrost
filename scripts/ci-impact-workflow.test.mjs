import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");

test("CI is unconditional for pull requests and covers merge queues", () => {
  assert.match(workflow, /^  pull_request:\s*$/mu);
  assert.doesNotMatch(workflow, /^  pull_request:\n(?:    .*\n)*?    paths:/mu);
  assert.match(workflow, /^  merge_group:\n    types: \[checks_requested\]$/mu);
});

test("CI has the classifier, canonical lint gate, and stable aggregation check", () => {
  assert.match(workflow, /^  ci-impact:\n    name: ci impact$/mu);
  assert.match(workflow, /^  lint:\n    name: lint$/mu);
  assert.match(workflow, /cargo clippy --all-targets --all-features -- -D warnings/u);
  assert.match(workflow, /^  pr-verification:\n    name: PR verification$/mu);
  assert.match(workflow, /if: \$\{\{ always\(\) \}\}/u);
});

test("selected component jobs are gated only by the classifier outputs", () => {
  for (const output of ["rust", "python", "rql_runtime", "mcp_contract", "lsp_contract", "policy_pack", "vscode", "pi_package", "agent_plugin"]) {
    assert.match(workflow, new RegExp(`needs\\.ci-impact\\.outputs\\.${output} == 'true'`, "u"));
  }
});

test("lint fast-fails before Rust-dependent and matrix-heavy validation", () => {
  for (const job of [
    "dependency-licenses",
    "crate-package",
    "rql-runtime",
    "mcp-contract",
    "lsp-contract",
    "policy-pack",
    "external-fixture",
    "rust",
    "python",
  ]) {
    assert.match(
      workflow,
      new RegExp(`^  ${job}:\\n(?:    .*\\n)*?    needs: \\[ci-impact, quick-policy, lint\\]$`, "mu"),
    );
  }
  for (const job of ["agent-plugin", "vscode", "pi-package"]) {
    assert.match(
      workflow,
      new RegExp(`^  ${job}:\\n(?:    .*\\n)*?    needs: \\[ci-impact, quick-policy\\]$`, "mu"),
    );
  }
});

test("the classifier includes deletions when it computes a pull-request diff", () => {
  const classifier = readFileSync(new URL("./ci-impact.mjs", import.meta.url), "utf8");
  assert.match(classifier, /--diff-filter=ACMRD/u);
});
