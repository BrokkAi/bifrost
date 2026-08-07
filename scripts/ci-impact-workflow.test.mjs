import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const benchmarkWorkflow = readFileSync(
  new URL("../.github/workflows/benchmark.yml", import.meta.url),
  "utf8",
);

test("CI is unconditional for pull requests and covers merge queues", () => {
  assert.match(workflow, /^  pull_request:\s*$/mu);
  assert.doesNotMatch(workflow, /^  pull_request:\n(?:    .*\n)*?    paths:/mu);
  assert.match(workflow, /^  merge_group:\n    types: \[checks_requested\]$/mu);
});

test("CI has the classifier, canonical lint gate, and stable aggregation check", () => {
  assert.match(workflow, /^  ci-impact:\n    name: ci impact$/mu);
  assert.match(workflow, /^  lint:\n    name: lint$/mu);
  assert.match(workflow, /^    needs: \[ci-impact, quick-policy\]\n    if: needs\.ci-impact\.outputs\.mode != 'docs'$/mu);
  assert.match(workflow, /cargo clippy --all-targets --all-features -- -D warnings/u);
  assert.match(workflow, /^  pr-verification:\n    name: PR verification$/mu);
  assert.match(workflow, /if: \$\{\{ always\(\) && !cancelled\(\) \}\}/u);
  assert.match(workflow, /LINT_SELECTED: \$\{\{ needs\.ci-impact\.outputs\.mode != 'docs' \}\}/u);
  assert.match(workflow, /check_result 'lint' "\$LINT_SELECTED" "\$LINT_RESULT"/u);
});

test("selected component jobs are gated only by the classifier outputs", () => {
  for (const output of ["rust", "python", "rql_runtime", "mcp_contract", "lsp_contract", "policy_pack", "vscode", "pi_package", "agent_plugin"]) {
    assert.match(workflow, new RegExp(`needs\\.ci-impact\\.outputs\\.${output} == 'true'`, "u"));
  }
});

test("MCP contracts run once on RMCP", () => {
  const start = workflow.indexOf("  mcp-contract:\n");
  assert.notEqual(start, -1);
  const remainder = workflow.slice(start);
  const nextJob = remainder.slice(1).search(/^  [a-z][a-z0-9-]*:\n/mu);
  const job = nextJob === -1 ? remainder : remainder.slice(0, nextJob + 1);

  assert.match(job, /name: MCP contract/u);
  assert.match(job, /cargo test -p brokk-bifrost-mcp --features nlp/u);
  assert.doesNotMatch(job, /matrix|BIFROST_MCP_RMCP/u);
});

test("the interactive benchmark uses the sole MCP host", () => {
  assert.match(
    benchmarkWorkflow,
    /- name: Run interactive latency gate[\s\S]*?scripts\/run-interactive-latency\.sh --profile/u,
  );
  assert.doesNotMatch(benchmarkWorkflow, /BIFROST_BENCHMARK_MCP_RMCP/u);
});

test("lint fast-fails before Rust-dependent and matrix-heavy validation", () => {
  for (const job of [
    "pinned-jvm-semantic-packs",
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

test("normal CI builds the pinned JVM semantic packs without publishing them", () => {
  const start = workflow.indexOf("  pinned-jvm-semantic-packs:\n");
  assert.notEqual(start, -1);
  const remainder = workflow.slice(start);
  const nextJob = remainder.slice(1).search(/^  [a-z][a-z0-9-]*:\n/mu);
  const job = nextJob === -1 ? remainder : remainder.slice(0, nextJob + 1);

  assert.match(job, /scripts\/build-pinned-jvm-semantic-packs\.sh/u);
  assert.doesNotMatch(job, /upload-artifact|gh release|cargo publish|maturin upload/u);
});

test("the classifier includes deletions when it computes a pull-request diff", () => {
  const classifier = readFileSync(new URL("./ci-impact.mjs", import.meta.url), "utf8");
  assert.match(classifier, /--diff-filter=ACMRD/u);
});
