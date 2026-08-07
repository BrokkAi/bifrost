# Repair UsageBench regressions from the August 7 benchmark

This ExecPlan is a living document. Maintain it under `.agents/PLANS.md`.

## Purpose / Big Picture

UsageBench must report only real references and must not fail because the
analyzer is still preparing its workspace. After this work, recursive calls
remain visible, shadowed identifiers stay excluded, Go receiver type
references appear in inverse usage results, and a cold symbol search has a
reliable readiness path.

## Progress

- [x] (2026-08-07 10:26Z) Compared Actions runs `31094360578` and `31168849324`.
- [x] (2026-08-07 10:37Z) Identified two JS/TS false positives, one Go inverse
  gap, and one cold `search_symbols` timeout.
- [x] (2026-08-07 13:28Z) Repair JS/TS recursive-hit classification and add
  source-level regressions.
- [x] (2026-08-07 12:18Z) Add Go receiver type references to inverse usage
  results and add coverage.
- [x] (2026-08-07 12:23Z) Repair cold `search_symbols` readiness and add
  coverage.
- [x] (2026-08-07 13:34Z) Run focused Rust tests, formatter, policy checks,
  and the four affected UsageBench cases.
- [x] (2026-08-07 14:12Z) Repair the related CommonJS LSP click-around
  regression found by the aarch64 CI job.

## Surprises & Discoveries

- Observation: The Go result did not lose an existing result.
  Evidence: UsageBench commit `65ba50e` added `func (c ComponentPath)` as a
  required inverse usage at `hugofs/rootmapping_fs.go:324`.
- Observation: The JS/TS false positives started with commit `dce914906`.
  Evidence: It changed `find_js_ts_usages` to retain every proven hit whose
  enclosing declaration equals a callable target.
- Observation: A cold `search_symbols` request can stop after 4.5 seconds.
  Evidence: The benchmark diagnostic and a first local MCP request both
  reported the request budget. A local retry completed after initialization.
- Observation: The local callback is in the queried function's nested Promise
  body, not in a separate function declaration.
  Evidence: `src/node/wrapper.ts` declares `const onMessage` on line 46 and
  uses it on lines 27 and 55. An owner-range fallback had treated it as the
  outer target declaration.
- Observation: A CommonJS destructuring binding can be an imported target.
  Evidence: CI job `92859509677` lost `widget.render()` after it marked the
  `Widget` binding from `require("./lib")` as a local shadow.

## Decision Log

- Decision: Keep recursive-call support, but prove the binding targets the
  callable before classifying it as `SelfReceiver`.
  Rationale: A same-name local binding is not a recursive call.
  Date/Author: 2026-08-07 / Codex
- Decision: Treat the Go receiver type as a required type reference.
  Rationale: The revised, human-approved ground truth requires it, and forward
  definition lookup already resolves it.
  Date/Author: 2026-08-07 / Codex
- Decision: Treat the TypeScript case as a readiness failure, not a missing
  semantic result.
  Rationale: Its forward definition lookup passed. The inverse request failed
  only because `search_symbols` exhausted its cold request budget.
  Date/Author: 2026-08-07 / Codex
- Decision: Use exact declaration ranges for `let`, `const`, and function
  declaration shadows. Keep the owner fallback only for named function
  expressions.
  Rationale: A local lexical declaration inside the target function must
  shadow it. A CommonJS named function expression needs its own recursive
  binding preserved.
  Date/Author: 2026-08-07 / Codex

## Outcomes & Retrospective

The repair keeps structured tree-sitter and analyzer binding data. It adds no
source-text fallback.

Focused validation passed:

- `cargo fmt --check`
- `cargo test --test suite_usages go_graph_strategy_finds_method_receiver_type_references`
- `cargo test --test suite_usages js_named_commonjs_function_expression_name_is_not_a_usage_but_recursion_is`
- `cargo test --test suite_usages ts_promise_callback_binding_does_not_impersonate_outer_function`
- `cargo test --test suite_mcp_cli lsp_click_around_regression::milestone_8_javascript_commonjs_object_click_around`
- `cargo test -p brokk-bifrost-mcp cold_workspace_deadline_tests --lib`
- `cargo test -p brokk-bifrost-mcp explicit_request_budget_wins_over_the_cold_workspace_fallback --lib`

The local binary built from this worktree passed all four cases from the
UsageBench `65ba50e` corpus: `real-project-v1-go-01-2` (12 true positives),
`js-commonjs-exported-member-usage` (3),
`real-project-v1-typescript-03-3` (3, no false positives), and
`real-project-v1-typescript-04-1` (4). The temporary archive needs release
metadata because it is not a Git worktree.

`bifrost.code-smells` completed without diagnostics. It reported 277 existing
repository findings and none in the changed files. There are no executable
repository policy roots.

## Context and Orientation

UsageBench calls Bifrost through MCP. `search_symbols` finds a declaration
before UsageBench calls inverse usage search. `scan_usages_by_location` then
returns each proved usage location. A `SelfReceiver` is a recursive call inside
the declaration that it calls. It is visible to editor references, but it is
not an external callsite.

The JS/TS inverse graph is in `crates/bifrost-js-ts/src/graph/`. Its current
post-filter uses only the enclosing code unit. It must not treat a local
binding with the target name as a call to that target. The Go inverse graph is
in `crates/bifrost-go/src/graph/`. It must model a method receiver type as a
reference to the declared type. The MCP request deadline is in
`crates/bifrost-mcp/src/`; its cold workspace behavior must not produce a
spurious failed benchmark case.

## Plan of Work

First, make the JS/TS recursive filter inspect the structured binding or
reference result. Retain only a call that resolves to the target. Add small
TypeScript and JavaScript fixtures. They must show that true recursion remains
visible and shadowed local names remain absent.

Second, extend the Go inverse collector with the structured receiver type node.
Record the occurrence only when its resolved type is the selected target. Add
a focused Go fixture with a named receiver. Assert forward definition and
inverse usages agree.

Third, trace the MCP cold-request state. Make `search_symbols` wait for the
initial workspace snapshot, or retry the bounded attempt through the existing
readiness mechanism. Add a process-isolated test when it needs clean global
state. The result must return after readiness, rather than report a temporary
budget error.

## Concrete Steps

Work from the repository root.

1. Use Bifrost symbol tools to read the graph and MCP entry points. Use `rg`
   only for literal diagnostics and test names.
2. Run the narrow test modules for each repaired path. Each test must fail
   before its repair and pass after it.
3. Run `cargo fmt` and focused featureless Rust tests. Run
   `scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets
   --all-features -- -D warnings` if the change reaches a broad crate surface.
4. Run Bifrost policy checks with `bifrost.code-smells` and every executable
   repository policy root. Treat a finding or unreliable result as failed
   validation.
5. Run the focused UsageBench cases against the repaired Bifrost binary when
   the runner can use the pinned source archives. The expected output has no
   failure for the four case IDs recorded above.

## Validation and Acceptance

Acceptance requires these observable results.

- A recursive JavaScript or TypeScript call is returned as `SelfReceiver`.
- A same-name local callback and a named function-expression binding are not
  returned for an outer callable.
- `func (c ComponentPath)` appears in inverse usages for `ComponentPath`.
- A cold `search_symbols` request succeeds after workspace readiness, or the
  documented retry returns the result without a 4.5-second failure.
- The affected UsageBench cases pass and the focused Rust tests pass.

## Idempotence and Recovery

The tests use inline projects or checked-in fixtures. They do not edit the
pinned real-project archives. Retry a cold-request test only with its clean
process setup. Do not change UsageBench ground truth to hide a Bifrost result.

## Artifacts and Notes

The comparison artifacts are temporary files under
`/private/tmp/usagebench-regression-eZPbMz`. The two Actions reports record
the exact Bifrost commits and result locations.

## Interfaces and Dependencies

Keep the existing `UsageHit`, `UsageProof`, and `SelfReceiver` types. Do not
add a string-matching fallback. Use tree-sitter nodes, lexical binding facts,
and existing analyzer indexes. Keep the MCP request-budget contract explicit.

Plan updated on 2026-08-07 because the user authorized implementation after
the evidence-only investigation.

Plan updated on 2026-08-07 after focused validation and exact-case benchmark
validation completed.
