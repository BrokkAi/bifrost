# Repair UsageBench regressions from the August 7 benchmark

This ExecPlan is a living document. Maintain it under `.agents/PLANS.md`.

## Purpose / Big Picture

UsageBench must report only real references and must not fail because the
analyzer is still preparing its workspace. After this work, recursive calls
remain visible, shadowed identifiers stay excluded, Go receiver type
references appear as editor-visible receiver mentions, and a cold symbol search has a
reliable readiness path.

## Progress

- [x] (2026-08-07 10:26Z) Compared Actions runs `31094360578` and `31168849324`.
- [x] (2026-08-07 10:37Z) Identified two JS/TS false positives, one Go inverse
  gap, and one cold `search_symbols` timeout.
- [x] (2026-08-07 13:28Z) Repair JS/TS recursive-hit classification and add
  source-level regressions.
- [x] (2026-08-07 12:18Z) Add Go receiver type mentions and coverage.
- [x] (2026-08-07 12:23Z) Repair cold `search_symbols` readiness and add
  coverage.
- [x] (2026-08-07 13:34Z) Run focused Rust tests, formatter, policy checks,
  and the four affected UsageBench cases.
- [x] (2026-08-07 14:12Z) Repair the related CommonJS LSP click-around
  regression found by the aarch64 CI job.
- [x] (2026-08-07 15:04Z) Repair the remaining JavaScript lexical-shadow
  regressions found by the aarch64 symbol suite.
- [x] (2026-08-07 15:42Z) Rebase onto current `origin/master` and keep the
  newer Go receiver `SelfReceiver` contract.
- [x] (2026-08-07 15:47Z) Re-run the Go receiver, JavaScript and TypeScript,
  symbol, and LSP regressions after the rebase.
- [x] (2026-08-07 15:50Z) Run the required `bifrost.code-smells` selection.

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
- Observation: A lexical name does not disprove a structured local binding.
  Evidence: CI job `92865678242` lost a returned property alias and an
  object-literal method receiver after lexical pre-registration hid both.
- Observation: Current master makes receiver type mentions editor-visible
  `SelfReceiver` hits, not external usages.
  Evidence: Commit `32ab2fb76` adds complete value, pointer, generic, and
  binding-name coverage for that contract.

## Decision Log

- Decision: Keep recursive-call support, but prove the binding targets the
  callable before classifying it as `SelfReceiver`.
  Rationale: A same-name local binding is not a recursive call.
  Date/Author: 2026-08-07 / Codex
- Decision: Treat the Go receiver type as an editor-visible `SelfReceiver`,
  not an external usage.
  Rationale: It is part of a method declaration. It must not increase external
  usage counts or change dead-code evidence.
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
- Decision: Restrict lexical pre-registration to statement blocks. Preserve
  target-owner bindings and structured target value and object facts.
  Rationale: A shadow filter can suppress heuristic matching, but it cannot
  override a binding proven by the local inference engine.
  Date/Author: 2026-08-07 / Codex

## Outcomes & Retrospective

The repair keeps structured tree-sitter and analyzer binding data. It adds no
source-text fallback.

Focused validation passed:

- `cargo fmt --check`
- `cargo test --test suite_usages go_receiver_type_mentions_are_editor_visible_self_receiver_hits`
- `cargo test --test suite_usages js_named_commonjs_function_expression_name_is_not_a_usage_but_recursion_is`
- `cargo test --test suite_usages ts_promise_callback_binding_does_not_impersonate_outer_function`
- `cargo test --test suite_mcp_cli lsp_click_around_regression::milestone_8_javascript_commonjs_object_click_around`
- `cargo test --test suite_symbols scan_usages_by_reference_preserves_javascript_property_alias_provenance`
- `cargo test --test suite_symbols scan_usages_location_target_selects_js_object_literal_method`
- `cargo test -p brokk-bifrost-mcp cold_workspace_deadline_tests --lib`
- `cargo test -p brokk-bifrost-mcp explicit_request_budget_wins_over_the_cold_workspace_fallback --lib`

The local binary built from this worktree passed the affected UsageBench cases.
The temporary archive needs release metadata because it is not a Git worktree.

The final `bifrost.code-smells` selection had no repository policy roots. It
returned `unreliable` with exit status 2 after 19.7 seconds. This is the
existing self-repository policy latency failure tracked by issue #1452. It is
not a clean policy result. No completed finding targets a changed file.

## Context and Orientation

UsageBench calls Bifrost through MCP. `search_symbols` finds a declaration
before UsageBench calls inverse usage search. `scan_usages_by_location` then
returns each proved usage location. A `SelfReceiver` is a recursive call inside
the declaration that it calls. It is visible to editor references, but it is
not an external callsite.

The JS/TS inverse graph is in `crates/bifrost-js-ts/src/graph/`. Its current
post-filter uses only the enclosing code unit. It must not treat a local
binding with the target name as a call to that target. The Go graph is in
`crates/bifrost-go/src/graph/`. It must model a method receiver type as an
editor-visible reference to the declared type. The MCP request deadline is in
`crates/bifrost-mcp/src/`; its cold workspace behavior must not produce a
spurious failed benchmark case.

## Plan of Work

First, make the JS/TS recursive filter inspect the structured binding or
reference result. Retain only a call that resolves to the target. Add small
TypeScript and JavaScript fixtures. They must show that true recursion remains
visible and shadowed local names remain absent.

Second, preserve the structured Go receiver type node as a `SelfReceiver`
editor hit. Record it only when its resolved type is the selected target. Add
a focused Go fixture with a named receiver. Keep external usages unchanged.

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
- `func (c ComponentPath)` appears as an editor-visible `SelfReceiver` for
  `ComponentPath`, but not as an external usage.
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
