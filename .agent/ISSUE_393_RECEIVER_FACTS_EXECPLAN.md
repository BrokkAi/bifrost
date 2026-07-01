# Define Composable Receiver Facts and Usage-Hit Surface Contracts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Issue #393 establishes a shared receiver/fact vocabulary and usage-hit surface contract before Bifrost adds object-sensitive, data-flow, or control-flow analysis. After this change, editor references can include useful internal receiver references such as `this.target()` while MCP `scan_usages`, relevance, call graph, rename, and dead-code surfaces can consistently filter those hits. The same contract will also guide JS/TS declaration extraction so `obj.x = 1` on a plain local does not create a false `obj.x` declaration.

The observable result is that #387 and #386 have concrete regression coverage: LSP references include same-class self/this receiver usages where appropriate, external-usage surfaces exclude them, and JS/TS no longer over-declares plain-local member assignments while keeping prototype/class/export assignment declarations.

## Progress

- [x] (2026-07-01T07:58Z) Created this ExecPlan at `.agent/ISSUE_393_RECEIVER_FACTS_EXECPLAN.md`.
- [x] (2026-07-01T08:03Z) Added the shared receiver/fact vocabulary and usage-hit surface helpers; focused surface and existing JS/TS/Python usage tests passed.
- [x] (2026-07-01T09:39Z) Implemented and tested self-receiver hit classification for #387 across JS/TS, C++, and Rust.
- [x] (2026-07-01T10:13Z) Implemented and tested JS/TS member-assignment declaration filtering for #386.
- [x] (2026-07-01T10:46+02:00) Ran focused tests, `cargo fmt`, `cargo clippy-no-cuda`, and `git diff --check`; committed after each completed milestone.

## Surprises & Discoveries

- Observation: `UsageHitKind` currently has only `Reference` and `Import`.
  Evidence: `src/analyzer/usages/model.rs` filters `Import` from `all_hits` and `into_either`, while `all_hits_including_imports` feeds IDE references.

- Observation: LSP references already use the inclusive hit surface.
  Evidence: `src/lsp/handlers/usage_hits.rs` calls `all_hits_including_imports`, while `scan_usages`, dead-code, rename, and call hierarchy filter import hits.

- Observation: #387 is already pinned by ignored tests.
  Evidence: `tests/cross_language_self_usages.rs` ignores C++, Rust, JS, and TS self/this receiver cases; C#, PHP, Scala, Go, and Ruby already pass.

- Observation: #386 is already pinned by ignored tests.
  Evidence: `tests/cross_language_attribute_target_declarations.rs` ignores JS and TS plain-local member-assignment cases.

- Observation: The first shared-surface milestone did not change existing JS/TS or Python usage graph behavior.
  Evidence: `cargo test --lib usage_hit`, `cargo test --test usages_js_ts_graph_test`, and `cargo test --test usages_python_graph_test` all passed after adding `UsageHitSurface`, `UsageHitKind::SelfReceiver`, and `receiver_facts`.

- Observation: JS/TS and Rust local, unexported member targets need same-file receiver scans before returning `NoGraphSeed`.
  Evidence: The unignored LSP fixtures use local `class Foo` / private Rust `fn target`; `cargo test --test cross_language_self_usages` only passed after adding no-seed same-file scans for structurally proven `this.target()` and `self.target()`.

- Observation: LSP declaration targeting for C++/Rust method declarations needed a broader declaration-name fallback.
  Evidence: The analyzers returned `Foo.target` from `enclosing_code_unit`, but LSP references returned `null` until `src/lsp/handlers/broad_symbol.rs` could find a matching declaration identifier in the containing AST node when no `name` field was present.

- Observation: Rust `self.field` and direct self field accesses are external receiver evidence, not `SelfReceiver` hits.
  Evidence: `cargo test --test usages_rust_graph_test` initially failed existing field receiver tests until `SelfReceiver` classification was narrowed to non-field targets with direct `self.method()` receivers.

- Observation: TypeScript already did not over-declare the ignored plain-local assignment fixture; the active fix was in JavaScript assignment declaration extraction.
  Evidence: `cargo test --test cross_language_attribute_target_declarations -- --ignored --nocapture` passed the TS ignored case before the JS fix, while JS produced `obj.spuriousmember`.

- Observation: JavaScript local-object function assignments are intentional declaration seeds even when the receiver object is a plain local.
  Evidence: `cargo test --test usages_js_ts_graph_test` failed `js_commonjs_exports_property_does_not_seed_unrelated_member_by_short_name` until the filter suppressed only non-function plain-local member assignments and preserved function-valued local member declarations.

- Observation: Final validation required only formatter churn plus two small clippy fixes after the behavioral milestones.
  Evidence: `cargo fmt` reformatted existing edited code, `cargo clippy-no-cuda` flagged one needless C++ return and one intentional Rust helper arity, and the rerun passed.

## Decision Log

- Decision: Implement #393 as “contract plus fixes,” not contract-only.
  Rationale: The user selected the scope that proves the abstraction with #386 and #387.
  Date/Author: 2026-07-01 / Codex planning

- Decision: Add a new `UsageHitKind::SelfReceiver` and a surface helper instead of hard-coding another set of `kind != ...` checks.
  Rationale: The existing `Import` split is the right precedent, but more surfaces will exist later.
  Date/Author: 2026-07-01 / Codex planning

- Decision: Keep object-sensitive pointer/value analysis out of this issue.
  Rationale: #394 owns bounded object-sensitive analysis; #393 should make the current layers composable and consistent first.
  Date/Author: 2026-07-01 / Codex planning

## Outcomes & Retrospective

- #387 milestone: unignored C++, JavaScript, TypeScript, and Rust cases in `tests/cross_language_self_usages.rs`. LSP references now include structurally proven same-class `this.target()` / `self.target()` hits for those languages, while `FuzzyResult::all_hits()` and usage graph surfaces exclude them as `SelfReceiver`.
- Added graph regressions proving same-class receiver calls do not create `usage_graph` edges for TypeScript, C++, and Rust.
- C++ also treats implicit same-owner calls (`target()`) as editor-visible self-receiver hits in the forward usage scan and skips them in the inverted graph.
- Deferred richer receiver/value analysis remains #394 territory: receiver chains such as object-sensitive local aliases are still only handled where existing structured resolver support proves them.
- #386 milestone: unignored JS and TS plain-local member-assignment declaration tests. JavaScript now suppresses non-function member assignments rooted at scoped plain locals or parameters, while preserving class/function/prototype roots and function-valued local object member declarations used by CommonJS export graphs. TypeScript remains covered by the cross-language regression and does not emit the plain-local assignment declaration.
- Final validation passed: the focused #393 test suites, `cargo fmt`, `cargo clippy-no-cuda`, and `git diff --check` all completed successfully.

## Context and Orientation

Usage hits live in `src/analyzer/usages/model.rs`. `UsageHitKind::Import` is already filtered from external-usage surfaces and included by LSP references. The public usage subsystem re-exports these types from `src/analyzer/usages/mod.rs`.

The LSP reference path starts in `src/lsp/handlers/references.rs` and uses `src/lsp/handlers/usage_hits.rs`. MCP `scan_usages` rendering filters in `src/searchtools.rs`. Dead-code and rename consumers also filter import hits directly today.

The missing self/this receiver behavior is language-specific. JS/TS usage graph code lives under `src/analyzer/usages/js_ts_graph/`. C++ lives under `src/analyzer/usages/cpp_graph/`. Rust lives under `src/analyzer/usages/rust_graph/`.

JS/TS declaration extraction lives in `src/analyzer/javascript/mod.rs`, shared by JavaScript and TypeScript analyzers.

## Plan of Work

First, add the shared surface contract. Extend `UsageHitKind` with `SelfReceiver`, add `UsageHitSurface` with `ExternalUsages` and `LspReferences`, add `UsageHitKind::included_in(surface)`, add `UsageHit::into_self_receiver`, and add `FuzzyResult::all_hits_for_surface`. Keep `all_hits` and `into_either` as external-usage helpers. Keep `all_hits_including_imports` as the LSP-inclusive compatibility helper, but implement it through `LspReferences` and update its docs so it now includes all editor-visible hits, not only imports.

Second, replace direct `hit.kind != UsageHitKind::Import` checks in searchtools, rename, dead-code, and tests with the new helper where those paths mean “external usages.” LSP references should continue to use the inclusive surface.

Third, add a small internal receiver contract module, `src/analyzer/usages/receiver_facts.rs`, with documented `pub(crate)` enums for receiver origin and receiver resolution state. This module is a vocabulary and documentation anchor for #393, not a full fact provider. It must explicitly distinguish Java/C#/C++/Scala/Rust lexical receivers, JS/Ruby runtime/context receivers, Python ordinary-parameter `self`, Go named receivers, module/export receivers, plain locals, unknown, ambiguous, and unsupported forms.

Fourth, implement #387. For JS/TS, C++, and Rust forward usage scans, when a same-class `this` / `self` / implicit receiver call is structurally proven, emit the hit as `SelfReceiver`. Add tests proving LSP references include those hits and MCP `scan_usages` excludes them. For whole-workspace `usage_graph`, do not emit edges for same-class self-receiver calls; add explicit graph tests for `caller -> target` same-class receiver calls so this does not depend only on self-recursion tests.

Fifth, implement #386. In `src/analyzer/javascript/mod.rs`, add declaration-extraction scope tracking for assignments. Suppress `obj.x = ...` declarations when the assignment receiver root is a plain local variable or parameter in lexical scope. Continue allowing declaration-worthy receivers: class/constructor function static members, `.prototype` members, `exports.x`, `module.exports.x`, and supported namespace/module receivers. Add JS and TS regression tests for both suppression and preserved declarations, then unignore the existing plain-local tests.

## Concrete Steps

From `/Users/dave/.codex/worktrees/a8df/bifrost`:

1. Confirm current state without rebasing or switching branches:

       git status --short --branch

2. Create `.agent/ISSUE_393_RECEIVER_FACTS_EXECPLAN.md` from this plan and commit that file alone.

3. Implement the hit-surface milestone and run:

       cargo test --lib usage_hit
       cargo test --test usages_js_ts_graph_test
       cargo test --test usages_python_graph_test

4. Implement the #387 milestone and run:

       cargo test --test cross_language_self_usages
       cargo test --test usages_js_ts_graph_test
       cargo test --test usages_cpp_graph_test
       cargo test --test usages_rust_graph_test
       cargo test --test usage_graph_ts_test
       cargo test --test usage_graph_cpp_test
       cargo test --test usage_graph_rust_test

5. Implement the #386 milestone and run:

       cargo test --test cross_language_attribute_target_declarations
       cargo test --test javascript_analyzer_test
       cargo test --test typescript_analyzer_test

6. Final validation:

       cargo fmt
       cargo clippy-no-cuda
       git diff --check

Commit after each milestone, staging only the files changed for that milestone.

## Validation and Acceptance

Acceptance is behavioral. `tests/cross_language_self_usages.rs` must no longer ignore the C++, Rust, JS, or TS self/this receiver tests. LSP references must report same-class self/this receiver hits, while `scan_usages` and graph-facing surfaces must not count them as external usage hits.

`tests/cross_language_attribute_target_declarations.rs` must no longer ignore the JS/TS plain-local member-assignment tests. Added regressions must prove prototype/class/export declarations still work.

The new `UsageHitSurface` tests must prove `ExternalUsages` excludes `Import` and `SelfReceiver`, while `LspReferences` includes both.

## Idempotence and Recovery

All code changes are incremental and test-backed. If a language-specific self-receiver implementation becomes too broad, keep the shared hit-surface contract and revert only that language slice to a structured `Unsupported` or no-hit behavior. Do not add regex or text-search fallbacks to make a failing receiver case pass.

Do not create or switch branches. Do not rebase. Work on the current branch and commit only milestone files.

## Interfaces and Dependencies

Add to `src/analyzer/usages/model.rs`:

    pub enum UsageHitKind {
        Reference,
        Import,
        SelfReceiver,
    }

    pub enum UsageHitSurface {
        ExternalUsages,
        LspReferences,
    }

    impl UsageHitKind {
        pub fn included_in(self, surface: UsageHitSurface) -> bool;
    }

    impl UsageHit {
        pub fn into_self_receiver(self) -> Self;
    }

    impl FuzzyResult {
        pub fn all_hits_for_surface(&self, surface: UsageHitSurface) -> BTreeSet<UsageHit>;
    }

Add `src/analyzer/usages/receiver_facts.rs` as an internal documented vocabulary module and export it only within the crate.

## Artifacts and Notes

Reference issues: #393, #394, #387, #386. The implementation should update #393 with final validation evidence after completion.

Revision note 2026-07-01 / Codex: initial ExecPlan created before code edits from the issue #393 implementation plan.
