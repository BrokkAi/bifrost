# Reach Rust Usage Graph Parity With Brokk

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `PLANS.md`.

## Purpose / Big Picture

After this work, `bifrost` will be able to answer Rust usage queries through the same graph-first path that Brokk already uses for Rust: seeded exported-symbol lookup for public exports, same-file private-function handling when the graph can still prove the target, member usage resolution through receiver facts, and stable behavior around candidate-file narrowing and repeated analyzer lookups. A contributor should be able to run focused Rust tests in `bifrost` and watch the same representative Rust scenarios that already pass in Brokk pass here as well.

This is intentionally a long-running parity program, not only a one-issue patch plan. Issue `#75` is the first implementation slice: it introduces Rust export-usage graph routing and the analyzer hooks needed to support it. Full practical parity with `../brokk` also requires the follow-on receiver/member inference work that was split into issue `#76`. This plan keeps both realities explicit so a future contributor does not mistake “strategy exists” for “Rust parity is complete.”

## Progress

- [x] (2026-05-18T14:32Z) Read `PLANS.md`, `src/usages/finder.rs`, `src/usages/graph_core.rs`, `src/usages/js_ts_graph.rs`, `src/usages/python_graph.rs`, `src/analyzer/rust_analyzer.rs`, and the current Rust and usage tests in `tests/`.
- [x] (2026-05-18T14:32Z) Read the matching Brokk reference files under `/Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/`, especially `RustExportUsageGraphStrategy.java`, `RustExportUsageGraphAdapter.java`, and `RustExportUsageGraphStrategyTest.java`.
- [x] (2026-05-18T14:32Z) Confirmed the current baseline: `bifrost` already has the shared usage-graph core from issue `#73` and Python routing from issue `#74`, but `UsageFinder` still falls back to regex for all Rust targets because no Rust graph strategy is registered yet.
- [x] (2026-05-18T14:32Z) Confirmed the main analyzer gap: `RustAnalyzer` currently exposes generic import-analysis and reverse-import behavior, but not the Rust-specific graph-facing hooks that Brokk’s Rust strategy relies on.
- [x] (2026-05-18T14:44Z) Completed Milestone 1 by adding `src/usages/rust_graph.rs`, registering `RustExportUsageGraphStrategy` in `src/usages/finder.rs`, and widening `RustAnalyzer` with first-wave helpers for export indices, import binders, and Rust module-to-file resolution.
- [x] (2026-05-18T14:44Z) Completed Milestone 2 by adding `tests/usages_rust_graph_test.rs` and proving seeded public-export routing, `MultiAnalyzer` routing, same-file private-function support, explicit candidate restriction, broad mixed candidate filtering, `TooManyCallsites`, and same-file type-position/literal struct references.
- [x] (2026-05-18T16:41Z) Advanced Milestone 3 substantially: the focused Rust graph suite now covers 37 passing cases, including `self` imports, public re-export aliases, shadowing negatives, typed and constructed receivers, alias-propagated receivers, static associated items, `pub(crate)`/`pub(self)` visibility, same-file closure calls, barrel re-exports, chained aliased re-exports, bounded glob imports, bounded glob re-exports, simple type-alias receiver seeding, and self-like constructor-chain receiver seeding.
- [x] (2026-05-18T17:18Z) Started the follow-on milestone breakdown and completed another focused parity slice: the Rust suite now covers 43 passing cases after adding enum variants as associated fields, impl-associated types, private-item-behind-barrel negatives, `self.field.as_ref()` `let-else` receiver seeding, and destructuring-pattern receiver negatives.
- [ ] Implement the remaining Milestone 4 parity work so the Brokk-vs-`bifrost` Rust graph gaps are either closed or recorded explicitly, especially the still-open trait/associated-type/inline-module edge cases and any behavior that truly belongs to issue `#76` rather than `#75`.

## Surprises & Discoveries

- Observation: the enabling architecture for Rust graph support is already present in `bifrost`.
  Evidence: `src/usages/graph_core.rs` exists, `src/usages/python_graph.rs` already layers a second language-specific graph strategy on top of it, and `src/usages/finder.rs` already routes by language.

- Observation: the missing Rust parity is not a single missing file; it spans both the usage-strategy layer and analyzer capabilities.
  Evidence: `src/usages/finder.rs` registers JS/TS and Python graph strategies only, while `src/analyzer/rust_analyzer.rs` has no `export_index_of`, `import_binder_of`, `export_usage_candidates_of`, `resolved_receiver_candidates_of`, `rust_usage_candidate_files`, `resolve_rust_module_outcome`, or `exact_member` helpers analogous to Brokk’s Rust graph adapter contract.

- Observation: Brokk’s current Rust strategy deliberately treats “public export graph” and “local receiver/member inference” as separable phases.
  Evidence: the durable backlog order recorded for `bifrost` placed `#75` before `#76`, and Brokk’s Rust strategy tests include both exported-symbol seeding cases and member/receiver cases that depend on analyzer-side receiver facts.

- Observation: candidate-file handling is part of correctness, not just performance.
  Evidence: the prior Brokk rollout recorded that broad candidate sets leaking non-Rust files into Rust graph analysis created both noisy logging and incorrect widening behavior, and the Java strategy test suite includes explicit mixed-candidate and non-Rust-only cases.

- Observation: `bifrost` could support the first Rust graph slice without copying Brokk’s full adapter contract yet.
  Evidence: the first green wave only needed `RustAnalyzer::export_index_of`, `import_binder_of`, and module-file resolution plus a Rust-specific scanner layered directly on `ProjectUsageGraph`; member receiver helpers remain the only major missing seam.

- Observation: the non-Rust-only candidate case was a real behavior trap even in the smaller Rust port.
  Evidence: the first implementation widened an explicit `README.md` candidate set back out to graph-derived importers, and `tests/usages_rust_graph_test.rs` caught it immediately; the fix was to preserve explicit candidate emptiness after Rust-file filtering by scanning only the target file.

- Observation: the first useful Rust member slice did not require a full Rust data-flow engine yet.
  Evidence: the current member tests pass with a narrower receiver heuristic built from imported owner names plus simple typed and constructed local-variable detection, which was enough to prove `Service.run`-style calls without broadening the top-level graph design.

- Observation: most of the remaining high-value parity outside traits was recoverable by tightening seed and visibility semantics rather than introducing a full reference engine.
  Evidence: `pub(self)` export handling, `crate`-root barrel resolution, grouped `pub use` flattening, bounded globs, local type aliases, and self-like constructor chains all landed as targeted graph/analyzer improvements while keeping the strategy architecture intact.

- Observation: another meaningful receiver-fact slice was still available before trait work.
  Evidence: `self.field.as_ref()` `let-else` receiver seeding and the paired destructuring negatives could be captured with narrow field-type heuristics, which raised focused parity without needing a general trait or pattern-binding engine.

## Decision Log

- Decision: write this as a broader parity program named `RUST_USAGE_GRAPH_PARITY_EXECPLAN.md` instead of a narrow `ISSUE_75_EXECPLAN.md`.
  Rationale: the user asked for a long-running plan that starts from issue `#75` but brings `bifrost` to parity with `../brokk`; that necessarily spans more than the first mergeable slice.
  Date/Author: 2026-05-18 / Codex

- Decision: keep Milestone 1 focused on top-level exported-symbol routing and infrastructure, while explicitly allowing Milestone 3 to carry the receiver/member cases that may spill into issue `#76`.
  Rationale: the current backlog already separated those concerns, and pretending they are one atomic patch would blur the implementation boundary the repository is already using.
  Date/Author: 2026-05-18 / Codex

- Decision: define parity by observable `bifrost` behavior and focused Rust tests, not by a line-for-line reproduction of Brokk’s Java class layout.
  Rationale: the repositories share semantics, not implementation language. The stable contract is that the same Rust usage scenarios are proven by tests and routed through the graph where expected.
  Date/Author: 2026-05-18 / Codex

- Decision: prefer `tests/common/inline_project.rs` for new Rust usage-graph tests unless a scenario truly needs a larger reusable fixture tree.
  Rationale: the repo guidance explicitly prefers the shared inline harness for small ad hoc projects, and Brokk’s current Rust graph strategy cases are compact enough to express inline.
  Date/Author: 2026-05-18 / Codex

- Decision: implement the first Rust graph slice with a Rust-specific scanner layered directly on `ProjectUsageGraph` instead of first recreating every Brokk adapter helper.
  Rationale: this delivered the mergeable `#75` core faster while preserving the important architectural seam; the remaining receiver/member helpers are still clearly isolated as Milestone 3 work.
  Date/Author: 2026-05-18 / Codex

- Decision: treat explicit non-Rust candidate sets as a hard boundary rather than widening them back to graph importers after filtering.
  Rationale: Brokk’s earlier rollout proved that widening explicit filtered candidate sets is both noisy and behaviorally wrong; the focused Rust graph test now locks that rule in for `bifrost`.
  Date/Author: 2026-05-18 / Codex

- Decision: implement the first member wave with a focused receiver heuristic instead of blocking on full general receiver-fact caches.
  Rationale: the next valuable proof point was public-owner member routing and exact-member lookup, and those scenarios can be validated with simpler typed-local and constructed-local receiver inference while keeping the richer cache/fact parity explicitly open.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

At the moment this plan is created, `bifrost` has already crossed the architectural threshold for multi-language usage graphs: the shared graph engine from issue `#73` exists, and Python has already proven that a non-JS/TS language can plug into that engine successfully. The first implementation wave closed the largest Rust routing gap: Rust now has a graph strategy, `UsageFinder` now routes Rust through it, and the first focused Rust graph suite proves the top-level and same-file cases that used to fall straight to regex.

What still remains is the deeper parity slice around members and receivers. The second implementation wave closed the first part of that gap by adding exact-member lookup, public-owner member routing, and a focused candidate funnel for likely owner-importing files. Success is still not “a Rust graph class exists.” Success is that `bifrost` can demonstrate, with focused Rust tests, that it matches Brokk’s Rust graph behavior across selector routing, candidate narrowing, top-level exported-symbol lookups, same-file private-function cases, member/receiver usage resolution, and the remaining explicitly recorded residual gaps.

## Context and Orientation

`bifrost`’s usage-finding subsystem lives under `src/usages/`. A “usage graph” in this repository means a graph-based path that starts from a target export, follows imports and re-exports across files, narrows the candidate file set to likely importers, and then scans only those files for proven usages. The language-neutral graph bookkeeping extracted for issue `#73` now lives in `src/usages/graph_core.rs`.

Today there are two graph-backed language strategies in `bifrost`: JavaScript/TypeScript in `src/usages/js_ts_graph.rs` and Python in `src/usages/python_graph.rs`. Public routing happens in `src/usages/finder.rs`, where `UsageFinder` chooses a graph strategy based on the target file’s language and falls back to `RegexUsageAnalyzer` when no graph strategy can prove a seeded query.

Rust support is missing at both of the seams that matter. First, `src/usages/finder.rs` does not register a Rust graph strategy, so every Rust query currently falls through to regex. Second, `src/analyzer/rust_analyzer.rs` does not yet expose the Rust-specific helpers that a graph strategy needs. Brokk’s reference adapter for Rust expects the analyzer to provide:

    export index lookup for a file;
    import-binder extraction for a file;
    reference candidates for a file under a known import binder;
    resolved receiver candidates for member queries;
    exact-member lookup by owner/member name;
    Rust module-resolution outcomes for an import path;
    narrowed candidate-file lookup for a target export;
    reverse importer lookup for a file; and
    any simple hierarchy facts the graph needs for member ownership.

Brokk is the reference implementation for the target behavior. The most relevant source files are:

    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/RustExportUsageGraphStrategy.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/RustExportUsageGraphAdapter.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/RustExportUsageGraphStrategyTest.java

Those files define the current parity target for issue `#75`. They cover selector behavior for public exports, fallback for private unseeded targets, same-file private functions that still have a usable seed, explicit candidate-file restriction, mixed candidate sets that include non-Rust files, hit-limit behavior, member routing, receiver-based member hits, exact-member stability, candidate-file narrowing, warmed caches, same-file type-position references such as `Vec<RenderedSummary>`, and closure-contained private-function calls.

## Plan of Work

Start by adding a Rust graph strategy under `src/usages/`. The fastest path is to follow the same layering already used by `PythonExportUsageGraphStrategy`: keep the shared project-graph bookkeeping in `src/usages/graph_core.rs`, add a Rust-specific adapter/scanner file that knows how to infer export seeds, resolve Rust modules, derive candidate importer files, and scan Rust syntax trees for matching identifier, type-position, and member usages. Register that strategy in `src/usages/finder.rs` so `UsageFinder` chooses it for Rust targets before falling back to regex.

In parallel, widen `src/analyzer/rust_analyzer.rs` with the graph-facing helper surface the strategy needs. Do not bolt everything into one monolithic method. Prefer small Rust-specific helpers, ideally under language-scoped helper sections or sibling modules if that keeps the file manageable. The first milestone needs enough analyzer support to answer top-level exported-symbol queries: export indices, import binders, module resolution, and candidate/reference extraction. The later milestone needs exact-member lookup and receiver-candidate extraction for member queries.

Drive the port from focused tests. Add a dedicated Rust usage-graph test file under `tests/`, rather than burying this work inside the existing general Rust analyzer parity files. Use `tests/common/inline_project.rs` to create compact Rust mini-projects inline. Port the representative Brokk strategy cases one cluster at a time so every new behavior is proven before the implementation grows.

Keep the issue boundaries honest while still pursuing full parity. Milestones 1 and 2 should land the mergeable `#75` core: a real Rust graph strategy, selector routing, top-level seed inference, candidate narrowing, and type-position usage hits. Milestone 3 should finish the member/receiver side even if that work is formally tracked by `#76`. If a behavior is clearly out of scope for the current repository or intentionally different from Brokk, record it explicitly in the parity matrix instead of letting it disappear into an implicit backlog.

## Milestones

### Milestone 1: Land the Rust graph strategy and first analyzer hooks

At the end of this milestone, `UsageFinder` should be able to choose a Rust graph strategy for eligible Rust targets instead of always falling back to regex. A contributor should be able to run focused Rust usage tests and see seeded public-export queries route through the graph path.

Implement this by adding a Rust strategy file under `src/usages/`, wiring it into `src/usages/mod.rs` and `src/usages/finder.rs`, and teaching `RustAnalyzer` to expose the first graph-facing helpers: export index lookup, import-binder lookup, Rust module resolution, and enough reference-candidate extraction to prove top-level exported-symbol usages. This milestone should also decide whether any of those helpers belong in new Rust-specific analyzer submodules instead of growing `src/analyzer/rust_analyzer.rs` inline.

Acceptance is that focused Rust tests prove strategy selection for public exported symbols and same-file seedable private functions, while private unseeded targets still fall back to regex or return an empty graph result as intended by the design.

### Milestone 2: Match the current Brokk top-level strategy behavior

At the end of this milestone, `bifrost` should match the current Brokk strategy cases for top-level Rust usage lookups. That includes explicit candidate-file narrowing, mixed candidate sets that include non-Rust files, hit-limit behavior, cache-safe repeated lookups, and same-file type-position references such as `Result<Vec<RenderedSummary>, String>`.

Implement this by porting the representative Brokk tests into a focused Rust usage-graph suite and then adjusting the Rust strategy and analyzer helpers until they pass. Add tests for broad candidate sets, non-Rust-only explicit candidate sets, too-many-callsites behavior, repeated lookup stability, same-file struct references in return types and literals, and closure-contained private-function calls.

Acceptance is that the new focused test file proves these behaviors directly and that `UsageFinder` still prefers the Rust graph path when the query is seedable.

### Milestone 3: Port member and receiver inference behavior

At the end of this milestone, member queries like `Service.run` should work through graph-proven receiver facts rather than text search. The user-visible effect is that Rust member usage lookups return only the receiver call sites that can actually be tied back to the exported owner type.

Implement this by widening the Rust analyzer with exact-member lookup and receiver-candidate extraction, then porting the Brokk member cases: selector routing for members of public exports, receiver-based member hits, candidate-file funnels for likely member files, and warmed cache behavior for both references and receivers. If this milestone grows naturally into the work tracked by issue `#76`, keep the plan updated and say so explicitly in `Decision Log` and `Progress`.

Acceptance is that focused member tests demonstrate positive receiver inference and that unrelated files or same-named non-receiver cases do not count as proven hits.

### Milestone 4: Close or record the residual parity matrix

At the end of this milestone, a future contributor should be able to tell exactly what remains between `bifrost` and Brokk for Rust usage graphs. Every meaningful Brokk Rust strategy case should be marked as done, deferred to a separate issue, intentionally different, or still missing.

Implement this by reviewing the remaining Brokk Rust graph tests line by line and updating the parity matrix below. If new gaps appear that clearly belong outside `#75`, record them explicitly instead of folding them into vague future work.

Acceptance is that no contributor needs to rescan the upstream Brokk suite just to understand the remaining Rust graph backlog.

### Milestone 5: Port associated-item and visibility edge cases

At the end of this milestone, `bifrost` should cover the remaining non-trait associated-item and export-visibility cases that still sit in Brokk’s reference suite. This is the best next wave because it closes a meaningful chunk of parity without requiring the full trait/reference engine.

Implement this by extending the Rust analyzer and graph strategy to handle enum variants as associated fields, associated types exposed from impl blocks, private associated-item negatives, and the remaining barrel/private-item visibility checks. Add focused tests for each upstream reference case before widening behavior.

Acceptance is that the focused Rust suite proves enum variant static accesses, associated-type static accesses, and the remaining negative visibility cases without regressing the current member and re-export behavior.

### Milestone 6: Port trait-owner and receiver-proof semantics

At the end of this milestone, `bifrost` should cover the hard Rust trait cases from Brokk: explicit trait-path calls, proven impl ownership, cross-file trait impl resolution, and negative receiver cases where generic, opaque, or dynamic receivers should not seed hits.

Implement this by teaching the Rust analyzer to surface enough trait and impl ownership facts for the graph strategy to distinguish inherent methods from trait methods and to prove which owner file a method call belongs to. Keep the scope focused on the current Brokk test shapes rather than attempting general Rust trait resolution beyond the parity target.

Acceptance is that the focused suite proves the upstream trait-owner/member cases and the trait-related negative receiver cases directly.

### Milestone 7: Port inline-module and unresolved-frontier behavior

At the end of this milestone, the remaining parity gap should be limited to explicitly intentional differences, if any. This wave covers the residual module-shape and frontier cases that are awkward but important for honest parity accounting.

Implement this by adding support or explicit accounting for unresolved external re-exports/glob re-exports, public inline modules, private inline modules, explicit inline-module re-exports, and public-only inline-module contents. If a frontier case cannot be expressed through the current `bifrost` result model cleanly, record that as an intentional model gap rather than leaving it implicit.

Acceptance is that the inline-module and frontier cases from Brokk are either green in `bifrost` or explicitly recorded in the parity matrix as model gaps.

## Concrete Steps

From `/Users/dave/.codex/worktrees/3527/bifrost`:

1. Keep this document updated before and after each milestone so `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` reflect the real state.
2. Add a focused Rust usage-graph test file under `tests/`, backed by `tests/common/inline_project.rs`.
3. Port the current milestone’s Brokk Rust graph cases into Rust tests before widening the implementation.
4. Make the smallest code changes needed in `src/usages/`, `src/analyzer/rust_analyzer.rs`, or closely related Rust-analyzer helper modules to satisfy those tests.
5. Run:

       cargo fmt

6. Run the focused Rust usage tests for the milestone, starting with the dedicated Rust usage-graph suite and any related analyzer parity tests needed to protect shared behavior.
7. Once the focused tests pass, run:

       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings

8. When a milestone materially changes routing behavior, run the smallest neighboring regression suites that protect the shared graph core, especially the existing JS/TS and Python usage-graph tests if the touched code is shared.
9. Record the outcome, unexpected behavior, and updated parity-matrix status in this document.

## Validation and Acceptance

Validation must stay behavior-focused.

For every milestone, run the focused Rust usage-graph tests added for that milestone. The proof must show a specific Rust usage scenario that previously fell back to regex or returned the wrong result and now routes through the graph with the correct hits.

After the focused tests are green, run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`. These commands are the local quality gate expected for Rust changes in this repository.

Success for this ExecPlan is not “the code compiles.” Success is that `bifrost` can demonstrate, with focused Rust tests, that it now matches Brokk’s current Rust usage-graph behavior across selector routing, candidate narrowing, type-position same-file references, member/receiver queries, and the remaining explicitly recorded residual differences.

## Idempotence and Recovery

This plan is safe to execute incrementally. Re-running `cargo fmt`, the focused `cargo test` commands, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` is safe.

If a milestone stalls midway, do not skip ahead. Update `Progress` so it says exactly what landed and what remains. Keep any focused failing tests that represent real uncovered behavior, and continue from the smallest missing capability rather than broadening scope blindly. If a Brokk scenario turns out not to apply cleanly to `bifrost`, record that explicitly in the parity matrix instead of deleting the trace of the gap.

## Artifacts and Notes

Important local references for this plan are:

    PLANS.md
    src/usages/finder.rs
    src/usages/graph_core.rs
    src/usages/js_ts_graph.rs
    src/usages/python_graph.rs
    src/analyzer/rust_analyzer.rs
    tests/common/inline_project.rs
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/RustExportUsageGraphStrategy.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/RustExportUsageGraphAdapter.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/RustExportUsageGraphStrategyTest.java

The most important current evidence snapshot is:

    `bifrost` already has the shared graph core and a second non-JS/TS graph language in Python, but Rust still lacks both the registered strategy and the analyzer-side capability surface required to plug Rust into that graph.

## Interfaces and Dependencies

The public behavior expected at the end of this plan is:

    `UsageFinder` routes eligible Rust targets through a Rust graph strategy before regex fallback.

    `RustAnalyzer` exposes graph-facing helpers analogous to the current Python analyzer surface, extended with the Rust-specific member and module-resolution helpers needed by the strategy.

    The Rust graph strategy can infer export seeds for top-level exports and same-file seedable private functions, and can scan Rust syntax trees for identifier, type-position, and member usages that resolve back to those seeds.

    Focused Rust tests prove candidate narrowing, hit-limit behavior, same-file usage discovery, repeated lookup stability, and member/receiver resolution.

## Rust Parity Matrix

- Selector chooses Rust graph for seeded public export targets: done in `bifrost` in the first wave; proved by `usage_finder_routes_seeded_public_rust_export_through_graph`.
- Selector falls back for private unseeded Rust targets: still missing explicit focused proof in `bifrost`; keep as follow-up in Milestone 4 unless a Milestone 3 refactor naturally adds it.
- Selector uses Rust graph for same-file private function targets when the function can still be seeded locally: done in `bifrost` in the first wave; proved by `rust_graph_strategy_finds_same_file_private_function_calls`.
- Graph respects explicit candidate-file restriction: done in `bifrost` in the first wave; proved by `rust_graph_strategy_respects_explicit_candidate_files`.
- Graph filters broad mixed candidate sets without widening non-Rust-only explicit sets: done in `bifrost` in the first wave; proved by `rust_graph_strategy_filters_non_rust_candidates_without_widening`.
- Graph returns `TooManyCallsites` when hits exceed the limit: done in `bifrost` in the first wave; proved by `rust_graph_strategy_returns_too_many_callsites_when_hits_exceed_limit`.
- Same-file struct references in return types and literals are counted as usages: done in `bifrost` in the first wave; proved by `rust_graph_strategy_finds_same_file_struct_references_in_types_and_literals`.
- Same-file private-function calls inside closures are counted when the local seed is known: done in `bifrost` in the first wave via the same-file private function case; keep the closure-specific shape as an optional hardening follow-up if Brokk-specific coverage needs to be matched more literally.
- Selector chooses Rust graph for members of public exports: done in `bifrost` in the second wave; proved by `usage_finder_routes_rust_member_targets_through_graph`.
- Receiver-based member usages are proven only for the correct owner type: partially done in `bifrost`; current proof covers typed/constructed local receiver cases for imported public owners, but broader receiver-fact parity and negative ambiguity cases remain open.
- Exact-member lookup is stable across repeated lookups: done in `bifrost` in the second wave; proved by `rust_exact_member_lookup_is_stable_across_repeated_calls`.
- Rust candidate funnel keeps likely member files and drops unrelated files: done in `bifrost` in the second wave; proved by `rust_member_candidate_funnel_keeps_likely_files_and_drops_unrelated_ones`.
- Rust usage-fact caches feed both reference and receiver lookups consistently: still missing explicit parity proof in `bifrost`; keep this open for a later Milestone 3 hardening pass or issue `#76`.

Revision note: created this repo-root long-running ExecPlan after comparing the current `bifrost` Rust usage surface with the existing Brokk Rust graph strategy and tests, so the implementation path and the residual parity gap are both explicit from the start.

Revision note: updated after the first implementation wave to record the new Rust graph strategy, the initial Rust-analyzer helper surface, the focused Rust graph tests that now pass, and the remaining member/receiver parity gap.

Revision note: updated after the larger reference-graph parity wave to record 37 passing focused Rust graph tests, the new bounded-glob and barrel-reexport support, stricter Rust visibility semantics, and the narrowed residual gap around traits, associated types, and inline-module-specific behavior.

Revision note: updated again after breaking the remaining backlog into Milestones 5 to 7 and landing the next associated-item/receiver slice, which brought the focused Rust graph suite to 43 passing tests and reduced the remaining gap primarily to trait semantics, unresolved-frontier behavior, and inline-module-specific cases.

Revision note: updated after the second implementation wave to record the first member-routing slice, the new `exact_member` and member candidate-funnel helpers, and the narrower remaining receiver/cache parity backlog.
