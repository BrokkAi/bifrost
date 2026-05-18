# Extract Reusable Local Receiver And Member Inference For Usage Graphs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this work, `bifrost` will be able to answer member-usage questions with a shared precision layer instead of separate language-specific heuristics. A contributor should be able to run focused usage tests and see that receiver/member queries such as “find usages of `Service.run`” or “find usages of `Foo.bar`” are proven through bounded local inference rather than broad text matching. The practical user-visible gain is fewer false positives and a clearer path to parity across JavaScript/TypeScript, Python, and Rust.

This plan is the implementation program for issue `#76`, “Add reusable local receiver/member inference for usage graphs.” The issue is not asking for another one-off language strategy. It is asking for a shared local inference layer that usage-graph strategies can reuse once the cross-language graph core from issues `#73`, `#74`, and `#75` exists. The current codebase has already reached that point: `src/usages/graph_core.rs` is shared, Python and Rust both have graph strategies, and both of those strategies already contain local inference logic that should be extracted instead of duplicated further.

## Progress

- [x] (2026-05-18 19:31Z) Read `.agent/PLANS.md`, `src/usages/finder.rs`, `src/usages/graph_core.rs`, `src/usages/js_ts_graph.rs`, `src/usages/python_graph.rs`, `src/usages/rust_graph.rs`, `RUST_USAGE_GRAPH_PARITY_EXECPLAN.md`, `PYTHON_USAGE_GRAPH_PARITY_EXECPLAN.md`, and the full body of GitHub issue `BrokkAi/bifrost#76`.
- [x] (2026-05-18 19:31Z) Confirmed the current baseline: Python and Rust both already implement language-specific local receiver/member inference, while JS/TS still relies mostly on direct import/member matching.
- [x] (2026-05-18 19:31Z) Chose a dedicated repo-root plan file, `LOCAL_USAGE_INFERENCE_EXECPLAN.md`, because this work is broader than any single language parity plan and is the shared follow-on for issue `#76`.
- [x] (2026-05-18 20:04Z) Completed Milestone 1 by adding `src/usages/local_inference.rs`, exporting the shared API from `src/usages/mod.rs`, and adding `tests/usages_local_inference_test.rs` to prove nested scopes, shadowing, seeding, alias propagation, snapshot queries, and ambiguity-cap degradation in isolation.
- [x] (2026-05-18 20:23Z) Completed Milestone 2 by replacing Python’s `ScopeFacts` propagation path with `LocalInferenceEngine` snapshots in `src/usages/python_graph.rs` while keeping the focused Python suites green.
- [x] (2026-05-18 20:31Z) Completed Milestone 3 by moving Rust receiver-name and alias propagation in `src/usages/rust_graph.rs` onto `LocalInferenceEngine` while preserving the focused Rust member and receiver suite.
- [x] (2026-05-18 20:41Z) Completed Milestone 4 by wiring `src/usages/js_ts_graph.rs` to use `LocalInferenceEngine` for local alias propagation of imported owners and proving that slice with a focused TypeScript test.
- [x] (2026-05-18 20:58Z) Completed Milestone 5 by running the focused shared, Python, Rust, and JS/TS usage suites plus `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`, then fixing the last two `clippy` blockers in the migrated loops.

## Surprises & Discoveries

- Observation: `bifrost` already has the architectural seam this issue needs.
  Evidence: `src/usages/graph_core.rs` is shared across strategies, `src/usages/finder.rs` already routes by language, and both `src/usages/python_graph.rs` and `src/usages/rust_graph.rs` add extra logic on top of the shared graph instead of bypassing it entirely.

- Observation: Python already contains a prototype of the shared concept, but it is trapped in Python-specific code.
  Evidence: `src/usages/python_graph.rs` defines `ScopeFacts`, `collect_scope_facts`, and `collect_scope_facts_from_source`, which already model local shadows, alias propagation, and receiver facts, but only through Python-specific regex extraction and Python-specific matching rules.

- Observation: Rust already proves that local receiver/member inference is valuable even with a narrower heuristic model.
  Evidence: `src/usages/rust_graph.rs` implements `scan_files_for_member_target`, `receiver_explicitly_mismatched`, and `infer_receiver_names`, which prove member hits through typed locals, constructor-seeded locals, and aliases instead of only matching same-named method calls.

- Observation: JS/TS is the least committed to a local inference design today.
  Evidence: `src/usages/js_ts_graph.rs` proves direct identifier and member hits from import edges, but it has no reusable local binding or alias engine comparable to Python’s `ScopeFacts` path or Rust’s receiver-name inference path.

- Observation: issue `#76` is intentionally sequenced after the shared graph engine and at least one additional language proof.
  Evidence: the GitHub issue body explicitly recommends `#73`, then at least one of `#74` or `#75`, and only then the reusable local receiver/member inference extraction.

- Observation: the shared engine did not need language-specific event enums to be useful in the first milestone.
  Evidence: `src/usages/local_inference.rs` is already able to model the current proven needs with a smaller contract: nested scope entry/exit, symbol shadowing, symbol seeding, alias propagation, snapshots, and ambiguity caps; the Python and Rust migrations can emit into that contract directly.

- Observation: the first Python migration bug was a convergence bug, not a missing capability in the shared engine.
  Evidence: the initial refactor re-applied `declare_shadow` on every fixed-point pass, which kept clearing bindings and caused several Python graph tests to run indefinitely; gating shadow declaration to first sight restored the monotonic behavior of the old `ScopeFacts` loop.

- Observation: Rust did not need a broader shared API to migrate its receiver propagation.
  Evidence: the existing Rust member cases still passed once typed-local seeding, constructor seeding, parameter seeding, `let` alias propagation, and `self.field.as_ref()` receiver seeding were expressed through `LocalInferenceEngine`; the remaining Rust-specific logic stayed where it belonged in trait-owner handling and explicit mismatch checks.

- Observation: JS/TS also fit the shared engine without demanding a syntax-agnostic parser.
  Evidence: the first JS/TS adoption slice only needed per-file alias extraction plus shared scoped propagation, and `tests/usages_js_ts_graph_test.rs` now proves that an imported owner can be referenced through a local alias in TypeScript.

- Observation: the final quality gate found only narrow cleanup items, not design regressions.
  Evidence: `cargo clippy --all-targets --all-features -- -D warnings` failed only on two collapsible `if` patterns in the migrated Python and Rust loops; no additional correctness gaps were exposed by the final test and lint pass.

## Decision Log

- Decision: make this a shared extraction plan rather than appending work to `PYTHON_USAGE_GRAPH_PARITY_EXECPLAN.md` or `RUST_USAGE_GRAPH_PARITY_EXECPLAN.md`.
  Rationale: issue `#76` is cross-cutting by design, and a shared plan makes the ownership boundary explicit: the deliverable is a reusable inference layer, not just “more Python parity” or “more Rust parity.”
  Date/Author: 2026-05-18 / Codex

- Decision: migrate Python first.
  Rationale: Python already has the clearest local-fact model in `ScopeFacts`, so it offers the easiest first extraction target and the best chance to stabilize the shared contract before bringing Rust’s more specialized receiver rules into it.
  Date/Author: 2026-05-18 / Codex

- Decision: keep syntax extraction language-specific, but make propagation and ambiguity handling shared.
  Rationale: tree-sitter node shapes differ too much across languages for one scanner to own all parsing, but scope handling, alias propagation, seed tracking, receiver/member resolution, and ambiguity caps are exactly the reusable logic the issue calls for.
  Date/Author: 2026-05-18 / Codex

- Decision: treat bounded ambiguity as a first-class result in the shared layer instead of silently continuing propagation.
  Rationale: the issue explicitly asks for guardrails against false-positive fanout. The shared engine must stop or degrade when too many possible targets accumulate, otherwise extraction would just centralize the current risk rather than fixing it.
  Date/Author: 2026-05-18 / Codex

- Decision: avoid designing the shared engine around Rust-only or Python-only type concepts.
  Rationale: the issue asks for a language-neutral API. The core contract should talk about local symbols, candidate receiver targets, aliases, and member-access events, while each strategy stays responsible for mapping its own syntax or type evidence into those common terms.
  Date/Author: 2026-05-18 / Codex

- Decision: keep the first shared API value-oriented instead of event-object-heavy.
  Rationale: the first implementation only needed a deterministic scoped symbol engine with methods for `enter_scope`, `exit_scope`, `declare_shadow`, `seed_symbol`, `seed_symbol_many`, and `alias_symbol`; introducing a larger event taxonomy before the migrations would have added complexity without increasing tested behavior.
  Date/Author: 2026-05-18 / Codex

- Decision: migrate Python by preserving its existing extraction heuristics and swapping only the propagation state.
  Rationale: the goal of Milestone 2 was to remove duplicated propagation logic without broadening Python semantics in the same step; keeping the same annotation, assignment, and alias extraction patterns made the migration easier to verify against the existing focused Python suites.
  Date/Author: 2026-05-18 / Codex

- Decision: keep Rust’s type- and trait-specific interpretation at the strategy edge while moving only local symbol propagation into the shared engine.
  Rationale: Rust still needs strategy-local logic for type-alias expansion, trait implementer selection, `Self`-like constructor recognition, and explicit mismatch checks, but alias propagation and receiver-local tracking were language-neutral enough to centralize safely.
  Date/Author: 2026-05-18 / Codex

- Decision: land a narrow JS/TS adoption slice in this issue instead of only documenting the seam.
  Rationale: local alias propagation for imported owners was small enough to implement and verify now, and doing so proves the shared engine works in the third strategy without dragging the broader JS/TS parity-hardening backlog into issue `#76`.
  Date/Author: 2026-05-18 / Codex

- Decision: treat Milestone 5 as a full completion gate rather than a soft smoke test.
  Rationale: after the three strategy migrations landed, the risk was no longer isolated to one file, so the right completion bar was all focused suites plus the repo formatting and lint gates, not just a subset of the previous milestone tests.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

The full plan is now complete. Milestone 1 landed a reusable scoped symbol engine in `src/usages/local_inference.rs` plus a direct test suite in `tests/usages_local_inference_test.rs`. Milestone 2 proved that the contract could absorb Python’s old `ScopeFacts` propagation path. Milestone 3 did the same for Rust alias and receiver-local propagation while leaving Rust-specific trait and type interpretation at the strategy edge. Milestone 4 added a small JS/TS adoption slice for local alias propagation of imported owners. Milestone 5 then closed the loop with focused test coverage and repo quality-gate validation. The main lesson is that the shared contract did not need to become syntax-aware to be useful; language-specific extraction and language-neutral propagation remained a stable boundary.

## Context and Orientation

The current usage-finding entry point lives in `src/usages/finder.rs`. `UsageFinder` selects a graph strategy for JavaScript, TypeScript, Python, and Rust, then falls back to `RegexUsageAnalyzer` only when a graph strategy returns `FuzzyResult::Failure`. The shared exported-symbol graph engine lives in `src/usages/graph_core.rs`. That shared graph knows how to collect export seeds, import edges, and re-export traversal, but it does not reason about local variables inside a function or method.

That missing reasoning is the subject of this plan. A “local inference layer” means a reusable engine that can track facts inside a function or method body, such as:

- a new local symbol being declared;
- a local symbol being seeded with a candidate receiver target;
- a local symbol becoming an alias of another local symbol;
- a scope starting or ending, which determines when a local fact stops being valid; and
- a receiver/member access such as `x.run()` or `foo.bar` being resolved back to the queried owner/member.

Today, those facts are implemented separately in each strategy. In `src/usages/python_graph.rs`, `ScopeFacts` stores `receiver_facts` and `local_shadows`, then helper functions derive those facts from source text. In `src/usages/rust_graph.rs`, member scanning uses typed locals, constructor-seeded locals, alias propagation, and negative mismatch checks to prove that a receiver belongs to the queried owner. In `src/usages/js_ts_graph.rs`, direct member matching exists, but there is no shared alias or local receiver model yet.

The intended end state is not a single universal parser. The intended end state is a shared inference module under `src/usages/` that each language strategy can feed with normalized events. Each strategy should keep its own tree-sitter walk or regex extraction where needed, but once the language-specific code has emitted local events, the shared engine should handle propagation, shadowing, ambiguity caps, and the “does this receiver/member access resolve back to the target?” decision.

The most relevant current files are:

    .agent/PLANS.md
    src/usages/finder.rs
    src/usages/graph_core.rs
    src/usages/js_ts_graph.rs
    src/usages/python_graph.rs
    src/usages/rust_graph.rs
    tests/usages_python_graph_test.rs
    tests/usages_rust_graph_test.rs
    tests/usages_js_ts_graph_test.rs
    tests/common/inline_project.rs
    RUST_USAGE_GRAPH_PARITY_EXECPLAN.md
    PYTHON_USAGE_GRAPH_PARITY_EXECPLAN.md

## Plan of Work

Start by introducing a new shared module, preferably `src/usages/local_inference.rs`, plus the corresponding `mod` declaration and exports in `src/usages/mod.rs`. The module must define the language-neutral contract for local inference. At minimum, it needs stable types for scope events, symbol declarations, receiver-target seeds, alias assignments, receiver/member access queries, ambiguity limits, and the shared result shape used by strategies to ask “does this access still resolve to the target?” Keep the names plain and descriptive; do not encode Python or Rust vocabulary into the public types.

Next, implement the reusable engine inside that module. The engine should accept a stream or list of normalized local events and maintain per-scope state. It must support nested scopes, shadowing, symbol seeding, alias propagation, and bounded candidate fanout. When ambiguity grows beyond a configured limit, the engine must stop proving that symbol rather than continuing to widen guesses. Provenance should be explicit enough that a strategy can tell whether a resolved receiver came from a direct seed, an alias chain, or a scope-local declaration. The exact public API can be an incremental builder, an event consumer, or a small state machine, but the result must be deterministic, testable in isolation, and cheap enough to use inside current usage scans.

After the engine exists, migrate Python first. Replace the current `ScopeFacts`-centric logic in `src/usages/python_graph.rs` with a Python-specific extraction pass that emits normalized events into the shared engine. The Python strategy should keep its current observable behavior as closely as possible during this migration. That means preserving the current positive cases around typed locals, typed parameters, instance attributes, constructed locals, aliases, qualified annotations, and inheritance-aware receiver matching, while also preserving the current negative behavior around shadows, unknown constructors, and ambiguous unions.

Then migrate Rust. Keep Rust-specific extraction in `src/usages/rust_graph.rs`, because the current member scanner depends on Rust syntax and lightweight type conventions such as typed locals, `Self`-like constructors, and explicit mismatch checks. The change in this milestone is to push alias propagation, scope-aware local binding, and bounded receiver tracking into the shared layer. If a Rust rule cannot fit the shared contract cleanly, widen the shared contract only when the concept is language-neutral; otherwise keep that rule as Rust-side pre-processing and document why.

Finally, decide how much JS/TS wiring belongs in this issue. The minimum acceptable landing from issue `#76` is the reusable module plus at least one graph strategy wired to it, which the issue body explicitly allows. The preferred landing is to wire at least the first JS/TS slice too, so `src/usages/js_ts_graph.rs` can prove member accesses through local aliases rather than only direct imported owner names. If that turns into too much scope for this issue, keep the shared engine and Python/Rust migrations here and update the JS/TS parity-hardening issue or plan with an exact list of the remaining adoption work.

Throughout the implementation, keep the plan current. Every time a milestone lands or changes shape, update `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` so another contributor can restart from this file alone.

## Milestones

### Milestone 1: Define the shared local-inference contract and prove it in isolation

At the end of this milestone, `bifrost` will have a shared local-inference module that can be tested without going through Python, Rust, or JS/TS strategies. A contributor should be able to run focused tests for nested scopes, seed propagation, alias propagation, shadowing, receiver/member resolution, and ambiguity caps and see them pass.

Implement this by adding the new module under `src/usages/` and a focused shared test file under `tests/`, likely `tests/usages_local_inference_test.rs`. Define the minimal public API needed by later strategy integrations, then write tests that prove direct seeding, alias chains, scope exit invalidation, shadowing, and cap-triggered degradation behavior.

Acceptance is that the shared engine tests demonstrate behavior the strategies can rely on without needing a language analyzer in the loop.

### Milestone 2: Migrate Python to the shared engine without regressing current behavior

At the end of this milestone, Python member queries should continue to work, but the receiver/local propagation logic should live in the shared module instead of the Python-specific `ScopeFacts` machinery. A contributor should be able to run the focused Python usage suites and see the same positive and negative cases still pass.

Implement this by replacing `ScopeFacts`, `collect_scope_facts`, and the related local-fact derivation logic in `src/usages/python_graph.rs` with a Python-specific event extractor that feeds the shared engine. Keep existing Python-specific analyzer hooks, annotation resolution, and inheritance matching where they are unless they become clearly reusable.

Acceptance is that `tests/usages_python_graph_test.rs` and `tests/usages_python_test.rs` still prove typed local, typed parameter, instance-attribute, constructed-local, alias, and negative shadowing behavior after the migration.

### Milestone 3: Migrate Rust receiver/member propagation to the shared engine

At the end of this milestone, Rust member queries should still prove receiver-bound usages, but alias propagation and local receiver tracking should come from the shared layer. A contributor should be able to run focused Rust usage tests and see that typed-local, constructed-local, alias-propagated, and mismatch-rejected member cases still behave correctly.

Implement this by refactoring `src/usages/rust_graph.rs` so Rust-specific extraction produces shared local-inference events and then delegates alias/receiver propagation to the shared module. Keep Rust-only concepts such as trait-owner handling, `Self`-like constructor recognition, and exact mismatch evidence at the strategy edge unless a cleaner language-neutral abstraction emerges naturally.

Acceptance is that `tests/usages_rust_graph_test.rs` still proves the current Rust member and receiver cases and that the shared-engine tests have gained any extra cases Rust exposed.

### Milestone 4: Decide and land the first JS/TS adoption slice, or record the exact follow-up seam

At the end of this milestone, the repository must make the JS/TS path explicit. Either `src/usages/js_ts_graph.rs` is wired to use the shared local-inference engine for at least one meaningful alias/member scenario, or this plan and the related JS/TS follow-up work clearly describe why the wiring was deferred and exactly what remains.

Implement this by reviewing the existing JS/TS member handling and choosing the smallest high-value first slice, such as local alias propagation for imported owners or bounded local receiver tracking for direct member expressions. If this is too large for issue `#76`, document the deferred seam precisely instead of leaving “JS/TS later” as an implicit backlog.

Acceptance is that a future contributor can tell, from code and tests, whether JS/TS already uses the shared engine and what adoption work remains if it does not.

### Milestone 5: Finish validation, harden ambiguity handling, and close the issue boundary honestly

At the end of this milestone, the shared local-inference layer should be proven by isolated engine tests plus the affected language integration tests, and the remaining backlog should be explicit. A contributor should be able to run the focused usage suites and quality gates and understand whether issue `#76` is complete or whether a narrowly-scoped follow-up remains.

Implement this by tightening ambiguous-target caps, adding any missing negative tests discovered during migration, and then running the focused usage suites plus the repo quality gates. Update this document’s retrospective and issue-boundary notes so no one mistakes “shared module exists” for “all languages fully adopted it.”

Acceptance is that the shared engine has direct test proof, Python and Rust are either fully migrated or explicitly limited, JS/TS status is explicit, and the remaining work is small enough to name concretely.

## Concrete Steps

From `/Users/dave/.codex/worktrees/77f2/bifrost`:

1. Keep this document updated before and after each milestone so `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` reflect the real state.
2. Add `src/usages/local_inference.rs` and wire it through `src/usages/mod.rs`.
3. Add a focused shared-engine test file under `tests/`, preferably backed by direct engine inputs rather than a full analyzer fixture.
4. Migrate Python first by replacing the local-fact propagation path in `src/usages/python_graph.rs` with event extraction plus shared inference.
5. Migrate Rust second by refactoring local receiver propagation in `src/usages/rust_graph.rs` onto the shared engine where the concept is language-neutral.
6. Decide whether to wire the first JS/TS slice in this issue or to record a precise follow-up seam in `src/usages/js_ts_graph.rs`-related tests and plan notes.
7. Run:

       cargo fmt

8. Run the focused shared and language usage tests for the active milestone. At minimum, these suites are likely to include:

       cargo test --test usages_local_inference_test
       cargo test --test usages_python_graph_test
       cargo test --test usages_python_test
       cargo test --test usages_rust_graph_test
       cargo test --test usages_js_ts_graph_test

   Only run the suites needed for the touched code while a milestone is in progress, but by the end of the plan the full affected set must be green.

9. Once the focused tests pass, run:

       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings

10. Record the outcome, newly discovered constraints, and any exact deferred seam in this document.

## Validation and Acceptance

Validation must stay behavior-focused.

The shared engine itself must have direct unit-test proof. Those tests must show nested scopes, shadowing, alias propagation, seed propagation, receiver/member resolution, and ambiguity-cap behavior without relying on a full analyzer setup.

The Python and Rust integrations must then prove that the shared engine preserves or improves the current behavior that users actually care about: typed receiver inference, alias propagation, receiver mismatch rejection, and protection against false positives from same-named unrelated symbols.

If JS/TS is wired in this issue, the JS/TS tests must prove at least one meaningful local-alias or local-receiver case that was not previously handled. If JS/TS is not wired in this issue, the validation for this plan must still prove that the shared module is ready for JS/TS adoption and that the remaining seam is documented precisely.

Run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` after the focused tests are green. Success for this ExecPlan is not “there is a new module.” Success is that member-usage precision now depends on a reusable bounded inference layer with direct test proof and at least one migrated strategy, with the remaining adoption work stated plainly.

## Idempotence and Recovery

This plan is safe to execute incrementally. Re-running `cargo fmt`, the focused `cargo test` commands, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` is safe.

If a migration stalls midway, do not delete the evidence. Keep the focused tests that exposed the gap, update `Progress` to state exactly which parts of the strategy still depend on old logic, and continue from the smallest remaining seam. If a language-specific behavior cannot fit the shared contract without making the contract language-specific, keep that behavior at the strategy edge and record the boundary explicitly in `Decision Log` rather than over-generalizing the engine.

## Artifacts and Notes

Important local references for this plan are:

    .agent/PLANS.md
    src/usages/finder.rs
    src/usages/graph_core.rs
    src/usages/js_ts_graph.rs
    src/usages/python_graph.rs
    src/usages/rust_graph.rs
    tests/usages_python_graph_test.rs
    tests/usages_python_test.rs
    tests/usages_rust_graph_test.rs
    tests/usages_js_ts_graph_test.rs
    tests/common/inline_project.rs
    RUST_USAGE_GRAPH_PARITY_EXECPLAN.md
    PYTHON_USAGE_GRAPH_PARITY_EXECPLAN.md

The most important current evidence snapshot is:

    `bifrost` already has a shared exported-symbol graph, but local receiver/member precision is still duplicated:
    Python uses `ScopeFacts`,
    Rust uses receiver-name and mismatch heuristics,
    and JS/TS has only a narrower direct member-binding path.

That is the extraction target for issue `#76`.

## Interfaces and Dependencies

The public behavior expected at the end of this plan is:

    `UsageFinder` still routes by language exactly as it does today, but migrated strategies use a shared local-inference layer for receiver/member precision instead of separate ad hoc propagation logic.

    `src/usages/local_inference.rs` exposes the language-neutral contract for scope events, local symbol seeding, alias propagation, ambiguity caps, and receiver/member resolution.

    `src/usages/python_graph.rs` and `src/usages/rust_graph.rs` keep language-specific extraction logic, but delegate language-neutral propagation and bounded resolution to the shared module.

    `src/usages/js_ts_graph.rs` either adopts the first slice of that shared module in this issue or documents the exact next adoption seam in code and tests.

The implementation dependencies for this plan are the existing shared graph engine in `src/usages/graph_core.rs`, the strategy routing in `src/usages/finder.rs`, and the current language-specific graph scanners and analyzers that already provide export seeds and candidate files. No new external library should be necessary unless a concrete test shows the current tree-sitter and standard-library tooling cannot express the needed event extraction cleanly.

Revision note: 2026-05-18 / Codex. Created this ExecPlan from issue `#76`, the current `bifrost` usage-graph implementation, and the existing Python/Rust parity plans so the shared receiver/member inference work can proceed as a standalone staged program.

Revision note: 2026-05-18 / Codex. Updated after Milestone 1 to record the landed shared engine, its direct test proof, and the decision to keep the first shared API method-driven rather than introducing a heavier event taxonomy before the first migrations.

Revision note: 2026-05-18 / Codex. Updated after Milestone 2 to record the Python migration, the fixed-point shadowing bug it exposed, and the decision to preserve Python’s existing extraction heuristics while moving only the propagation state into the shared engine.

Revision note: 2026-05-18 / Codex. Updated after Milestone 3 to record the Rust migration, the evidence that no broader shared API was needed for Rust receiver propagation, and the decision to keep Rust-specific type and trait interpretation at the strategy edge.

Revision note: 2026-05-18 / Codex. Updated after Milestone 4 to record the landed JS/TS local-alias slice, the evidence that JS/TS could consume the shared engine without a shared parser, and the decision to land that slice now rather than only documenting it as follow-up work.

Revision note: 2026-05-18 / Codex. Updated after Milestone 5 to record the final test and lint gates, the last `clippy` cleanup, and the completion of the full issue `#76` execution plan.
