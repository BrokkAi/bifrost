# Add IDE edge-function value propagation to summary dataflow

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's query-local summary dataflow solver can currently answer which finite facts reach a program point, but a client cannot attach a reusable value transformer to a fact transition. After this change, a language-neutral client can define a finite value domain and composable edge functions, run them through the same local, call, summary, matched-return, exceptional, budget, cancellation, quality, and witness machinery, and inspect both relative jump functions and final root values.

The new capability is separately named. Existing `DistributiveDataflowProblem`, `DirectFlowProblem`, `SummaryDataflowResult`, typestate clients, and `solve_with_summaries` continue to compile and execute without allocating IDE state. The behavior is observable in a new `tests/dataflow_ide.rs` integration suite: a finite qualifier client applies constants and transforms, meets branch results deterministically, composes through a helper summary and exact return, converges through recursion, distinguishes exceptional and call-to-return paths, and agrees with an intentionally simple repeated-scan reference.

## Progress

- [x] (2026-07-26 07:52Z) Verified live issue #1172, synced the detached worktree from `257c1322` to `origin/master` at `5d228346`, and preserved the unrelated untracked `.brokk/` directory.
- [x] (2026-07-26 07:52Z) Diagnosed the current fact, summary, matched-return, budget, quality, witness, direct-flow, and typestate seams against commits `201770cd`, `3e94f809`, `c8df49d3`, and `5d228346`.
- [x] (2026-07-26 07:52Z) Chose and documented the IDE-only captured-topology/two-phase architecture and wrote this ExecPlan.
- [x] (2026-07-26 08:31Z) Milestone 1: defined the public finite value, edge-function, transition, input, result, and five IDE-specific budget contracts.
- [x] (2026-07-26 08:31Z) Milestone 2: recorded canonical IDE transfer relations through the unchanged fact summary solver and implemented the bounded jump-function fixed point.
- [x] (2026-07-26 08:31Z) Milestone 3: exposed deterministic relative jump summaries and root values, including exact call/summary/return composition and recursion reuse metrics.
- [ ] Milestone 4: the independent repeated-scan oracle and focused identity, branch, call, recursion, exceptional, call-to-return, shared-summary, cancellation, budget, seed-order, quality, and witness regressions are green; provider/callback-order coverage and final regression validation remain.
- [ ] Milestone 5: complete guided specialist review and the focused, strict Clippy, and full all-feature validation gates.

## Surprises & Discoveries

- Observation: the current Bifrost navigation plugin cannot bind this worktree even though the repository itself is healthy.
  Evidence: every indexed lookup fails because the installed plugin accepts cache schema 11 while `.brokk/bifrost_cache.db` has `user_version = 12`. The user-owned cache remains untouched; exact source, `rg`, and git history supplied the diagnosis.

- Observation: current `SummaryState` already preserves the exact topology needed by IDE without changing the semantic provider.
  Evidence: call processing owns the exact `CallTransfer`; callee paths are relative to one entry fact; `IncomingKey` identifies the caller entry, call point, input fact, and transfer index; `IcfgExitProfile::project_matched_return` returns only the matching normal or exceptional continuation.

- Observation: an IDE improvement is independent of fact reachability and path quality.
  Evidence: `publish_path_outputs` currently drops an already-reached fact/quality, but two such paths may carry different edge functions whose meet changes the jump function and must reactivate dependants. `PathQualityFrontier` therefore cannot double as the value lattice.

- Observation: the typestate client merged at `5d228346` intentionally encodes its finite state in IFDS facts.
  Evidence: `TypestateFlowProblem` still implements `DistributiveDataflowProblem`. It is a regression boundary for #1172, not a client to migrate in this slice.

- Observation: capture-time edge-function meets need their own sink limit, not only a charge after fact discovery.
  Evidence: a duplicate IDE transition can require client algebra before a relation is committed. The collector now receives the remaining operation budget and returns an atomic typed partial result before calling `meet_edge_functions`; `capture_meet_budget_stops_before_running_client_algebra` proves the client meet counter remains zero at a zero limit.

- Observation: the IDE layer can reconstruct exact call transfers without changing `SummaryState` or rematerializing the provider.
  Evidence: a captured call edge retains its call-site origin, callee entry, proof, and completeness; the immutable caller semantics supply the two continuations. Normal, exceptional, deferred call-to-return, two-caller reuse, direct recursion, and mutual recursion fixtures all resolve through the expected targets, and the repeated-scan reference agrees on recursive root values.

## Decision Log

- Decision: add a separately named `IdeDataflowProblem` rather than extending or replacing `DistributiveDataflowProblem`.
  Rationale: fact-only clients keep their public contract, result layout, callback row type, and runtime path. IDE clients explicitly opt into value and edge-function algebra.
  Date/Author: 2026-07-26 / Codex

- Decision: implement IDE as two bounded phases sharing one provider-backed summary traversal.
  Rationale: an IDE adapter runs the existing fact summary solver and records the complete canonical `(input fact, semantic edge) -> (output fact, edge function)` relation while callbacks are already being evaluated. A second IDE-only worklist operates over those captured relations and the exact reached/end-summary rows. This avoids copying the 2,600-line summary solver, does not rematerialize provider data, and adds no IDE field or branch to ordinary fact-only state.
  Date/Author: 2026-07-26 / Codex

- Decision: keep relative jump functions and final values as distinct result views.
  Rationale: a callee summary maps its own entry fact to an exit fact and must remain reusable across callers. Relative reached rows and end summaries expose jump functions. Final values are computed only for root-relative rows from explicit root seed values and are met at identical `(program point, fact)` states.
  Date/Author: 2026-07-26 / Codex

- Decision: define composition in path order: `compose(first, second)` means apply `first`, then `second`.
  Rationale: exact return replay is then written and tested as `caller jump -> call function -> callee summary function -> matched-return function`, avoiding ambiguous mathematical notation.
  Date/Author: 2026-07-26 / Codex

- Decision: intern client edge functions and values at the IDE boundary and use dense query-local IDs in hot tables.
  Rationale: clients may use structurally large finite lookup tables. The solver clones at most once per unique interned value/function and otherwise queues compact IDs; finalization sorts and remaps IDs so public results do not depend on callback or provider order.
  Date/Author: 2026-07-26 / Codex

- Decision: keep quality and witness behavior owned by the underlying fact result.
  Rationale: proof/completeness describes semantic evidence, not a client lattice. Witness retention remains opt-in and best-effort exactly as it is today; IDE edge functions neither depend on nor disappear with witness storage.
  Date/Author: 2026-07-26 / Codex

## Outcomes & Retrospective

Milestones 1 through 3 are implemented. Ordinary fact-only code remains unchanged apart from the additive work-dimension definition and its exhaustive test match. IDE clients opt into `IdeDataflowProblem` and receive an owned `IdeSummaryDataflowResult` containing the original fact result, deterministic function/value arenas, relative reached/end-summary jump functions, root point values, and IDE-only metrics.

The optimized layer currently passes 16 source-backed focused test cases (including the shared harness tests). The proving qualifier client demonstrates local identity, two-way branch meet under reversed source layout, exact normal and exceptional returns, explicit deferred call-to-return, two-caller summary reuse, cancellation during client composition, atomic exhaustion of all five IDE dimensions, capture-time algebra gating, deterministic duplicate seed meet, and witness independence. Direct and mutual recursion agree with an independent provider-backed repeated-scan oracle.

Focused strict Clippy (`cargo clippy --test dataflow_ide --no-default-features -- -D warnings`) is green. Milestone 4 still needs final order-perturbation/regression confirmation, and Milestone 5 still needs the required specialist review, strict all-feature Clippy, and full all-feature tests.

## Context and Orientation

`src/analyzer/dataflow/problem.rs` defines `DataflowEdge`, `DataflowOutput`, and the fact-only `DistributiveDataflowProblem`. A fact is a small finite client identity such as an abstract memory location. Each callback maps one input fact to zero or more output facts for one of five semantic edge families: ordinary local flow, call, matched return, explicit call-to-return, and exceptional local flow.

`src/analyzer/dataflow/summary.rs` is the optimized provider-backed fact solver. A `PathEdgeKey` means that one fact reaches one program point relative to a particular procedure entry fact. Callee entry paths deliberately start relative to the callee, while `IncomingCall` retains the exact caller prefix. `EndSummaryRow` records a relative entry-to-exit fact relation. `apply_summary` combines one incoming call, one matching callee end summary, and one exact matched-return projection before publishing back into the caller entry. The iterative worklist, not recursive Rust calls or a call-depth bound, converges direct and mutual recursion.

`src/analyzer/dataflow/summary_result.rs` owns deterministic public fact rows, end summaries, semantic coverage, termination, work, cache metrics, and optional witnesses. `src/analyzer/dataflow/quality.rs` owns the independent proof/completeness frontier. `src/analyzer/dataflow/budget.rs` owns atomic request-local work dimensions. `src/analyzer/dataflow/direct.rs` is the simplest fact-only regression client.

An IDE, or Interprocedural Distributive Environment, adds a finite client value to the exploded fact graph. An edge function transforms a value along one fact transition. A jump function is the composition of edge functions from one relative procedure entry to one reached fact. When two paths reach the same state, their jump functions meet pointwise. A procedure end summary is therefore a reusable entry-to-exit jump function, not one caller-specific concrete value.

The new IDE layer will call the existing summary solver through a private adapter. The adapter projects each `(output fact, edge function)` transition to its output fact for reachability while retaining the full canonical transition in an IDE-only trace. When fact discovery reaches a fixed point, the trace and the deterministic fact result define a finite graph of direct relations plus summary-application relations. A direct relation depends on one source jump. A summary application depends on the caller jump and the callee exit jump; it composes the call, relative callee summary, and exact return functions without crossing callers.

`tests/common/dataflow_summary_reference.rs` is the precedent for an intentionally simple repeated-scan oracle. A new IDE reference will independently rescan relative paths, incoming calls, and end summaries until no met function changes. `tests/dataflow_summaries.rs` already provides source-backed patterns for recursion, shared callees, normal and exceptional returns, explicit call-to-return flow, exact budgets, witness/quality behavior, and order permutations.

## Plan of Work

Milestone 1 defines contracts and budgets without changing ordinary propagation. Create `src/analyzer/dataflow/ide.rs` and `src/analyzer/dataflow/ide_result.rs`. `IdeDataflowProblem` owns associated `Fact`, `Value`, and `EdgeFunction` types; a distinguished zero fact and zero value; identity, composition, application, value meet, and pointwise edge-function meet operations; and the five callbacks emitting `IdeTransition<Fact, EdgeFunction>`. Document the algebra and finite-convergence requirements. `IdeSummarySolveInput` holds a root, explicit fact/value seeds, and optional witness retention. Duplicate seed facts meet their values; the zero fact/value is always implicit.

Define dense result-local edge-function and value IDs, deterministic root point-value rows, relative reached jump rows, relative end-summary jump rows, IDE metrics, and `IdeSummaryDataflowResult`. The IDE result owns the ordinary `SummaryDataflowResult` so coverage, quality, termination, facts, and witnesses remain available. Add IDE-specific malformed-input/invariant errors.

Extend `SolverWork` and `SolverBudgetDimension` with independently reported bounds for retained IDE relations, unique edge functions, edge-function algebra operations, unique values, and value algebra operations. Preserve atomic reserve semantics and update exhaustive test helpers. At the end of Milestone 1, contract tests prove algebra direction, zero-seed behavior, invalid/zero limits where applicable, distinct budget labels, and unchanged compilation of direct/fact-only clients.

Milestone 2 implements captured topology and jump convergence. Add a private fact adapter implementing `DistributiveDataflowProblem` for any `IdeDataflowProblem`. Each callback uses an IDE output collector that cooperatively observes the fact solver's cancellation/output signal, canonicalizes output facts, meets duplicate edge functions for the same output fact, adds the implicit zero/identity transition, and records one complete relation keyed by owned semantic edge plus input fact. Repeated callback evaluation reuses the recorded relation. Trace retention is limited before publication; exhaustion becomes an outer `IdeRelations` budget termination and never claims a fixed point.

After `solve_with_summaries` completes, skip IDE finalization if fact discovery was cancelled or budget-stopped. Otherwise build deterministic direct and summary-application rows from the trace and the fact result. Ordinary, exceptional, and explicit call-to-return rows stay within one relative entry. Call rows reconstruct the exact `CallTransfer` from the source call handle, callee entry, continuations, proof, and completeness already present in the semantic handles. Each matching `TabulationEndSummary` uses `IcfgExitProfile::project_matched_return`; absent or boundary projections publish no returned relation. The resulting hyperedge identifies its caller source, callee exit summary source, call function, exact return function, and caller target.

Seed every relative entry row with identity. Use an iterative queue indexed by reached-row IDs. A direct dependency composes its source jump with one edge function. A summary dependency composes caller jump, call function, callee exit jump, and return function in path order. At an identical target row, meet the candidate with the retained jump and enqueue the target only if the function changes. Index summary dependencies from both inputs so direct and mutual recursion converge through deltas. Cache composition and meet by dense function IDs and charge every cache miss and publication before mutation.

Milestone 3 finalizes deterministic public results. Sort unique functions and remap dense IDs independently of discovery order. Zip every base reached row and end summary with its relative jump function. Apply root-relative jump functions to the seed value associated with their exact entry fact, meet values at identical root `(point, fact)` rows, intern the resulting values, and retain the fact result's path-quality frontier separately. Partial IDE results expose only atomically published functions/values and keep the outer termination authoritative.

Add `IdeMetrics` counters for captured/direct/summary relations, jump updates, algebra cache hits/misses, summary-function applications, and repeated reuse of one relative end-summary function. Two callers of one helper must increment reuse without creating caller-specific callee summaries.

Milestone 4 adds independent validation. Create `tests/common/dataflow_ide_reference.rs` with an obviously simple repeated-scan fixed point over owned facts/functions and direct provider calls. It must not use production jump tables, dense IDs, caches, or worklists. Create `tests/dataflow_ide.rs` with a small finite qualifier lattice and complete lookup-table edge functions. The lookup table makes identity, constant/transform functions, composition, pointwise meet, equality, and application closed and directly comparable.

Focused fixtures prove local transformation and branch meet, one helper call with call/callee/return composition, shared summary reuse without cross-return, direct and mutual recursion with multiple improvement waves, normal and exceptional return separation, explicit call-to-return flow, callback/provider/seed permutations, path-quality preservation, witness independence, cancellation, each new budget dimension, and agreement with the reference. Existing `dataflow_clients`, `dataflow_tabulation`, `dataflow_summaries`, and `typestate_client` suites guard the fact-only boundary. Extend `tests/measure_dataflow_lifecycle.rs` only if a stable focused assertion can demonstrate that ordinary `solve_with_summaries` allocates no IDE trace; do not turn the decision-grade ignored benchmark into a brittle timing test.

Milestone 5 performs the guided review required by the issue workflow. Review the complete diff for security, duplication, issue intent/correctness, operational boundedness, and architecture. Fix every accepted critical/high issue and all lower findings that affect algebra correctness, determinism, cancellation, atomic budgets, stack safety, exact return matching, or disabled-path overhead. Run focused suites throughout, then strict all-feature Clippy through the isolated-target helper and the complete `cargo test --features nlp,python` matrix.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/1567272f-591e-48f6-a60c-6e761010a5ba/bifrost`.

Inspect the exact state before and after each milestone:

    git status --short --branch
    git diff --check

Run formatting and focused tests during development:

    cargo fmt --all -- --check
    cargo test --features nlp,python --test dataflow_clients --test dataflow_tabulation --test dataflow_summaries --test dataflow_ide --test typestate_client

Run the strict lint gate through the repository cleanup helper:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Run the complete feature-enabled matrix before the final review checkpoint:

    cargo test --features nlp,python

The worktree is currently detached because the user requested a sync to `origin/master` and repository rules prohibit creating or switching branches without an explicit request. Milestone commits are allowed by the repository's ExecPlan exception and remain reachable through this worktree's detached `HEAD`; stage only files named by the completed milestone and never use `git add -A`. Do not push or open a pull request unless the user explicitly asks.

## Validation and Acceptance

The implementation is accepted when a finite proving client emits fact/function transitions over the same `IcfgProvider` used by fact-only summary tabulation and obtains a fixed-point IDE result with deterministic root values, relative reached jump functions, and reusable entry-to-exit functions.

A local transform followed by another transform applies in documented path order. A constant edge function overrides its input. Two branches reaching the same root `(point, fact)` meet to the same value under reversed edge, callback, seed, and provider order.

A helper call composes the caller jump, call function, callee-relative summary function, and matching return function. Two callers reuse one callee summary, resume only at their own normal or exceptional continuation, and increment a public summary-reuse metric.

Direct and mutual recursion terminate through an iterative fixed point. A fixture requiring more than one function improvement wave reaches the same functions and root values as the repeated-scan reference without a synthetic call-depth boundary or recursive Rust traversal.

Normal return, exceptional return, and explicit call-to-return edges invoke and compose the correct callback family. No exceptional exit returns to a normal continuation or a different call site. A call-to-return path does not claim the callee body ran.

Cancellation and each applicable fact, semantic, IDE relation, function, operation, value, and witness budget return distinguishable incomplete outcomes. No partial result reports a fixed point, and every exposed dense ID resolves inside its owning result.

`PathQualityFrontier`, semantic coverage, and optional witnesses remain byte-for-byte/equality independent of client values. Witness truncation cannot change a jump function or root value. IDE value meet cannot upgrade proof or completeness.

Ordinary `solve_with_summaries`, `DistributiveDataflowProblem`, `DirectFlowProblem`, and the merged typestate client require no IDE types and allocate no IDE trace, function arena, value arena, or IDE worklist. Their focused regression suites remain unchanged and green.

The optimized IDE result agrees with the intentionally simple reference on every focused finite fixture. Formatting, focused all-feature tests, strict Clippy, and the complete all-feature test suite pass.

## Idempotence and Recovery

All edits are ordinary Rust, tests, and this plan. Cargo commands are safe to rerun. Use `scripts/with-isolated-cargo-target.sh` for isolated Clippy artifacts and do not create manually named `/tmp/bifrost-*` targets.

If a callback or algebra operation cancels midway, discard the staged transition, function, value, graph relation, or jump update and return the outer typed partial result. If the captured IDE trace overflows, do not attempt a value fixed point from missing transitions. If final ID sorting/remapping fails an invariant, return `IdeDataflowError` rather than exposing unresolved IDs.

Do not delete, replace, migrate, or stage `.brokk/bifrost_cache.db`; it belongs to the user and currently demonstrates a plugin/cache schema compatibility issue. Use exact source and `rg` until a compatible Bifrost plugin is available.

## Artifacts and Notes

Live issue #1172 names `problem.rs`, `summary.rs`, `summary_result.rs`, `direct.rs`, the two existing dataflow references, and the lifecycle benchmark. It explicitly excludes typestate compilation, taint policy, heap/value oracles, SMT, RQL, persistence, and WPDS/SPDS extensions.

The critical composition relation is:

    target_jump = meet(
        retained_target_jump,
        compose(caller_jump, call_function, callee_end_jump, return_function),
    )

The critical separation is:

    fact reachability and PathQualityFrontier
        remain in SummaryDataflowResult

    relative jump functions and root values
        live only in IdeSummaryDataflowResult

The Bifrost MCP compatibility failure should be reported separately after implementation or sooner if the user asks. It is not a reason to weaken code navigation or modify the cache.

## Interfaces and Dependencies

`src/analyzer/dataflow/ide.rs` must define a contract equivalent to:

    pub struct IdeTransition<Fact, EdgeFunction> { ... }

    pub struct IdeDataflowSeed<Fact, Value> { ... }

    pub trait IdeDataflowProblem {
        type Fact: Copy + Eq + Hash + Ord;
        type Value: Clone + Eq + Hash + Ord;
        type EdgeFunction: Clone + Eq + Hash + Ord;

        fn zero_fact(&self) -> Self::Fact;
        fn zero_value(&self) -> Self::Value;
        fn identity_edge_function(&self) -> Self::EdgeFunction;
        fn meet_values(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
        fn compose_edge_functions(
            &self,
            first: &Self::EdgeFunction,
            second: &Self::EdgeFunction,
        ) -> Self::EdgeFunction;
        fn apply_edge_function(
            &self,
            function: &Self::EdgeFunction,
            value: &Self::Value,
        ) -> Self::Value;
        fn meet_edge_functions(
            &self,
            left: &Self::EdgeFunction,
            right: &Self::EdgeFunction,
        ) -> Self::EdgeFunction;

        // normal, call, return, call-to-return, and exceptional callbacks
        // emit IdeTransition<Self::Fact, Self::EdgeFunction> rows.
    }

The documented algebra requires value and edge-function meet to be associative, commutative, and idempotent; composition to be associative with the declared identity; application to respect path-order composition; pointwise function meet to agree with value meet; and the closure reachable from one finite request to stabilize. Incorrect client algebra may exhaust an explicit operation budget but can never be reported as a fixed point.

`IdeSummarySolveInput` must accept a root and borrowed `IdeDataflowSeed` rows, add the zero fact/value implicitly, canonicalize duplicate seed facts with value meet, and expose the existing witness-retention builder.

`IdeSummaryDataflowResult` must provide the authoritative outer termination/work/semantic-work/metrics, borrow or own the underlying fact result, iterate relative reached and end-summary jump functions, resolve result-local function/value IDs, expose deterministic root point values, and delegate coverage/fact/witness access without reinterpreting path quality.

Use only existing standard-library collections, `crate::hash::{HashMap, HashSet}`, dense-ID helpers, semantic handles, work-budget helpers, and dataflow result types. Do not add dependencies, source-text parsing, recursion, policy types, typestate branches, taint branches, or persisted summaries.

Revision note, 2026-07-26 07:52Z: Initial plan written after live issue verification, remote sync, code/history diagnosis, and explicit comparison of a generic-core refactor with an IDE-only captured-topology phase. The selected design preserves the fact-only kernel and avoids a second provider traversal while still giving jump functions their own monotone fixed point.
