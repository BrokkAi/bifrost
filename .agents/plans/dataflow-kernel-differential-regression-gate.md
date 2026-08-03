# Add a deterministic differential regression gate for the shared data-flow kernel

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost has three production views over the shared distributive data-flow kernel: bounded snapshot tabulation computes reachable facts, interprocedural summary tabulation computes reusable entry-to-exit relations, and IDE tabulation additionally computes edge functions and values. Each view already has an intentionally simple repeated-scan reference implementation under `tests/common`, but the current tests compare selected hand-written language fixtures rather than one deterministic, bounded family of language-neutral graphs.

After this change, the consolidated semantic test suite will enumerate a small named inventory of synthetic interprocedural control-flow graphs (ICFGs), solve every supported scenario through production and the existing independent reference implementation, and apply deterministic metamorphic mutations that preserve semantics while perturbing discovery order. The focused tests will demonstrate that reachability, summary relations, and IDE values are stable across repeated runs, seed and edge permutations, fact interning changes, worklist discovery changes, witness retention, and reusable-summary replay. Exact low budgets will demonstrate typed incomplete termination and will never be accepted as a clean negative.

## Progress

- [x] (2026-08-03 08:20Z) Fetched `origin/master`, verified detached `HEAD` `fbad832bfd6856f4280a5b91a310864250243989` exactly matches it, and confirmed the worktree had no pre-existing changes.
- [x] (2026-08-03 08:31Z) Read `.agents/PLANS.md`, the three reference implementations, the three focused production test modules, and the production tabulation, summary, IDE, budget, result, witness, and ICFG interfaces relevant to the gate.
- [x] (2026-08-03 08:40Z) Chose a shared synthetic scenario vocabulary and normalized projection contract; record the detailed decision below.
- [x] (2026-08-03 07:05Z) Ran the unchanged focused baseline: tabulation 7 passed, summaries 28 passed, and IDE 20 passed.
- [x] (2026-08-03 07:18Z) Added the shared eight-scenario synthetic fixture/provider and a validated public `IcfgSnapshot::try_from_parts` construction seam that preserves caller-controlled within-source edge order.
- [x] (2026-08-03 07:31Z) Added the differential and metamorphic gates to all three focused modules, including reusable-summary, witness, repetition, multiple fact/seed, and exact budget assertions.
- [x] (2026-08-03 07:34Z) Investigated two comparison mismatches. Both minimized to fixture-contract mistakes before any production change: one IDE variant changed the transfer relation instead of only callback order, and one legacy summary provider intentionally supplied a partial relation. No solver defect was found.
- [x] (2026-08-03 07:43Z) Completed focused tests, formatting, focused strict Clippy, `git diff --check`, and the Bifrost repository policy selection. Reviewed all policy findings against the changed paths; none apply to changed files. All files remain unstaged and uncommitted.

## Surprises & Discoveries

- Observation: The current modules already contain isolated reference comparisons for call/return edges, loops, direct and mutual recursion, exceptional returns, output permutations, witness retention, and reusable summaries. The missing protection is a common finite inventory and a common mutation matrix, not another oracle.
  Evidence: `tests/suite_semantic/dataflow_tabulation.rs` has `assert_matches_reference`; `tests/suite_semantic/dataflow_summaries.rs` compares `reached_projection`; and `tests/suite_semantic/dataflow_ide.rs` compares point values, reached jump functions, and summary functions.

- Observation: `IcfgSnapshot` exposes traversal but not construction. Source-backed fixtures therefore cannot independently permute a language-neutral graph's edge rows or dense node assignment.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic/icfg.rs` keeps all six snapshot fields private and only `SnapshotBuilder::freeze` constructs them.

- Observation: The simple reference implementations repeatedly scan sets until no rows change and do not share the production worklist or production fact interner. They are suitable differential oracles provided the new tests compare semantic projections and do not copy production queue logic into test support.
  Evidence: `reference_solve`, `reference_summary_projection`, and `reference_ide_projection` each maintain their own reached sets/maps and repeated-scan convergence.

- Observation: One combined Bifrost source-intelligence request took about 50 seconds and returned a truncated response whose original size was reported as roughly 205,884 tokens.
  Evidence: The call combined `get_summaries` for the six requested files, `search_symbols` for broad solver terms, and `most_relevant_files`; it exceeded the repository's five-second latency threshold and the response budget.

- Observation: Synthetic semantic artifacts cannot use `Language::None`, even when their IR is entirely language-neutral, because artifact validation requires an analyzable language identity.
  Evidence: The first fixture construction failed validation until the artifact used `Language::Rust` solely as an identity carrier; graph topology and solver behavior remain source-language independent.

- Observation: Reversing IDE transition rows is only semantics-preserving when the same multiset of transitions is emitted in every variant. Adding a duplicate `Top` transition in only the discovery-order variant legitimately changed the meet result.
  Evidence: Production and `reference_ide_projection` agreed on both results, while the cross-variant equality failed. Emitting the duplicate transition in every variant and reversing only its order restored the intended metamorphic contract.

- Observation: The pre-existing fixed reusable-summary provider is deliberately partial and therefore is not an equivalent-summary oracle for an entire root solve.
  Evidence: Cached and fresh results differed only outside the provider's one advertised observation. The new regression extracts every complete callee summary relation from a fresh solve before comparing reuse, fresh solve, and reference.

- Observation: The default `rustc` and `clippy-driver` on this host report the same Rust release but were built against LLVM 22.1.2 and 22.1.6 respectively, causing E0514 before linting.
  Evidence: Running the focused isolated-target Clippy command with `RUSTC=/opt/homebrew/bin/rustc` paired the Homebrew compiler with its Clippy driver; the first real lint found one type-complexity issue, which was fixed with a named result struct, and the strict rerun passed.

## Decision Log

- Decision: Use a checked-in deterministic scenario list rather than generated random graphs or a property-testing crate.
  Rationale: The requested shapes fit in a small explicit inventory, stable scenario names make failures actionable, and a fixed list keeps runtime and budget assertions reproducible.
  Date/Author: 2026-08-03 / Codex

- Decision: Put shared synthetic semantic construction, provider behavior, scenario names, fact labels, and normalization helpers in `tests/common/dataflow_regression.rs`; keep solver-specific algebra and assertions in the three requested test modules.
  Rationale: Graph topology and call/return contracts should be authored once, while IFDS facts, IDE lattices, reusable-summary extraction, and public result completeness remain owned by their respective test modules. This avoids both source-language branches and an oracle that duplicates the production algorithm.
  Date/Author: 2026-08-03 / Codex

- Decision: The fixed scenario inventory is `straight_line`, `diamond_join`, `loop`, `nested_call`, `matched_return`, `recursive_scc`, `exceptional_return`, and `cleanup`. Intraprocedural snapshot tabulation uses every shape representable as an edge-kind graph. Summary and IDE tabulation use procedure-local semantics plus a deterministic provider for all interprocedural shapes. Unsupported combinations are explicit in the scenario metadata rather than silently skipped.
  Rationale: These names map one-to-one to the requested coverage and ensure any mismatch is already minimized to a bounded fixture. A scenario should contain no more than a few procedures, facts, calls, and points.
  Date/Author: 2026-08-03 / Codex

- Decision: Compare normalized semantic projections, never internal dense IDs, fact IDs, insertion order, work counters, or witness arena IDs. Snapshot reachability projects to `(scenario point label, fact label)`. Summary reachability projects to `(procedure label, point label, fact label)`. IDE additionally compares normalized point values, reached jump functions, and end-summary jump functions using the existing reference key contracts.
  Rationale: Metamorphic variants deliberately perturb dense node assignment and fact interning. Only meaning, not allocation history, is invariant. Work counters are tested separately only where an exact low budget identifies the typed exhausted dimension.
  Date/Author: 2026-08-03 / Codex

- Decision: A fresh production solve and an equivalent reusable-summary solve must match the same reference projection. Witness-disabled and witness-enabled solves must match in reachability and IDE values, while witness-specific assertions only check that enabled evidence reconstructs.
  Rationale: Summary reuse and witness retention are optimizations/evidence features, not alternate reachability semantics.
  Date/Author: 2026-08-03 / Codex

- Decision: Do not modify solver behavior on the first mismatch. First add or split out a test named `regression_<scenario>_<property>` containing only the minimal graph, facts, mutation, and projection needed to reproduce it; then diagnose and fix the production root cause.
  Rationale: This preserves the independent oracle as evidence and prevents broad harness changes from hiding a concrete defect.
  Date/Author: 2026-08-03 / Codex

- Decision: Do not commit milestones despite the normal ExecPlan checkpoint convention.
  Rationale: The user explicitly prohibited commit, push, and PR actions for this task, which overrides the plan convention.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The gate now covers eight named scenarios: straight line, diamond/join, loop, nested call, matched return, recursive SCC, exceptional return, and cleanup. The direct and summary matrices run five representations (baseline plus seed, edge, fact-interning, and combined worklist-discovery mutations); IDE runs the four applicable representations because IDE's test algebra has no independently interned fact domain. Every case has multiple seeds and facts, repeats an identical solve, and compares normalized semantic projections with the existing repeated-scan reference implementation.

The contract deliberately excludes dense node IDs, fact IDs, insertion order, work counters, and witness arena IDs. Tabulation compares reachable `(point, fact)` rows. Summary comparison includes procedure-relative reachable rows. IDE compares materialized point values, reached jump functions, and end-summary functions. Witness on/off must preserve those projections. Complete extracted reusable callee summaries must produce the same root projection as a fresh solve and the reference.

The matrix catches order-sensitive queueing or deduplication, unstable fact interning, lost join/loop propagation, call/return mismatch, SCC non-convergence, exceptional/cleanup edge omissions, witness-induced semantic changes, stale or incomplete reusable-summary publication, nondeterministic repeated fixed points, and budget exhaustion reported as a clean result. Exact low-budget regressions exhaust `PropagatedOutputs` for direct and summary tabulation and `IdePropagations` for IDE; each returns typed incomplete evidence and only asserts that its partial projection is a subset of the complete result.

No production solver defect was found. The two mismatches encountered were minimized to fixture-contract errors described above and fixed without changing solver behavior. The only production change is the general validated snapshot-construction API and reuse of it by `SnapshotBuilder::freeze`.

Final validation: tabulation 9 passed, summaries 31 passed, IDE 22 passed; `cargo fmt --all -- --check` passed; `RUSTC=/opt/homebrew/bin/rustc scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost --test suite_semantic --no-default-features -- -D warnings` passed; and `git diff --check` passed. `bifrost.code-smells` completed all 12 policies and reported repository-wide pre-existing findings, but zero findings reference any changed file.

## Context and Orientation

An interprocedural control-flow graph, abbreviated ICFG, is a directed graph whose nodes are program points and whose edge kinds distinguish ordinary local control flow, calls, matched normal or exceptional returns, and modeled call-to-return bypasses. `crates/bifrost-analysis/src/analyzer/semantic/icfg.rs` owns the language-neutral ICFG types. `crates/bifrost-analysis/src/analyzer/dataflow/tabulation.rs` runs a finite distributive may-analysis over a bounded `IcfgSnapshot`. `crates/bifrost-analysis/src/analyzer/dataflow/summary.rs` tabulates procedure-relative path edges and entry-to-exit summaries directly from immutable procedure semantics and an `IcfgProvider`. `crates/bifrost-analysis/src/analyzer/dataflow/ide.rs` layers edge-function composition, meet, and value materialization on the summary result.

The three independent test oracles are `tests/common/dataflow_reference.rs`, `tests/common/dataflow_summary_reference.rs`, and `tests/common/dataflow_ide_reference.rs`. They intentionally use straightforward repeated scanning. They are not production implementations and must remain unchanged except for narrowly necessary projection conveniences. The focused integration modules are `tests/suite_semantic/dataflow_tabulation.rs`, `tests/suite_semantic/dataflow_summaries.rs`, and `tests/suite_semantic/dataflow_ide.rs`; they compile inside the consolidated `suite_semantic` harness declared by `tests/suite_semantic/main.rs`.

A metamorphic mutation changes representation or discovery order without changing the graph's meaning. The gate will use explicit variants for seed emission order, edge-row order, fact ordering/interning, and worklist discovery order. Every variant is normalized back to stable scenario, procedure, point, fact, value, and function labels before comparison. Repeated runs execute the identical variant more than once to catch hidden mutable state or nondeterministic iteration.

A generous budget is one whose per-dimension limits are deliberately far above this bounded family's maximum work. Every generous run must reach `SolverTermination::FixedPoint` and equal its reference. A low-budget case sets one exact public solver dimension just below the measured complete requirement, reruns the same fixed scenario, and requires `SolverTermination::ExceededBudget` with that dimension. Its result must report incomplete coverage; an absent target fact in that result is not asserted as a clean negative.

## Plan of Work

First run each existing module unchanged to establish that `origin/master` is green in this environment. Record test counts and any environmental failure in this plan.

Next add `tests/common/dataflow_regression.rs`. It will construct a synthetic `SemanticArtifact` from public immutable semantic IR parts: stable locators, one proven complete evidence row, basic blocks, program points, local control edges, and call-site rows. It will expose a deterministic provider whose `call_transfers` returns the exact declared call relation for the selected scenario and whose default exit-profile behavior derives normal or exceptional exit evidence from those procedure-local semantics. Scenario metadata will expose readable procedure and point labels so every solver result can be normalized without comparing dense IDs. The same file will build bounded snapshot views for the intraprocedural solver.

If a general snapshot-construction API is necessary, add the smallest validated constructor to `IcfgNodeKey` and `IcfgSnapshot` in `crates/bifrost-analysis/src/analyzer/semantic/icfg.rs`. It must validate node endpoints, preserve caller-supplied within-source edge order for metamorphic coverage, compute outgoing and incoming compact adjacency indexes iteratively, reject invalid endpoints with `SemanticProviderError`, and remain useful to third-party `IcfgProvider` implementations rather than being named as a test hook. Reuse the existing frozen-edge validation and compact-index logic instead of copying it.

Then extend `dataflow_tabulation.rs` with one matrix test over the supported named snapshot shapes. A small problem will emit at least two nonzero facts from at least two seeds. Variants will reverse seed callbacks, reorder equivalent outgoing edges, and remap the stable fact labels to different `Ord` ranks so production fact IDs and queue discovery order differ. Each complete production projection must equal `reference_solve`, equal all other variants, and equal repeated identical runs. A separate exact low-budget test will prove typed incomplete termination and avoid any negative assertion on facts beyond the published prefix.

Extend `dataflow_summaries.rs` with the interprocedural scenario matrix. It will compare `SummaryDataflowResult` reachability to `reference_summary_projection`, compare witness-off to witness-on, repeat solves, reverse provider transfer rows and local edge rows where valid, and alter fact rank and seed order. For a representative nested/shared-callee scenario, extract complete reusable procedure summaries from a fresh solve, serve them through `ReusableSummaryProvider`, and require the reusable solve to equal both the fresh solve and reference. Add an exact low-budget assertion against a named solver dimension and require incomplete result semantics.

Extend `dataflow_ide.rs` with the same interprocedural inventory and mutations using a finite closed value lattice and edge-function table. Compare all three existing reference projections: point values, reached jump functions, and end-summary jump functions. Extract equivalent reusable IDE summaries from a fresh solve and require cached/fresh/reference equality. Run witnesses enabled and disabled and compare reachability and all IDE values/functions. Add an exact IDE-specific low-budget assertion that returns a typed partial result without publishing a clean negative.

If a mismatch occurs, stop the broad change at that point, copy the smallest failing scenario into one explicitly named regression test, and confirm it fails without any production solver modification. Only then change the production root cause and retain both the minimized regression and bounded family coverage.

Finally run formatting, the three focused modules, focused strict Clippy for the consolidated semantic test target and changed library target without NLP, `git diff --check`, and the repository policy gate. Review the complete diff against `origin/master`, update this plan with exact results, and leave all changes unstaged and uncommitted.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/0876/bifrost`.

Establish the baseline:

    cargo test --test suite_semantic -- dataflow_tabulation::
    cargo test --test suite_semantic -- dataflow_summaries::
    cargo test --test suite_semantic -- dataflow_ide::

After each implementation increment, rerun the affected command above. At final validation run:

    cargo test --test suite_semantic -- dataflow_tabulation::
    cargo test --test suite_semantic -- dataflow_summaries::
    cargo test --test suite_semantic -- dataflow_ide::
    cargo fmt --all -- --check
    cargo clippy --workspace --test suite_semantic --no-default-features -- -D warnings
    git diff --check

The focused Clippy command deliberately excludes `nlp` because this task only changes the language-neutral data-flow kernel and its tests. If Cargo does not accept the selected test target with `--workspace`, use the equivalent package-qualified command discovered from `cargo metadata` and record the exact replacement here.

Before completion, call Bifrost `list_policies`, discover any executable repository policy roots named by repository guidance, and issue one `run_policy` request selecting `bifrost.code-smells` plus those roots with evaluation date `2026-08-03` and `fail_on: warning`. A `finding` requires review or repair. An `unreliable` result is a failed validation, not a clean gate.

## Validation and Acceptance

The gate is accepted when all eight named scenarios are represented, with unsupported solver/scenario combinations explicitly documented. Every supported generous production run reaches a fixed point and matches the appropriate existing reference projection. The mutation matrix proves semantic equality across seed emission, edge rows, fact ranking/interning, worklist discovery, and repeated execution. At least one scenario uses multiple seeds and multiple nonzero facts.

Fresh and reusable summary solves have equal normalized reachability. Fresh and reusable IDE solves have equal normalized point values, reached functions, and summary functions. Enabling witness retention changes only evidence availability and witness-related work; normalized reachability and IDE results remain equal.

Each low-budget regression names the exact exhausted `SolverBudgetDimension`, terminates without hanging, reports incomplete termination/coverage, and does not treat absence from the partial result as a proven negative. The three focused modules, formatting check, focused strict Clippy, and whitespace check pass. The Bifrost policy result is clean, or any unreliable result/finding is reported exactly without being called green.

## Idempotence and Recovery

All scenarios use immutable in-memory fixtures and deterministic IDs. Repeating tests creates no persistent cache and does not depend on source-language lowering. No command stages, commits, pushes, or publishes. If a test process is interrupted, rerun the same focused command. If a low-budget threshold changes because legitimate solver work accounting changes, recompute it from the same scenario's generous run and retain the assertion that the constrained limit is exactly one less than the named completed dimension.

If snapshot construction validation fails, fix the synthetic graph definition rather than weakening validation. If a reference comparison exhausts `SemanticBudget`, raise only the test's generous semantic budget because the scenario family is finite and tiny. Never replace the reference comparison with production-derived expected rows.

## Artifacts and Notes

The initial repository state was:

    ## HEAD (no branch)
    HEAD = fbad832bfd6856f4280a5b91a310864250243989
    origin/master = fbad832bfd6856f4280a5b91a310864250243989
    left/right count = 0 0
    BIFROST_MCP_RMCP=on

Final focused counts are 9 tabulation tests, 31 summary tests, and 22 IDE tests. The policy run completed all 12 built-in `bifrost.code-smells` rules; the report status was `finding`, with no finding in any changed file. The working tree contains only the seven intended modified or new paths and remains unstaged.

## Interfaces and Dependencies

No new dependency is permitted. The test family uses only the standard library, `brokk_bifrost` public semantic/data-flow APIs, and existing common test support.

`tests/common/dataflow_regression.rs` will expose scenario and mutation types with stable labels, a synthetic artifact/provider constructor, snapshot construction, and normalization helpers needed by more than one focused module. It must not contain a solver, repeated-scan algorithm, or copied production transfer logic.

If required, `crates/bifrost-analysis/src/analyzer/semantic/icfg.rs` will expose validated constructors conceptually equivalent to:

    impl IcfgNodeKey {
        pub fn new(point: ProgramPointHandle, call_context: impl Into<Box<[CallSiteHandle]>>) -> Self;
    }

    impl IcfgSnapshot {
        pub fn try_from_parts(
            nodes: impl Into<Box<[IcfgNodeKey]>>,
            edges: impl Into<Box<[IcfgEdge]>>,
            boundaries: impl Into<Box<[IcfgBoundary]>>,
        ) -> Result<Self, SemanticProviderError>;
    }

The constructor may refine its input types during implementation, but it must validate all dense endpoints and build both directional adjacency indexes without sorting away the within-source edge-order mutation.

Revision note (2026-08-03): Created the initial self-contained plan after fetching `origin/master` and studying the requested reference and production test files. The design deliberately centralizes graph construction while leaving all oracle behavior in the three existing reference implementations.

Revision note (2026-08-03): Closed the plan after implementing the eight-scenario gate, minimizing two fixture-contract mismatches, completing all requested validation, and reviewing repository policy findings against the changed paths.
