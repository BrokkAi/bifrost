# Add in-memory summary tabulation and recursive fixed points for issue #820

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md`. It is the issue-specific implementation plan for the second child of GitHub issue #820. It builds on the bounded snapshot solver already present under `src/analyzer/dataflow/`, but it is self-contained and does not assume that a reader has seen the earlier plan.

## Purpose / Big Picture

Bifrost already has a deterministic data-flow runner over one context-expanded `IcfgSnapshot`. That runner deliberately stops recursive expansion at a configured call-depth frontier. After this change, an analysis can instead start from a semantic `ProcedureHandle` and compute procedure entry-to-exit summaries in memory. Direct recursion and mutual recursion converge through a finite monotone fixed point, and two callers that send the same fact into one callee reuse the same callee summary while still returning to their own exact continuations.

The behavior is visible in `tests/dataflow_summaries.rs`. A depth-one bounded snapshot of a recursive Java method retains a call-depth boundary, while the new summary solve reaches a fixed point without any call-depth parameter. Further tests show mutual recursion, one shared callee reused by distinct callers, normal and exceptional matched returns, explicit deferred call-to-return arms, incomplete semantic outcomes, cancellation, summary-specific budgets, deterministic output, and equality with an intentionally simple repeated-scan reference.

This child is query-local and in-memory. It does not add SQLite persistence, witness reconstruction, IDE edge functions, heap integration, taint, finite-state protocols, typestate, policy compilation, or RQL.

## Progress

- [x] (2026-07-24 06:20Z) Fetched the live remote and created `dave/820-summary-fixed-point-tabulation` exactly at `origin/master` commit `b594a149`.
- [x] (2026-07-24 06:20Z) Verified live issue #820 and audited the landed bounded solver, semantic ICFG provider, recursive snapshot frontier, result/budget contracts, and source-backed test harness with three parallel specialists.
- [x] (2026-07-24 06:20Z) Chose the demand-driven provider-backed architecture and wrote this second-child ExecPlan.
- [x] (2026-07-24 07:48Z) Extracted the provider-owned procedure-exit profile and matched-return/call-boundary projections, then kept the existing ICFG unit and contract suites green.
- [x] (2026-07-24 07:48Z) Added summary-specific result rows, coverage, reuse metrics, and independently bounded end-summary, incoming-call, and provider-materialization work.
- [x] (2026-07-24 07:48Z) Implemented the iterative relative path-edge, incoming-call, end-summary, and exact replay tables, and verified that the existing bounded solver/client regression suites remain green after sharing transfer evaluation.
- [x] (2026-07-24 09:03Z) Added the independent provider-backed repeated-scan reference and the first 11 summary behaviors covering direct/mutual recursion, reuse without cross-return, both return families, deferred bypass, incomplete providers, cancellation, malformed provider rows, every summary budget, and permutation determinism.
- [x] (2026-07-24 11:42Z) Fixed every actionable specialist-review finding: exact provider profile/provenance validation, compact incoming rows and replay indexes, shared profile/transfer scratch storage, deterministic projected-edge canonicalization, bounded cached bypass replay, precise return-gap text accounting, and atomic seed, coverage, incoming, and summary-application publication.
- [x] (2026-07-24 11:42Z) Expanded the integration suite to 18 tests, including a multi-fact recursive delta-replay fixed point, exact cache-materialization counts, retained and absent semantic-budget payloads, staged-output cancellation, and dimension-specific no-publication assertions.
- [x] (2026-07-24 12:42+02:00) Completed formatting, focused gates, strict all-feature Clippy, and the full serialized `cargo test --features nlp,python` suite outside the sandbox. The isolated target was removed automatically.
- [x] (2026-07-24 11:42Z) Ran five specialist reviews and fixed every actionable algorithm, semantic-contract, resource-boundedness, architecture, and test-coverage finding.
- [x] (2026-07-24 12:17Z) Ran a final post-fix verifier across return caching, incoming staging, replay cancellation, local-edge deduplication, deterministic evidence ordering, and public-result ownership; it reported no actionable findings.

## Surprises & Discoveries

- Observation: true recursive convergence cannot be recovered from `IcfgSnapshot`.
  Evidence: `src/analyzer/semantic/icfg.rs` keys snapshot nodes by an expanded call-frame sequence and emits `IcfgLimitKind::CallDepth` when `IcfgSnapshotLimits.max_call_depth` is reached. A solver over that frozen slice cannot discover topology that the provider intentionally omitted.

- Observation: the landed transfer contract was already prepared for a second backend.
  Evidence: `DistributiveDataflowProblem` receives procedure-local `ProgramPointHandle` endpoints, while only `BoundedSnapshotDataflowProblem` owns dense `IcfgNodeId` seeds. The new runner can therefore reuse all five transfer families without exposing snapshot contexts to clients.

- Observation: return matching is not just a continuation lookup.
  Evidence: the private `expand_return` path in `src/analyzer/semantic/icfg.rs` scans return-affecting semantic gaps on paths from procedure entry to a specific exit, downgrades proof and completeness, and retains unknown continuation states as typed boundaries. Reimplementing only the obvious call-site match in `dataflow` would silently lose those semantics.

- Observation: precomputed SCCs are not required for this child.
  Evidence: finite path-edge, incoming-call, and end-summary tables grow monotonically; replaying a new summary across waiting incoming calls naturally reaches the same recursive and mutually recursive fixed point with an iterative worklist. Issue #819 graph utilities may proceed independently.

- Observation: the public semantic envelope is not by itself sufficient to preserve the snapshot builder's exact internal quality precedence.
  Evidence: an exit-local exceeded-budget gap is exposed as an available `Unknown` profile, while the bounded snapshot previously retained its internal `Truncated` quality when combining that gap with other unsupported or ambiguous gaps. The exit profile therefore privately retains its exact local quality for snapshot replay, while summary clients continue to see the stable public envelope and concrete gap evidence.

- Observation: procedure-exit evidence must be relative to the exact summary entry, not merely the procedure.
  Evidence: a provider may legally select a noncanonical entry in `CallTransfer`. Computing the return-gap path mask from the declared entry could either miss a gap unique to that selected entry or import a gap from an unreachable canonical-entry branch. `IcfgExitProfile` and both caches therefore use `(procedure, entry, exit)`.

- Observation: an explicit applied-return deduplication table is unnecessary and creates a potentially unbounded Cartesian-product allocation.
  Evidence: a replay is triggered only when one incoming quality or one end-summary quality is newly admitted; whichever side arrives second owns that pair exactly once. Removing the table keeps retained state linear in incoming and summary rows, while an explicit `summary_applications` budget bounds the unavoidable replay work.

- Observation: summary coverage must own the evidence that a snapshot-backed result could otherwise dereference.
  Evidence: summary results have no backing ICFG edge table. `SummaryEdge` now retains proof and completeness, dispatch boundaries retain their structured provenance, and unique coverage rows are incrementally deduplicated and independently bounded.

- Observation: provider cache hits still need their own bounded execution path.
  Evidence: call-to-return projections are fact-independent but transfer callbacks are fact-sensitive. The solver now caches one canonical projected edge set, replays only its transfer relation for later facts, checks cancellation per edge, and charges every callback/output while avoiding repeated provider, provenance, and boundary work.

- Observation: semantically distinct provenance rows can collapse to one solver edge.
  Evidence: two valid dispatch boundaries may retain different oracle evidence while projecting to the same procedure-local edge. Coverage retains both boundaries, but projected edges are sorted and deduplicated before transfer evaluation so equivalent topology cannot double-charge flow budgets.

- Observation: the main worktree target can become materially larger than the source under all-feature validation.
  Evidence: the accumulated generated `target/` reached 104 GiB and exhausted the filesystem during final review validation. `cargo clean` removed only reproducible build artifacts; subsequent complete gates use `scripts/with-isolated-cargo-target.sh` so temporary targets are removed automatically.

- Observation: caching a matched return is useful only if replay does not deep-clone its proof, completeness, and gap evidence.
  Evidence: the exact matched-return projection cache owns one `Arc<SummaryEdge>` per call-transfer/entry/exit relation. Coverage sets borrow or clone that shared allocation, the cache is discarded before result construction, and `Arc::unwrap_or_clone` performs at most the one unavoidable clone when a single edge must appear in both public incomplete-evidence categories.

- Observation: the repository's JS/TS deadlock watchdog is sensitive to machine load during a fully parallel all-feature run.
  Evidence: the first complete run reached the unrelated `jsts_usage_graph_deadlock` binary after the 1,868-test library suite had passed, but one case exceeded its 60-second watchdog. The binary passed alone in 19.96 seconds and passed again, in context, when the full suite was serialized; the remainder of that serialized suite and doc tests also passed.

## Decision Log

- Decision: add a second solver entry point over a root `ProcedureHandle` and generic `IcfgProvider`; do not extend the bounded snapshot runner or add a second call stack to it.
  Rationale: the snapshot already represents one bounded context expansion. A provider-backed summary runner needs procedure-local topology beyond that expansion, and its incoming-call table is the valid-path matching mechanism.
  Date/Author: 2026-07-24 / Codex

- Decision: keep every callee path edge and end summary relative to a callee entry fact with `PathQuality::PROVEN_COMPLETE`; retain caller prefix and call-edge quality on the incoming-call row.
  Rationale: folding a caller prefix into a callee summary would make the row caller-specific and prevent sound reuse. At a matched return, the runner conjoins the incoming quality, relative end-summary quality, and return-edge quality.
  Date/Author: 2026-07-24 / Codex

- Decision: include the exact callee entry point in a summary-entry identity.
  Rationale: `CallTransfer` explicitly carries `callee_entry`; assuming one canonical entry would collapse distinct provider relations even if current language adapters normally choose the procedure's declared entry.
  Date/Author: 2026-07-24 / Codex

- Decision: pass root entry facts through `SummarySolveInput` instead of adding them to `DistributiveDataflowProblem`.
  Rationale: seeds are runner-specific. The bounded runner already isolates dense snapshot seeds in `BoundedSnapshotDataflowProblem`; a borrowed root plus entry-fact slice gives the summary runner the same separation without inventing a second analysis trait.
  Date/Author: 2026-07-24 / Codex

- Decision: add a default provider operation that describes one exact procedure-entry-to-exit relation, and a shared pure projection that matches that exit to one incoming call.
  Rationale: procedure-exit gap analysis belongs beside semantic ICFG construction and consumes `SemanticBudget`. The pure matched-return projection can then be reused by the bounded snapshot and summary runner, preserving exact continuation, proof, completeness, and typed boundary behavior.
  Date/Author: 2026-07-24 / Codex

- Decision: keep solver work and semantic-provider work distinct.
  Rationale: summary rows, incoming rows, and provider cache misses consume solver-owned limits; source/oracle/exit materialization consumes `SemanticBudget`. A semantic budget boundary must not be mislabeled as `SolverTermination::ExceededBudget`.
  Date/Author: 2026-07-24 / Codex

- Decision: extend `SolverWork` with `end_summaries`, `incoming_calls`, `provider_materializations`, `summary_applications`, and `coverage_rows`.
  Rationale: the first three bound independently retained tables and provider cache misses. The latter two bound matched-return Cartesian-product work and owned incomplete-evidence rows, preventing no-op returns or repeated boundaries from escaping the fact-worklist limits.
  Date/Author: 2026-07-24 / Codex

- Decision: canonicalize every client relation and provider transfer set before assigning fact, procedure, incoming, or summary identities.
  Rationale: equivalent relations emitted in a different order must produce identical dense IDs, budget failures, metrics, and public results.
  Date/Author: 2026-07-24 / Codex

- Decision: retain exact semantic boundary provenance separately from canonical projected solver edges.
  Rationale: provenance-distinct boundaries remain observable coverage, but applying the same collapsed procedure edge more than once would make solver work and budget termination depend on evidence multiplicity rather than topology.
  Date/Author: 2026-07-24 / Codex

- Decision: keep compact call origins and shared exit profiles in retained summary state.
  Rationale: incoming rows need only an exact cache key plus relative identities, and end summaries may share one immutable provider profile. Reconstructing semantic calls or cloning profile payloads during every replay adds work without strengthening identity or evidence.
  Date/Author: 2026-07-24 / Codex

- Decision: cache exact matched-return projections as shared owned evidence, but clear that private cache before constructing public coverage.
  Rationale: replaying a recursive summary can revisit the same semantic return many times. Sharing avoids repeated proof and reason-string allocation while preserving an ordinary owned public result with no cache-dependent lifetime.
  Date/Author: 2026-07-24 / Codex

- Decision: expose query-local end summaries and reuse metrics, but do not create a persistent summary identity.
  Rationale: issue #820 owns correctness-critical tabulation summaries. Cross-query semantic, taint, and protocol summary keys belong to later #823/#817 work after the in-memory shapes and reuse measurements stabilize.
  Date/Author: 2026-07-24 / Codex

## Outcomes & Retrospective

The second solver backend is complete. It terminates direct and mutual recursion without a call-depth parameter, publishes deterministic query-local end summaries, reports observable summary reuse, and retains semantic and solver incompleteness without partial publication. The production worklist agrees with an intentionally simple repeated-scan implementation, including a multi-wave recursive fact transition that cannot pass through a single replay.

The review materially tightened the implementation rather than changing its scope. Exact provider profiles and dispatch provenance are validated before caching; root facts, callback outputs, incoming rows, summaries, applications, and coverage all have atomic bounded publication; expensive semantic projections are shared without exposing private cache ownership; and cancellation is checked before allocation and during replay. No heap model, taint client, finite-state protocol, persistence, witness reconstruction, IDE edge function, policy compiler, or RQL integration was added. Those remain later children built on this kernel.

## Context and Orientation

`src/analyzer/dataflow/problem.rs` defines `DistributiveDataflowProblem`. A fact type must be finite for one run and implement `Copy`, equality, hashing, and ordering. Five unary callbacks describe ordinary, call, return, explicit call-to-return, and exceptional flow. The kernel preserves the distinguished zero fact across each edge.

`src/analyzer/dataflow/tabulation.rs` is the first #820 runner. It accepts `IcfgSolveInput`, whose `IcfgSnapshot` already contains expanded call contexts and matched return edges. It interns facts, propagates a FIFO worklist, retains a nondominated proof/completeness frontier, and reports deterministic work and coverage. It remains the appropriate backend when a caller already has a bounded snapshot.

`src/analyzer/semantic/icfg.rs` owns the semantic ICFG provider. `IcfgProvider::call_transfers` resolves one call site to materialized callee entries plus explicit dispatch boundaries. `WorkspaceIcfgProvider::snapshot` currently performs three pieces of topology logic that the new runner must share: it suppresses local call-scaffolding edges when a call is expanded, turns modeled dispatch boundaries into explicit call-to-continuation edges, and matches a callee exit to the exact incoming call while applying return-affecting semantic gaps.

A path edge in this plan is not a graph edge. It is a dynamic-programming row saying that, for one procedure entry fact, a current fact reaches one procedure-local program point. An end summary says that the same entry fact reaches a normal or exceptional exit fact. An incoming-call row remembers which exact caller/call relation is waiting for a callee entry summary. When either side of that relation grows, the solver replays only the newly available combinations.

`PathQuality` is the conjunction of two independent booleans: whether a concrete path is proven and whether it is complete. A `PathQualityFrontier` retains nondominated concrete profiles. Summaries must keep that frontier; joining proof from one path with completeness from another would fabricate a path that was never observed.

## Plan of Work

First, refactor `src/analyzer/semantic/icfg.rs` without changing snapshot behavior. Add a provider-visible procedure-exit descriptor containing the exit handle, normal/exceptional kind, proof, and completeness. Its default provider operation iteratively computes the existing entry-to-exit path mask, selects return-affecting gaps, charges the same semantic work, and returns an explicit `SemanticOutcome`. Extract pure helpers for matched return projection and modeled boundary continuations. Make the existing snapshot builder cache and consume those operations. Focused ICFG tests must remain unchanged and green before the summary solver is added.

Second, extend the data-flow contracts. In `src/analyzer/dataflow/quality.rs`, add internal quality conjunction and proof/completeness application. In `src/analyzer/dataflow/budget.rs`, add five summary dimensions: retained end summaries, retained incoming calls, provider materializations, summary applications, and owned coverage rows. In `src/analyzer/dataflow/problem.rs` and a small shared transfer helper, reuse one callback collector and edge-family dispatcher between both runners so zero preservation, cancellation checkpoints, callback-row bounds, canonicalization, and atomic publication have one interpretation.

Third, add `src/analyzer/dataflow/summary_result.rs`. Define `SummaryEntry`, `SummaryReachedFact`, `TabulationEndSummary`, owned observed edges, point-keyed semantic/dispatch/continuation boundaries, `SummaryCoverage`, deterministic `SummaryMetrics`, `SummaryDataflowResult`, and `SummaryDataflowError`. Dense `FactId` values remain run-local. Public rows carry semantic handles, while result construction sorts by deterministic procedure discovery ordinal and local IDs.

Fourth, add `src/analyzer/dataflow/summary.rs`. `SummarySolveInput` borrows the root procedure and root entry facts. The runner interns the zero fact first, assigns deterministic procedure ordinals, and maintains:

- path-edge frontiers keyed by procedure entry, current point, and current fact;
- a FIFO queue of newly admitted path qualities;
- end-summary frontiers keyed by entry, exit kind, and exit fact;
- incoming-call rows keyed by exact caller entry, call point/fact, canonical transfer index, and callee entry;
- per-entry incoming and summary indexes that preserve insertion order;
- per-run call-transfer and procedure-exit provider caches;
- a fact-independent canonical call-to-return projection cache and one reusable transfer-output scratch set.

At an ordinary point, apply the appropriate local callback. At a call point, retain unusual non-scaffolding local edges, query and canonicalize the call-transfer set once, evaluate `call_flow`, create callee entry rows and exact incoming-call rows atomically, and apply only explicitly modeled call-to-return boundary arms. At an exit, incorporate provider-owned exit evidence into an end summary. A new incoming quality replays existing summaries; a new summary quality replays waiting incoming rows. Return projection chooses only the matching normal or exceptional continuation and applies `return_flow` before publishing back into the original caller entry context.

Every table grows monotonically and every key component is finite for a finite semantic artifact and finite fact domain. The implementation uses no recursive Rust calls and no call-depth bound.

Fifth, add `tests/common/dataflow_summary_reference.rs`. This runner repeatedly scans frozen copies of its reached rows, incoming rows, and end summaries until none changes. It deliberately has no optimized worklist, solver budget, metrics, or witness storage. It may use the shared provider-owned semantic topology projections, but it must independently implement fixed-point scheduling. Production and reference results are compared after projecting to semantic point/fact and entry-to-exit relations.

Finally, add `tests/dataflow_summaries.rs` using `InlineTestProject`, `resolve_procedure_handle`, and real `WorkspaceIcfgProvider` instances. Java static methods provide complete direct and mutual recursion fixtures. TypeScript or Java explicit throwing fixtures cover exceptional returns. Rust async construction covers deferred boundary arms. Small provider wrappers weaken an otherwise complete call outcome and reverse equivalent transfer order. Tests must assert exact matched continuations, no cross-return, semantic versus solver budget distinction, cancellation atomicity, deterministic equality, and nonzero reuse.

## Concrete Steps

Work from the repository root:

    /Users/dave/.codex/worktrees/547e95c0-eeb5-4cbf-90c7-b86162312407/bifrost

After the semantic extraction, run:

    cargo fmt
    cargo test --test icfg_contract

Expect all existing ICFG contract tests to pass with no changed assertion.

After adding the summary contracts and engine, run:

    cargo test --test dataflow_tabulation --test dataflow_clients --test dataflow_summaries --test icfg_contract

Expect 12 client tests, 11 bounded tabulation tests, 18 tests in the summary binary, and 25 ICFG contract tests to pass. A direct-recursion test explicitly demonstrates that a depth-two snapshot has a call-depth boundary while `solve_with_summaries` terminates at `FixedPoint`; a separate multi-fact test requires successive recursive summary deltas to produce `Wave2`.

Before review, run the repository gates with one coherent Rust toolchain. On this host, use the rustup 1.96 toolchain binaries if Homebrew `rustdoc` or `cargo-clippy` selects a different LLVM build:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

If an isolated target is needed, wrap the command with `scripts/with-isolated-cargo-target.sh`; do not create a manually named target directory under `/tmp`.

## Validation and Acceptance

The child is accepted when all of the following behavior is demonstrated:

- A recursive procedure and a mutually recursive pair terminate at a fixed point without a call-depth configuration or recursive Rust stack growth.
- A second caller of the same callee entry/fact consumes an already shared end-summary relation, increments deterministic reuse metrics, and returns only to its own call site's continuation.
- Normal and exceptional exit summaries select their matching continuation and dispatch the existing `return_flow` callback with proof/completeness equivalent to bounded snapshot construction.
- Explicit deferred dispatch boundaries use `call_to_return_flow`; ordinary materialized calls do not receive an invented bypass.
- Partial, unknown, unsupported, unproven, or semantic-budget-limited provider work remains visible in `SummaryCoverage` and prevents `is_complete()`.
- Pre-cancellation and callback-triggered cancellation return `SolverTermination::Cancelled` without publishing outputs after the cancellation checkpoint.
- `end_summaries`, `incoming_calls`, `provider_materializations`, `summary_applications`, and `coverage_rows` each produce their own exact `SolverBudgetDimension` failure and do not partially publish the charged row.
- Reversing equivalent root facts, callback facts, and provider transfer rows produces an exactly equal public result, work record, coverage, and metrics.
- The repeated-scan reference and optimized solver agree on small direct, recursive, mutually recursive, normal-return, exceptional-return, and boundary fixtures.
- Existing bounded snapshot data-flow and ICFG tests remain green.

## Idempotence and Recovery

Formatting and tests are safe to rerun. All summary state is request-local and discarded with the result; there is no database migration or persistent cache to repair. The pre-existing untracked `.brokk/` directory is outside this plan and must remain untouched.

If the semantic extraction changes existing snapshot behavior, stop and restore equivalence before continuing; do not compensate in the summary solver. If a fixture exposes a real adapter uncertainty, retain it as typed incomplete coverage or choose a fixture with a complete structured call relation. Do not add text-search or regex fallbacks.

Commit only the files changed by this plan. Checkpoints should separate the plan, shared semantic/contract seam, fixed-point engine, tests, and post-review fixes so each milestone can be inspected independently.

## Artifacts and Notes

The starting branch is:

    dave/820-summary-fixed-point-tabulation
    HEAD = origin/master = b594a149b14a4e555823634ed5ab64a3071331db

The intended table relationship is:

    caller path edge
        -> call_flow
        -> incoming row for (callee entry, entry fact)
        -> relative callee path edges
        -> end summary
        -> exact incoming/end-summary replay
        -> return_flow
        -> original caller entry context

Caller quality is deliberately absent from the relative callee rows. It is reintroduced only in the final replay conjunction.

## Interfaces and Dependencies

In `src/analyzer/semantic/icfg.rs`, add the provider-owned exit contract:

    pub struct IcfgExitProfile {
        callee_entry: ProgramPointHandle,
        callee_exit: ProgramPointHandle,
        kind: ReturnTransferKind,
        gap_reason: Option<Box<str>>,
    }

    pub trait IcfgProvider: DispatchOracle {
        fn call_transfers(...);
        fn exit_profile(
            &self,
            callee_entry: &ProgramPointHandle,
            callee_exit: &ProgramPointHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError>;
        fn snapshot(...);
    }

The default `exit_profile` implementation is usable by custom providers because immutable procedure handles contain the local CFG and semantic gaps. Shared projection helpers turn one incoming call relation plus one `IcfgExitProfile` into either a matched return edge, an absent continuation, or a typed continuation boundary. Provider transfer rows are validated before either backend publishes them.

In `src/analyzer/dataflow/summary.rs`, expose:

    pub struct SummarySolveInput<'a, Fact> {
        root: &'a ProcedureHandle,
        entry_facts: &'a [Fact],
    }

    pub fn solve_with_summaries<P, Provider>(
        input: SummarySolveInput<'_, P::Fact>,
        provider: &Provider,
        problem: &P,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<SummaryDataflowResult<P::Fact>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem,
        Provider: IcfgProvider + ?Sized;

`SummaryDataflowResult` must expose the interned fact table, deterministic reached rows, deterministic `TabulationEndSummary` rows, coverage, termination, solver work, semantic-work delta, and metrics. `is_complete()` requires a fixed point and complete coverage.

No new external dependency is required.

Plan revision note (2026-07-24): Created the second-child plan after refreshing live issue and remote state, reading the landed first-child contracts, and completing independent provider-seam, engine, and test-design audits. The plan chooses relative procedure summaries and exact incoming-call replay so recursion converges without extending the bounded context-expanded snapshot. Updated after implementation, five specialist reviews plus a post-fix verifier, strict Clippy, focused regression gates, and the complete serialized all-feature test suite.
