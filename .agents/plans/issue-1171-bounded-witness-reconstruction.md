# Add bounded witness reconstruction to summary dataflow

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's query-local summary dataflow solver can currently report that a fact reached a program point or procedure exit, but it cannot explain one concrete valid interprocedural path that established that result. After this change, a client can opt into bounded witness retention, select one exact proof/completeness quality from a reached fact or end summary, and reconstruct a deterministic source-backed path without rerunning reachability.

The path remains context-respecting across calls and returns. When two callers reuse one callee summary, each reconstructed witness returns to the caller that supplied the matching incoming-call row. Normal returns, exceptional returns, and explicit call-to-return boundaries remain distinct. Witness retention and reconstruction are bounded, iterative, stack-safe, and independent of policy, taint, typestate, and IDE value-domain types.

The behavior is observable in `tests/dataflow_summaries.rs`. Focused tests request witnesses for local flow, helper calls, shared summaries, both return families, recursion, incomplete evidence, and explicit call-to-return flow. They also show deterministic witnesses under provider and callback permutations, exact partial outcomes at witness budgets, and successful reconstruction for every retained quality after cancellation or a budget stop.

## Progress

- [x] (2026-07-25 12:11Z) Verified live issue #1171, its parent #820, related child #1172, current branch and remote state, and the implementation/history introduced by pull requests #1123 and #1141.
- [x] (2026-07-25 12:11Z) Diagnosed the publication seam: exact derivations are computed in `summary.rs` and then discarded when only `PathQualityFrontier` is retained.
- [x] (2026-07-25 12:11Z) Wrote this ExecPlan with opt-in retention, quality-specific evidence, atomic publication, matched-return expansion, and bounded iterative reconstruction.
- [x] (2026-07-25 12:56Z) Milestone 1: defined the generic witness contracts, opt-in retention configuration, reconstruction limits, and `WitnessRelations` solver work dimension.
- [x] (2026-07-25 12:56Z) Milestone 2: retained seed and ordinary-edge evidence atomically, added bounded iterative reconstruction for reached facts and end summaries, and compacted result-owned evidence to active roots.
- [x] (2026-07-25 12:56Z) Milestone 3: retained exact incoming-call and end-summary alternatives, expanded matched normal and exceptional returns through summary-application nodes, and verified shared-callee contexts do not cross-return.
- [x] (2026-07-25 13:37Z) Milestone 4: completed bounded quality-valid reconstruction, explicit end-summary gap evidence, deterministic capped alternatives, prompt cancellation/budget finalization, differential topology checks, and behavior-focused coverage.
- [x] (2026-07-25 13:54Z) Milestone 5: completed all five guided specialist reviews, addressed every accepted finding, and passed the focused suites, strict all-feature Clippy, and the complete post-review all-feature test matrix.

## Surprises & Discoveries

- Observation: the solver already retains the identities needed to prevent cross-return, even though it does not retain predecessors.
  Evidence: `IncomingKey` contains the callee entry, caller entry, call point, call fact, and transfer index; `matched_return_projection` combines that row only with an end summary for the same callee entry.

- Observation: a callee path edge is deliberately relative to a callee entry fact and starts at `PathQuality::PROVEN_COMPLETE`, while the caller prefix and call-edge quality live on the incoming-call row.
  Evidence: `publish_call_outputs` inserts the relative callee entry path with proven/complete quality and separately inserts the caller-derived quality into `IncomingCall.qualities`. A witness must preserve that separation or summary reuse becomes caller-specific.

- Observation: `PathQualityFrontier` can retain incomparable concrete qualities.
  Evidence: `quality.rs` keeps proven/partial and unproven/complete paths simultaneously. Witness references therefore belong to `(state, concrete quality)`, never to a state-level merged proof/completeness pair.

- Observation: the existing summary tests already contain every required control-flow topology except witness assertions.
  Evidence: focused fixtures cover direct and mutual recursion, multi-wave replay, a shared callee used from two call sites, normal and exceptional returns, explicit deferred call-to-return flow, cancellation, exact publication budgets, and provider/callback permutations.

- Observation: alternative truncation must follow the retained derivation, not only the final result slot.
  Evidence: a two-branch merge can hit its one-alternative cap before its retained predecessor is propagated farther. Marking the retained evidence node lets every downstream reconstruction report that an earlier choice was omitted.

- Observation: Cargo's shared target contained host artifacts built by two rustc identities when a direct Clippy command was attempted.
  Evidence: featureless focused tests pass, while direct Clippy reported `cc` metadata compiled by an incompatible rustc with the same displayed version. The required final Clippy gate will use `scripts/with-isolated-cargo-target.sh` as repository guidance specifies.

- Observation: an exit profile's return-affecting gap is part of an end summary's concrete quality even before a caller-specific matched return is applied.
  Evidence: guided architecture review found that eliding the `EndSummary` evidence node produced an `UNPROVEN_PARTIAL` witness whose emitted steps all appeared proven and complete. Reconstruction now emits a source-backed `EndSummaryGap` step, and tests fold every complete witness back to its requested quality.

- Observation: opt-in behavior requires compact disabled-state metadata as well as no arena nodes.
  Evidence: the first implementation embedded four `Vec`s in every internal and public row even with retention disabled. `WitnessAlternatives` now stores one optional boxed table, so its disabled representation is one pointer-sized word.

- Observation: result finalization is still part of cancellation responsiveness.
  Evidence: security and operational reviews identified that unconditional arena compaction could traverse and copy up to the four-million-relation default after cancellation. Non-fixed-point results now consume the already-budgeted arena without compaction or ID remapping.

## Decision Log

- Decision: witness retention is opt-in through `SummarySolveInput`, and the default remains disabled.
  Rationale: existing direct-flow and fact-only summary clients remain usable without witness allocations or material disabled-path work. A client that needs explanations makes the retention cost explicit.
  Date/Author: 2026-07-25 / Codex

- Decision: retain evidence by `(PathEdgeKey, PathQuality)`, `(EndSummaryKey, PathQuality)`, and incoming-call row plus `PathQuality`.
  Rationale: one state may retain incomparable qualities. Associating a predecessor only with the state could fabricate a proven/complete combination no concrete path established.
  Date/Author: 2026-07-25 / Codex

- Decision: use an append-only query-local evidence arena with opaque dense IDs, and require every new node to reference only already-published nodes.
  Rationale: this produces an acyclic derivation graph even when semantic control flow is recursive. Reconstruction can use an explicit stack without recursive Rust calls or cycle-dependent call-depth limits.
  Date/Author: 2026-07-25 / Codex

- Decision: retain a configurable, strictly bounded number of alternatives per concrete state/quality and a separate global `WitnessRelations` solver-work budget.
  Rationale: the per-key cap prevents local path explosion, while the global budget bounds total query memory and makes failure visible as an ordinary partial solver result.
  Date/Author: 2026-07-25 / Codex

- Decision: cap the public per-quality alternative setting at 64 and centralize candidate staging in the arena.
  Rationale: an unbounded client-selected `usize` made duplicate admission quadratic and could delay cooperative cancellation. One admission operation now checks committed and transaction-staged duplicates, applies the strict cap, allocates the dense ID, and marks truncation consistently at every publication seam.
  Date/Author: 2026-07-25 / Codex

- Decision: bind public result rows to an enabled solve with a private shared owner token and validate the requested root descriptor during reconstruction.
  Rationale: `FactId` and evidence IDs are result-local. Logical row equality remains deterministic, while a clone from the same result is accepted and a semantically equal row from another solve is rejected before expansion.
  Date/Author: 2026-07-25 / Codex

- Decision: reconstruction has query-time step and evidence-expansion limits rather than reusing `DataflowRequest`.
  Rationale: reconstruction happens after the solve has finished and may be requested more than once. Its outcome must report its own work, truncation, and omitted-step lower bound without mutating the completed solver budget.
  Date/Author: 2026-07-25 / Codex

- Decision: keep policy adaptation downstream and make witness steps own semantic handles and evidence.
  Rationale: `src/analyzer/dataflow/` must remain independent of `src/analyzer/policy/`. Program-point and call-site handles let a policy adapter resolve source mappings without rerunning reachability.
  Date/Author: 2026-07-25 / Codex

## Outcomes & Retrospective

The implementation now has one generic query-local evidence arena, compacted to active roots at a fixed point and moved directly into partial results so cancellation and budget stops do not trigger a large uninterruptible copy. Public reconstruction is opt-in, result-owned, quality-specific, iterative, independently step/expansion bounded, and reports prefix truncation, omitted alternatives, work, and exclusive retained bytes. Incoming call prefixes remain separate from callee-relative paths until one exact matched return combines them. End-summary gaps are explicit public steps, so proof/completeness folding matches the requested quality.

All five guided reviews ran: security, duplication, issue intent/correctness, operational, and architecture. Accepted findings led to compact disabled-row storage, centralized bounded alternative staging, active-frontier-only admission and compaction roots, exact requested-root and matched call/return validation, result ownership tokens, source-backed end-summary gap steps, accurate owned-string byte accounting, and prompt non-fixed-point finalization.

Post-review focused validation passes `dataflow_clients` (12), `dataflow_tabulation` (11), all 26 `dataflow_summaries` tests, and the witness contract unit tests. Strict `cargo clippy --all-targets --all-features -- -D warnings` passes through the isolated-target helper. The complete `cargo test --features nlp,python` matrix also passes: all 1,904 library tests and every integration suite completed without failures. After the final duplicate-derivation equality tightening, the exact focused suites and strict Clippy gate passed again.

## Context and Orientation

`src/analyzer/dataflow/summary.rs` contains the optimized query-local summary solver. A path edge in this module is a dynamic-programming row: for one procedure entry fact, another fact reaches one program point. `PathEdgeKey` identifies that row. `SummaryState.reached` maps it to `PathQualityFrontier`, a small set of nondominated proof/completeness combinations.

`SummaryState.worklist` processes `QueuedPath { key, quality }` rows iteratively. `initialize` publishes root seeds. `process_local_edges` and `propagate_owned_edge` evaluate ordinary control-flow callbacks. `process_call` handles explicitly modeled call-to-return edges and real callees. `publish_call_outputs` creates a relative callee entry row plus an `IncomingCall` that remembers the exact caller and transfer. `process_exit` and `publish_end_summary` retain entry-to-exit relations. `replay_existing_summaries` and `apply_summary` combine one exact incoming quality, one exact end-summary quality, and one matched return edge before publishing back into the original caller entry.

`src/analyzer/dataflow/summary_result.rs` defines the owned public result. `SummaryReachedFact` reports one reached row, `TabulationEndSummary` reports one entry-to-exit relation, and `SummaryDataflowResult` owns facts, rows, coverage, termination, work, semantic work, and reuse metrics. It will also own the compact witness store.

`src/analyzer/dataflow/quality.rs` defines `PathQuality` and `PathQualityFrontier`. Proof and completeness are two separate booleans. Component-wise dominance removes only qualities that are no better in either component.

`src/analyzer/dataflow/budget.rs` defines `SolverWork` and `SolverBudgetDimension` with the `define_work_dimensions!` macro. Every retained solver structure must have an exact dimension and must be charged before publication. `DataflowRequest::reserve` stages a charge with cancellation checks around it.

`src/analyzer/semantic/icfg.rs` defines `ProcedureIcfgEdge`, `CallTransfer`, `IcfgExitProfile`, `IcfgEdgeKind`, and matched-return projection. Those language-neutral semantic handles are the topology and source-mapping boundary a witness needs. The new dataflow module must not import policy, taint, typestate, or IDE client types.

`tests/dataflow_summaries.rs` uses `InlineTestProject` and real `WorkspaceIcfgProvider` instances. `tests/common/dataflow_summary_reference.rs` provides an intentionally simple repeated-scan reachability implementation. It may gain a witness-topology validator, but it must not copy the optimized predecessor algorithm.

## Plan of Work

Milestone 1 introduces contracts without changing propagation. Create `src/analyzer/dataflow/witness.rs`. Define `WitnessRetentionLimits` with a disabled value and a positive maximum-alternatives constructor; `WitnessReconstructionLimits` with positive step and expansion limits; an opaque `WitnessEvidenceId`; a public `SummaryWitness`, `SummaryWitnessStep`, and `SummaryWitnessStepKind`; and explicit reconstruction errors/outcomes. A reconstructed step retains program-point handles, an optional call origin, `IcfgEdgeKind` where applicable, `ProofStatus`, and `EvidenceCompleteness`. Add a crate-private stable ordinal for `PathQuality`. Export the public contracts from `src/analyzer/dataflow/mod.rs`. Extend the work-dimension macro in `budget.rs` with `WitnessRelations`.

At the end of Milestone 1, contract unit tests prove that zero limits are rejected, disabled retention is explicit, and the new budget dimension fails atomically. Run formatting, dataflow library tests, and `dataflow_clients`; then update this plan and commit only the milestone files.

Milestone 2 adds the evidence arena and local propagation. Extend `SummarySolveInput` with witness retention and a builder that opts in without changing existing constructors. Pass the limits into `SummaryState::new`. Add an append-only arena plus path-quality slots. Seed nodes identify the entry program point and fact. Edge nodes reference an already-retained predecessor and own the exact `ProcedureIcfgEdge` plus input/output facts. Update `initialize`, `propagate_owned_edge`, and `publish_path_outputs` so evidence staging and state publication share one staged budget charge and cancellation boundary. Candidates may fill an unused alternative slot only when their exact quality remains active in the post-insert frontier, and never exceed the per-quality cap.

Move the arena and active path evidence into `SummaryDataflowResult::from_parts`. Add a reconstruction entry point for `SummaryReachedFact` and one concrete retained quality. The first reconstruction implementation handles seed and ordinary/call-to-return edge nodes with an explicit stack. It validates evidence ownership and endpoints while expanding. At a fixed point, `finish` iteratively compacts the arena to nodes reachable from active frontier qualities so dominated or replaced candidates do not inflate the public result; cancellation and budget stops preserve dense IDs and move the already-bounded arena without a second traversal.

At the end of Milestone 2, tests prove an exact intraprocedural witness, an explicit call-to-return witness, an unavailable result when retention is disabled, bounded deep iterative reconstruction, and atomic cancellation/budget behavior. Run focused suites, update this plan, and commit.

Milestone 3 adds interprocedural evidence. Extend each `IncomingCall` with quality-specific witness alternatives that reference the exact caller-path evidence and the call `ProcedureIcfgEdge`. A callee entry path remains a relative seed; it must not embed caller evidence. Extend each `EndSummaryRow` with quality-specific evidence pointing to the exact exit path and exit profile. In `apply_summary`, build a summary-application evidence node from one incoming alternative, one end-summary alternative, and the exact matched return edge. Iterate alternatives in canonical order and stop at the configured cap before allocating extra nodes.

Expand summary-application nodes iteratively into caller prefix, call edge, callee-relative path, and matched return. Validate that the incoming callee key equals the summary entry, that the call origin and transfer index identify the retained call transfer, that the exit profile matches the requested entry and exit, and that the return edge targets the retained caller procedure. Boundary-only or absent matched-return projections do not fabricate a returned path.

At the end of Milestone 3, extend the shared-callee test to request both continuation witnesses and assert that each contains only its own call site. Add normal-return, exceptional-return, helper-summary, direct-recursion, mutual-recursion, and multi-wave replay witness assertions. Run focused suites, update this plan, and commit.

Milestone 4 completes bounds and independent validation. Preserve exact path quality through every evidence node and recompute the conjunction during reconstruction, rejecting a chain that does not equal the requested quality. Mark alternative retention truncation independently from step truncation. When a step or expansion limit is reached, return the retained prefix with `truncated = true`, a conservative omitted-step lower bound, and exact reconstruction-work counters.

Extend provider/callback permutation tests to compare reconstructed witnesses. Add a fixture with proven/partial and unproven/complete paths at one state and request each quality separately. For cancellation and every witness-related budget, iterate all retained reached rows and end summaries and reconstruct every active quality, proving that no dangling reference was published. Add a test helper beside the repeated-scan reference that checks each reconstructed semantic edge against the procedure-local topology and exact matched-return projection; this helper validates the optimized result but does not reconstruct predecessors itself. Add an integration-test-only adapter that projects generic witness steps into a reporting-shaped record without importing policy from the dataflow module.

At the end of Milestone 4, run formatting, focused tests with `nlp,python`, strict Clippy through the isolated target helper, and the full feature-enabled test suite. Update this plan and commit.

Milestone 5 performs the guided review required by the issue workflow. Compute the complete branch diff against `origin/master` and run security, duplication, intent/correctness, operational, and architecture reviews in parallel. Fix every accepted critical or high finding and any lower-severity finding that affects correctness, determinism, boundedness, stack safety, or maintainability. Rerun the focused and full validation gates, record concise evidence below, complete the retrospective, and commit the reviewed result. Do not push or open a pull request unless the user explicitly asks.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/1b57/bifrost`.

Inspect the exact current state before each milestone:

    git status --short --branch
    git diff --check

Run formatting and focused tests during development:

    cargo fmt --all -- --check
    cargo test --features nlp,python --test dataflow_clients --test dataflow_tabulation --test dataflow_summaries

Run the strict lint gate through the repository cleanup helper:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Run the complete feature-enabled test suite before final review:

    cargo test --features nlp,python

Stage only the files named in the completed milestone. Never use `git add -A`. Each milestone commit message must explain both the behavior added and why its chosen representation preserves quality, context, and boundedness.

## Validation and Acceptance

The implementation is accepted when all of the following are observable:

With retention disabled, existing `SummarySolveInput::new` clients return the same facts, reached rows, summaries, coverage, termination, work, and metrics, and witness queries report that retention was not requested.

With retention enabled, a reached intraprocedural fact reconstructs a deterministic sequence beginning at its entry seed and following real semantic program points to the requested target.

A helper-call continuation reconstructs a call edge, the callee-relative path, and the exact matched return. Two caller sites reusing one callee summary reconstruct different call origins and different continuations without crossing.

Normal and exceptional witnesses contain their matching return kinds. An explicit call-to-return witness contains the modeled continuation edge and does not claim that the deferred callee body executed.

Direct and mutual recursion reach a fixed point and reconstruct through an iterative bounded API without a Rust stack overflow or a synthetic call-depth boundary.

For every requested concrete `PathQuality`, the reconstructed path's proof/completeness conjunction equals that quality. Incomparable frontier entries remain separate.

Provider, seed, and callback permutations produce equal public results and equal reconstructed witnesses.

Witness retention never exceeds its per-quality alternative cap or global solver-work budget. Reconstruction never exceeds its requested step or expansion bounds. Any omitted work is reported explicitly, and cancellation or an exceeded budget never leaves an active result row pointing to absent evidence.

The focused tests, strict all-feature Clippy gate, and complete `cargo test --features nlp,python` suite pass.

## Idempotence and Recovery

All edits are ordinary source and test changes and can be reapplied safely. Cargo commands may be rerun. Isolated Clippy targets are created and removed by `scripts/with-isolated-cargo-target.sh`; do not create manually named temporary Cargo target directories.

If a milestone test exposes a design error, keep the last verified milestone commit intact, update `Decision Log` and `Progress`, and repair the active milestone without resetting unrelated user changes. If evidence publication is partially implemented, do not weaken tests or add ignore annotations. Complete the atomic stage-and-commit path before moving on.

The Bifrost navigation plugin may create an untracked `.brokk/` cache while this plan is being executed. It is not part of the implementation and must never be staged.

## Artifacts and Notes

Live issue #1171 identifies `src/analyzer/dataflow/summary.rs`, `summary_result.rs`, `quality.rs`, and policy's existing reporting-only `BoundedWitness` shape. Pull request #1141 explicitly left witness reconstruction out of the summary-fixed-point child, so this plan builds on that checked-in state rather than altering the existing recursion or ICFG algorithms.

The most important current publication chain is:

    initialize / propagate_owned_edge / publish_call_outputs
        -> reached frontier and queued concrete quality
        -> publish_end_summary
        -> replay_existing_summaries / apply_summary
        -> publish_path_outputs in the exact caller entry context

The witness implementation must retain evidence at these existing seams. It must not add a second reachability pass, enumerate complete paths during propagation, or persist query-local evidence to SQLite.

## Interfaces and Dependencies

`src/analyzer/dataflow/witness.rs` must define public, policy-independent retention and reconstruction contracts. Exact names may be refined during Milestone 1, but the final interface must provide the following capabilities:

    WitnessRetentionLimits::disabled()
    WitnessRetentionLimits::new(max_alternatives_per_quality)
    WitnessReconstructionLimits::new(max_steps, max_expansions)
    SummaryDataflowResult::witness_for_reached(reached, quality, limits)
    SummaryDataflowResult::witness_for_end_summary(summary, quality, limits)

The returned witness must expose:

    steps
    quality
    truncated
    omitted_steps_lower_bound
    reconstruction work
    retained size or bytes

The implementation may use `Vec`, `HashMap`, `Box<[T]>`, and existing dense-ID/work-budget helpers. Do not add a dependency. Prefer append-only IDs and iterative traversal over reference counting or recursive ownership. Semantic topology comes only from existing types in `crate::analyzer::semantic`; no source-text parsing or string matching is permitted.

Revision note, 2026-07-25: Initial plan written after live issue verification and code-level diagnosis. It resolves the opt-in, quality identity, atomic publication, context matching, and bounded reconstruction decisions before implementation.

Revision note, 2026-07-25 12:56Z: Milestones 1-3 implemented. Recorded result compaction, propagated alternative truncation, focused validation evidence, and the isolated-target requirement for the remaining Clippy gate.

Revision note, 2026-07-25 13:37Z: Milestone 4 completed and all five guided reviews addressed. Recorded end-summary gap evidence, compact disabled metadata, centralized capped admission, result ownership/root validation, matched-return validation, cancellation-safe finalization, retained-byte accounting, and post-review focused/Clippy evidence.

Revision note, 2026-07-25 13:54Z: Milestone 5 completed. Recorded the clean full all-feature matrix and the exact-state focused and strict-Clippy reruns after the final derivation-equality tightening.
