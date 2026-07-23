# Build the first bounded data-flow tabulation kernel for issue #820

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md`. It is the issue-specific implementation plan for the first child of GitHub issue #820, not a claim that the entire solver epic is complete.

## Purpose / Big Picture

Bifrost already materializes a bounded, language-neutral interprocedural control-flow graph, or ICFG, whose call and return edges carry exact call-site context. After this change, an analysis client can seed finite facts at ICFG nodes and run one iterative may-data-flow computation across intraprocedural, call, return, call-to-return, and exceptional edges. The result preserves the input graph's uncertainty, reports cancellation and each work limit distinctly, and returns deterministic reached facts.

The observable proof is a direct-flow client with one fact and no protocol state. On small inline projects, its reached nodes match ordinary bounded ICFG reachability across direct calls, matched normal and exceptional returns, deferred call-to-return continuations, loops, and recursive depth frontiers. A deliberately slow repeated-scan implementation in test code must produce the same reached facts as the optimized worklist.

This first child deliberately stops before reusable procedure summaries, recursive summary convergence beyond the bounded ICFG, witness reconstruction, IDE edge functions, heap/value-oracle integration, taint, typestate automata, SQLite persistence, policy compilation, and RQL. Those are later #820 or downstream issue slices.

## Progress

- [x] (2026-07-23 11:25Z) Verified live issue #820 and synchronized the detached worktree to `origin/master` at `447638f1`.
- [x] (2026-07-23 11:50Z) Audited the current `IcfgSnapshot`, semantic outcome, cancellation, budget, receiver-analysis, fixed-point, compact-graph, and test-harness seams with parallel specialists.
- [x] (2026-07-23 12:15Z) Froze the bounded first-child scope and created this issue-specific ExecPlan.
- [x] (2026-07-23 14:46Z) Implemented the public problem, input, budget, outcome, and direct-flow contracts under `src/analyzer/dataflow/`.
- [x] (2026-07-23 14:46Z) Implemented deterministic iterative propagation and path/input completeness accounting; `cargo check --lib` passes.
- [x] (2026-07-23 15:10Z) Added the independent repeated-scan reference and behavior-focused direct/differential tests; the two new integration binaries pass 20 tests in total, including 12 dataflow cases and their shared harness tests.
- [x] (2026-07-23 15:50Z) Ran formatting, focused tests, strict all-target/all-feature Clippy, and the complete `nlp,python` regression suite. The final unrestricted all-feature pass was green across library, binary, integration, and doc-test targets.
- [x] (2026-07-23 15:50Z) Completed architecture, security/resource, test/intent, API/scope, and duplication reviews. Fixed both high-risk architecture findings, added the missing behavior regressions, and retained only two low-value test-helper duplication notes.
- [x] (2026-07-23 16:19Z) Simplified the unmerged child after three focused audits: collapsed solver finalization, reused transfer buffers, stopped staging dominated frontiers, tightened solver-only API, made the direct client rely on kernel-owned zero propagation, and removed the two test-helper duplications. The focused 45-test dataflow/ICFG gate remains green.
- [x] (2026-07-23 17:15Z) Fixed all seven guided-review findings: bounded callback emission, shared budget and dense-ID machinery, non-fabricable fact IDs, snapshot-owned invariant validation, cohesive dataflow contract modules, and shared source-backed fixtures. The expanded focused gate passes 12 client, 10 tabulation, and 25 ICFG contract tests.
- [x] (2026-07-23 17:34Z) Resolved the post-fix resource audit by replacing proxy sink limits with exact prospective multi-dimensional charges and adding ignored-stop plus cross-dimension burst coverage. Restored the two public-contract explanations lost during the module split and reconciled this living plan with the sealed-snapshot architecture.
- [x] (2026-07-23 18:04Z) Completed the post-fix architecture, resource, and test re-reviews with no remaining findings. Re-ran strict all-feature Clippy and the complete unrestricted `nlp,python` test matrix; every enabled target passed.
- [x] (2026-07-23 20:20Z) Resolved the fresh post-rebase findings by sealing outcome provenance, separating procedure-local transfers from snapshot seeds, and making constrained budget outcomes permutation-independent. Focused validation, strict Clippy, the complete enabled test matrix, and all three specialist re-reviews are green.

## Surprises & Discoveries

- Observation: the worktree was detached at `b1bcfef5`, 130 commits behind the foundation described by the user, even though the quoted readiness report said it was at current `origin/master`.
  Evidence: after `git fetch origin --prune`, `git rev-list --left-right --count HEAD...origin/master` printed `0 130`; a detached fast-forward moved it to `447638f1`.

- Observation: `IcfgSnapshot` is already context-expanded, so adding a second solver call stack would duplicate and risk contradicting the ICFG's valid-path semantics.
  Evidence: `src/analyzer/semantic/icfg.rs` stores `IcfgNodeKey.call_context`, pushes a frame on call expansion, and pops the matching frame before publishing return edges. `tests/icfg_contract.rs` already proves that two sites calling one callee do not cross-return.

- Observation: current call-to-return edges are narrower than canonical IFDS bypass edges.
  Evidence: `CallToNormalContinuation` and `CallToExceptionalContinuation` are emitted for modeled deferred-invocation boundaries. Ordinary resolved-call scaffolding is suppressed, so this child must dispatch existing bypass edges without claiming that every materialized call has one.

- Observation: a bare `IcfgSnapshot` does not contain the quality of its construction.
  Evidence: `SemanticOutcome<IcfgSnapshot>` distinguishes complete, ambiguous, unknown, unsupported, unproven, budget-exhausted, and cancelled results. Some semantic-budget exits retain a partial snapshot without enough boundary metadata to reconstruct that top-level state.

- Observation: true recursive summary convergence cannot be recovered from a bounded snapshot alone.
  Evidence: `IcfgSnapshotLimits.max_call_depth` stops recursive expansion and publishes a typed boundary. A solver cannot summarize call topology that the snapshot does not contain.

- Observation: Bifrost symbol search does not currently return macro-generated dense semantic ID definitions such as `ProgramPointId`, `CallSiteId`, `ControlEdgeId`, and `BlockId`.
  Evidence: `search_symbols` returned no definitions; `rg` located the generating macro invocation in `src/analyzer/semantic/ids.rs`. This is a tooling follow-up candidate and does not require a workaround in the solver.

- Observation: exposing context-expanded `IcfgNodeKey` rows through the generic transfer contract would let client semantics depend on a materialized call stack and prevent sound procedure-summary reuse.
  Evidence: the post-rebase architecture review traced the original descriptor through `IcfgNodeKey.call_context`. The final `DataflowEdge` instead carries procedure-local `ProgramPointHandle` endpoints plus kind, origin, proof, and completeness; `BoundedSnapshotDataflowProblem` owns the separate dense context-specific seed contract.

- Observation: both a post-callback-only charge and per-row multidimensional publication charges are incorrect callback boundaries.
  Evidence: a post-callback-only design can allocate an arbitrary relation, while per-row fact/state/output checks make the typed exceeded dimension depend on emission order. The final sink uses one independently budgeted `callback_rows` cap, then sorts the complete retained relation and atomically checks its exact fact, zero-inclusive state, callback-row, and propagated-output publication charge. It returns `false` at the cap and retains cancellation precedence; clients must still return cooperatively because no Rust callback interface can preempt arbitrary client CPU work.

- Observation: current source-backed ICFG adapters do not expose a stable unproven-complete edge topology for an end-to-end incomparable-path-frontier fixture.
  Evidence: local edges are proven-complete; currently unproven dispatch edges also carry partial completeness; return gaps downgrade both axes; and C++ virtual open-world uncertainty is retained as a separate boundary rather than an unproven edge. The frontier and edge-conjunction algebra therefore have focused unit regressions, while solver-level frontier requeue remains a later test when a contract-backed topology exists. No synthetic production snapshot constructor was added only for testing.

- Observation: the macOS all-feature test link requires the repository's documented PyO3 dynamic-lookup flags.
  Evidence: the first isolated run failed while linking `libbrokk_bifrost.dylib` with unresolved `_Py*` symbols. Re-running with `RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup'` passed the linker boundary.

- Observation: three existing benchmark subprocess tests cannot run inside the managed sandbox.
  Evidence: the sandboxed all-feature run passed 1,717 library tests before `benchmark::mcp_session` tests failed to spawn helpers with `Operation not permitted`. The same tests passed in the unrestricted run.

- Observation: `broken_stdout_pipe_is_an_operational_status_two_failure` is transient under the full concurrent suite on this host.
  Evidence: one unrestricted full run observed status 1 instead of 2. An immediate focused rerun passed, and the final complete warm all-feature run also passed the entire `bifrost_policy_cli` target.

## Decision Log

- Decision: implement a bounded snapshot solver as the first #820 child and explicitly defer end-summary recursion, reusable summaries, witnesses, and IDE edge functions.
  Rationale: this matches the user's requested minimal slice and avoids presenting call-depth truncation as recursive convergence. The later summary child needs a procedure-local/provider seam capable of representing topology beyond one bounded context-expanded snapshot.
  Date/Author: 2026-07-23 / Codex

- Decision: use `IcfgNodeId` as the context abstraction and key reached states by `(IcfgNodeId, FactId)`.
  Rationale: the final #818 API is context-specific, unlike the older roadmap sketch that used procedure-local `ProgramPointId`. Published call and return edges already encode valid matched contexts.
  Date/Author: 2026-07-23 / Codex

- Decision: require callers to supply `IcfgSolveInput`, which pairs `&IcfgSnapshot` with an `IcfgInputStatus`, and provide conversion from `&SemanticOutcome<IcfgSnapshot>`.
  Rationale: the solver must not turn a partial, unproven, unsupported, budget-exhausted, or cancelled input graph into a complete negative merely because the partial snapshot itself remains traversable. Raw `(snapshot, status)` construction is private; public construction preserves the provider envelope through `SemanticOutcome`.
  Date/Author: 2026-07-23 / Codex

- Decision: keep procedure-local unary transfers in `DistributiveDataflowProblem` and put dense context-specific seeds in the bounded-runner-only `BoundedSnapshotDataflowProblem`.
  Rationale: lifting unary fact-to-fact-set functions pointwise over reached facts structurally supplies union-distributive may semantics. Procedure-local edge descriptors keep those callbacks reusable by a later summary backend, while the current snapshot runner can still accept explicit `IcfgNodeId` seeds. A non-distributive client needs a separately named backend.
  Date/Author: 2026-07-23 / Codex

- Decision: intern orderable run-local client facts inside the kernel, with the distinguished zero fact interned first.
  Rationale: dense `FactId` values make hot reached-state keys compact. The kernel injects zero at every explicit seed node and preserves it across every edge after invoking the client callback, which supplies the standard zeroed-flow control carrier even when a client kills all domain facts. Sorting and deduplicating seeds and transfer outputs before interning makes IDs and result order deterministic without using sorted maps in the worklist.
  Date/Author: 2026-07-23 / Codex

- Decision: keep input quality, solver termination, per-state path quality, and global coverage separate.
  Rationale: a proven path can support a may finding while another reachable partial edge or boundary prevents a complete absence claim. Cancellation or a solver budget is a run termination cause, not a rewrite of the provider's input status.
  Date/Author: 2026-07-23 / Codex

- Decision: use five independently charged solver dimensions—interned facts, reached states, flow evaluations, callback rows, and propagated outputs—and separate the deterministic callback-row cap from atomic semantic publication charges.
  Rationale: seed and transfer buffers cannot contain more unique rows than the remaining callback-row budget. Relations that fit that cap are sorted and deduplicated before the full fact/state/callback/output charge is computed, so equivalent output permutations select the same exceeded dimension and attempted work. Relations beyond the cap stop at its deterministic `limit + 1` row without retaining further output.
  Date/Author: 2026-07-23 / Codex

- Decision: share fixed-width dense-ID generation and multidimensional atomic budget accounting as private analyzer infrastructure.
  Rationale: semantic materialization and data-flow solving need the same overflow-safe mechanics but retain different public IDs, work fields, defaults, validation rules, and error text. Private generators and a generic ledger remove policy-free duplication while preserving those domain contracts. `FactId` intentionally omits `Default` and public construction so clients cannot fabricate the run-local zero ID.
  Date/Author: 2026-07-23 / Codex

- Decision: enforce all `IcfgSnapshot` edge invariants while the private builder seals the snapshot, not on every solve.
  Rationale: snapshot fields and constructors are sealed, so source/target validity and interprocedural call origins can be checked once before publication. Cloning preserves those invariants; rescanning an immutable snapshot in every solver run duplicated work and exposed unreachable dataflow errors.
  Date/Author: 2026-07-23 / Codex

- Decision: preserve `ControlEdgeKind::Cleanup` as an ordinary intraprocedural callback while routing only `Exceptional` and `AsyncExceptional` local edges through `exceptional_flow`.
  Rationale: cleanup is a distinct semantic edge and must remain visible through the edge descriptor; treating every cleanup edge as exceptional would invent a control interpretation.
  Date/Author: 2026-07-23 / Codex

- Decision: retain the component-wise nondominated frontier of concrete path qualities per reached state.
  Rationale: joining proof and completeness component-wise could fabricate a proven-complete quality from two different paths when neither individual path established both. Conversely, a proof-first total order is not preserved by conjunction with later edge quality: a discarded unproven-complete path can become stronger after a later unproven edge. The frontier contains at most the two incomparable proven-partial and unproven-complete profiles, queues each newly admitted profile independently, and discards only component-wise dominated paths.
  Date/Author: 2026-07-23 / Codex

- Decision: keep seed canonicalization and zero-fact propagation exclusively in the kernel, and keep the corresponding construction and frontier mutators crate-private.
  Rationale: the direct client should prove the kernel contract without repeating it. Its transfer callbacks intentionally emit nothing because its sole fact is zero; successful graph reachability therefore directly exercises kernel preservation. Clients can inspect result IDs and path quality without fabricating either one.
  Date/Author: 2026-07-23 / Codex

## Outcomes & Retrospective

The first bounded #820 child is complete. The additive production module contains reusable procedure-local unary transfers, a bounded-snapshot seed contract, run-local deterministic fact interning, kernel-owned zero injection and preservation, outcome-derived input quality, component-wise nondominated path frontiers, five-dimensional atomic budgeting, cancellation checkpoints, a one-state direct-flow client, and a FIFO worklist over every current ICFG edge family. The independent repeated-scan implementation agrees with the worklist on calls, matched normal and exceptional returns, deferred continuations, cleanup, loops, fact generation and killing, and bounded recursion.

Architecture review found two high-risk issues before finalization: the original zero fact was interned but not automatically propagated, and a proof-first single path quality could discard an incomparable path that later became stronger after edge conjunction. Both were corrected in production and covered by focused regressions. The guided review then identified seven architectural and contract simplifications. Its resource follow-up produced bounded callback sinks and ignored-stop coverage. A fresh post-rebase review found three remaining API-foundation issues: forgeable input-status pairing, context-expanded transfer descriptors, and callback-order-dependent budget termination. The final design makes public input construction outcome-derived, splits reusable transfer semantics from snapshot seeds, and canonicalizes each bounded relation before multidimensional publication accounting. The change still does not touch #1107's active receiver, semantic-oracle, storage, or structural-query surfaces.

Validation is green: `cargo fmt --all -- --check`; `git diff --check`; 12/12 dataflow client tests; 11/11 tabulation tests; 25/25 existing ICFG contract tests; strict `cargo clippy --all-targets --all-features -- -D warnings`; and the complete `cargo test --features nlp,python` library, binary, and integration matrix. The library target reported 1,724 passed and 5 ignored. The initial doc-test phase selected Homebrew `rustdoc` against rustup-built artifacts and failed crate compatibility; the same phase passed with explicit coherent rustup `cargo`, `rustc`, and `rustdoc` binaries (there are currently zero doc tests). The scope boundary remains unchanged: this child establishes context-respecting propagation over a bounded ICFG, not reusable procedure summaries, unbounded recursive convergence, heap or taint clients, typestate automata, persistence, policy compilation, or RQL.

## Context and Orientation

`src/analyzer/semantic/icfg.rs` defines the immutable input graph. `IcfgSnapshot` stores dense `IcfgNodeId` and `IcfgEdgeId` rows, canonical outgoing and incoming adjacency, and typed boundaries. `IcfgNodeKey` contains a scoped `ProgramPointHandle` plus the full bounded call-context sequence. `IcfgEdgeKind` distinguishes intraprocedural control, call, normal return, exceptional return, normal call-to-return continuation, and exceptional call-to-return continuation. Each edge also carries `ProofStatus` and `EvidenceCompleteness`.

`src/analyzer/semantic/provider.rs` defines `SemanticOutcome<T>`, `SemanticBudget`, and `SemanticRequest`. Its outcome envelope is part of the solver input contract because `IcfgSnapshot` alone cannot say whether graph construction was complete. `src/cancellation.rs` defines the shared cooperative `CancellationToken`.

`src/analyzer/mod.rs` is the analyzer module registry. `pub mod dataflow;` exposes the new implementation, while private `dense_id` and `work_budget` modules share policy-free mechanics with semantic IDs and budgets. `src/analyzer/semantic/icfg.rs` owns snapshot invariants at sealing. Receiver analysis, semantic oracles, storage, structural search, policy, and RQL files remain out of scope.

A fact is one finite abstract proposition supplied by a client. The kernel interns each distinct typed fact into a run-local dense `FactId`; these IDs are not stable across runs or snapshots. A reached state is one `(IcfgNodeId, FactId)` pair. A transfer function maps one input fact on one typed edge to zero or more output facts. Since the kernel applies that unary relation independently to each reached fact and unions the results, the accepted problem is a distributive may problem.

Path quality describes the strongest individual path retained for one reached state. It has independent proof and completeness axes derived monotonically from traversed edges. Global coverage records every reachable unproven edge, partial edge, and stopped ICFG boundary, because any of them can hide additional facts even when already reached facts remain useful.

## Plan of Work

Create `src/analyzer/dataflow/problem.rs`. Define the dense `FactId`, typed `DataflowSeed<Fact>`, and a procedure-local `DataflowEdge` descriptor containing semantic endpoint handles, kind, call origin, proof, and completeness without snapshot IDs or expanded contexts. Define `DistributiveDataflowProblem` with an orderable, copyable, hashable associated `Fact`, a distinguished `zero_fact`, and separate `normal_flow`, `call_flow`, `return_flow`, `call_to_return_flow`, and `exceptional_flow` callbacks. Define `BoundedSnapshotDataflowProblem` only for explicit context-specific snapshot seeds. No callback receives the whole reached set or a protocol type.

Create cohesive private dataflow contract modules behind one stable facade: `input.rs` for `IcfgInputStatus`, checked `IcfgSolveInput` conversion, and malformed-input errors; `budget.rs` for solver work, dimensions, limits, and request controls; `quality.rs` for concrete path quality and its nondominated frontier; and `result.rs` for termination, coverage, reached rows, and result accessors. A result is globally complete only when its input status is complete, termination reached a fixed point, and no reachable unproven edge, partial edge, or ICFG boundary was observed.

Create `src/analyzer/dataflow/tabulation.rs`. Rely on the sealed `IcfgSnapshot` edge invariants and validate every emitted seed node. Intern the zero fact first, inject it beside every explicit seed, canonicalize seeds by `(node, fact)`, and use a FIFO `VecDeque` plus hash-backed reached/interner tables. Never iterate a hash table to schedule work. Route callbacks through bounded, cancellation-aware output sinks that deduplicate against one deterministic row cap, then canonicalize the complete retained relation and preflight its full multidimensional publication charge. For each current state and nondominated path-quality profile, traverse the already canonical successor row, invoke exactly one transfer family, preserve zero automatically, check cancellation, stage all work charges, then publish fact IDs and new or quality-improved states atomically. Requeue a profile only when it is newly admitted to a state's frontier. Freeze facts and reached rows deterministically.

Create `src/analyzer/dataflow/direct.rs`. Implement a one-fact `DirectFlowProblem` whose sole fact is the kernel-preserved zero fact, so its five callbacks need not reproduce identity propagation. Its constructor accepts explicit seed node IDs; it never assumes that dense node zero is the analysis root. This is a small real client rather than a typestate-shaped test double.

Create `src/analyzer/dataflow/mod.rs` to document and re-export the public surface. Add `pub mod dataflow;` to `src/analyzer/mod.rs`.

Create `tests/common/dataflow_reference.rs`. Implement an intentionally slow fixed-point by repeatedly scanning all ICFG edges and all currently reached typed facts in canonical order until no fact changes. It must independently classify the five edge families and use a `BTreeMap` or `BTreeSet` for clarity. It has no compact worklist, budgets, summary cache, witness table, or production interner. Add it to `tests/common/mod.rs`.

Create `tests/dataflow_tabulation.rs`. Use `InlineTestProject` and the public ICFG provider to build small TypeScript and Rust snapshots. Differentially compare the worklist and repeated-scan solvers for loops, fact generation and killing, direct calls, two call sites to one callee, normal and exceptional returns, and deferred normal/exceptional call-to-return edges. Assert repeat-run equality under seed and transfer-output permutations, including simultaneous constrained budgets, and reject invalid seed IDs. Test malformed edge endpoints and missing interprocedural origins at the private snapshot-sealing boundary, because published snapshots cannot contain them.

Create `tests/dataflow_clients.rs`. Run `DirectFlowProblem` through the same public solver and prove its reached nodes equal bounded ICFG reachability. Cover input-quality preservation, a reachable recursive-depth boundary, cancellation before seeding and during propagation, all five budget dimensions, ignored-stop callback bursts, and tighter cross-dimension limits. Cancellation during propagation can be deterministic by letting a test problem cancel a shared token from its first transfer callback; the solver's post-callback checkpoint must win before output publication.

After focused behavior is green, run formatting and strict lint. Then run the feature-enabled repository tests required by the local instructions. Finally, run parallel security, duplication, intent, operational, and architecture review over the completed diff, resolve all high-risk findings, and update this plan with evidence and retrospective.

## Concrete Steps

Run all commands from the repository root:

    /Users/dave/.codex/worktrees/547e95c0-eeb5-4cbf-90c7-b86162312407/bifrost

Confirm the exact starting state:

    git status --short --branch
    git rev-parse HEAD
    git rev-list --left-right --count HEAD...origin/master

Expected before edits:

    ## HEAD (no branch)
    ?? .brokk/
    447638f181cfb915aa77c989234169e6e6b89ea6
    0  0

The `.brokk/` directory is an untracked analyzer cache and must not be staged, deleted, or treated as part of this issue.

After implementing the first contract and kernel, run:

    cargo fmt
    cargo test --test dataflow_tabulation --test dataflow_clients

Expected: both new test binaries report `test result: ok`, and the differential tests report exact equality between canonical reached rows from the worklist and reference implementations.

Run the existing ICFG contract beside the new solver tests:

    cargo test --test icfg_contract --test dataflow_tabulation --test dataflow_clients

Expected: the existing matched-call topology remains unchanged and all three test binaries pass.

Run strict lint in a self-cleaning isolated target:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Expected: Clippy exits successfully with no warnings.

Run the full feature-enabled gate on macOS with the repository's PyO3 linker mode:

    env RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup' \
        BIFROST_SEMANTIC_INDEX=off \
        scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Expected: all enabled library and integration tests pass, with only repository-documented ignored tests. No semantic model downloads or real semantic-index threads may start.

## Validation and Acceptance

The problem contract is accepted when a client can supply a finite ordered fact type, a distinguished zero fact, reusable procedure-local implementations of all five unary transfer families, and a separate set of explicit context-specific seeds for the bounded snapshot runner without importing typestate, taint, heap, policy, or language-adapter types.

The kernel is accepted when direct, call, return, call-to-return, and local exceptional edges each invoke exactly one matching callback; zero is injected at every seed and survives every edge without preventing callbacks from generating facts; `Cleanup` stays visible as its original control kind; invalid seeds fail rather than appearing as isolated nodes; and matched returns never cross call contexts.

Determinism is accepted when seed and output permutations produce byte-for-byte equal typed results, work reports, coverage rows, fact IDs, and reached ordering. Internal hash iteration must not influence scheduling or output.

Budgeting is accepted when each of `interned_facts`, `reached_states`, `flow_evaluations`, `callback_rows`, and `propagated_outputs` can independently stop a run with an exact typed `SolverBudgetExceeded` value. A failed charge publishes none of that transfer's staged facts or states. Cancellation before and during work returns `Cancelled`, retains deterministic prior partial results, and wins over output publication after a callback cancels the token.

Completeness is accepted when input `Unknown`, `Unsupported`, `Unproven`, `ExceededBudget`, or `Cancelled` status survives into the result; a reachable partial/unproven edge or boundary prevents `is_complete`; and already reached may facts remain available. A recursive call-depth frontier must stay explicitly incomplete rather than being described as summary convergence.

The differential reference is accepted when it independently reaches the same typed `(node, fact)` set on every small fixture. The direct client is accepted when its one fact follows all available ICFG edge families and its reached node set equals ordinary bounded graph reachability.

No acceptance claim in this child covers reusable end summaries, true recursion beyond `IcfgSnapshotLimits`, canonical bypass edges for every resolved call, witnesses, IDE values/edge functions, value or heap bindings, taint, FSA typestate, persistence, policy, or query integration.

## Idempotence and Recovery

The implementation is additive. Re-running formatting and tests is safe. Solver runs borrow immutable snapshots and client definitions; all fact IDs, reached tables, queues, budgets, and coverage rows are run-local. A cancelled or budget-exhausted run cannot publish a cache entry because this child has no reusable cache.

If a transfer fails a budget charge, leave that transfer's output unpublished and return the deterministic partial result accumulated before it. If a source fixture produces an incomplete ICFG, preserve that status and continue only over the available snapshot. Do not fabricate missing recursive, external, or deferred control.

If strict validation exposes a design problem, update the Decision Log before changing the contract. Do not add a fallback text scan, duplicate ICFG, second call stack, storage row, or typestate-specific branch to make a fixture pass.

## Artifacts and Notes

The live issue is `#820 — Epic: Implement a modular meet-over-valid-paths solver kernel`. Its current first-child foundation is commit `447638f1`.

The most important pre-implementation evidence is:

    IcfgNodeKey = ProgramPointHandle + boxed call-site context
    IcfgEdgeKind = Intraprocedural | Call | NormalReturn | ExceptionalReturn
                   | CallToNormalContinuation | CallToExceptionalContinuation
    IcfgProvider::snapshot -> SemanticOutcome<IcfgSnapshot>

The first-child flow is:

    outcome-derived ICFG input + typed seeds
                    |
          deterministic fact interning
                    |
       FIFO propagation over canonical edges
                    |
       reached facts + path/input quality
                    |
       fixed point | cancelled | exact budget

## Interfaces and Dependencies

In `src/analyzer/dataflow/problem.rs`, define these public contracts, allowing minor naming refinement during implementation only if the Decision Log is updated:

    pub struct FactId(u32);

    pub struct DataflowSeed<F> {
        pub node: IcfgNodeId,
        pub fact: F,
    }

    pub struct DataflowEdge<'graph> {
        edge_id: IcfgEdgeId,
        edge: &'graph IcfgEdge,
        source: &'graph IcfgNodeKey,
        target: &'graph IcfgNodeKey,
    }

    pub trait DistributiveDataflowProblem {
        type Fact: Copy + Eq + Hash + Ord;

        fn zero_fact(&self) -> Self::Fact;
        fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>);
        fn normal_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut dyn DataflowOutput<Self::Fact>);
        fn call_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut dyn DataflowOutput<Self::Fact>);
        fn return_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut dyn DataflowOutput<Self::Fact>);
        fn call_to_return_flow(
            &self,
            edge: DataflowEdge<'_>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        );
        fn exceptional_flow(
            &self,
            edge: DataflowEdge<'_>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        );
    }

Across `src/analyzer/dataflow/{input,budget,quality,result}.rs`, define and re-export:

    IcfgInputStatus
    IcfgSolveInput<'graph>
    SolverWork
    SolverBudgetDimension
    SolverBudget
    SolverBudgetExceeded
    DataflowRequest<'request>
    PathQuality
    DataflowCoverage
    SolverTermination
    ReachedFact
    DataflowResult<Fact>
    DataflowError

In `src/analyzer/dataflow/tabulation.rs`, expose:

    pub fn solve<P: DistributiveDataflowProblem>(
        input: IcfgSolveInput<'_>,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<DataflowResult<P::Fact>, DataflowError>;

Use only existing standard-library and repository dependencies: `VecDeque`, ordinary vectors and boxed slices, `crate::hash::{HashMap, HashSet}`, current semantic ICFG/provider types, and `CancellationToken`. Do not add a graph, solver, property-test, persistence, or algebra crate in this child.

Plan revision note (2026-07-23): Created the issue-specific plan after live GitHub verification, detached-worktree synchronization, current-API code navigation, and three parallel architecture/precedent audits. The plan corrects the older roadmap sketch from procedure-local CFG IDs to context-specific `IcfgSnapshot` IDs, makes input quality mandatory, and narrows this child to bounded deterministic propagation so later summary and IDE work remains honest. Finalized it after five specialist review categories, two architecture corrections, focused and differential coverage, strict lint, and the complete feature-enabled regression gate.
