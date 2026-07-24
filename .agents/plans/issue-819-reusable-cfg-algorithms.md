# Implement reusable, bounded CFG algorithms for issue #819

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation proceeds. Follow `.agents/PLANS.md` when revising it.

## Purpose / Big Picture

Bifrost’s immutable per-callable control-flow graphs already expose dense point and edge identities plus canonical outgoing and incoming adjacency. The ICFG builder nevertheless contains its own forward and reverse graph walk to decide which semantic gaps can affect a particular return. Issue #819 introduces one crate-internal, bounded, stack-safe algorithm layer over that existing representation and immediately makes the ICFG return-path calculation its first production consumer.

After this work, internal analysis code can ask for deterministic reachability, DFS order and reverse postorder, strongly connected components, SCC-derived loop regions, or a shortest witness path without reimplementing graph traversal. Every operation cooperates with cancellation, independently limits node and edge visits, and either returns a complete result or a typed stop reason; it never publishes an exact-looking partial answer. The new layer does not add a public query, RQL field, dependency, persisted artifact, or global memoization.

Dominators and post-dominators are deliberately not part of this work. The present data-flow solver does not consume them, heap strong updates use explicit certificates, and the roadmap has no named SSA, control-dependence, or dominance-pruning client. The benchmark and evidence note record this as a no-go decision rather than unfinished implementation.

## Progress

- [x] (2026-07-24 10:35+02:00) Verified the attached issue branch, fetched `origin`, confirmed the branch is clean at `7748331e`, and found the one newer `origin/master` commit is release-metadata-only with no overlap.
- [x] (2026-07-24 10:44+02:00) Audited the immutable CFG representation, ICFG return-mask cache, cancellation and budget conventions, existing lifecycle benchmarks, and the broader typestate roadmap.
- [x] (2026-07-24 11:26+02:00) Implemented the dense bidirectional `ProcedureSemantics` view, shared node/edge budgets and cancellation, complete iterative reachability/DFS/Kosaraju/loop/path algorithms, and seven synthetic tests including a 100,000-node chain.
- [x] (2026-07-24 11:42+02:00) Replaced the ICFG builder’s bespoke return-path traversals with shared forward/reverse reachability while preserving precharge/cancellation/cache behavior; all 41 CFG, 25 ICFG, and 11 tabulation contracts plus the new artifact-isolation unit regression pass.
- [x] (2026-07-24 13:06+02:00) Added and compiled the ignored release benchmark and pinned-corpus runner, covering six algorithm families over deep, branch-heavy, cyclic, irreducible, disconnected, exceptional, VS Code, and PetClinic datasets with versioned provenance-rich JSON output.
- [ ] Add the ignored release benchmark, runner, versioned JSON output, lifecycle evidence note, and roadmap checkpoint.
- [ ] Run focused tests, the benchmark matrix, formatting, strict all-feature Clippy, and the complete `nlp,python` suite.
- [ ] Complete specialist review, resolve material findings, and record final outcomes.

## Surprises & Discoveries

- Observation: `ProcedureSemantics` already has every base relation required by the algorithm layer.
  Evidence: its points and control edges use dense typed IDs, and its successor/predecessor iterators follow the immutable canonical edge arrays. No representation conversion or graph dependency is needed.

- Observation: the current return-path cache is already at the correct lifecycle boundary.
  Evidence: `SnapshotBuilder::return_path_masks` is keyed by `(ProcedureHandle, exit)` and exists only while constructing one ICFG snapshot. `ProcedureHandle` includes the immutable artifact instance, so equal-looking procedures from distinct artifacts cannot alias.

- Observation: current production consumers do not repeatedly derive whole-snapshot RPO, SCCs, loops, or paths.
  Evidence: repository searches find only the return-affecting gap traversal as a repeated local graph derivation; the solver performs its own problem-state worklist and heap strong updates use explicit update certificates.

- Observation: the existing CFG iterators were concretely double-ended but their opaque public return bounds did not advertise that fact.
  Evidence: the generic view initially could not preserve reverse canonical stack insertion through the opaque iterator type. Adding the truthful `DoubleEndedIterator` bound required no representation or behavior change.

## Decision Log

- Decision: define a crate-private `DenseBidirectionalGraph` trait with dense node lookup, canonical successor and predecessor iterators, and typed edge endpoint lookup, then implement it directly for `ProcedureSemantics`.
  Rationale: algorithms remain representation-independent without allocating an adapter graph, and the production implementation preserves the canonical CFG edge order.
  Date: 2026-07-24.

- Decision: use one mutable request object containing a two-dimensional node/edge budget and a borrowed cancellation token.
  Rationale: all algorithms share exact accounting and stop classification, while callers choose request-local limits. A failed operation returns only its typed stop reason and accumulated work, never a partial result.
  Date: 2026-07-24.

- Decision: implement DFS, Kosaraju, component walks, and path reconstruction iteratively.
  Rationale: callable graphs can be deep or adversarial; the 100,000-node chain test must not depend on the process stack.
  Date: 2026-07-24.

- Decision: define loop regions from cyclic SCCs and call them loop regions, not natural loops.
  Rationale: SCC membership does not prove dominance. Regions retain self-loops, external entry nodes, traversal-relative DFS back edges, and explicit single-entry versus multi-entry structure without implying reducibility.
  Date: 2026-07-24.

- Decision: retain only the existing query-local ICFG return-mask memoization.
  Rationale: it has a demonstrated repeated consumer and immutable-artifact scope. RPO, SCC, loop, and path results remain on demand because no production path currently repeats the same whole-snapshot derivation.
  Date: 2026-07-24.

- Decision: do not implement dominators or post-dominators under #819.
  Rationale: there is no named consumer, benchmark target, or correctness claim requiring them. Adding unused dominance machinery would create validation and lifecycle obligations without product evidence.
  Date: 2026-07-24.

## Outcomes & Retrospective

This section will be completed after implementation, measurement, validation, and review. It will state the checkpoint commits, exact gates run, benchmark artifact location, measured lifecycle decision, and any remaining work outside #819.

## Context and Orientation

`src/analyzer/semantic/ir/artifact.rs` owns `ProcedureSemantics` and its immutable `ControlFlowGraph`. `ProgramPointId` and `ControlEdgeId` are dense typed identities. `ProcedureSemantics::successor_edges` and `predecessor_edges` expose the canonical adjacency.

The new `src/analyzer/semantic/cfg_algorithms.rs` module is crate-private and is registered from `src/analyzer/semantic/mod.rs`. It owns the generic graph contract, request-local budgets and stop reasons, complete result types, and the iterative algorithms.

`src/analyzer/semantic/icfg.rs` owns `SnapshotBuilder`. Its `return_path_masks` map currently memoizes the intersection of points reachable from a callee entry and points that can reach a selected exit. The refactor must preserve its existing up-front `SemanticWork` charge, cancellation-to-snapshot-quality behavior, and `(ProcedureHandle, ProgramPointId)` cache key.

The ignored benchmark is a test target exercised by `scripts/run-cfg-algorithm-benchmarks.sh`. It measures synthetic deep chains, branch-heavy graphs, reducible and multi-entry cycles, disconnected regions, exceptional/multiple-exit topology, and materialized procedures from the same pinned VS Code and Spring PetClinic revisions used by `tests/measure_semantic_cfg.rs`. Output is versioned JSON containing exact repository and toolchain provenance, absolute cold and repeated timings, visited work, stable result digests, and retained result-byte estimates.

The durable interpretation is recorded in `.agents/docs/issue-819-cfg-algorithm-benchmark-2026-07-24.md`. The broader roadmap checkpoint is `.agents/plans/language-agnostic-composable-typestate-platform.md`.

## Plan of Work

### Milestone 1: generic algorithms

Add the crate-private module and trait. A graph maps every valid typed node to one dense index and back, exposes canonical directed adjacency in both directions, and resolves typed edge identities to endpoints. The production implementation delegates to `ProcedureSemantics`.

Add two-dimensional work accounting and a request object borrowing a `CancellationToken`. Each first node visit charges one node; each examined adjacency charges one edge. Budget exhaustion reports the failed dimension, limit, attempted amount, and already completed work. Cancellation reports completed work. Invalid nodes are a separate input error. Results are returned only from successful calls.

Implement forward and reverse reachability with dense-order result iteration. Implement a traversal forest using explicit enter, edge-examine, and finish actions so preorder, postorder, reverse postorder, and gray-target back edges have deterministic iterative semantics. Implement iterative Kosaraju SCC decomposition; sort members by dense index and components by their smallest member, then remap component identities. Derive loop regions from SCCs of size greater than one or singleton SCCs with a self-edge. Preserve external entry nodes, use the first dense member as the entry for a closed/root cyclic region, retain internal DFS back-edge identities, and distinguish one from multiple entries. Implement canonical-adjacency breadth-first shortest paths with both node and edge sequences and deterministic first-parent tie breaking.

Unit tests use a small immutable test graph whose edge constructor deliberately accepts permuted and parallel rich edges before canonicalization. Cover all topologies and stop modes in the issue request, including a 100,000-node chain and cancellation triggered after a deterministic number of checks.

### Milestone 2: ICFG consumer

Replace the two bespoke stacks in `cache_return_path_mask` with the shared forward and reverse reachability operations. Continue to precharge exactly the existing `SemanticWork`; give the algorithm request limits equal to that operation’s full point/edge scan allowance so the new internal budget cannot change a successfully precharged result. Translate cancellation to `SnapshotQuality::Cancelled`; an internal budget stop is an invariant failure because the semantic budget already reserved twice the full graph.

Add a regression that proves return-affecting gaps on entry-to-exit paths weaken only the same returns as before, while disconnected gaps do not. Add an artifact-isolation regression using distinct immutable artifacts with equal local procedure identities/topology differences, proving the builder never reuses a mask across artifact instances.

### Milestone 3: measurement and evidence

Add the ignored release benchmark and runner. The runner validates or obtains the pinned corpora using the existing environment-variable convention, records multiple independent samples, and writes a schema-versioned JSON artifact without rewriting source files. Synthetic cases provide guaranteed coverage even when external corpora are unavailable; a retained evidence run must include both exact pinned repositories.

For each graph, compute all algorithms cold and repeatedly, black-box results, record exact node/edge work, stable digests, and conservative retained result bytes. Verify every repeat has the same digest and work. Record absolute durations rather than only ratios, plus Bifrost commit/tree state, corpus commits/dirty state, Rust/Cargo/OS/architecture/profile, and timer semantics.

Write the evidence note with stack-safety and determinism results, repeated-consumer audit, cache/persistence decision, and dominance no-go. Mark the broader roadmap #819 checkpoint complete only after focused validation and review.

### Milestone 4: validation and review

Run the requested focused library and integration tests, ignored release matrix, formatting check, isolated strict all-target/all-feature Clippy, and complete `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python`.

Review the final diff for security/boundary behavior, duplication, Rust correctness and tests, benchmark/automation portability, and architecture/lifecycle consistency. Resolve material findings and rerun affected gates. Update this plan’s living sections before each checkpoint commit.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/20ff/bifrost`.

    cargo test --lib analyzer::semantic::cfg_algorithms
    cargo test --no-default-features --test semantic_cfg_contract --test icfg_contract --test dataflow_tabulation
    scripts/run-cfg-algorithm-benchmarks.sh
    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

Checkpoint commits are made on the current issue branch after each milestone. Stage only files changed for #819. Do not push or open a pull request.

## Validation and Acceptance

Acceptance requires:

1. Synthetic tests prove canonical deterministic results despite edge-construction permutation and parallel typed edges.
2. Every traversal is iterative and the 100,000-node chain passes without stack growth.
3. Reachability, DFS/RPO, SCC, loop regions, and shortest paths correctly cover self-loops, nested and irreducible cycles, disconnected regions, exceptional/multiple exits, zero-length and unreachable paths, and invalid nodes.
4. Node and edge exhaustion, pre-cancellation, and deterministic mid-traversal cancellation return typed failures with no result.
5. ICFG behavior is unchanged for return-affecting gaps and masks cannot cross artifact instances.
6. The release benchmark emits reproducible schema-versioned JSON with cold/repeat timings, work, digests, retained bytes, and exact provenance, including both pinned external corpora in the retained evidence.
7. The evidence note justifies query-local return-mask memoization, rejects broader persistence, and records dominance as an evidence-backed no-go.
8. All listed test, formatting, Clippy, and full-feature gates pass after specialist review.

## Idempotence and Recovery

The algorithms are pure over immutable snapshots except for request-local accounting. Re-running tests or benchmarks does not mutate analyzer caches beyond ordinary test-local state. Benchmark output is written to an explicit caller-selected path; rerunning replaces only that artifact after a successful complete measurement.

If an algorithm fails, its `Result` contains no partial analysis value. If the ICFG integration is interrupted, the builder does not insert a return mask. If a checkpoint gate fails, update this plan with the discovery, fix the root cause, and rerun the smallest affected gate before the full sequence.

The script must use repository-relative paths, `mktemp` for temporary state, and cleanup traps. It must not create manually named Cargo target directories. External corpus commits and dirty state are checked before retained evidence is accepted.

## Artifacts and Notes

The implementation produces:

- `src/analyzer/semantic/cfg_algorithms.rs`
- focused unit and ICFG regression tests
- `scripts/run-cfg-algorithm-benchmarks.sh`
- a schema-versioned benchmark JSON artifact under `.agents/docs/`
- `.agents/docs/issue-819-cfg-algorithm-benchmark-2026-07-24.md`
- an updated #819 checkpoint in `.agents/plans/language-agnostic-composable-typestate-platform.md`

The benchmark digest is a deterministic validation fingerprint, not a cryptographic API commitment. Retained byte counts are conservative owned-result estimates and exclude immutable base CFG storage.

## Interfaces and Dependencies

The module remains crate-private. Its conceptual interfaces are:

    trait DenseBidirectionalGraph {
        type Node;
        type Edge;
        fn node_count(&self) -> usize;
        fn node_at(&self, index: usize) -> Option<Self::Node>;
        fn node_index(&self, node: Self::Node) -> Option<usize>;
        fn successors(&self, node: Self::Node)
            -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + DoubleEndedIterator + '_;
        fn predecessors(&self, node: Self::Node)
            -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + DoubleEndedIterator + '_;
        fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)>;
    }

    struct CfgAlgorithmRequest<'a> {
        budget: &'a mut CfgAlgorithmBudget,
        cancellation: &'a CancellationToken,
    }

Operations return `Result<CompleteResult, CfgAlgorithmError>`. Successful result types expose canonical dense-order membership or ordered node/edge identities plus exact work used. The implementation uses only the Rust standard library and existing Bifrost semantic types and cancellation token.

Revision note (2026-07-24): Created the focused issue #819 execution record after live branch, source, consumer, lifecycle, and benchmark-boundary verification.

Revision note (2026-07-24): Marked Milestone 1 complete after the focused algorithm suite passed all seven tests, including the 100,000-node stack-safety case.

Revision note (2026-07-24): Marked Milestone 2 complete after shared reachability replaced the ICFG stacks and the focused contract matrix plus distinct-artifact cache regression passed.

Revision note (2026-07-24): Added the compiled release measurement harness and runner; retained measurement, evidence interpretation, and roadmap closure remain.
