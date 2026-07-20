# Separate CodeQuery planning, execution, profiling, and shared graph materialization

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this work, a `query_code` request will no longer use its parsed recursive expression as its execution strategy. Bifrost will lower the authored query into an explicit logical dependency graph, choose concrete physical operators, and execute those operators through a bounded scheduler. A user will be able to inspect an explain view before execution and a profile after execution, including operator timing, cardinality, shared-cache behavior, dependency waiting, scheduling overhead, and concurrency. Independent union branches will run concurrently only when measurements show that scheduling them is faster than the current sequential path.

The work also creates a safe boundary for expensive derived graph layers. Concurrent branches requesting the same graph snapshot will share one complete in-flight materialization. If profiling identifies a stable SQL-backed relation worth loading into memory, Bifrost will bulk-read only the required columns, remap persistent identities to typed dense IDs, and freeze an immutable compact adjacency snapshot. SQL-backed graph loading is a measured later optimization, not a prerequisite for the first planning refactor.

The first independently verifiable milestone is deliberately sequential. Existing JSON and Rune Query Language (RQL) inputs lower to a dense logical directed acyclic graph, physical planning selects explicit sequential set operators, the current semantics execute through that physical plan, and an internal structured profile reports `peak_concurrency = 1`. No Rayon task, future, or guessed scheduling threshold is introduced in that milestone.

## Progress

- [x] (2026-07-20 14:28Z) Confirmed the clean issue branch, fetched `origin`, verified the branch equals current `origin/master` and its upstream at `ce79d33b`, and read live issue #918.
- [x] (2026-07-20 14:28Z) Traced the parser, recursive executor, branch budgets, shared request caches, compact graph primitives, persisted snapshot path, semantic single-flight cache, and focused regression suites.
- [x] (2026-07-20 14:28Z) Inspected the reference implementation's SQL-to-memory graph techniques and separated transferable techniques from unsuitable sparse-ID, repeated-build, and quadratic paths.
- [x] (2026-07-20 14:28Z) Chose the storage-neutral sequential plan spine and the measured later graph-materialization boundary described below.
- [x] (2026-07-20 15:09Z) Milestone 1: lowered authored queries into a logical DAG, selected and executed an explicit sequential physical plan without public semantic change, added opt-in structured explain/profile observations, completed adversarial review, and passed the focused tests plus strict all-target/all-feature Clippy.
- [ ] Milestone 2: complete operator instrumentation and benchmark representative compositional queries before defining a scheduling heuristic.
- [ ] Milestone 3: introduce exact derived-layer dependency keys and cancellation-aware complete-value single-flight, then run a promote-or-discard SQL-to-memory graph materialization experiment.
- [ ] Milestone 4: add a bounded scheduler plus sequential and parallel union implementations, select between them with benchmark-derived policy, and preserve deterministic semantics and budgets.
- [ ] Milestone 5: expose explain/profile through the supported query surfaces, document measured thresholds and rejected alternatives, and complete adversarial review and repository validation.

## Surprises & Discoveries

- Observation: `CodeQueryPlan` is already a semantic recursive tree, but it is also the execution strategy.
  Evidence: `src/analyzer/structural/search.rs::execute_plan` directly pattern-matches `CodeQueryPlanSource`, recursively executes branches in authored order, assigns fair budgets from cumulative mutable state, and immediately combines rows.

- Observation: the current request state already shares completed structural seeds and several semantic caches, so the new plan boundary must preserve those reuse and charging semantics before adding concurrency.
  Evidence: `QueryExecutionState` owns `seed_cache`, `indexed_declarations`, `reference_cache`, `call_cache`, and the lazy `DirectImportGraph`; focused tests prove complete and truncated seed reuse, roll-forward budgets, branch provenance, and root-only limits.

- Observation: Bifrost already contains a cancellation-aware same-key single-flight implementation that publishes complete values only.
  Evidence: `CompleteSemanticArtifactCache` in `src/analyzer/semantic/service.rs` uses a retained-value cache, an in-flight leader/follower map, cancellation-polled waiters, retry after an incomplete leader, and tests proving one lowerer call for concurrent requests. Later query graph caching should generalize or reuse this lifecycle instead of cloning it.

- Observation: `PoolSafeMemo` deliberately permits duplicate builds in some Rayon contexts.
  Evidence: blocking a worker on work queued to the same saturated pool previously deadlocked. A query scheduler must model dependency waiting or use a build executor that cannot starve, rather than placing a naive condition variable around arbitrary Rayon work.

- Observation: existing compact graph types are useful implementation evidence but are not a drop-in query graph cache.
  Evidence: `CompactDirectedGraph<K>` needs a complete node list and edge vector, sorts the edge list twice, duplicates endpoint adjacency for both orientations, and has no generation key, cancellation, tracing, or in-flight lifecycle. `ControlFlowGraph` in `src/analyzer/semantic/ir.rs` is the stronger pattern: one canonical rich-edge table, outgoing row boundaries, and incoming edge IDs built by count, prefix sum, and scatter.

- Observation: persisted structural snapshots proved large warm materialization wins but also measurable cold and storage costs.
  Evidence: the 200-file benchmark improved warm materialization from 140.420 ms to 43.573 ms and the 400-file benchmark from 539.081 ms to 144.334 ms, while cold materialization regressed 16.8–21.1 percent and database size grew roughly 37–38 percent. This supports measuring a specific stable relation rather than persisting every graph.

- Observation: the reference repository's useful loader pattern is narrower than its product claims.
  Evidence: its good paths bulk-select graph-critical columns, remap persistent IDs to dense local IDs, preallocate adjacency, and build compressed sparse rows. Other paths rebuild on every request, allocate from `MAX(id) + 1` without a sparsity guard, or use linear endpoint lookup and edge deduplication. Bifrost should borrow the former techniques and reject the latter.

- Observation: Bifrost navigation found the relevant executor symbols, but `scan_usages_by_location` omitted known external uses of `CodeQueryPlan` and `DetailedCodeQueryResult`; a multi-target scan also stalled while individual scans were fast. `search_git_commit_messages` associated at least one hash with the next commit's message.
  Evidence: direct symbol reads and local `rg`/`git show` confirmed the missing uses and corrected the commit mapping. Treat these as separate Bifrost tooling follow-ups, not as evidence about issue #918's implementation.

- Observation: lowering one authored step suffix into individual DAG nodes exposes control-flow state that the recursive executor previously carried implicitly.
  Evidence: exact parity required `final_in_authored_suffix` on step nodes plus a private halted-pipeline result bit. Without them, cancellation could retain a wrong-domain intermediate row or a later step could run after an earlier step exhausted its budget. Cancellation polling also had to remain at authored Seed/Set entry, immediately before each Step, and at root Limit finalization so test cancellation checkpoints did not move.

- Observation: a shared DAG node and one execution of an incoming dependency edge are different identities.
  Evidence: two union branches can reference one interned Seed node while each occurrence still replays diagnostics and charges its fair branch budget. Profile observations now retain the shared node ID and a stable nested branch-slot path, so later parallel completion order cannot erase per-invocation attribution.

- Observation: useful profiles must not turn semantically distinct same-topology queries into the same explanation or distort the ordinary path being measured.
  Evidence: explain nodes now include canonical seed and step JSON, authored suffix finality, set operator, and limit count. Profiling is opt-in; ordinary detailed and public execution allocates no explain, branch path, observation vector, or `Instant` timer. Observations distinguish completed, skipped, and cancelled operators and separate operator-local clipping from the aggregated result status.

- Observation: this machine has rustup Cargo before Homebrew Cargo but Homebrew `cargo-clippy` before rustup's proxy on `PATH`.
  Evidence: plain `cargo clippy` compiled dependencies with the pinned rustup compiler and then invoked Homebrew Clippy, yielding `E0514` incompatible-compiler metadata despite the same displayed release. Direct `rustup run 1.96.0 cargo-clippy` used the pinned driver and passed the strict gate.

## Decision Log

- Decision: keep the authored `CodeQueryPlan` frontend unchanged in the first milestone and lower it into a new internal `LogicalQueryPlan`.
  Rationale: JSON, RQL, schema validation, editor support, and public clients already agree on this semantic IR. Separating execution does not require another public syntax migration.
  Date/Author: 2026-07-20 / Codex

- Decision: represent the logical plan as an arena of typed dense node IDs with explicit `Seed`, `Step`, `Set`, and terminal `Limit` nodes.
  Rationale: arena IDs make dependencies cheap to reference, make shared seeds a real DAG rather than duplicated tree nodes, provide stable profile identities, and keep traversal bounded by the existing 64-node and depth-16 parser contract.
  Date/Author: 2026-07-20 / Codex

- Decision: intern exact repeated seeds by the existing canonical structured seed key, while retaining ordered dependency edges for every branch occurrence.
  Rationale: two branches may share seed materialization but still need distinct branch provenance, budgets, and downstream steps. Sharing the seed node exposes reusable work without collapsing semantic branch edges.
  Date/Author: 2026-07-20 / Codex

- Decision: make physical set choices explicit as `SequentialUnion`, `SequentialIntersection`, and `SequentialExcept` before adding alternatives.
  Rationale: a concrete physical operator boundary is independently explainable and testable now and later permits `ParallelUnion` or a dense-ID set implementation without changing parsing or logical semantics.
  Date/Author: 2026-07-20 / Codex

- Decision: preserve the current deterministic evaluation, provenance, cancellation, truncation, and fair roll-forward budget behavior in Milestone 1.
  Rationale: the first refactor establishes measurement seams. Concurrency and cost policy must not be entangled with proving semantic parity.
  Date/Author: 2026-07-20 / Codex

- Decision: instrument before selecting scheduling thresholds.
  Rationale: branch cost depends on cold versus warm state, repository and language mix, output cardinality, shared dependency contention, and merge overhead. Semantic labels such as `union` or `imports_of` are not sufficient cost estimates.
  Date/Author: 2026-07-20 / Codex

- Decision: use exact versioned derived-layer cache keys and publish only complete immutable values.
  Rationale: a cache key must distinguish workspace/store generation, graph kind, projection or filter, resolver configuration, and representation version. Partial or cancelled graph builds cannot support complete negative conclusions and must not enter the ready cache.
  Date/Author: 2026-07-20 / Codex

- Decision: do not wire SQL or `CompactDirectedGraph` into the first milestone.
  Rationale: the store currently serializes access through one connection mutex, existing graph/snapshot shapes do not carry the scheduler lifecycle, and prior experiments show that compacting the final adjacency can miss the resolver-dominated cost. Profiling must identify the exact stable intermediate first.
  Date/Author: 2026-07-20 / Codex

- Decision: when a SQL-backed graph experiment is justified, use minimal ordered projections, a sparsity-aware persistent-to-dense remap, exact preallocation, count/prefix-sum/scatter adjacency, and one canonical payload table referenced by both orientations.
  Rationale: these techniques minimize SQL decoding, hashing, sorting, allocation, and payload duplication while retaining Bifrost's typed semantic identities. A density guard avoids allocating memory proportional to a sparse persistent ID maximum.
  Date/Author: 2026-07-20 / Codex

- Decision: profile repeated DAG-node executions by both shared node ID and stable authored branch-slot path.
  Rationale: node identity describes reusable logical work; branch path describes the invocation that owns budget admission, provenance, diagnostics, and later scheduler placement. Keeping both prevents parallel completion order from becoming accidental attribution.
  Date/Author: 2026-07-20 / Codex

- Decision: make profiling an explicit opt-in collector and record operator disposition separately from forwarded row cardinality and aggregated result status.
  Rationale: normal queries should not pay measurement overhead, while a skipped parent may legitimately forward a cancelled child's terminal-domain partial rows. A disposition plus operator-local and propagated status represents that case without claiming the parent produced those rows.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. Parsed JSON and RQL now converge on a dense dependency-first logical DAG with exact shared seed nodes, then select a one-to-one physical plan with explicit seed, step, sequential set, and root-limit operators. The existing query path executes through that plan while preserving authored branch order, fair budget roll-forward, cache replay and charging, provenance, diagnostics, cancellation checkpoints, intermediate-step exhaustion, and the global `limit + 1` probe.

The internal opt-in profile carries a semantic physical explanation, stable shared node and branch-invocation identities, self-time, input and forwarded output cardinality, disposition, local clipping, propagated truncation/cancellation, and `peak_concurrency = 1`. Ordinary query and policy execution leave profiling disabled. Review found and corrected explain-semantic loss, invocation ambiguity, skipped-operator status, unconditional instrumentation overhead, hidden set clipping, and forwarded partial-row accounting.

Validation passed with 5 execution-plan tests, 85 structural query tests, 3 focused profile tests, all 73 `code_query_pipelines` tests, `cargo fmt --all`, `git diff --check`, and pinned-toolchain `cargo-clippy --all-targets --all-features -- -D warnings`. No SQL loader, graph cache, scheduler, guessed parallel threshold, public profile surface, or new dependency was added. Those remain explicitly gated by Milestones 2 through 5.

## Context and Orientation

The public query frontend lives under `src/analyzer/structural/query/`. `ir.rs` defines `CodeQuery`, the recursively authored `CodeQueryPlan`, `CodeQuerySeed`, typed `QueryStep` values, and set operators. `decode.rs` validates canonical JSON, `sexp.rs` lowers RQL, and `json.rs` produces canonical structured forms. A `CodeQueryPlan` node currently contains either a seed or a set composition followed by zero or more typed steps. `CodeQuery` owns the result limit and rendering detail.

The current executor is `src/analyzer/structural/search.rs`. `execute_internal` validates the authored plan, constructs a mutable `QueryExecutionState`, and calls recursive `execute_plan`. `execute_seed` scans deterministic candidate files and materializes structural rows. `apply_plan_steps` runs semantic traversals. `fair_branch_limits` reserves part of the remaining request budget for each authored branch. `combine_set_rows` implements exact typed union, intersection, and subtraction while preserving deterministic order and bounded provenance. Rendering happens only after internal execution and must remain outside the physical operators.

The name `QueryPlan` in `src/analyzer/structural/planner.rs` refers only to seed-scan anchor pruning. It is not a whole-query logical or physical plan. New types therefore use the explicit names `LogicalQueryPlan` and `PhysicalQueryPlan` to avoid confusing the two responsibilities.

A directed acyclic graph, or DAG, is a set of nodes connected by one-way dependency edges with no cycles. An arena stores all nodes in one vector and refers to them with small typed integer IDs. In this plan every logical dependency points to an earlier arena node, so node order is also a valid execution postorder and easy to validate.

A physical operator is the implementation chosen for one logical operation. For example, logical union says which sets must be combined, while `SequentialUnion` says to execute and merge the branches in authored order on the current thread. Later `ParallelUnion` can implement the same logical operation through the bounded scheduler.

A derived layer is an expensive reusable analysis value such as a complete import topology, hierarchy relation, call relation, or another resolver intermediate. Single-flight means that concurrent requests for one exact key elect one builder while other consumers wait or yield; all consumers receive the same complete immutable value. Failed, partial, stale, or cancelled construction is not published.

The reusable storage primitives live in `src/compact_graph.rs`. The persisted analyzer store is in `src/analyzer/store/mod.rs`, its schema migrations are under `migrations/cache/`, and structural snapshot hydration is split across `src/analyzer/structural/provider.rs`, `facts.rs`, and `tree_sitter_analyzer.rs`. The semantic artifact lifecycle worth reusing is in `src/analyzer/semantic/service.rs`. The canonical shared-payload bidirectional graph construction pattern is `ControlFlowGraph` in `src/analyzer/semantic/ir.rs`.

The most important behavioral regression suite is `tests/code_query_pipelines.rs`. Existing tests cover exact endpoint identity, branch order, nested composition, common suffix steps, identical complete and truncated seed reuse, fair budgets, rejected-work charging, resumable import graph work, cancellation, and applying the global result limit only after composition.

## Plan of Work

Milestone 1 adds a storage-neutral sequential plan spine. Create `src/analyzer/structural/execution/plan.rs` and its module boundary. Define `LogicalQueryNodeId`, `LogicalQueryPlan`, and explicit logical nodes for seeds, individual typed steps, set operations, and the root limit. Lower a validated `CodeQuery` in bounded postorder. Reuse the existing structured seed cache key to intern exact repeated seeds; keep repeated dependency IDs in set input arrays so branch occurrence and order remain visible. Record each node's terminal `QueryValueKind` and validate that every dependency ID is smaller than its consumer.

Lower the logical arena one-to-one into `PhysicalQueryPlan`. Select `SeedScan`, `PipelineStep`, `SequentialUnion`, `SequentialIntersection`, `SequentialExcept`, and `Limit` operators. Add a deterministic serializable explain model containing physical node ID, logical node ID, operator, typed output domain, and ordered dependencies.

Refactor `search.rs::execute_internal` into the explicit stages `validate and lower -> physical selection -> sequential physical execution -> render`. Execute seed, step, set, and limit nodes through the existing helpers and shared `QueryExecutionState`; do not change those helpers' semantics. Wrap node execution with a structured internal observation containing node ID, operator, elapsed wall time, input rows, output rows, truncation, and cancellation. The request profile contains the physical explain model and `peak_concurrency`, which is exactly one for this milestone. Existing public `query_code` output remains unchanged.

Milestone 2 turns the profile skeleton into decision-grade measurement. Add cache hit, miss, and wait counts; dependency wait time; rows or edges visited; merge time; scheduling overhead; temporary allocation estimates where practical; and cancellation/early-termination markers. Extend the benchmark harness with representative composed queries and versioned machine-readable results. Cover cold and warm caches, distinct and identical branches, small and large outputs, shared graph prerequisites, multiple repository sizes and languages, and sequential versus experimental unconstrained execution. Do not publish a threshold until repeated optimized runs separate scheduler wins from noise.

Milestone 3 creates explicit shared dependency keys and a promote-or-discard graph materialization experiment. Generalize the complete-value single-flight lifecycle from `CompleteSemanticArtifactCache` instead of duplicating leader, waiter, cancellation, retry, and publication logic. The key includes workspace or store generation, derived-layer kind, projection/filter/configuration identity, and representation version. First prove with an in-memory fake layer that concurrent consumers cause one build, cancelled waiters do not cancel the leader, a failed leader wakes a retry, and incomplete results are never cached.

Only then select one stable expensive layer from profile evidence. Its SQL reader must select only identity and topology columns, order rows so grouping is linear, and avoid reconstructing rich `FileState` values. Build a domain-owned node arena and typed dense IDs. If persistent IDs are dense enough, an indexed vector remap is allowed; otherwise use a pre-sized hash remap. Build adjacency with degree counts, prefix sums, and scatter. Store rich edge payload once and use edge IDs for the reverse orientation. Validate all endpoints and boundaries before publishing `Arc<Snapshot>`, then drop temporary remap, degree, and dedup structures. Benchmark SQL scan, decode/remap, freeze, vertices, edges, retained bytes, cold/warm reuse, sibling contention, and invalidation separately. Discard the implementation if end-to-end profile data does not justify it.

Milestone 4 adds the bounded scheduler and real physical alternatives. The scheduler owns a fixed parallelism budget and dispatches only ready DAG nodes. It must not recursively spawn arbitrary tasks from operators. Implement sequential and parallel union as separate physical operators over the same exact typed rows. Keep branch occurrence as edge metadata so shared node materialization can be reused while branch provenance is attached deterministically. Preserve the existing global budgets and reserve work for every branch; synchronize counter admission before committing scans or graph expansion. Propagate cancellation to queued and running work and ensure dependency waits cannot starve the executor. Use measured cost/cardinality/cache state to select parallel union, with sequential as the conservative fallback. Add bitmap-backed set operations only for a domain with proven stable dense identities; do not coerce heterogeneous query domains into one global integer namespace.

Milestone 5 exposes and documents the result. Add supported `explain` and `profile` query wrappers or equivalent root controls through the declarative schema registry, RQL parser, JSON decoder, source diagnostics, hover, TextMate grammar, MCP schema, CLI/REPL, Python models, VS Code, and executable docs. Explain shows logical sharing, physical choices, and dependencies. Profile adds observations, cache behavior, waits, concurrency, cancellation, and budget use without changing ordinary result ordering. Document the benchmark-derived threshold with absolute elapsed times and repository scales, plus rejected storage and scheduling alternatives. Complete adversarial review and full validation.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/740b/bifrost` on the existing branch `918-modularise-query-planning-and-execution-for-measurable-parallel-scheduling`. Do not create or switch branches. At the start of this plan the branch and its upstream both equal `ce79d33b`.

For Milestone 1, run:

    cargo fmt --all
    cargo test analyzer::structural::execution
    cargo test analyzer::structural::query
    cargo test --test code_query_pipelines
    rustup run 1.96.0 cargo-clippy --all-targets --all-features -- -D warnings
    git diff --check

If an isolated target is necessary, use `scripts/with-isolated-cargo-target.sh`; never create a manually named Bifrost target directory in `/tmp`.

After the milestone implementation, update this plan's progress, discoveries, decisions, outcome, concrete validation evidence, and revision note. Review `git status --short` and the exact diff. Stage only this plan and files changed for the milestone, then create a multiline checkpoint commit explaining why the new boundary exists. Do not push or open a pull request unless explicitly requested.

For later benchmark work, use ignored configurable tests with versioned JSON result lines and repeat optimized candidate/baseline runs in alternating order. Record absolute times as well as percentages. Cold runs must start without a ready derived layer; warm runs must prove the exact generation-matched layer was reused; contention runs must prove sibling branches requested the same key.

## Validation and Acceptance

Milestone 1 is accepted when equivalent JSON and RQL queries lower to identical logical explain structures; exact repeated seeds produce one seed node referenced by multiple branch edges; all dependency IDs precede their consumers; a union selects `SequentialUnion`; the root limit is explicit; and the structured execution profile reports deterministic operator identities and `peak_concurrency = 1`. The existing query pipeline suite must remain green, with no public result, ordering, provenance, diagnostic, truncation, cancellation, or budget change.

The complete issue is accepted when an explain view proves parsed, logical, physical, and scheduled stages are distinct; logical plans represent shared dependencies; physical implementations are selectable and independently tested; the scheduler bounds concurrency; union has measured sequential and parallel paths; same-key derived layers single-flight; operator metrics are structured; profile exposes plan, timing, cardinality, cache behavior, waiting, and concurrency; benchmark artifacts compare cold/warm and sequential/parallel behavior across representative scales; the selected threshold is justified with concrete measurements; and deterministic presentation, cancellation, and query budgets remain correct.

Graph materialization is accepted only when a behavior-parity test validates exact typed nodes and edges, corruption or stale-generation input cannot publish a ready snapshot, concurrent same-key consumers receive one shared `Arc`, and repeated measurements show a useful end-to-end win rather than only a faster final adjacency loop.

## Idempotence and Recovery

Plan lowering and execution are read-only over the analyzer. Re-running focused tests is safe and writes only normal Cargo artifacts and inline temporary projects. Node IDs are snapshot-local and must never be persisted or treated as semantic identities.

If the physical executor refactor changes any existing semantic test, stop and restore the prior behavior before adding concurrency. Do not relax the regression assertion or add an ignore annotation. Record the discovered coupling in this plan and make the sequential operator reproduce it explicitly.

If a single-flight leader fails, its permit must remove the in-flight entry and wake waiters so one may retry. If cancellation occurs, incomplete construction is discarded. If waiting could block work queued to the same bounded pool, change scheduling or the build executor; do not work around the deadlock by silently allowing unbounded threads.

If a SQL graph experiment regresses cold latency, memory, write amplification, or database size beyond its declared gate, remove or leave it behind an experiment-only path and record the result. Durable rows remain authoritative; an in-memory graph snapshot can always be rebuilt for the exact generation.

## Artifacts and Notes

The intended first-milestone plan shape for two identical union branches is:

    logical node 0: Seed(canonical foo query) -> structural_match
    logical node 1: Set(Union, inputs [0, 0]) -> structural_match
    logical node 2: Limit(input 1, count 20) -> structural_match

The physical explanation for the same query is:

    physical node 0: SeedScan, dependencies []
    physical node 1: SequentialUnion, dependencies [0, 0]
    physical node 2: Limit(20), dependencies [1]
    peak_concurrency: 1

The later SQL-to-memory freeze algorithm is:

    read minimal ordered node rows
    build typed semantic arena and persistent-to-dense remap
    read minimal ordered edge rows and validate/remap endpoints
    count degrees for each orientation
    prefix-sum counts into row offsets
    scatter canonical edge IDs into outgoing/incoming rows
    validate offsets, endpoints, generation, and representation version
    publish Arc<immutable snapshot>
    release remap and construction buffers

Revision note (2026-07-20): Created the self-contained issue #918 plan after live issue inspection, current-code diagnosis, prior Bifrost graph/snapshot measurement review, and primary-source study of the reference repository. The plan deliberately starts with a sequential logical/physical execution spine and postpones SQL graph loading and parallel scheduling until structured profiles can justify them.

Revision note (2026-07-20, Milestone 1): Recorded the completed sequential plan spine, implicit recursive-executor state that had to become explicit, semantic explain and invocation-profile review fixes, opt-in instrumentation boundary, exact validation results, and the pinned Clippy invocation required by this machine's mixed rustup/Homebrew command lookup.

## Interfaces and Dependencies

In `src/analyzer/structural/execution/plan.rs`, Milestone 1 should provide types equivalent to:

    pub(crate) struct LogicalQueryPlan { ... }
    pub(crate) struct LogicalQueryNodeId(u32);
    pub(crate) enum LogicalQueryOperator {
        Seed(Box<CodeQuerySeed>),
        Step { input: LogicalQueryNodeId, step: QueryStep },
        Set { op: SetOperator, inputs: Box<[LogicalQueryNodeId]> },
        Limit { input: LogicalQueryNodeId, count: usize },
    }

    pub(crate) struct PhysicalQueryPlan { ... }
    pub(crate) struct PhysicalQueryNodeId(u32);
    pub(crate) enum PhysicalQueryOperator {
        SeedScan,
        PipelineStep,
        SequentialUnion,
        SequentialIntersection,
        SequentialExcept,
        Limit,
    }

The exact field visibility may remain private behind accessors. Each logical node carries its terminal `QueryValueKind`; each physical node points back to one logical node and retains ordered physical dependencies. `LogicalQueryPlan::lower(&CodeQuery)` validates and lowers the authored query. `PhysicalQueryPlan::select(LogicalQueryPlan)` chooses the sequential implementation. `PhysicalQueryPlan::explain()` returns a deterministic serializable structure without borrowing internal arenas.

The internal profile types belong beside execution, not in MCP result models. Milestone 1 needs a request profile and per-operator observation sufficient to prove plan identity, elapsed wall time, cardinality, truncation, cancellation, and sequential peak concurrency. Later milestones extend this same model rather than adding a second profiler.

Do not add a new dependency for Milestone 1. Use the repository hash-map alias, `std::time::Instant`, existing cancellation and budget types, and current typed row/set helpers. Later scheduling should prefer existing runtime facilities only after their worker-blocking behavior has been proven safe. Later derived-layer caching should extract a generic complete-value lifecycle from the semantic cache or reuse it directly; it must not maintain two subtly different single-flight implementations.
