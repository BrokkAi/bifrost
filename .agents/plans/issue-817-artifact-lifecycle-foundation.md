# Establish measured artifact lifecycles for issue #817

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md`. It implements the first independently useful checkpoint of GitHub issue #817, “Engineer compact semantic graph snapshots and lifecycle-aware persistence.” It does not claim to close the issue: reusable procedure, taint, and protocol summaries do not yet exist, so their storage shape and persistence decision remain downstream work with #820 and #823.

## Purpose / Big Picture

Bifrost already has several different analysis artifacts with deliberately different lifetimes. Per-file structural facts are packed in SQLite because cross-process hydration proved worthwhile. Complete semantic artifacts and callable control-flow graphs are retained in a bounded memory cache because an equivalent persistence experiment failed its cold-write gate. ICFG slices, oracle projections, and data-flow work are request- or generation-local. Those decisions are currently spread across plans, benchmark tests, and implementation comments.

After this checkpoint, a contributor can inspect one artifact matrix to learn who owns each artifact, how it is identified and invalidated, what representation it uses, what evidence supports its current lifetime, and which measurements are required before changing that decision. Benchmark authors can evaluate persistence candidates with one typed promotion-gate API rather than copying thresholds. A fresh-process data-flow lifecycle benchmark will demonstrate the cost and retained size of the current bounded exploded state while recording that it is intentionally ephemeral, not a persistence candidate.

The observable outcome is a retained benchmark report over generated projects, inline TypeScript and Java, and exact pinned VS Code and Spring PetClinic revisions. It reports semantic/ICFG construction, first and repeated solver execution, counts, work, memory, completeness, and checksums. It does not create a database table or pretend that repeated rebuilding of query-owned work is a cache miss.

## Progress

- [x] (2026-07-24 07:41Z) Verified the clean existing #817 branch, fetched `origin`, and fast-forwarded it from `7748331e` to current `origin/master` at `71b3d3f8`.
- [x] (2026-07-24 07:41Z) Re-read `.agents/PLANS.md`, the live issue, the semantic roadmap, the completed CFG/ICFG and oracle lifecycle evidence, the structural snapshot implementation, and the first bounded #820 solver child.
- [x] (2026-07-24 07:44Z) Published the artifact lifecycle matrix and checkpointed the plan in `b1aeef86`.
- [x] (2026-07-24 07:49Z) Added the reusable artifact-promotion benchmark API, migrated the semantic CFG persistence gate without changing its report shape, and passed focused unit and integration tests.
- [ ] Add the fresh-process data-flow lifecycle benchmark and runner.
- [ ] Run the retained matrix, record the evidence and decision, and complete focused and repository-wide validation.
- [ ] Run specialist review, resolve findings, update the retrospective, and checkpoint the reviewed result.

## Surprises & Discoveries

- Observation: issue #820 is still open, but its first bounded context-respecting data-flow child is already on `master`.
  Evidence: commit `201770cd` added `src/analyzer/dataflow/`; its checked-in ExecPlan explicitly defers reusable summaries, recursive summary convergence, witnesses, and persistence.

- Observation: the current persistence gate is decision-grade but local to one ignored integration benchmark.
  Evidence: `tests/measure_semantic_cfg_persistence.rs::gate_for_dataset` owns the six threshold checks and aggregate conjunction that later candidates need to reuse.

- Observation: the existing semantic/CFG and oracle measurements answer different lifecycle questions.
  Evidence: `.agents/docs/semantic-cfg-lifecycle-benchmark-2026-07-20.md` tested an optimistic equivalent packed projection and rejected production SQLite on cold-write overhead; `.agents/docs/semantic-oracle-lifecycle-benchmark-2026-07-21.md` measured memory-cache and query-arena behavior but did not build a persistence candidate.

- Observation: the issue branch was one commit behind `origin/master`, and the delta changed release metadata only.
  Evidence: fast-forward `7748331e..71b3d3f8` changed the VS Code and plugin release metadata files without touching analysis code.

## Decision Log

- Decision: make this checkpoint a lifecycle foundation, not a summary-storage implementation.
  Rationale: raw semantic/CFG persistence already has a measured no-go, oracle arenas are query-owned, and reusable summary types do not yet exist. Defining a packed summary DTO now would freeze an implementation-shaped format without a concrete consumer.
  Date/Author: 2026-07-24 / Codex

- Decision: standardize promotion gates in the existing public `benchmark` module rather than adding a runtime artifact registry.
  Rationale: persistence promotion is an experimental decision made from fresh-process samples. Runtime caches still need domain-specific keys and completeness rules; a central runtime registry would obscure rather than enforce those semantics.
  Date/Author: 2026-07-24 / Codex

- Decision: missing or invalid measurements make a candidate ineligible.
  Rationale: unavailable RSS, a zero rebuild duration, non-finite or negative timings, or impossible byte measurements cannot safely support promotion. The evaluator must report the missing/invalid observation rather than treating it as a pass.
  Date/Author: 2026-07-24 / Codex

- Decision: preserve the six predeclared CFG persistence thresholds as the issue-wide default gate.
  Rationale: changing thresholds after observing a result would invalidate the prior decision process. Candidates may declare stricter thresholds, but a looser exception requires a new recorded decision before samples are collected.
  Date/Author: 2026-07-24 / Codex

- Decision: classify bounded data-flow results and worklists as `ephemeral_not_eligible`.
  Rationale: they contain concrete seeds, run-local dense fact IDs, budgets, truncations, and path-quality frontiers. Repeating the same solve measures their cost but does not create semantic reuse identity. #823 summaries are the separate reusable projection.
  Date/Author: 2026-07-24 / Codex

- Decision: use fresh processes with two discarded warmups and seven retained samples.
  Rationale: this matches the completed semantic CFG persistence protocol and keeps process startup, allocator state, and page-cache effects visible in the raw evidence.
  Date/Author: 2026-07-24 / Codex

## Outcomes & Retrospective

Work is in progress. The intended outcome is a reusable promotion evaluator, a complete lifecycle matrix, and a reproducible data-flow lifecycle report with no production persistence change. Update this section after each checkpoint with exact commands, results, deviations, and remaining #817 work.

## Context and Orientation

`src/compact_graph.rs` contains `CompactRows<T>` and `CompactDirectedGraph<K>`, the shared immutable dense-row primitives. `CompactRows` stores a boxed `u32` row-boundary array and a boxed value array. `CompactDirectedGraph` owns snapshot-local node identities plus outgoing CSR and incoming CSC rows. CSR means a compact row representation optimized for outgoing traversal; CSC is the corresponding incoming representation.

`src/analyzer/structural/facts.rs` defines per-file syntax facts and their packed snapshot DTO. `migrations/cache/0007-structural-facts-snapshots.sql` keys persisted rows by content blob OID, language, and snapshot format version. `src/analyzer/structural/provider.rs` hydrates that representation only for generation-live disk content and treats missing, corrupt, or incompatible rows as misses.

`src/analyzer/semantic/ids.rs::SemanticArtifactKey` identifies one mounted immutable source artifact by workspace mount, workspace-relative path, language, disk or overlay source revision, adapter version, semantic IR version, configuration, and dependency fingerprint. `src/analyzer/semantic/service.rs::CompleteSemanticArtifactCache` caches only complete validated artifacts, uses strict same-key single flight, and bounds retained weight. `src/analyzer/semantic/icfg.rs::IcfgSnapshot` stitches context-bearing nodes and matched call/return edges on demand for one workspace generation and explicit limits.

`src/analyzer/semantic/oracle/` defines request-bounded value-flow, dispatch, heap, alias, and access-path results. They retain explicit completeness and uncertainty. They are not complete whole-workspace indexes.

`src/analyzer/dataflow/` contains the first #820 solver child. `solve` consumes an outcome-derived `IcfgSolveInput`, a finite distributive problem, a five-dimensional `SolverBudget`, and cancellation. It creates run-local `FactId`s, reached states, path-quality frontiers, worklists, coverage, and a deterministic `DataflowResult`. No data-flow cache or summary store currently exists.

`tests/measure_semantic_cfg_persistence.rs` is the existing persistence experiment. Its local gate requires at least 30 percent and 50 milliseconds of hydration improvement, at most 10 percent hydration RSS growth, serialized bytes no more than twice estimated hydrated bytes, and build-plus-write overhead no more than 25 percent or 250 milliseconds. Every required external corpus must pass every gate.

The two pinned external repositories are:

- VS Code at `19e0f9e681ecb8e5c09d8784acaa601316ca4571`, supplied through `BIFROST_SEMANTIC_TS_REPO`.
- Spring PetClinic at `f182358d02e4a68e52bdbabf55ca7800288511e7`, supplied through `BIFROST_SEMANTIC_JAVA_REPO`.

The local validated checkouts are `/Users/dave/Workspace/test-repos/vscode-semantic-cfg` and `/Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg`. The runner must accept other paths at the same clean commits and must never modify either repository.

## Plan of Work

First publish `.agents/docs/semantic-artifact-lifecycle-matrix.md`. For every artifact in scope, state the owner and consumers, lifetime, complete cache key or identity inputs, invalidation behavior, hot representation, completeness admission rule, expected reuse, current observability, evidence, and decision. Include future summary artifacts as pending shapes, not implemented rows. Keep raw worklists, truncations, and witness paths explicitly ephemeral.

Next add `src/benchmark/artifact_lifecycle.rs` and re-export it from `src/benchmark/mod.rs`. Define validated public benchmark types:

    pub struct ArtifactPromotionThresholds {
        pub minimum_hydration_speedup_percent: f64,
        pub minimum_hydration_saved_ms: f64,
        pub maximum_hydration_rss_ratio: f64,
        pub maximum_serialized_to_hydrated_bytes_ratio: f64,
        pub maximum_build_write_time_ratio: f64,
        pub maximum_build_write_overhead_ms: f64,
    }

    pub struct ArtifactPromotionMeasurement {
        pub rebuild_ms: f64,
        pub build_write_ms: f64,
        pub hydrate_ms: f64,
        pub rebuild_peak_rss_bytes: Option<u64>,
        pub hydrate_peak_rss_bytes: Option<u64>,
        pub serialized_bytes: u64,
        pub estimated_hydrated_bytes: u64,
    }

    pub fn evaluate_artifact_promotion(
        thresholds: ArtifactPromotionThresholds,
        measurement: ArtifactPromotionMeasurement,
    ) -> Result<ArtifactPromotionEvaluation, ArtifactPromotionInputError>;

`ArtifactPromotionEvaluation` must retain calculated speedup/saving plus a typed status for every gate and an aggregate `passed` value. The error must distinguish invalid thresholds from invalid measurements. Ratios must be compared without overflowing byte multiplication. Floating values must be finite and nonnegative; rebuild time and estimated hydrated bytes must be greater than zero. RSS must be present and nonzero for both modes to pass the RSS gate.

Give `ArtifactPromotionThresholds::default()` the six existing #817 thresholds. Add focused unit tests for exact boundaries, one failure at a time, missing RSS, invalid floats, zero denominators, and large byte values.

Refactor `tests/measure_semantic_cfg_persistence.rs` to construct `ArtifactPromotionMeasurement` from its retained medians and use the shared evaluator. Keep its JSON gate fields and recommendation semantically unchanged so the historical aggregate remains comparable. Add an assertion that the shared default thresholds equal the values named by the benchmark report.

Then create `tests/measure_dataflow_lifecycle.rs`. The ignored test has a sample mode and an aggregate mode selected by environment, following the existing semantic benchmark conventions. It builds these datasets:

- deterministic generated TypeScript branch and call-chain projects at two bounded sizes;
- fixed inline TypeScript and Java call/branch/exception projects;
- pinned VS Code rooted at the unique semantic procedure `src/vs/base/common/arrays.ts::quickSelect`;
- pinned Spring PetClinic rooted at the unique semantic procedure `src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java::processFindForm`.

Select external procedures structurally from their complete `SemanticArtifact` by exact relative path and final declaration name. Fail if selection is missing or ambiguous. Materialize the ICFG with explicit limits recorded in the output. Preserve any typed incomplete outcome instead of filtering it into an empty graph.

Run two benchmark-local clients over each available snapshot. The direct client uses the production `DirectFlowProblem`. The finite-fact client seeds fact one and emits the current fact plus its successor up to sixteen through every transfer family. It is deterministic, union-distributive, finite, and exists only to pressure reached-state growth; it is not a production analysis client.

Each sample reports Bifrost commit and dirty-tree fingerprint, toolchain/machine context, dataset repository identity, ICFG limits and outcome, semantic/ICFG construction time, first and immediate-repeat solve time, nodes, edges, boundaries, facts, reached rows, all five solver-work dimensions, termination, completeness, deterministic checksum, estimated shallow result bytes, peak RSS where supported, cache status `not_applicable_run_local`, and serialized size `not_applicable`.

The aggregate validates identical provenance and topology/work checksums within each dataset/client group, retains rounds two through eight, computes medians, and emits the recommendation `ephemeral_not_eligible; persist reusable summaries only after #823 defines and measures them`. It must not pass the samples through the persistence gate because no equivalent serialized candidate was built.

Create `scripts/run-dataflow-lifecycle-benchmarks.sh`. It uses `set -euo pipefail`, validates optional external roots and exact clean commits, creates one `mktemp -d` work directory, removes it on exit, runs nine release processes, retains seven sample JSON rows, runs aggregation, and prints exactly one `BIFROST_DATAFLOW_LIFECYCLE_BENCHMARK=` record. It sets `BIFROST_SEMANTIC_INDEX=off` and does not create a manually named Cargo target directory.

After collecting the retained matrix, write `.agents/docs/dataflow-lifecycle-benchmark-2026-07-24.md` with the exact command, Bifrost/toolchain/machine and dataset revisions, all retained samples or the aggregate’s raw-sample section, medians, counts, limits, memory observations, and recommendation. Update the lifecycle matrix and this plan with the measured evidence.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/dc95/bifrost`.

Confirm the synchronized branch:

    git status --short --branch
    git rev-parse HEAD origin/master
    git rev-list --left-right --count HEAD...origin/master

Expected before issue edits: a clean worktree, attached #817 branch, and zero divergence from `origin/master`.

After the lifecycle matrix and ExecPlan are complete:

    git diff --check
    git status --short

Stage only those two files and commit a multiline checkpoint describing why unsupported artifact shapes remain unpersisted.

After adding the benchmark API and migrating the CFG gate:

    cargo fmt
    cargo test benchmark::artifact_lifecycle
    cargo test --test measure_semantic_cfg_persistence

Expected: the focused unit tests pass; the ignored release measurement remains ignored in the ordinary integration-test run; all non-ignored DTO and aggregation tests pass.

After adding the data-flow benchmark:

    cargo test --test measure_dataflow_lifecycle
    cargo test --test dataflow_tabulation --test dataflow_clients

Expected: benchmark schema/aggregation validation and all existing solver behaviors pass. The expensive measurement itself remains ignored.

Run the retained matrix:

    BIFROST_SEMANTIC_TS_REPO=/Users/dave/Workspace/test-repos/vscode-semantic-cfg \
    BIFROST_SEMANTIC_JAVA_REPO=/Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg \
      scripts/run-dataflow-lifecycle-benchmarks.sh

Expected: the runner prints progress to stderr and exactly one aggregate JSON marker to stdout. Every group has rounds two through eight, stable checksums/counts, and an `ephemeral_not_eligible` recommendation.

Run formatting and strict lint:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Run the complete feature-enabled suite on macOS:

    env RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup' \
        BIFROST_SEMANTIC_INDEX=off \
        scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Expected: every enabled library, binary, integration, and doc-test target passes apart from repository-documented ignored tests. If the managed sandbox blocks helper subprocesses, rerun the exact command with host access and record both outcomes.

## Validation and Acceptance

The lifecycle matrix is accepted when every current promoted or measured semantic artifact has a named owner, lifetime, full identity inputs, invalidation behavior, representation, completeness rule, observability, evidence link, and explicit decision. Future summaries may be pending, but their required key dimensions and promotion prerequisites must be stated.

The gate API is accepted when the default evaluator exactly reproduces the six predeclared semantic CFG checks; all checks must pass for promotion; missing or invalid evidence cannot pass; and callers receive typed per-gate results suitable for JSON reporting.

The migrated CFG benchmark is accepted when its existing external-corpus decision remains a no-go for the same reason: VS Code build-plus-write absolute overhead exceeds 250 milliseconds.

The data-flow benchmark is accepted when all seven retained samples per group have stable topology, work, result, and checksum identity; first and repeated solves reach fixed points where the input ICFG is complete; incomplete ICFG input remains visibly incomplete; and every required provenance/count/time/memory field is present or explicitly unavailable.

The lifecycle decision is accepted when the report distinguishes repeated computation from cache reuse and leaves raw exploded states, worklists, truncations, and concrete results ephemeral. No SQLite migration, packed data-flow DTO, cache insertion, or durable dense `FactId` may be introduced.

Repository acceptance additionally requires formatting, strict all-target/all-feature Clippy, focused persistence/data-flow tests, and the complete `nlp,python` test matrix.

## Idempotence and Recovery

The benchmark runner is read-only with respect to source repositories and creates all samples in a unique temporary directory removed by its trap. Re-running it produces a new evidence record without changing tracked files. It validates exact external commits before doing expensive work.

The promotion evaluator is pure. Re-running an evaluation cannot change cache or database state. Invalid inputs return errors before computing a recommendation.

The CFG gate migration must preserve the old aggregate fields. If the shared evaluator changes the old decision, stop and fix the semantic mismatch rather than editing thresholds or expected output.

If an external procedure selector becomes ambiguous at the pinned revision, fix the structural selector to use its complete declaration locator; do not use source-text parsing or choose the first match. If an external repository is unavailable, generated and inline sample mode may be used for development, but the retained final matrix is incomplete until both exact pinned repositories run.

No new migration exists to roll back. Checkpoint commits are scoped by milestone. Do not stage unrelated files, push, or open a pull request.

## Artifacts and Notes

The lifecycle flow established by this checkpoint is:

    concrete complete artifact shape
                    |
          explicit identity and lifetime
                    |
       baseline + equivalent candidate samples
                    |
     all predeclared promotion gates pass?
              /                 \
           yes                   no
      versioned DTO         retain current owner
      + safe miss rules     + record measured no-go

Raw data-flow state exits before the candidate branch because it is query-owned:

    seeds + exact ICFG + client + budgets
                    |
        run-local facts/worklists/result
                    |
       ephemeral_not_eligible
                    |
     future reusable summary projection (#823)

Existing evidence:

- `.agents/docs/semantic-cfg-lifecycle-benchmark-2026-07-20.md`
- `.agents/docs/semantic-oracle-lifecycle-benchmark-2026-07-21.md`
- `.agents/docs/sqlite-backed-compact-graph-applicability.md`
- `.agents/plans/sqlite-backed-compact-structural-snapshots.md`
- `.agents/plans/issue-820-bounded-dataflow-tabulation.md`

## Interfaces and Dependencies

The benchmark API uses only `std`, existing `serde` derives if JSON serialization is useful to callers, and the existing `src/benchmark` module. It adds no dependency.

`ArtifactPromotionThresholds::default()` is the stable #817 baseline for equivalent packed artifacts:

    speedup_percent >= 30.0
    saved_ms >= 50.0
    hydrate_rss / rebuild_rss <= 1.10
    serialized_bytes / estimated_hydrated_bytes <= 2.0
    build_write_ms / rebuild_ms <= 1.25
    build_write_ms - rebuild_ms <= 250.0

`ArtifactPromotionEvaluation` exposes measured speedup and saving, six typed gate outcomes, and aggregate `passed`. A gate outcome distinguishes `Passed`, `Failed`, and `Unavailable`; invalid numeric inputs are errors rather than gate outcomes.

The data-flow benchmark consumes only public production interfaces: `WorkspaceAnalyzer`, semantic materialization, `IcfgProvider`, `IcfgSnapshotLimits`, `IcfgSolveInput`, `DirectFlowProblem`, the finite `BoundedSnapshotDataflowProblem`, `SolverBudget`, `DataflowRequest`, and `solve`. It must not add a test-only public snapshot constructor.

Plan revision note (2026-07-24): Created the issue-specific lifecycle-foundation plan after synchronizing the existing #817 branch, verifying current issue/dependency state, and auditing the completed structural, semantic/CFG, oracle, ICFG, and first data-flow solver lifecycles. The scope intentionally standardizes evidence and measures request-local data-flow state without inventing summary persistence before #823.
