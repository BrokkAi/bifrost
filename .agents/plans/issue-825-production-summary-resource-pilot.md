# Integrate production typestate summaries and prove the Java/TypeScript resource pilot

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while implementation proceeds. This document follows `.agents/PLANS.md` and covers the first production-summary integration milestone of GitHub issue #825, “Deliver a cross-language resource typestate pilot and benchmark suite.”

## Purpose / Big Picture

Bifrost already has a source-backed typestate solver, stable semantic and protocol summary artifact types, CodeQuery/RQL typestate findings, and `.rqlp` policy rendering. Those pieces are not integrated: production CodeQuery and policy execution still invoke the uncached client, and the reusable summary path is exercised only by tests and benchmarks. A reusable hit also marks witness evidence as omitted, so it cannot yet produce the exact same public witness as an uncached run.

After this milestone, one bounded in-memory repository owned by an immutable workspace generation will serve production typestate analysis. Production semantic dependencies will be projected into stable reusable semantic summaries and then into protocol summaries. Warm and cold executions will expose identical findings, witnesses, completeness, and diagnostics; stale or incomplete cache evidence will be rejected and recomputed rather than weakening results. Explicit hit, miss, rejection, eviction, and recomputation counters will make that behavior measurable. Equivalent Java and TypeScript resource-lifecycle fixtures will exercise the internal client, CodeQuery JSON, RQL source, `.rqlp`, and human, JSON, and SARIF policy output.

This is the first #825 milestone, not the entire issue. It records repeated-root and repeated-policy timings and counts, but leaves the larger representative-corpus campaign, accuracy matrix, persistence decision, and #826 precision recommendations for later milestones.

## Progress

- [x] (2026-07-28 06:39Z) Refreshed the issue branch and `origin`, fetched live issue #825, and confirmed `HEAD`, `origin/master`, and the issue remote are all `b40d3611` with a clean worktree.
- [x] (2026-07-28 06:39Z) Diagnosed the production gap across reusable summaries, CodeQuery, policy coordination, report rendering, and workspace generation ownership.
- [x] (2026-07-28 06:39Z) Chose a workspace-generation-scoped in-memory lifetime and defined exact semantic parity independently from lifecycle metrics.
- [x] (2026-07-28 14:04Z) Implemented the bounded generation owner, production semantic projector, operation-local and cumulative lifecycle counters, oldest-entry result eviction, retained-byte accounting, and focused repository/invalidation tests.
- [x] (2026-07-28 14:04Z) Made exact generation-local result snapshots the witness-preserving production hit path; projected protocol rows are tried speculatively and rejected before publication to callers when their existing omission markers prove they cannot preserve exact witnesses.
- [x] (2026-07-28 14:04Z) Routed the internal production client, CodeQuery/RQL, and `.rqlp` policy execution through shared workspace-generation or policy-batch repositories.
- [x] (2026-07-28 14:04Z) Added equivalent Java/TypeScript resource-pilot coverage across internal, JSON CodeQuery, RQL, `.rqlp`, JSON, human, and SARIF paths.
- [x] (2026-07-28 14:04Z) Recorded repeated-root and repeated-policy timings and proved generation and dependency invalidation.
- [x] (2026-07-28 14:04Z) Completed five specialist reviews, addressed their critical/high findings, and passed focused all-feature tests, the Python harness, formatting, and strict all-target/all-feature Clippy.

## Surprises & Discoveries

- Observation: `solve_typestate_with_reusable_summaries` has no production callers; only `tests/typestate_client.rs` and `tests/measure_summary_lifecycle.rs` exercise it.
  Evidence: exact `rg` references show production policy at `src/analyzer/policy/typestate_policy.rs:418` and CodeQuery at `src/analyzer/structural/search/typestate.rs:144` both call `solve_typestate_with_summaries`.

- Observation: current reusable hits are intentionally not witness-equivalent.
  Evidence: `SummaryState::apply_reusable_callee_summaries` in `src/analyzer/dataflow/summary.rs` calls `mark_reusable_witnesses_omitted`, and existing `tests/typestate_client.rs` asserts cached findings contain retention-truncated witness markers.

- Observation: repository validity and public report identity are already well separated.
  Evidence: `ProtocolSummaryKey` contains procedure, protocol, binding, schema, and entry facts; `PolicyReportDocument` is the one input to human, JSON, and SARIF renderers. Presentation fields therefore do not need to enter cache keys.

- Observation: several broad Bifrost `scan_usages_by_location`, `most_relevant_files`, and `search_symbols` calls produced no output after 30–120 seconds and were terminated, while exact source lookup remained responsive.
  Evidence: both the primary diagnostic and specialist agent reproduced the behavior; exact symbol sources plus `rg` were used only for the stalled reference-count checks.

- Observation: an exact result hit must reproduce budget accounting as well as output to remain observationally identical in profiled and policy execution.
  Evidence: the cache stores exact semantic, solver, and policy-provider execution charges; a hit stages all three and is rejected if any charge no longer fits.

- Observation: policy compilation consumes presentation-dependent semantic bookkeeping before typestate execution even when two policies have the same analysis contract.
  Evidence: normalizing only the policy-batch semantic-allowance key enabled a genuine second-policy hit while exact stored work was still replayed and budget-dependent results remained unpublishable.

- Observation: production semantic projection can publish reusable helper rows while deliberately skipping an ineligible caller row.
  Evidence: the two-caller production test records published protocol summaries with `ProjectionSkipped`, then proves a compatible helper row is attempted, rejected for witness omission, and recomputed to the uncached result.

- Observation: prepared CodeQuery work now retains a repository generation lease and crossed Clippy's large-enum threshold.
  Evidence: boxing the `ToolCallPreparation::Ready` payload restored a compact dispatch enum without changing the prepared-call contract.

## Decision Log

- Decision: scope the in-memory repository to one immutable workspace generation.
  Rationale: `SearchToolsService` already owns the generation boundary and rotates protocol registrations on updates. This permits reuse across CodeQuery and service-backed policy requests without accepting stale artifact handles. Standalone CLI evaluation builds one immutable analyzer and therefore naturally owns one disposable generation for its policy batch.
  Date/Author: 2026-07-28 / Codex

- Decision: semantic parity excludes lifecycle counters but includes every public finding, witness step and truncation marker, completeness state, and diagnostic.
  Rationale: warm and cold work legitimately differs, while policy/finding identity and evidence must not. Counters belong in work reports and profiling output, never in semantic hashes or finding identities.
  Date/Author: 2026-07-28 / Codex

- Decision: reuse fails closed when complete bounded witness evidence cannot be restored.
  Rationale: the existing omission marker is honest but violates this milestone’s exact warm/cold witness contract. A cache candidate with stale, partial, cancelled, over-budget, or insufficient witness evidence must increment rejection and recomputation instead of silently degrading the report.
  Date/Author: 2026-07-28 / Codex

- Decision: use existing stable semantic, procedure, dependency, recursive-group, protocol, and binding identities rather than a production-only key family.
  Rationale: issue #823 already established the invalidation contract. Production integration should construct and validate those artifacts, not create a parallel cache whose keys can drift.
  Date/Author: 2026-07-28 / Codex

- Decision: keep the repository memory-only in this milestone.
  Rationale: #823’s lifecycle evidence did not justify a portable persisted representation, and #825 first needs exact production behavior and useful warm measurements.
  Date/Author: 2026-07-28 / Codex

- Decision: use an exact generation-local result snapshot as the accepted witness-preserving cache artifact in this milestone.
  Rationale: existing portable protocol rows intentionally omit stable witness fragments. Exact snapshots preserve findings, witnesses, completeness, diagnostics, and work accounting today; compatible portable rows are still projected and exercised, but any actual witness-omitting application is rejected before it can affect output.
  Date/Author: 2026-07-28 / Codex

- Decision: prepared service work captures an `Arc` to the repository that matches its immutable workspace generation, and generation advance swaps in a successor repository.
  Rationale: in-flight work may finish against its old immutable owner without racing publication into the new generation, while stale generation calls fail closed.
  Date/Author: 2026-07-28 / Codex

- Decision: treat unresolved call boundaries as an explicit reusable semantic effect and never erase incomplete evidence while projecting production summaries.
  Rationale: an incomplete external or dynamic boundary is semantic evidence, not absence; preserving it keeps cold and warm completeness/diagnostics aligned.
  Date/Author: 2026-07-28 / Codex

- Decision: expose lifecycle deltas from each solve rather than subtracting two global repository snapshots.
  Rationale: global before/after subtraction attributes concurrent requests to the wrong response. Operation-local counters are deterministic; cumulative counters remain available for repository observability.
  Date/Author: 2026-07-28 / Codex

- Decision: evict exact results by oldest insertion sequence under hard entry and retained-byte limits.
  Rationale: the policy is deterministic, cheap at the current 1,024-entry bound, and makes eviction and subsequent recomputation directly testable without adding a more complex recency structure.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The first production-summary integration milestone is implemented. `ProductionTypestateSummaryRepository` owns production semantic summaries, portable protocol rows, and exact witness-preserving results for one workspace generation or standalone policy batch. Publication is generation-guarded, dependency identities flow through callers, memory is bounded by entry and estimated owned-byte limits, and both cumulative and operation-local hit, miss, rejection, eviction, and recomputation counts are public.

Cold and warm exact results are equal for Java and TypeScript, including findings, witnesses, completeness, coverage, and diagnostics. CodeQuery JSON and RQL use the same repository-aware public entry; `.rqlp` batches share one disposable repository; the canonical policy document preserves identity and evidence through JSON, human, and SARIF renderers. The Python work model exposes the five counters.

Focused validation passed 103 all-feature Rust tests with two measurement tests ignored during the ordinary run, then both ignored measurements passed explicitly. The canonical Python harness passed 59 tests. `cargo check --all-targets --all-features`, `cargo fmt --all`, and isolated `cargo clippy --all-targets --all-features -- -D warnings` passed.

Measured on this machine and debug test profile, repeated Java roots were 8,262 microseconds cold and 18 microseconds warm; TypeScript was 5,540 microseconds cold and 20 microseconds warm. Each pair recorded one miss, one recomputation, and one hit with exact result equality. A two-policy Java `.rqlp` batch took 3,136,979 microseconds; the second compatible policy recorded one hit and zero misses or recomputations.

The deliberate remaining #825 work is portable cross-root witness-safe protocol reuse. Production semantic summaries and protocol rows are real and reusable candidates, but rows that actually omit a stable witness fragment are rejected and recomputed. This milestone therefore delivers safe production caching and exercises protocol projection without claiming that the later portable witness representation is complete. The larger representative-corpus campaign, persistence decision, and #826 precision evaluation also remain outside this checkpoint.

## Context and Orientation

The generic reusable artifact contract lives in `src/analyzer/dataflow/reusable_summary.rs`. `ProcedureSummaryIdentity` brands one source-backed procedure with artifact, declaration, schema, semantics, context, behavior, and origin. `ProcedureSummaryKey` adds exact dependency and recursive-group fingerprints. `SemanticProcedureSummary` retains stable transfers/effects and completeness. `CompleteSummaryRepository` admits only complete summaries under bounded entry and retained-byte limits.

The protocol-specific layer lives in `src/analyzer/typestate/summary.rs`. `ProtocolSemanticSummarySet` validates one exact complete semantic summary per procedure. `ProtocolSummaryKey` adds protocol, binding, schema, and entry-fact identity. `CompleteProtocolSummaryRepository` is bounded and complete-only. `solve_typestate_with_reusable_summaries` supplies repository rows only at callee boundaries, then projects complete query-local results back into stable protocol summaries. `src/analyzer/dataflow/summary.rs` performs the actual reusable-row application and owns witness-arena integration.

The internal uncached client entry is `solve_typestate_with_summaries` in `src/analyzer/typestate/client.rs`. The production entry added here must preserve that function as a test oracle while making repository ownership explicit rather than global.

CodeQuery/RQL execution enters through `src/analyzer/structural/search/typestate.rs`. `TypestateQueryState` already caches a complete analysis inside one request so a duplicate root is not solved twice, but its misses use the uncached client. `QueryAnalysisContext` in `src/analyzer/structural/analysis_context.rs` validates protocol registration generation, root, protocol hash, binding-plan hash, and artifact freshness. The production repository is an additional reusable layer; it must not replace those admission checks.

Policy evaluation enters `evaluate_policy_inputs` in `src/analyzer/policy/coordinator.rs`, which creates one `ProductionTypestatePolicyEvaluator` for a whole policy batch. `evaluate_compiled_typestate` in `src/analyzer/policy/typestate_policy.rs` currently loops over roots and invokes the uncached client. The policy work report already accepts typed named metrics. `src/analyzer/policy/report.rs` builds one canonical `PolicyReportDocument`, and `src/analyzer/policy/render/` renders that same document as human, JSON, or SARIF.

`SearchToolsService` in `src/searchtools_service.rs` owns the active `WorkspaceAnalyzer`, an atomic workspace generation, prepared CodeQuery/policy requests, and generation advancement. It is the long-lived production owner. A generation lease is an immutable capability pairing a repository scope with the generation number. Prepared work may read or publish only while that number remains current.

The pilot protocol is the language-neutral `unallocated -> open -> closed` resource lifecycle in `tests/fixtures/typestate/resource-lifecycle.protocol.json` and `tests/fixtures/policies/resource-lifecycle.rqlp`. The Java and TypeScript projects must express equivalent acquisition, helper/alias flow, use, close, normal and exceptional exits, and deliberate invalid cases without language branches in the protocol or solver.

## Plan of Work

### Milestone 1: generation repository and production semantic projection

Create `src/analyzer/typestate/production.rs` and export it from `src/analyzer/typestate/mod.rs`. Define a bounded repository scope containing `CompleteSummaryRepository`, `CompleteProtocolSummaryRepository`, the active generation, retained-entry/byte accounting, and cumulative lifecycle counters. Counter semantics are exact: a hit is an exact accepted reusable entry; a miss has no exact valid entry; a rejection found or produced a candidate that could not be used or published; an eviction removes an entry because the generation rotated or the bounded policy selected a victim; recomputation is a live solve performed after a miss or rejection. Expose immutable counter snapshots and per-operation deltas.

Add a production semantic projector that walks call transfers iteratively from requested roots under explicit procedure/call/semantic budgets. It must use structured `ProcedureHandle`, `CallSiteHandle`, `CallTransferSet`, `SemanticOutcome`, and artifact identities. Build direct dependency edges, compute strongly connected components iteratively, construct `SummaryRecursiveGroupKey` manifests, and publish components in dependency order. Create `SemanticProcedureSummary` values through the public validators with exact call dependencies and inferred provenance. Any ambiguous, incomplete, cancelled, unsupported, stale, or over-budget dependency closure is a typed non-publication/rejection, never a partial complete artifact.

Focused tests must prove deterministic projection, direct dependency invalidation, atomic recursion, artifact/configuration change invalidation, hard bounds, generation rotation, and the five counters. End this milestone with `cargo fmt --all -- --check`, the new focused test plus `reusable_summaries` and `typestate_client`, strict Clippy, a plan update, and a checkpoint commit.

### Milestone 2: witness-preserving production admission

The implemented milestone retains exact, immutable, generation-local `TypestateSummaryResult` snapshots as the accepted production artifact. The result key covers root identity, protocol and binding hashes, canonical entry facts, provider execution state, and request allowance. Publication excludes cancelled, over-budget, limited, non-fixed-point, or witness-retention-truncated results. Hits atomically replay the exact semantic, solver, and policy-provider charge before returning the same snapshot.

Production semantic summaries are still projected into `CompleteSummaryRepository` and `CompleteProtocolSummaryRepository`. Compatible protocol rows are applied only in a speculative solve. If no row is used, that solve may be accepted; if a row is used, the existing witness-omission marker causes rejection and a cold solve before public output. The two-caller test proves the projected helper candidate is tried, rejection is counted, and the recomputed result equals the uncached oracle.

Portable canonical witness fragments remain a later #825 milestone. They are not required for exact same-root or same-policy production hits now, and this checkpoint does not bump the persisted protocol schema or claim accepted cross-root portable witness reuse.

### Milestone 3: production client, CodeQuery, and policy integration

Add a production client entry in `src/analyzer/typestate/client.rs` or `production.rs`. It receives a generation lease, exact roots, protocol/bindings, finite semantic and solver budgets, cancellation, and evidence limits. It obtains or projects semantic validity summaries, invokes the reusable solver, validates the generation again before publication, and returns the final diagnostic-neutral result plus lifecycle delta. The existing uncached entry remains the parity oracle.

Thread the generation scope through `SearchToolsService`, prepared CodeQuery and run-policy values, `QueryAnalysisContext`, and `TypestateQueryState`. Keep the request-local whole-analysis cache and report its hit count separately. Add reusable hit, miss, rejection, eviction, and recomputation fields to `CodeQueryTypestateWork`, its serde/profile projections, and the Python/editor client models that mirror the public work shape.

Give `ProductionTypestatePolicyEvaluator` the same scope. The coordinator creates one disposable scope for standalone batches or receives the active service scope. Add the lifecycle delta as `typestate.summary_*` work metrics without changing policy hashes, finding IDs, completion, or diagnostics. Repeated compatible policies may reuse propagation artifacts even when presentation metadata differs.

Tests must prove duplicate roots inside one query, helper reuse across roots/requests, repeated compatible policies, stale prepared-query/policy rejection, and no publication after generation advance. Run focused CodeQuery, context, policy, CLI, LSP, Python-model, and VS Code suites, formatting, strict Clippy, update the plan, and checkpoint.

### Milestone 4: Java/TypeScript public vertical and measurements

Add a table-driven `tests/common/typestate_pilot.rs` harness and `tests/typestate_pilot.rs`, using `InlineTestProject` for inline projects. Equivalent Java and TypeScript cases must cover safe, invalid, ambiguous/inconclusive, unsupported/incomplete, helper/alias, factory return, normal/exceptional flow, and dependency change behavior. One compiled protocol definition must run both languages.

Exercise cold and warm internal production client runs, CodeQuery JSON, equivalent RQL source, `.rqlp` evaluation, and human, JSON, and SARIF rendering. Compare normalized findings, witness IDs and steps, primary/related locations, certainty, completeness, and diagnostics. Rendering assertions must prove the same canonical policy and finding identities rather than matching entire formatting byte-for-byte where formats deliberately differ.

Add an ignored measurement case or dedicated test runner that emits deterministic JSON with exact Bifrost commit/dirty state, fixture revision, languages/features, machine metadata, repeated-root/policy count, cold/warm time, retained bytes, artifact/row counts, all five lifecycle counters, and canonical result checksums. Timing is evidence, never a correctness threshold in this first milestone.

Run all focused suites, `cargo fmt --all -- --check`, `scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings`, and `BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python`. Use the matching rustup `RUSTDOC` if the known Homebrew/rustup LLVM metadata mismatch appears. Complete the guided security, duplication, intent, operations, and architecture reviews, resolve confirmed critical/high findings, record evidence, and checkpoint.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/9307/bifrost`.

Inspect the active branch and remote before each checkpoint:

    git status --short --branch
    git rev-list --left-right --count HEAD...origin/master

After Milestone 1:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test typestate_production_summary --test reusable_summaries --test typestate_client
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

After Milestone 2:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test typestate_production_summary --test typestate_client
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

After Milestone 3:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test code_query_typestate --test code_query_typestate_context --test bifrost_policy_cli --test bifrost_lsp_server
    bash scripts/test_python.sh
    (cd editors/vscode && npm test)

After Milestone 4 and review:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check
    git status --short --branch

Every managed isolated target must be removed automatically by `scripts/with-isolated-cargo-target.sh`. Do not create manually named Cargo targets. If Python-enabled linkage requires the repository’s established macOS dynamic-symbol flags, record the exact successful invocation here.

## Validation and Acceptance

The repository milestone passes when an exact second analysis records hits, a changed dependency records misses and recomputation, incomplete evidence records rejection, a bounded victim or generation rotation records eviction, and a stale lease cannot publish. Counter transitions must be deterministic and retained-byte accounting must stay within configured bounds.

The semantic projector passes when Java and TypeScript production ICFG data create canonical complete summaries whose keys change after source, adapter/configuration, context/behavior, dependency, or recursive topology changes. No source string splitting, regex dispatch, or hand-authored dependency list may substitute for structured calls.

Witness reuse passes when normalized cold and warm finding reports are equal, including every bounded witness step, source location, proof/completeness state, and truncation lower bound. If fixed evidence limits cannot preserve that equality, the warm path must reject and recompute, with counters proving the decision.

The public vertical passes when one protocol runs both Java and TypeScript through the internal production client, CodeQuery JSON, RQL, `.rqlp`, and canonical policy reporting. JSON, human, and SARIF must retain the same policy ID, finding ID, primary/related locations, witness identity and membership, certainty, and completeness. Safe, invalid, ambiguous, unsupported, and incomplete outcomes must remain distinguishable.

The milestone is complete when repeated roots and policies have reproducible timing/count evidence, generation/dependency invalidation is proven, all focused and feature-complete gates pass, specialist review has no unresolved critical/high finding, and this ExecPlan records the final outcome.

## Idempotence and Recovery

All repositories are caches: clearing or rotating them may reduce performance but must not change semantic output. Projection and publication are deterministic and complete-only. Generation rotation is monotonic and old leases cannot mutate the new generation. Repeating tests creates fresh inline projects and managed temporary Cargo targets.

Keep edits and commits limited to this plan and implementation files. Stage paths explicitly; never use `git add -A`. Preserve unrelated worktree content. If a milestone exposes an adapter or solver correctness defect, minimize it in the pilot and fix the structured source rather than weakening parity expectations or adding source-text fallback logic.

## Artifacts and Notes

The branch started at:

    b40d3611 (HEAD, origin/master, origin/825-deliver-a-cross-language-resource-typestate-pilot-and-benchmark-suite)

Relevant landed prerequisites are `a5262c1d` for reusable semantic/protocol/taint summaries, `3270a588` for CodeQuery/RQL typestate, `85def175` for production typestate policy execution, `7059c687` for Java/TypeScript exact value-flow conformance, and `1e0ec9cf` for durable policy configuration and suppressions.

The Bifrost navigation latency observation is not part of implementation. After this milestone, report it as a possible follow-up with the exact stalled tool shapes if it remains reproducible.

## Interfaces and Dependencies

The implemented production layer exposes these responsibility-equivalent interfaces:

    pub struct ProductionTypestateSummaryRepository { ... }
    pub struct TypestateSummaryRepositoryLimits { ... }
    pub struct ProductionSummaryLifecycleCounters {
        pub hits: usize,
        pub misses: usize,
        pub rejections: usize,
        pub evictions: usize,
        pub recomputations: usize,
    }

    impl ProductionTypestateSummaryRepository {
        pub fn new() -> Self;
        pub fn with_limits(limits: TypestateSummaryRepositoryLimits) -> Self;
        pub fn admit_generation(&self, generation: u64) -> TypestateSummaryRepositoryRotation;
        pub fn successor_generation(&self, generation: u64) -> Self;
        pub fn counters(&self) -> ProductionSummaryLifecycleCounters;
    }

    pub fn project_production_semantic_summaries(
        roots: &[ProcedureHandle],
        provider: &impl IcfgProvider,
        request: &mut SemanticRequest<'_>,
    ) -> Result<..., ...>;

    pub fn solve_typestate_with_production_summaries(
        generation: u64,
        root: &ProcedureHandle,
        entry_facts: &[TypestateFact],
        provider: &impl IcfgProvider,
        projection_provider: &impl IcfgProvider,
        execution_context: ProductionTypestateExecutionContext<'_>,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
        repository: &ProductionTypestateSummaryRepository,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<..., ...>;

The production layer reuses `SemanticProcedureSummary`, `CompleteSummaryRepository`, `ProtocolSemanticSummarySet`, `CompleteProtocolSummaryRepository`, `solve_typestate_with_reusable_summaries`, `SummaryWitness`, and existing canonical semantic locators. It adds no external crate dependency and no persistence format.

Plan revision note (2026-07-28): Created after live issue/branch verification, Bifrost-backed diagnosis, and specialist implementation planning. Updated after implementation and review to record exact-result admission, speculative portable-row rejection, generation ownership, public-path integration, validation, and measurements. The later portable witness representation and representative benchmark/precision campaign remain outside this first milestone.
