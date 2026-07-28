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
- [ ] Implement the bounded generation owner, semantic projector, lifecycle counters, and focused repository/invalidation tests.
- [ ] Extend protocol-summary evidence so accepted warm hits preserve the same bounded source-backed witnesses as cold solves; reject and recompute when that contract cannot be met.
- [ ] Route the internal production client, CodeQuery/RQL, and `.rqlp` policy execution through the shared generation repository.
- [ ] Add the equivalent Java/TypeScript resource pilot and cross-path parity assertions.
- [ ] Record repeated-root and repeated-policy measurements and generation/dependency invalidation evidence.
- [ ] Run focused and CI-equivalent validation, complete specialist review, address confirmed findings, and update the retrospective.

## Surprises & Discoveries

- Observation: `solve_typestate_with_reusable_summaries` has no production callers; only `tests/typestate_client.rs` and `tests/measure_summary_lifecycle.rs` exercise it.
  Evidence: exact `rg` references show production policy at `src/analyzer/policy/typestate_policy.rs:418` and CodeQuery at `src/analyzer/structural/search/typestate.rs:144` both call `solve_typestate_with_summaries`.

- Observation: current reusable hits are intentionally not witness-equivalent.
  Evidence: `SummaryState::apply_reusable_callee_summaries` in `src/analyzer/dataflow/summary.rs` calls `mark_reusable_witnesses_omitted`, and existing `tests/typestate_client.rs` asserts cached findings contain retention-truncated witness markers.

- Observation: repository validity and public report identity are already well separated.
  Evidence: `ProtocolSummaryKey` contains procedure, protocol, binding, schema, and entry facts; `PolicyReportDocument` is the one input to human, JSON, and SARIF renderers. Presentation fields therefore do not need to enter cache keys.

- Observation: several broad Bifrost `scan_usages_by_location`, `most_relevant_files`, and `search_symbols` calls produced no output after 30–120 seconds and were terminated, while exact source lookup remained responsive.
  Evidence: both the primary diagnostic and specialist agent reproduced the behavior; exact symbol sources plus `rg` were used only for the stalled reference-count checks.

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

## Outcomes & Retrospective

Implementation has not started. The architectural diagnosis and chosen lifecycle are complete. Update this section after every checkpoint with the behavior proven, validation run, remaining risk, and whether production reuse was actually beneficial.

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

### Milestone 2: witness-preserving protocol reuse

Extend the stable protocol summary evidence contract so accepted rows carry bounded canonical witness fragments. A fragment contains workspace-relative semantic locators, edge kind, call origin, proof, and completeness; it contains no dense fact IDs, node indexes, absolute mount, policy fields, or renderer configuration. Bump the protocol summary schema.

When projecting a complete result, retain fragments only under fixed production entry/byte/step bounds. When applying a cache hit, remap each fragment against the current protocol, binding plan, procedure points, and call sites, then insert it into the live witness arena so the same caller/callee/call-return path reconstructs as in the cold solve. If any requested evidence is unavailable or the fragment is truncated, reject the cache candidate before it affects the public result and recompute live. Do not fabricate edges or upgrade proof/completeness.

Extend `tests/typestate_client.rs` to compare normalized complete cold and warm reports, including findings, witness steps, truncation, certainty, completeness, and diagnostics. Preserve tests for ambiguity, budget/cancellation, normal/exceptional return, direct/mutual recursion, protocol/binding changes, and incomplete publication. Run focused tests, formatting, strict Clippy, update this plan, and checkpoint.

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

Names may be refined, but the production layer must expose responsibility-equivalent interfaces:

    pub struct TypestateSummaryRepositoryScope;
    pub struct TypestateSummaryGenerationLease;
    pub struct ProtocolSummaryLifecycleCounters {
        pub hits: u64,
        pub misses: u64,
        pub rejections: u64,
        pub evictions: u64,
        pub recomputations: u64,
    }

    impl TypestateSummaryRepositoryScope {
        pub fn new(generation: u64, limits: ...) -> Self;
        pub fn lease(&self, generation: u64) -> Result<TypestateSummaryGenerationLease, ...>;
        pub fn rotate(&self, next_generation: u64) -> ...;
        pub fn counters(&self) -> ProtocolSummaryLifecycleCounters;
    }

    pub fn project_production_semantic_summaries(
        roots: &[ProcedureHandle],
        provider: &impl IcfgProvider,
        lease: &TypestateSummaryGenerationLease,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<..., ...>;

    pub fn solve_typestate_with_production_summaries(
        root: &ProcedureHandle,
        entry_facts: &[TypestateFact],
        provider: &impl IcfgProvider,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
        lease: &TypestateSummaryGenerationLease,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<..., ...>;

The production layer reuses `SemanticProcedureSummary`, `CompleteSummaryRepository`, `ProtocolSemanticSummarySet`, `CompleteProtocolSummaryRepository`, `solve_typestate_with_reusable_summaries`, `SummaryWitness`, and existing canonical semantic locators. It adds no external crate dependency and no persistence format.

Plan revision note (2026-07-28): Created after live issue/branch verification, Bifrost-backed diagnosis, and specialist implementation planning. The plan chooses workspace-generation ownership, treats exact witness parity as a cache admission requirement, integrates every named public path, and leaves the later representative benchmark/precision campaign outside this first milestone.
