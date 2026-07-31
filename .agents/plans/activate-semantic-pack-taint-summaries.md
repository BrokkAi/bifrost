# Activate semantic-pack procedure summaries in production taint

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds.

This plan follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, an activated semantic-model pack can describe the value-flow behavior of an exact external Java procedure and the production taint policy path will use that behavior. A user can run a normal set-oriented taint policy with `require-model`; an attacker-controlled argument passed through a declaration whose body is unavailable can reach a sensitive sink through the activated parameter-to-return summary. The existing taint compiler, batching coordinator, value-flow plan, summary solver, retained witness projection, classification, CVSS, and renderers remain the only execution route.

The observable proof is a Java vertical test. It activates one reviewed procedure-summary pack, runs one production policy, and retains the modeled call/return witness, diagnostic-neutral taint finding, broad fallback classification, and policy projection. The same suite proves strict activation, real-body precedence, conflict failure, propagation identity invalidation, unrelated-pack stability, one-solve compatible batching, and an in-memory warm path with no per-call catalog lookup.

## Progress

- [x] (2026-07-31 18:25 SAST) Inspected the clean detached worktree at `90f5eeba`, fetched `origin`, read `.agents/PLANS.md`, and traced the active runtime, compiled-summary binder, production taint compiler, dispatch boundary, value-flow precedence, batching, and retained projection contracts.
- [x] (2026-07-31 18:25 SAST) Confirmed Handoff A is `ResolvedActiveSemanticModels::procedure_summaries_for` plus `acquire_active_semantic_models`, Handoff B is `bind_compiled_procedure_summaries`, and the installation seam is `ValueFlowPlan::with_external_summaries`.
- [x] (2026-07-31 19:52 SAST) Milestone 1: retained validated exact external procedure descriptors on unmaterialized dispatch boundaries, sourced only from resolved `CodeUnit`, signature metadata, semantic call receiver metadata, and mounted artifact identity.
- [x] (2026-07-31 19:52 SAST) Milestone 2: added explicit policy-batch activation authority, one generation-cached acquisition, plan-local exact lookup, iterative family dependency closure, Handoff B binding, and `ValueFlowPlan::with_external_summaries` installation.
- [x] (2026-07-31 19:52 SAST) Milestone 3: added the required Java `RequireModel` vertical and regressions for activation near misses, body precedence, target conflicts, relevant/unrelated identity, shared solves, and warm catalog accounting.
- [ ] Milestone 4: run focused suites, formatting, strict featureless Clippy, the repository policy gate, review the diff, and complete the retrospective. Focused production/oracle/runtime/binder/value-flow suites and formatting are green; Clippy and policy validation remain.

## Surprises & Discoveries

- Observation: the value-flow client already implements the requested precedence.
  Evidence: `ValueFlowPlan::visit_boundary_transfers` checks an exact external summary first, then a curated call model, then applies the configured fallback. Missing heap or capture carriers make the selected model incomplete instead of falling through to a different model.

- Observation: production taint compilation currently drops external dispatch boundaries.
  Evidence: `TaintPolicyCompiler::discover_value_flow` retains only `DispatchCandidate` values and their call bindings. `DispatchBoundaryKind::Unmaterialized` retains a locator, but the lower call-relation layer discards the exact `CodeUnit` signature and parameter metadata before policy compilation.

- Observation: active semantic models are already cached by analyzer snapshot and canonical activation request, but no production consumer acquires them.
  Evidence: `AnalyzerSnapshotCaches` owns `SemanticModelRuntimeCache`; `acquire_active_semantic_models` uses it and returns `Built` then `Cached`, while source search finds production uses only in the runtime integration tests.

- Observation: broad concurrent Bifrost MCP calls are still unreliable on the hand-written host.
  Evidence: the initial concurrent symbol/file/summary batch exceeded its request-wide budget after about twelve seconds, while narrow retries completed in under a second. A later four-target usage scan exhausted its ten-second budget after 8.6 seconds. Issue #1423 owns this failure class.

- Observation: Java receiver presence must come from the semantic call row rather than declaration spelling.
  Evidence: the required fixture uses `this.external(...)`; the retained descriptor records `SemanticCallSite::receiver` and never guesses static/instance shape from source modifiers or the locator.

- Observation: propagation identity comparisons require one mounted analyzer snapshot.
  Evidence: independent inline projects intentionally produce different workspace mount identities. The relevant/unrelated and body-precedence regressions therefore reuse one snapshot and vary only generation-cache request keys and active catalog content.

## Decision Log

- Decision: add a semantic-oracle external procedure descriptor instead of teaching the policy compiler to interpret locators, signatures, or source text.
  Rationale: dispatch already owns the exact resolved `CodeUnit`, signature metadata, mounted semantic artifact, and declaration locator. Keeping those structured facts together prevents a second parser and lets every downstream client use the same typed boundary.
  Date/Author: 2026-07-31 / Codex

- Decision: add an explicit semantic-model runtime input to the analyzer-backed policy coordinator and acquire it once before compiling any taint policy.
  Rationale: the catalog and activation request are host-owned authority. Passing that authority explicitly avoids a global default or an ambiguous “last active set” in analyzer caches, while the existing snapshot cache provides same-generation reuse.
  Date/Author: 2026-07-31 / Codex

- Decision: make each compiled `ValueFlowPlan` receive only summaries reached from exact external descriptors in that discovery plus their compiled dependency closure.
  Rationale: `ValueFlowPlan::propagation_semantics_hash` already hashes the installed summary-set fingerprint. A plan-local set therefore invalidates reuse for a changed relevant summary without hashing unrelated active packs.
  Date/Author: 2026-07-31 / Codex

- Decision: preserve existing policy-authored `external_models` rejection.
  Rationale: semantic-pack activation is independent host analysis authority. This work must not enlarge public policy syntax or create a competing model source.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

Milestones one through three are implemented. The production route now acquires active semantic models once, keeps structured exact targets on normal dispatch discovery, selects only matching summary families and closure, binds them through the existing pure binder, and installs the canonical plan-local set before the existing taint batch planner solves. No policy vocabulary, solver, secondary propagation route, presentation rerun, or global active-set hash was added. The Java vertical and all requested negative/cache/identity/batching regressions pass. Final Clippy and repository policy validation remain.

## Context and Orientation

All paths are repository-relative. `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` is Handoff A. It strictly activates catalog shards from versioned evidence, stores decoded shards in one immutable `ResolvedActiveSemanticModels`, and indexes procedure records by language, artifact-relative path, symbol, receiver presence, and parameter count. `acquire_active_semantic_models` reuses a `CompleteValueCache` owned by the current analyzer snapshot, so one canonical request is built once per generation and warm acquisition returns the same `Arc`.

`crates/bifrost-analysis/src/analyzer/semantic_model/summary_binding.rs` is Handoff B. `bind_compiled_procedure_summaries` accepts one selected compiled family, exact target bindings, and an `ExternalSummaryCompatibilityKey`, validates all targets and dependencies, computes recursive groups, lowers transfers/effects, and returns the existing `ExternalSemanticSummarySet`.

`crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs` contains `TaintPolicyCompiler`. It executes stored selectors, binds source and sink carriers, discovers procedure snapshots and exact call bindings, constructs one `ValueFlowPlan` per maximal call region, wraps it in `TaintAnalysisPlan`, and sends compatible plans through `TaintBatchPlanner`. `ProductionTaintPolicyEvaluator::prepare` compiles every runnable taint policy before partitioning, solving, collecting findings, and retaining one report for public and policy projections.

`crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/dispatch.rs` converts exact language-aware definition lookup into `DispatchCandidate` bodies or typed `DispatchBoundary` values. A declaration with no published procedure becomes `DispatchBoundaryKind::Unmaterialized`, but today that variant retains only a `SemanticLocator`. The new descriptor will retain the already-structured symbol, receiver/parameter boundary shape, artifact key, and locator at this layer. Policy code will consume its fields directly.

`crates/bifrost-analysis/src/analyzer/value_flow/plan.rs` owns the immutable plan. `with_external_summaries` validates dependency and fallback compatibility. `visit_boundary_transfers` already applies a matching exact external summary before a curated call model and before fallback. `summary_port_carrier` binds receiver, positional parameter, normal return, and exceptional return from the semantic call row. Heap and capture ports require an explicit `ValueFlowSummaryLocationBinding`; absent bindings keep the modeled boundary incomplete and do not silently select a lower-precedence model.

## Plan of Work

Milestone 1 will introduce a small validated external procedure descriptor in the semantic oracle. The workspace dispatch adapter will construct it only when exact definition and signature metadata, mounted artifact identity, and procedure declaration locator are available. It will compose the already-normalized callable name and exact signature metadata without splitting or reparsing them. Declarations with a materialized body remain candidates and do not emit the descriptor, preserving body precedence. Existing boundary rendering, ordering, work accounting, and semantic contract tests will be updated.

Milestone 2 will add an explicit optional semantic-model runtime authority to the analyzer-backed coordinator entry point. The coordinator will call `acquire_active_semantic_models` once before `ProductionTaintPolicyEvaluator::prepare`, pass one immutable active set to every compiler, and surface cancelled/unavailable activation truthfully. During discovery, the compiler will collect exact external descriptors. For each plan it will query Handoff A by descriptor, fail closed on conflicts, compute the selected record dependency closure iteratively, build exact Handoff B bindings, and call `ValueFlowPlan::with_external_summaries`. Empty matches install no set. The compatibility key will use current summary schema/semantics/context behavior, the root dependency fingerprint, and the policy's existing `UnmodeledCallBehavior`.

Milestone 3 will extend `tests/suite_bench_policy/taint_policy_adapter.rs` and focused semantic tests. The Java fixture will pass a tainted source argument through a declaration-only external method into a sensitive sink under `require-model`. Tests will inspect witness steps and the same retained policy projection. Variants will change activation artifact/version evidence, provide a body, register equal-rank conflicting targets, change selected summary content, change only an unrelated pack, and execute two compatible presentation variants. The warm test will acquire once, assert cached reuse, then prove target queries and policy compilation do not increase catalog lookup accounting.

Milestone 4 will run the narrow semantic-oracle, semantic-model, value-flow, and policy adapter tests first. It will then run `cargo fmt --all -- --check`, featureless strict Clippy through `scripts/with-isolated-cargo-target.sh`, and one Bifrost policy request selecting `bifrost.code-smells` plus every executable repository policy root. Findings will be fixed or explained; unreliable policy execution remains a failed validation result.

## Concrete Steps

From `/Users/dave/.codex/worktrees/4041/bifrost`, use these task-scoped commands as implementation progresses:

    cargo test --test suite_semantic -- semantic_model_runtime:: semantic_model_summary_binding:: value_flow_client::
    cargo test --test suite_bench_policy -- taint_policy_adapter::
    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh /Users/dave/.cargo/bin/cargo-clippy clippy -p brokk-bifrost-analysis --all-targets --no-default-features -- -D warnings

No NLP feature is needed because this work does not touch semantic search. If the local Homebrew/rustup Clippy split reproduces E0514, use the rustup toolchain's exact `cargo-clippy` binary as recorded in the preceding binder plan.

## Validation and Acceptance

The required vertical test passes only when the production coordinator uses an activated exact parameter-to-return summary under `RequireModel`. It must assert the modeled call/return witness, one diagnostic-neutral taint finding, the broad fallback classification, the policy finding projection, and one propagation solve.

Wrong artifact digest or package version evidence must leave the pack inactive and must not create the modeled flow. Replacing the declaration-only method with a real body must use the body even when the matching pack is active. Equal-rank conflicting summary targets must produce a failed or inconclusive policy outcome rather than choose one. Changing a relevant summary must change propagation compatibility; changing only an unrelated active pack must not. Two policies with compatible propagation semantics but different observation or presentation data must retain one shared solve. Catalog accounting must remain unchanged across per-call runtime-index lookups and warm policy compilation after the generation-cached active value is acquired.

Existing optimistic/paranoid/require-model behavior, curated models, batching, public taint projection, classification, CVSS, report limiting, and renderers must remain on their current routes. There must be no RQL/schema/editor change, solver change, summary persistence, navigation overlay, or policy-level external-model implementation.

## Idempotence and Recovery

All catalog fixtures are ephemeral or temporary and all production changes are additive or local contract extensions. Re-running compilation and tests is safe. The active runtime publishes only complete generation-fresh values. A failed binder returns a typed compiler failure and installs no partial summary set. If a test exposes an unrelated baseline failure, record it separately and keep the focused acceptance result distinct.

The worktree is detached, so this plan will not create or switch a branch. ExecPlan checkpoint commits are permitted by repository instructions, but each checkpoint will stage only files changed for this plan. No push, rebase, or pull request is authorized.

## Artifacts and Notes

Current base:

    90f5eeba Add deterministic compiled procedure summary binder (#1424)

MCP dogfood evidence on the hand-written host is owned by GitHub issue #1423. Exact narrow retries worked, so implementation can continue while preserving the failed batch timing as product evidence.

## Interfaces and Dependencies

The semantic boundary descriptor must expose the exact mounted `SemanticArtifactKey`, procedure-role `SemanticLocator`, normalized symbol, receiver presence, and bounded formal parameter count. It must validate that artifact and locator mount/path/language agree. It must not depend on semantic-model DTOs.

The policy coordinator will expose an analyzer-backed entry point that accepts `SemanticPackCatalog`, `SemanticModelActivationRequest`, and optional `SemanticModelActivationPersistence` as one explicit borrowed context. Existing entry points remain compatible and mean no semantic-pack enrichment.

`TaintPolicyCompiler` will accept an optional `Arc<ResolvedActiveSemanticModels>`. Its summary selection helper will consume `ProcedureSummaryTargetKey`, `ActivatedProcedureSummary`, `ExactProcedureSummaryTargetBinding`, `ExternalSummaryCompatibilityKey`, and `bind_compiled_procedure_summaries`. It will install the result only through `ValueFlowPlan::with_external_summaries`.

Revision note (2026-07-31 18:25 SAST): created the initial self-contained plan after tracing both handoffs, production dispatch/taint/value-flow code, tests, and current repository state. The plan keeps activation authority explicit, summary sets plan-local, policy syntax unchanged, and all propagation/presentation work on the existing route.

Revision note (2026-07-31 19:52 SAST): completed the structured dispatch, activation/binding, and vertical-test milestones; recorded receiver-metadata and mount-identity discoveries; and left only final Clippy, policy, and retrospective gates open.
