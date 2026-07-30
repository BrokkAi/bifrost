# Expose retained production taint findings through CodeQuery and RQL

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It implements GitHub issue #1364 and builds directly on the checked-in production taint adapter plan in `.agents/plans/issue-824-production-taint-adapter.md` and the registered value-flow query plan in `.agents/plans/issue-1297-codequery-value-flow-endpoints.md`. This document repeats the relevant architecture so it remains usable on its own.

## Purpose / Big Picture

After this change, a host that has already run Bifrost's production taint compiler and solver can register the immutable retained result under a bounded name such as `request:http-to-database`. A schema-version-7 CodeQuery or RQL query can then select a procedure and apply `taint` to obtain the existing diagnostic-neutral `taint_finding` rows. The query does not load a policy, compile source or sink declarations, run propagation, reconstruct witnesses, or assign vulnerability metadata. It validates the host-owned result, selects the entry for the exact structured procedure identity, and projects evidence that the production run already retained.

The observable demonstration is an inline Java project with compatible multiple-source and multiple-sink demand. Production preparation compiles and solves it once, policy rendering consumes the retained `TaintFindingReport`, and a registered JSON query plus equivalent RQL query consume that same report. Their `CodeQueryTaintFinding` values are field-for-field equal to `PolicyBatchOutcome::taint_findings()` when the projection limits match. Repeating the `taint` step in a union or later request does not increase `taint.propagation_solves`; missing, conflicting, stale, wrong-root, generation-mismatched, and plan/report-mismatched registrations produce stable typed diagnostics rather than empty results or implicit work.

## Progress

- [x] (2026-07-30 20:55 SAST) Verified the clean issue branch, fetched `origin`, confirmed the branch is exactly aligned with its upstream, and read live issue #1364 plus predecessor PRs #1329, #1343, and #1348.
- [x] (2026-07-30 21:05 SAST) Traced the production compiler, batch planner, one-solve path, retained finding report, public projector, policy outcome, value-flow registration precedent, query pipeline, runtime boundary, and service snapshot lifecycle.
- [x] (2026-07-30 21:15 SAST) Completed the guided diagnosis and repository-native planning pass and recorded the implementation design in this ExecPlan; the delegated planning pass was interrupted after source exploration, so the primary agent completed the plan from the verified code paths.
- [x] (2026-07-30 21:20 SAST) Received plan approval and began Milestone 1 on the existing issue branch.
- [x] (2026-07-30 21:43 SAST) Milestone 1: extracted one immutable retained production taint result per compatible batch, made policy and public projection consume the same plan/report pair, added conservative retained-memory and artifact accounting, and passed all five focused taint-policy adapter tests.
- [ ] Milestone 2: add bounded generation-scoped taint-result registration, exact-root lookup, and prepared-request snapshots.
- [ ] Milestone 3: add schema-v7 `taint`/`taint_ref` JSON and RQL vocabulary and projection-only typed execution.
- [ ] Milestone 4: complete public transports, editor support, docs, lifecycle/equivalence tests, and final validation.
- [ ] Run the required five-perspective guided review, remediate accepted findings, and update this plan with the final outcome.

## Surprises & Discoveries

- Observation: the production path already creates exactly the reusable result #1364 needs, but drops it after two immediate projections.
  Evidence: `ProductionTaintPolicyEvaluator::prepare` calls `solve_and_project_batch`; that function creates a local `TaintFindingReport`, passes it to `project_taint_finding_report` and `project_policy_findings`, and then retains only projection payloads and public rows.

- Observation: the public wire model is already present even though the typed query pipeline cannot produce it.
  Evidence: `CodeQueryResultValue::TaintFinding`, `CodeQueryTaintFinding`, `CodeQueryTaintOrigin`, and `CodeQueryTaintWitness` are handled by Rust, Python, LSP, CLI, and VS Code transports, while `SemanticPipelineValue` has no taint-finding variant and schema version 6 has no `taint` step.

- Observation: the schema-v6 value-flow adapter is the lifecycle precedent but the wrong execution precedent.
  Evidence: `ValueFlowPlanRegistrationSet` provides bounded aliases, generation validation, exact-root handles, and prepared snapshots, but `ValueFlowQueryState::endpoints` solves on a cache miss. A taint traversal must never contain an analogous solve branch.

- Observation: public taint IDs currently receive the batch propagation-semantics string as their projection scope.
  Evidence: `solve_and_project_batch` passes `batch.compatibility().propagation_semantics()` to `project_taint_finding_report`. Using `taint_ref` instead would make aliases change IDs and would break field-for-field equality with policy output.

- Observation: the installed Bifrost skills are visible, but this task exposes none of their code-intelligence or policy-checking MCP calls.
  Evidence: tool discovery found no `search_symbols`, `get_symbol_sources`, `list_policies`, or `run_policy`. Repository-native search is the current navigation fallback, and no policy-pack success may be claimed unless those tools become callable.

## Decision Log

- Decision: retain one immutable `ProductionTaintAnalysisResult` per executed compatible batch root, and let a `TaintResultRegistration` contain a deterministic collection of those entries.
  Rationale: one logical standalone request can produce several roots. A collection permits one host reference while exact structured procedure identity still selects only one result. The entry owns the compiled plan, compatibility/projection identity, report, artifact keys, and creation limits needed for safe projection.
  Date/Author: 2026-07-30 / Codex

- Decision: make production preparation the sole compiler and solver authority, then expose its retained results from `PolicyBatchOutcome` for in-process host registration.
  Rationale: embedded or workspace-backed taint declarations already enter through the real policy registry and `TaintPolicyCompiler`. Reusing the coordinator output avoids another loader, compiler, batch planner, or solve path. The CodeQuery step accepts only `taint_ref`; it never accepts policy paths or source/sink expressions.
  Date/Author: 2026-07-30 / Codex

- Decision: compute public finding, origin, event, and witness IDs from a canonical retained projection scope stored with the production result, never from the registration alias.
  Rationale: two aliases of one immutable result must return identical rows, and policy/query projection of one report must be field-for-field equal. The existing propagation-semantics scope remains part of the canonical production identity.
  Date/Author: 2026-07-30 / Codex

- Decision: registration identity includes workspace generation, exact per-root procedure identity, the complete batch compatibility key, a deterministic plan digest, semantic artifact keys, report/plan owner identity, collection limits, and canonical projection scope.
  Rationale: a reference must not silently bind to semantically different propagation, a different workspace snapshot, a report produced by another plan, or different truncation authority. Pointer identity may validate ownership in-process but is not used in public IDs or serialized state.
  Date/Author: 2026-07-30 / Codex

- Decision: register equal immutable results by an indexed digest and allow different references to alias one allocation; reject the same reference with a different identity transactionally.
  Rationale: this matches protocol/value-flow behavior, bounds lock-held work, and keeps aliasing deterministic without repeated deep comparisons.
  Date/Author: 2026-07-30 / Codex

- Decision: add `CodeQueryTaintLimits` for row, origin, witness, step, and retained-byte projection only; do not add solver or semantic-work limits to the taint step.
  Rationale: all expensive analysis happened before registration. Query limits may take a deterministic prefix of retained evidence and mark truncation/incompleteness, but cannot reconstruct omitted evidence or upgrade a partial result.
  Date/Author: 2026-07-30 / Codex

- Decision: publish `taint` and `taint_ref` at schema version 7, extend `file_of` for `taint_finding`, and do not add a separate witness traversal because witnesses are finding-owned fields in the existing result.
  Rationale: the issue requires `procedure -> taint_finding` and existing transports already carry bounded finding-owned witnesses. Adding another result envelope or witness representation would duplicate the landed contract.
  Date/Author: 2026-07-30 / Codex

- Decision: place new CodeQuery taint integration modules under `tests/suite_cross_language/` and extend `tests/suite_bench_policy/taint_policy_adapter.rs` for production equivalence/solve-count evidence.
  Rationale: `.agents/docs/test-harness-consolidation-2026-07.md` reserves new root integration binaries for process-isolated tests. These tests do not need process-global isolation and should reuse `InlineTestProject` for small projects.
  Date/Author: 2026-07-30 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. Production policy preparation now retains the authoritative plan/report pair as a `ProductionTaintAnalysisResult`; both public taint rows and policy findings are projected from that pair, and `PolicyBatchOutcome` exposes the immutable retained results for later host registration. The focused adapter tests prove one retained result for compatible policies and field-for-field reprojection equality, while retained-byte and artifact accounting establish the bounds needed by Milestone 2. The existing compiler, batch planner, one-solve path, finding collector, projector, policy classification, CVSS, and transport models remain authoritative.

## Context and Orientation

The production taint policy bridge lives in `crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs`. `TaintPolicyCompiler` executes already-resolved structured selectors and binds their results to semantic values. `ProductionTaintPolicyEvaluator::prepare` compiles all runnable taint policies before evaluation, passes their `TaintPolicyPlan` values to `TaintBatchPlanner::partition`, and calls `solve_and_project_batch` once for each compatible batch. A compatible batch is a set of policy plans whose propagation semantics are equal even when their source/sink observation subsets differ.

`crates/bifrost-analysis/src/analyzer/taint/plan.rs` defines `TaintAnalysisPlan`, the immutable solver input for one root procedure, and `TaintBatchCompatibilityKey`, which records the workspace snapshot, propagation semantics, unmodeled-call behavior, and taint universe. `crates/bifrost-analysis/src/analyzer/taint/finding.rs` defines `TaintFindingReport`. The report owns the branded `TaintSummaryResult`, sorted sink findings, per-origin contributing classes, bounded witnesses, completion, and truncation counters. The branded owner shared by plan and result prevents a report from being interpreted with the wrong plan.

`crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs` defines `project_taint_finding_report`. It is already a pure projector: it reads the plan and retained report, applies `CodeQueryTaintProjectionLimits`, builds stable source-backed IDs and locations, and invokes neither propagation nor witness reconstruction. Production policy preparation currently passes the batch propagation-semantics string as the projector's scope.

`crates/bifrost-analysis/src/analyzer/policy/coordinator.rs` defines `PolicyBatchOutcome`. It currently retains the canonical policy report and already-projected public taint rows, but not the plan/report pair that produced them. This plan changes the outcome to retain immutable production taint analysis results and derives its public rows from those results. Policy classification, messages, severity, CWE, CVSS, suppression, canonical reporting, and SARIF remain downstream policy responsibilities and are not added to CodeQuery.

Host-owned query registrations live in `crates/bifrost-analysis/src/analyzer/structural/analysis_context.rs`. Protocol and value-flow registrations demonstrate bounded references, immutable aliases, retained-memory accounting, workspace-generation checks, semantic-artifact validation, request-local opaque handles, and exact-root resolution. `QueryAnalysisContext` imports only references used by the decoded query. A stale handle is a handle created by another context generation; it must fail even if its numeric slot matches a current slot.

The public query language is schema-owned. `crates/bifrost-analysis/src/analyzer/structural/query/schema.rs` is the only vocabulary registry for operations, fields, aliases, shapes, signatures, descriptions, semantic facets, and minimum schema versions. `ir.rs`, `decode.rs`, `json.rs`, `sexp.rs`, and `source.rs` consume that metadata for typed plans, parsing, canonical rendering, validation ranges, hover, completion, and help. The current head is schema 6 and exposes registered value flow but no taint traversal.

`crates/bifrost-analysis/src/analyzer/structural/search/mod.rs` owns private pipeline values and typed step dispatch. It currently imports protocol and value-flow references into `QueryAnalysisContext`. `crates/bifrost-runtime/src/code_intelligence.rs` is the transport-neutral execution boundary. `crates/bifrost-mcp/src/searchtools_service.rs` owns long-lived registration sets, snapshots them while preparing a request, and clears them when workspace generation advances. The taint result set must cross the same boundaries.

In this plan, a "retained production result" means a value created by the one authoritative production compile/batch/solve/collect path. It includes enough identity and evidence to validate and project later but contains no policy classification. A "registration" is an in-memory, non-persisted mapping from a bounded `namespace:name` reference to one immutable retained-result collection. A "projection limit" can omit a deterministic suffix of retained rows or evidence and mark that omission; it cannot create evidence that the production report did not retain.

## Plan of Work

### Milestone 1: Retain the authoritative production result

In `crates/bifrost-analysis/src/analyzer/taint/plan.rs` and `finding.rs`, add the read-only identity, owner-validation, semantic-artifact visitation, and conservative retained-byte methods needed by a host registration. Count plan-owned structures, report/result structures, origin/class rows, witness allocations, witness steps, and artifact allocations separately so registration limits cannot be bypassed by a large report. Keep traversal iterative and reuse `ValueFlowPlan` artifact visitors and retained-byte helpers.

In `crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs`, introduce `ProductionTaintAnalysisResult` as the immutable result of one `TaintBatch`. It owns an `Arc<TaintAnalysisPlan>`, an `Arc<TaintFindingReport>`, the complete `TaintBatchCompatibilityKey`, canonical projection scope, exact production collection/projection limits, artifact keys, and deterministic identity digest. Refactor `solve_and_project_batch` into a narrow execute-and-retain function followed by policy projection. `ProductionTaintPolicyEvaluator` keeps these retained results rather than only public rows. Policy projections and public taint rows must both call `project_taint_finding_report` or `project_policy_findings` with the retained object's exact plan and report.

In `crates/bifrost-analysis/src/analyzer/policy/coordinator.rs`, store the retained immutable result collection in `PolicyBatchOutcome` and expose a read-only accessor suitable for host registration. Keep `taint_findings()` and `taint_query_results()` source-compatible by deriving or retaining rows from the same result objects. Do not expose `LoadedPolicy`, internal classification DTOs, or mutable solver state.

Extend `tests/suite_bench_policy/taint_policy_adapter.rs` with instrumentation proving compatible multi-source/multi-sink demand creates one retained production result and one `taint.propagation_solves` increment. Prove policy projection and public projection consume the same plan/report allocation, produce unchanged rows, and perform no witness reconstruction or propagation on repeated projection. Include plan/report mismatch and conservative retained-byte unit coverage.

Acceptance is the focused taint policy adapter module passing with existing policy output unchanged, followed by formatting and `git diff --check`. Update this plan and commit only milestone files with a multiline checkpoint message explaining why the result ownership changed.

### Milestone 2: Register and lease immutable taint results

In `crates/bifrost-analysis/src/analyzer/structural/analysis_context.rs`, add `TaintResultRef`, `TaintResultRegistration`, `TaintResultRegistrationSet`, limits, outcomes, errors, indexed identity, and an opaque `TaintResultHandle`. A registration receives the current workspace generation and a non-empty deterministic collection of `Arc<ProductionTaintAnalysisResult>` entries. Sort entries once by structured procedure identity, reject duplicate roots with different identities, and select by semantic artifact key plus `SemanticLocator`, not rendered names or source text.

Registration must be transactional and independently bound reference count, unique result collections, retained plan bytes, semantic artifact bytes, report bytes, witness bytes, and per-entry counts. Re-registering the same reference and identity is unchanged. Different references may alias the same indexed immutable collection. Rebinding a reference is a conflict. Context construction validates generation and every artifact within the shared cancellation-aware validation budget. Resolution rechecks context generation, registration identity, exact root, and plan/report ownership. Map failures to taint-specific unresolved-reference, stale-registration, stale-handle, generation, root, and plan/report diagnostic codes without collapsing them into protocol or value-flow errors.

Extend `QueryAnalysisContext::new_with_all_registrations_and_summaries` with taint registrations and requested taint references. Keep convenience constructors by supplying empty taint sets. Export the host types from `crates/bifrost-analysis/src/analyzer/structural/mod.rs`.

In `crates/bifrost-mcp/src/searchtools_service.rs`, add a `query_taint_results` lock, registration/unregistration methods, snapshot it into `PreparedQueryCode`, clear it on workspace-generation changes, and preserve prepared-request snapshot isolation. In `crates/bifrost-runtime/src/code_intelligence.rs` and structural execution entry points, extend the analysis-registration lease to carry protocol, value-flow, and taint sets while retaining simpler existing entry points through empty defaults.

Add `tests/suite_cross_language/code_query_taint_context.rs` and one `mod code_query_taint_context;` entry in its `main.rs`. Use `InlineTestProject`. Cover reference parsing, conflict/idempotence/aliasing, every independent memory limit, duplicate-root rejection, stale generation, stale artifacts, stale cross-context handles, exact-root mismatch, plan/report mismatch, snapshot isolation, invalidation, and mount-independent identity.

Acceptance is the new context module plus focused runtime/service registration tests passing. Update this plan and commit the milestone explicitly.

### Milestone 3: Add schema-v7 projection-only execution

Advance `SCHEMA_VERSION` and the declared RQL lineage from 6 to 7. In `query/schema.rs`, add semantic facet `Taint`, operation `taint` with `procedure -> taint_finding`, required `taint_ref`, value shape `TaintResultRef`, and RQL form `(taint :taint-ref namespace:name query)`. Add `TaintFinding` to `QueryValueKind`; add `TaintTraversal` and `QueryStep::Taint` in `ir.rs`; extend `file_of` to accept taint findings. All spelling, field, signature, help, and minimum-version data must come from the registry.

Update `decode.rs`, `json.rs`, `sexp.rs`, and `source.rs` for required-field decoding, canonical JSON/RQL rendering, duplicate/unknown/missing fields, schema-version rejection, path-precise invalid-domain diagnostics, hover, completion, and help. Update `structural/execution/plan.rs` so explain mode reports the taint semantic facet but does not resolve a registration.

Create `crates/bifrost-analysis/src/analyzer/structural/search/taint.rs` as a small projection adapter. It resolves `TaintResultHandle` for the selected `SemanticProcedureValue`, retrieves the exact retained entry, applies `CodeQueryTaintLimits`, and calls `project_taint_finding_report`. There is no compiler, provider, solver, `DataflowRequest`, `SolverBudget`, or witness reconstruction in this module. Cache only projected rows by exact retained entry plus effective limits if repeated branches would otherwise repeat allocation; work counters report registration resolutions, projection cache hits, retained rows considered, rows emitted, and truncation, never propagation solves.

Extend `SemanticPipelineValue`, keys, public projection, detailed provenance, `file_of`, ordering, set composition, and result rendering for the existing `CodeQueryTaintFinding` model. Requested-reference discovery must scan every branch and common suffix. Missing registration or any validation failure must become a typed invalid/incomplete result before execution. Cancellation during bounded projection remains cancelled or incomplete, never clean.

Define validated `CodeQueryTaintLimits` in `results.rs` with finite maxima for findings, origins per finding, witnesses per finding, steps per witness, per-witness bytes, and aggregate projected bytes. The effective values are the minimum of query limits and the retained production authority. Lower limits take a deterministic prefix, preserve stable identities for retained items, set existing truncation/completeness fields, and never upgrade incomplete evidence.

Add `tests/suite_cross_language/code_query_taint.rs` and its harness module entry. Use one inline Java fixture and production preparation from Milestone 1. Prove JSON/RQL equality, field-for-field equality with `PolicyBatchOutcome::taint_findings`, same result through two aliases, union/repeated-step reuse without solve increments, deterministic ordering/deduplication, `file_of`, lower query limits, retained incompleteness, cancellation, missing/stale/root/mismatch diagnostics, invalid domain ranges, and explicit schema 6 rejection.

Acceptance is the query parser/source/planner tests plus both new taint integration modules passing. Update this plan and commit the milestone explicitly.

### Milestone 4: Complete public surfaces and release-quality validation

Update `crates/bifrost-mcp/src/mcp_extended.rs` and any shared schema/help metadata to describe schema 7 and the registered retained-result contract. Verify CLI, LSP, MCP, Python, and VS Code paths accept and render the already-existing `taint_finding` result without a parallel envelope. Add only missing strict-model, URI-enrichment, text/detail rendering, and navigation cases.

Update `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json` from the conservative schema vocabulary to recognize `taint`, `taint-ref`, and `taint_ref`. Add grammar, query, completion, hover, formatting, and result tests. Update compatible-head fixtures from 6 to 7 only where they intentionally track the head; preserve explicit older pins.

Update public guides under `docs/src/content/docs/` for JSON and RQL syntax, host-owned registration, immutable execution scope, exact-root selection, retained-evidence limits, diagnostics, and the policy-neutral boundary. Add executable examples and docs tests showing that query syntax names only `taint_ref`, not policy files or arbitrary sources/sinks.

Run the five guided-review specialists against the full issue diff: security, duplication, intent, operations, and architecture. Address all critical/high findings and selected lower findings, adding minimized regressions for discovered recurring behavior. If a review smell is mechanically expressible in RQL, follow the repository review-policy instructions before adding a built-in policy rule.

After review remediation, run task-scoped featureless validation first from `/Users/dave/.codex/worktrees/055f/bifrost`:

    cargo fmt --all -- --check
    git diff --check
    cargo test --test suite_bench_policy -- taint_policy_adapter::
    cargo test --test suite_cross_language -- code_query_taint:: code_query_taint_context:: code_query_public_api:: structural_search_planner:: code_query_docs:: code_query_tutorials::
    cargo test --test suite_mcp_cli -- code_intelligence_runtime:: bifrost_lsp_server::
    cargo test --test suite_semantic -- taint_client:: value_flow_client::
    bash scripts/test_python.sh
    npm --prefix editors/vscode test

Run strict Clippy through managed isolated storage. This is an actual final gate, so use the repository-required all-feature command after checking disk space and ensuring no sibling NLP build is active:

    df -h .
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Before completion, use the installed `brokk:bifrost-policy-checking` skill and run `bifrost.code-smells` plus every executable repository policy root in one request if `list_policies` and `run_policy` are callable. Treat `finding` as review work and `unreliable` as failed validation; rerun after fixes. If the tools remain absent, record that precise environment limitation without claiming success.

Update `Outcomes & Retrospective`, record concise validation transcripts, run final status/diff review, and commit the last reviewed milestone. Do not push or open a pull request unless the user explicitly requests it.

## Concrete Steps

Work only on the existing branch `1364-add-standalone-taint-codequeryrql-over-retained-production-findings`. Do not create, switch, or rebase branches. Before each milestone, confirm `git status --short --branch` and preserve unrelated changes. Use `apply_patch` for source edits and stage only files changed in that milestone.

For Milestone 1, first add failing ownership/equivalence tests, then extract the retained result and rerun:

    cargo test --test suite_bench_policy -- taint_policy_adapter::
    cargo fmt --all -- --check
    git diff --check

For Milestone 2, add the context module and run:

    cargo test --test suite_cross_language -- code_query_taint_context::
    cargo test --test suite_mcp_cli -- code_intelligence_runtime::

For Milestone 3, add parser/execution tests before implementation and run:

    cargo test -p brokk-bifrost-analysis structural::query
    cargo test --test suite_cross_language -- code_query_taint:: structural_search_planner::

For Milestone 4, run the transport/editor/docs and final commands listed above. After every milestone, update `Progress`, `Surprises & Discoveries`, `Decision Log`, command transcripts, and the revision note at the bottom of this file. Commit only after the focused tests, formatter, and diff check pass.

## Validation and Acceptance

The main acceptance fixture must start from production taint declarations executed through the existing policy registry and `TaintPolicyCompiler`. It must create more than one source and sink in a compatible batch and prove exactly one `taint.propagation_solves` increment. No query branch, alias, repeated request, policy projection, or public projection may increment that metric or call the taint solver again.

With equal projection limits, the JSON query, RQL query, and `PolicyBatchOutcome::taint_findings()` must serialize to equal `taint_finding` values, including IDs, sink identity, reached labels/classes, origins, origin labels, proof, completeness, ambiguity, witness IDs, witness steps, truncation flags, and omitted lower bounds. Different references that alias the same registration must produce identical IDs and rows.

Reducing query limits must only remove a deterministic suffix of retained findings/origins/witness material. It must preserve retained IDs, mark truncation and partial completeness, and never reconstruct evidence omitted by production collection. A retained report that is already incomplete stays incomplete even when query output fits its limits.

All lifecycle failures must be distinguishable by typed diagnostic code and impact: missing reference, conflicting registration, stale context handle, workspace-generation mismatch, stale semantic artifact, root mismatch, plan/report mismatch, validation-budget exhaustion, cancellation, and projected-byte exhaustion. None may become an empty complete result.

Schema tests must show that omitted version selects 7, explicit versions 2 through 6 preserve their behavior, version 6 rejects `taint` at the authored operation range, malformed `taint_ref` is range-precise, and invalid input domains fail before workspace execution. Hover, completion, help, canonical JSON/RQL round-trip, formatter, and TextMate grammar must derive or agree with the registry.

Transport tests must prove that Rust, MCP/LSP, CLI, Python, and VS Code continue to use `result_type: "taint_finding"`. No new policy message, severity, classification, CWE, CVSS, suppression, SARIF, or generic vulnerability fields may appear in the standalone result.

## Idempotence and Recovery

All compilation, solving, registration, query, formatting, and test commands are safe to repeat against the same immutable workspace. Registration is transactional: a rejected conflict or memory limit leaves counts, aliases, and retained allocations unchanged. Prepared query snapshots remain valid against their captured generation even if a later alias is removed, while a workspace-generation advance invalidates live registrations for later requests.

Use the repository-managed Cargo target helper for isolated final builds. Never create manually named `/tmp/bifrost-*` or `/private/tmp/bifrost-*` targets. If an isolated build is interrupted, rerun the same helper; it removes its managed target automatically unless explicitly retained.

Do not use `git reset --hard`, broad checkout, `git add -A`, or destructive cleanup. If a milestone fails, update this plan with the observed failure, fix forward, and rerun its focused tests. If unrelated user changes appear, leave them untouched and stage only explicit milestone files.

## Artifacts and Notes

Starting state:

    branch: 1364-add-standalone-taint-codequeryrql-over-retained-production-findings
    HEAD: 77a8d2fb4fdc
    upstream divergence: 0 ahead, 0 behind
    worktree: clean before this plan file
    RQL schema head: 6

Current authoritative execution trace:

    PolicyRegistry / LoadedPolicy
      -> TaintPolicyCompiler
      -> TaintBatchPlanner::partition
      -> solve_taint_batch_with_witnesses (once per compatible batch)
      -> collect_taint_findings_with_limits
      -> local TaintFindingReport
      -> project_taint_finding_report + project_policy_findings
      -> report dropped

Target trace:

    production preparation
      -> Arc<ProductionTaintAnalysisResult>
           owns exact plan + report + identity + limits
      -> policy projection
      -> PolicyBatchOutcome retained result accessor
      -> host TaintResultRegistrationSet
      -> QueryAnalysisContext / exact-root TaintResultHandle
      -> schema-v7 taint projection only

## Interfaces and Dependencies

At the end of Milestone 1, `crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs` must expose an immutable result to the rest of the analysis crate with responsibilities equivalent to:

    pub struct ProductionTaintAnalysisResult {
        plan: Arc<TaintAnalysisPlan>,
        report: Arc<TaintFindingReport>,
        compatibility: TaintBatchCompatibilityKey,
        projection_scope: Box<str>,
        collection_limits: TaintFindingCollectionLimits,
        projection_limits: CodeQueryTaintProjectionLimits,
        identity: ProductionTaintAnalysisIdentity,
    }

It must provide read-only accessors, exact root identity, semantic artifact visitation/keys, conservative retained plan/report/witness bytes, and a plan/report ownership validator. Incidental field placement may change, but no caller may construct an unvalidated plan/report pair.

`PolicyBatchOutcome` must expose the immutable results without exposing mutable evaluator state:

    pub fn taint_analysis_results(&self) -> &[Arc<ProductionTaintAnalysisResult>];

At the end of Milestone 2, `analysis_context.rs` must provide bounded public host types equivalent to:

    pub struct TaintResultRef(...);
    pub struct TaintResultRegistration(...);
    pub struct TaintResultRegistrationSet(...);
    pub enum TaintResultRegistrationOutcome { Inserted, Aliased, Unchanged }

    impl TaintResultRegistration {
        pub fn new(
            workspace_generation: u64,
            results: Vec<Arc<ProductionTaintAnalysisResult>>,
        ) -> Result<Self, TaintResultRegistrationError>;
    }

    impl QueryAnalysisContext {
        pub fn taint_result_handle(&self, taint_ref: &TaintResultRef) -> Option<TaintResultHandle>;
        pub fn resolve_taint_result(
            &self,
            workspace_generation: u64,
            expected_root: &ProcedureHandle,
            handle: TaintResultHandle,
        ) -> Result<&ProductionTaintAnalysisResult, QueryAnalysisContextError>;
    }

At the end of Milestone 3, schema-owned query types must include:

    pub struct TaintTraversal {
        pub taint_ref: TaintResultRef,
    }

    QueryStep::Taint(TaintTraversal)
    QueryValueKind::TaintFinding

and `CodeQueryExecutionLimits` must include `taint: CodeQueryTaintLimits`. The adapter in `structural/search/taint.rs` accepts only the workspace, generation, analysis context, exact procedure, reference, projection limits, row/byte budget, and cancellation. It has no dependency on `TaintPolicyCompiler`, `TaintBatchPlanner`, `solve_taint_batch_with_witnesses`, `DataflowRequest`, or witness reconstruction APIs.

Revision note (2026-07-30): Created the initial self-contained plan after live issue/remote verification and guided diagnosis. The plan chooses a retained per-batch production result, a multi-root host registration keyed by structured procedure identity, schema-v7 projection-only execution, and alias-independent public IDs so policy and query output can be exactly equivalent.

Revision note (2026-07-30 21:43 SAST): Recorded Milestone 1 completion after the focused adapter suite passed. The implementation keeps the production plan/report allocation intact, routes both projections through it, and adds the conservative ownership accounting required for bounded registration.
