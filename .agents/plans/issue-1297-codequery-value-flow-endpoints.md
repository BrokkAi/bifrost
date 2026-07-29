# Expose value-flow endpoints and witnesses through CodeQuery/RQL

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It implements GitHub issue #1297, a native child of #824. Issue #1205 remains responsible for the shared cross-language source-backed conformance harness and language-adapter readiness; this plan changes the typed query adapter and reuses existing focused value-flow fixtures only.

## Purpose / Big Picture

After this change, an embedding that already owns an immutable `ValueFlowPlan` can register it under a bounded namespaced reference and query its diagnostic-neutral results through ordinary CodeQuery JSON or RQL. A schema-version-6 `value_flow` step maps a selected `procedure` to typed `flow_endpoint` rows. Each row keeps reachability, certainty, ambiguity, and completion distinct, so an exact positive, a may-flow, ambiguous discovery, an incomplete solve, and a budget-exhausted solve cannot be confused. A following `witness` step maps reached endpoints to bounded source-backed `flow_witness` rows using evidence retained by that same solver run.

The observable demonstration is one inline Java project whose existing production `ValueFlowPlan` is registered in `SearchToolsService`. Equivalent JSON and RQL queries select the root procedure, execute the existing `solve_value_flow_with_witnesses` client exactly once, and return equal endpoint and witness data. A second request with a deliberately tiny solver budget returns explicit incomplete/budget metadata and never a clean negative.

This is not a policy feature. It adds no severity, message, policy identity, vulnerability class, CWE, CVSS, SARIF classification, taint semantics, `.rqlp` evaluator, or source/sink authoring syntax.

## Progress

- [x] (2026-07-29 09:50 SAST) Verified the clean detached worktree at current `origin/master` `ece1e5ee`, fetched remote state, and read live #824 and #1205.
- [x] (2026-07-29 09:50 SAST) Created enhancement issue #1297 with the exact adapter scope, assigned it, and attached it as a native child of #824.
- [x] (2026-07-29 09:50 SAST) Traced `ValueFlowPlan`, `solve_value_flow_with_witnesses`, `ValueFlowSummaryResult`, schema-v5 typestate registration, typed query execution, and editor/documentation surfaces.
- [x] (2026-07-29 11:38 SAST) Milestone 1: added bounded generation-scoped value-flow plan registrations, transactional retained-memory/artifact accounting, prepared-request snapshots, and focused registration coverage.
- [x] (2026-07-29 11:38 SAST) Milestone 2: published schema v6 `flow_endpoint`/`flow_witness` domains through the declarative registry, JSON/RQL parsing and rendering, validation ranges, hover/completion, explain/schema metadata, and grammar tests.
- [x] (2026-07-29 11:38 SAST) Milestone 3: added a request-local adapter over `solve_value_flow_with_witnesses`, one-solve caching, all-sink outcome projection, and retained-evidence-only bounded witnesses.
- [x] (2026-07-29 11:38 SAST) Milestone 4: carried strict typed results through SearchToolsService, CodeIntelligenceRuntime, MCP/LSP enrichment, Python, VS Code, grammar, executable docs, and text/detail rendering without policy classification.
- [x] (2026-07-29 11:38 SAST) Milestone 5: completed focused Rust, Python, VS Code, docs, planner, public-API, typestate-regression, and all-feature/all-target Clippy validation; recorded the environment-limited full-feature link and unreliable policy-pack outcomes below.
- [x] (2026-07-29 13:20 SAST) Synced the detached worktree to current `origin/master` `e30cdc53` and completed an adversarial guided review of the 44-file working diff.
- [x] (2026-07-29 14:05 SAST) Remediation milestone A: merged runtime solver coverage with plan discovery, made exact/may and stable entry-carrier semantics part of endpoint identity, clamped query witness limits, streamed public steps, and added pre-projection endpoint plus aggregate witness ledgers.
- [x] (2026-07-29 14:05 SAST) Remediation milestone B: retained value-flow provenance in context-construction errors, prepared plan accounting and a semantic digest outside the session lock, and replaced linear deep comparisons/pointer recounting with an indexed registration identity.
- [x] (2026-07-29 14:05 SAST) Remediation milestone C: extracted shared witness projection and bounded reference-codec infrastructure, fixed the newly exposed `file_of` executor omission, and expanded the focused suite from 8 total tests to 16 including shared harness tests.
- [x] (2026-07-29 16:42 SAST) Remediation milestone D: reran focused Rust/Python/VS Code/docs/transport validation, passed the exact all-target/all-feature Clippy gate, reran the required repository policy selection, attempted the full `nlp,python` suite through integration-test linking, and reconciled the remaining environment/policy limitations below.
- [x] (2026-07-29 16:47 SAST) Final reconciliation: formatter and diff checks remain clean. During the long validation run `origin/master` advanced from reviewed snapshot `e30cdc53` to `f4432169`; the intervening #1205 harness/language-adapter and semantic-model changes do not overlap this worktree's modified paths, and the detached dirty worktree was deliberately not rebased.
- [x] (2026-07-29 18:05 SAST) Publication reconciliation: attached the work to `dave/issue-1297-codequery-value-flow-endpoints`, rebased cleanly onto current `origin/master` `7437d6f8`, fixed the upstream-added watcher-test initializer to include value-flow registrations, and passed post-rebase NLP-free formatting, Python-feature Clippy, 78 focused Rust tests, 62 Python tests, and 79 VS Code tests. The warmed policy result remains unreliable for the same five repository-wide discovery-budget limitations and reports no new changed-line finding.

## Surprises & Discoveries

- Observation: the low-level client already distinguishes reached, complete not-reached, and incomplete inconclusive outcomes.
  Evidence: `src/analyzer/value_flow/result.rs` exposes `ValueFlowSinkOutcome::{Reached, NotReached, Inconclusive}` and derives completeness from the plan plus `SummaryDataflowResult`.

- Observation: a reached meeting already retains enough solver evidence for a pure witness projection.
  Evidence: `ValueFlowSummaryResult::witness_for_meeting` delegates to the retained summary result by reached index and rejects a meeting from another result.

- Observation: may and must are not symmetric guarantees in the existing client.
  Evidence: `ValueFlowMayStatus` is `Proven` or `Unproven`, while `ValueFlowMustStatus` currently has only `NotEstablished`. The public adapter must not invent a must-flow claim.

- Observation: plan discovery and solver termination are separate completeness dimensions.
  Evidence: `ValueFlowPlan::discovery_status()` records complete, ambiguous, unsupported, budget, cancellation, or unknown semantic input; `SummaryDataflowResult::termination()` separately records fixed point, cancellation, or solver-budget exhaustion.

- Observation: schema version 5 is already a compatibility point for declaration-bounded containment.
  Evidence: `src/analyzer/structural/query/ir.rs` declares `SCHEMA_VERSION = 5`, and `schema.rs` retains explicit versions 2, 3, 4, and 5. Value-flow vocabulary therefore requires version 6 rather than changing version 5 in place.

- Observation: concurrent broad Bifrost code-intelligence calls can stall while exact single-symbol lookup is fast.
  Evidence: one exact `ValueFlowPlan` symbol search completed in 615 ms, while batched `get_summaries`/symbol/relevance requests did not complete after 63 to 105 seconds and were terminated. A focused performance issue must record the reproducible request before completion.

- Observation: `ValueFlowPlan` registration needs to account for considerably more than its top-level boxed slices.
  Evidence: the final memory review found plan-owned external summaries, curated evidence, hash-table carrier clones, fallback indexes, source/sink carrier clones, and proof/completeness strings. `retained_bytes` now charges those nested allocations while continuing to exclude separately registered semantic artifacts.

- Observation: the policy engine completed the pack report but could not reliably evaluate every selected rule.
  Evidence: the final `bifrost.code-smells` run returned exit 2 with 12 runs: 7 complete and 5 inconclusive. Its findings in changed files all point to pre-existing lines outside this diff; because the pack status is unreliable, it is recorded as a validation limitation rather than a clean gate.

- Observation: the full `nlp,python` test build now selects and links Python 3.13 correctly, but the complete integration-binary fan-out exhausts the host filesystem.
  Evidence: `PYO3_PYTHON=/opt/homebrew/opt/python@3.13/bin/python3.13 cargo test --features nlp,python` compiled the feature-enabled crate and reached integration-test linking before `ld` failed with `errno=28 (No space left on device)` for `analyzer_capability_parity`, `policy_sarif_rendering`, and other concurrently linked targets. The workspace `target` directory was 56 GiB and the data volume had 1.2 GiB free afterward. The Python harness independently passed 60 tests.

- Observation: `cargo`, `rustc`, and Clippy can resolve to two ABI-incompatible Rust 1.96.0 distributions on this host even though their version strings match.
  Evidence: Cargo/rustc initially resolved through rustup (LLVM 22.1.2) while `cargo-clippy` and `clippy-driver` resolved through Homebrew (LLVM 22.1.6), producing E0514 in `build.rs`. Prepending the rustup 1.96.0 tool directory aligned the complete toolchain. The exact `cargo clippy --all-targets --all-features -- -D warnings` gate then found one necessary eight-parameter private snapshot boundary; the repository-approved narrow `allow(clippy::too_many_arguments)` was applied there, and the rerun passed in 25m25s.

- Observation: the guided review found that the first implementation applies the generic pipeline row cap only after `project_endpoints` has materialized all sink outcomes, and `ValueFlowSummaryResult::sink_outcome` scans every meeting once per sink.
  Evidence: `src/analyzer/structural/search/value_flow.rs` builds an unbounded `Vec`, while `src/analyzer/value_flow/result.rs::sink_outcome` filters the complete meeting slice on every call.

- Observation: solver-time semantic provider failures survive in `SummaryCoverage` independently from plan discovery.
  Evidence: typestate records `solved.result().result().coverage().semantic_status()`, while the initial value-flow adapter records and renders only `ValueFlowPlan::discovery_status()`.

- Observation: the Bifrost code-reading request for the core remediation symbols exceeded its request-wide budget after roughly 70 seconds.
  Evidence: `get_symbol_sources` returned MCP error `-32603`; local structured source inspection was used to continue. Existing issue #1298 owns this latency path.

- Observation: schema validation accepted `file_of` after `flow_endpoint` and `flow_witness`, but execution had no corresponding match arms.
  Evidence: the new complete-negative/file projection regression reached the executor's supposedly unreachable domain arm. Adding both flow-domain projections made the full 16-test value-flow suite green.

## Decision Log

- Decision: use `value_flow: procedure -> flow_endpoint` with required `plan_ref`, and overload `witness` as `flow_endpoint -> flow_witness`.
  Rationale: the procedure is the exact registered analysis root; the plan already owns resolved source/sink bindings. Reusing `witness` preserves the existing typed projection model without adding a second solver operation.
  Date/Author: 2026-07-29 / Codex

- Decision: publish the new vocabulary as schema version 6 while retaining exact versions 2 through 5.
  Rationale: explicit old pins must keep their published meaning. Compatible head can advance without altering older JSON or RQL.
  Date/Author: 2026-07-29 / Codex

- Decision: model endpoint semantics with independent `reachability`, `certainty`, and `completion` fields.
  Rationale: one flattened outcome enum cannot truthfully describe a reached may-flow whose overall solve also exhausted a budget. Orthogonal fields preserve exact/may/ambiguous/incomplete/budget information without precedence tricks.
  Date/Author: 2026-07-29 / Codex

- Decision: emit one endpoint per reached source/sink meeting, and one source-less endpoint for each sink with no meeting.
  Rationale: this retains every positive source identity while making complete `not_reached` and incomplete `inconclusive` sink outcomes queryable instead of disappearing as empty results.
  Date/Author: 2026-07-29 / Codex

- Decision: retain the existing `must = not_established` value explicitly.
  Rationale: the solver proves may reachability today; the adapter must expose, not overstate, that contract.
  Date/Author: 2026-07-29 / Codex

- Decision: registrations accept only preconstructed in-memory `ValueFlowPlan` values and JSON/RQL carry only a bounded namespaced reference.
  Rationale: semantic handles must not cross the wire, and query execution must consume the existing plan rather than parse source/sink names or rebuild adapter facts.
  Date/Author: 2026-07-29 / Codex

- Decision: cache a completed or incomplete solve by the exact registration/root pair for one request; do not add persisted result caching.
  Rationale: duplicate query rows must not rerun the solver, while persisted or reusable cross-query summary ownership remains outside this child.
  Date/Author: 2026-07-29 / Codex

- Decision: keep all policy projection and taint work out of issue #1297.
  Rationale: the user explicitly requested diagnostic neutrality and little overlap with #1205. This plan proves the public result/witness adapter only.
  Date/Author: 2026-07-29 / Codex

- Decision: register immutable plans by conservative plan-owned and artifact-owned byte totals, with nested plan allocations charged independently from semantic artifact allocations.
  Rationale: the host boundary must reject oversized registrations transactionally without double-counting shared artifact bodies or undercounting plan-specific indexes, cloned carriers, evidence, and summary metadata.
  Date/Author: 2026-07-29 / Codex

- Decision: treat all eleven guided-review findings as a release-blocking remediation queue rather than accepting known adapter debt.
  Rationale: the high findings violate the advertised exact/may/incomplete/budget contract or allow work to escape host limits; the remaining findings have already produced semantic drift and weak regression coverage.
  Date/Author: 2026-07-29 / Codex

- Decision: make endpoint and witness budgets request-local and debit them before reconstruction or public-value allocation.
  Rationale: per-row clipping after materialization does not bound CPU or peak memory. A deterministic ledger can stop work early and expose typed truncation instead of relying on client cancellation.
  Date/Author: 2026-07-29 / Codex

- Decision: derive the in-process registration identity from a canonical cryptographic digest of the plan's equality-relevant stable structures, then index that identity exactly like protocol registrations.
  Rationale: hashing is performed once outside service locks; alias lookup and registration counts become constant-time without trusting run-local pointers or repeatedly comparing large plans.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

Issue #1297 is implemented as a schema-v6, diagnostic-neutral CodeQuery/RQL adapter over the existing `ValueFlowPlan` and solver. Hosts register immutable plans through a bounded generation-scoped capability. `value_flow` returns typed endpoint rows that keep reachability, certainty, must status, ambiguity, completion, and termination orthogonal; `witness` performs a bounded pure projection from retained solver evidence. JSON and RQL share the declarative schema, and strict result models now span Rust, Python, MCP/LSP, and VS Code. No policy severity, classification, taint vocabulary, or `.rqlp` execution was added.

Focused validation passed before and after publication integration: all 16 value-flow integration/shared-harness tests, 13 typestate regressions, 20 structural planner tests, 5 public API tests, 3 CodeQuery documentation tests, and 21 tutorial tests; the earlier query-unit, shared-witness-projection, mixed-registration, and `cargo check --lib` checks also remain green. The final transport runs passed 62 Python tests and 79 VS Code checks/tests. `cargo fmt`, `git diff --check`, the exact all-target/all-feature Clippy command before publication, and the post-rebase all-target Python-feature Clippy command passed with one repository-approved `too_many_arguments` annotation on the necessary private snapshot boundary.

The comprehensive `nlp,python` integration matrix was not repeated after publication integration because this change is unrelated to semantic search and repository guidance now reserves NLP builds for relevant or explicitly comprehensive gates. Its earlier concurrent-link attempt exhausted the host disk rather than exposing a code failure. The Bifrost policy pack remains formally unreliable: five repository-wide rules exhaust discovery budgets (with stable-anchor loss on two), while the warmed 894 ms rerun's only two findings in touched files resolve to unchanged pre-existing `sort()` calls in `src/analyzer/structural/search/mod.rs`. The rebased branch is pushed for review.

## Context and Orientation

`src/analyzer/value_flow/plan.rs` defines `ValueFlowPlan`, an immutable set of already-resolved semantic carriers, local/call transfers, source bindings, sink bindings, and discovery status for one root `ProcedureHandle`. `src/analyzer/value_flow/client.rs` defines `solve_value_flow_with_witnesses`; it adapts that plan to the shared summary data-flow solver and retains bounded witness evidence. `src/analyzer/value_flow/result.rs` converts solver facts to `ValueFlowMeeting` rows, exposes per-sink reached/not-reached/inconclusive outcomes, and reconstructs a witness from retained evidence.

`src/analyzer/structural/analysis_context.rs` currently contains bounded host registration and request-scoped resolution for typestate. Extend the same host-owned capability boundary with a separate `ValueFlowPlanRef`, registration set, opaque handle, and resolution path. A host registration is branded by the workspace generation and the plan root. It must retain and validate every semantic artifact identity reachable from the plan, not only the root.

`src/analyzer/structural/query/schema.rs` is the declarative source of truth for public operations, fields, RQL forms, signatures, descriptions, accepted aliases, and value shapes. `ir.rs`, `decode.rs`, `json.rs`, `sexp.rs`, and `source.rs` consume that registry to form and validate canonical CodeQuery plans. No private keyword or editor-only option table may be introduced.

`src/analyzer/structural/search/semantic.rs` owns the request semantic budget and the query-local typestate adapter. Add a sibling value-flow adapter in `src/analyzer/structural/search/value_flow.rs`. `src/analyzer/structural/search/mod.rs` owns private pipeline values and execution; `results.rs` owns wire result models, diagnostics, limits, work counters, text rendering, and detailed provenance.

`src/searchtools_service.rs` captures immutable analyzer and registration snapshots for a prepared request. `src/code_intelligence.rs` is the transport-neutral execution boundary. Python models live under `bifrost_searchtools/`; RQL result UI lives in `editors/vscode/src/rql_query.ts`; grammar lives in `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`; public guides live under `docs/src/content/docs/`.

In this plan, “exact” means the existing meeting has `ValueFlowMayStatus::Proven` and no ambiguity marker. “May” means a meeting exists but proof is unproven. “Ambiguous” means the plan's semantic discovery status is ambiguous; it remains explicit even when a meeting is reached. “Incomplete” means semantic discovery or the solver did not establish a complete fixed point. “Budget exhausted” identifies the semantic or solver budget that prevented completeness. None of these terms imply policy severity or exploitability.

## Plan of Work

### Milestone 1: Register immutable value-flow plans safely

In `src/analyzer/value_flow/model.rs` and `plan.rs`, add read-only structured visitors for every retained semantic artifact key and allocation in a plan, plus a conservative retained-byte count. Walk handles iteratively. Cover the root, carriers, source/sink points, local and call rules, fallback profiles, summary-location bindings, curated models, and any call/procedure handles they retain. Do not infer identities by source text.

In `src/analyzer/structural/analysis_context.rs`, add `ValueFlowPlanRef` with the same bounded namespace/name grammar as `ProtocolRef`, `ValueFlowPlanRegistration`, `ValueFlowPlanRegistrationSet`, limits, outcomes, errors, an opaque request handle, and context resolution. Registration is transactional. Re-registering the same reference and same plan/root/generation is unchanged; rebinding it is a conflict. The store is bounded by references, registrations, retained plan bytes, and retained semantic-artifact bytes. A prepared context validates current workspace generation, exact root identity, and every artifact key within the same cancellation-aware validation budget used by typestate.

Expose the host types from `src/analyzer/structural/mod.rs`. Add focused context tests for parsing, all independent limits, conflict/idempotence, snapshot isolation, stale generations, stale artifacts, wrong roots, and cross-context handles.

Acceptance is `cargo test --test code_query_value_flow_context` passing with deterministic typed errors, followed by `cargo fmt --check` and `git diff --check`.

### Milestone 2: Add schema-v6 typed algebra

Change `SCHEMA_VERSION` to 6 and extend the explicit lineage 2 -> 3 -> 4 -> 5 -> 6. Add `FlowEndpoint` and `FlowWitness` to `QueryValueKind`. Add `ValueFlowTraversal { plan_ref }`, `QueryStep::ValueFlow`, and overload `QueryStep::Witness` by input domain. Extend `file_of` for both new source-backed domains.

In the declarative registry add semantic facet `ValueFlow`, operation `value_flow` with signature `procedure -> flow_endpoint` and `since: 6`, `plan_ref` with JSON spelling `plan_ref` and RQL spelling `plan-ref` plus the existing underscore compatibility alias, and the `ValueFlowPlanRef` value shape. Update `witness` and `file_of` signatures/descriptions to mention both typed branches. Explain mode declares value-flow work only on `value_flow`; witness remains a pure projection.

Teach JSON and RQL to round-trip:

    {
      "schema_version": 6,
      "match": {"kind": "function", "name": "run"},
      "steps": [
        {"op": "procedure_of"},
        {"op": "value_flow", "plan_ref": "embedding:fixture-flow"},
        {"op": "witness", "max_steps": 32, "max_bytes": 16384}
      ]
    }

and:

    (witness :max-steps 32 :max-bytes 16384
      (value-flow :plan-ref "embedding:fixture-flow"
        (procedure-of (function :name "run"))))

Add parser, canonical-rendering, schema-version, invalid-domain, unknown/duplicate/missing-option, validation-range, hover, completion, formatting, and physical-plan tests. Explicit versions 2 through 5 must reject the new operation at its authored range while otherwise retaining current behavior.

Acceptance is the query unit suite, source validation tests, editor hover/completion tests, and planner tests passing.

### Milestone 3: Execute once and project diagnostic-neutral results

Create `src/analyzer/structural/search/value_flow.rs`. Resolve the registration for each `SemanticProcedureValue`, verify the exact root, and call `solve_value_flow_with_witnesses` with the request cancellation token, shared semantic budget, finite `SolverBudget`, and bounded `WitnessRetentionLimits`. Cache the `Arc<ValueFlowSummaryResult>` or a deterministic failure by exact plan registration/root for one request.

Define finite `CodeQueryValueFlowLimits` inside `CodeQueryExecutionLimits`: solver work, retained witness relations/bytes, reconstruction steps/expansions, and public witness bytes. Validate positive hard maxima before execution. Record solves, cache hits, meetings, sink outcomes, reached rows, fixed points, cancellations, solver budgets, semantic completion, witnesses, retained steps/bytes, and truncation in `CodeQueryValueFlowWork` nested under semantic work.

Define public `CodeQueryFlowEndpoint` with stable ID, plan reference, source event (optional for negative/inconclusive sinks), sink event, source/sink sites, reachability, may status, must status, ambiguity, completion, solver termination, path qualities, and source-backed primary path/range. Stable IDs hash length-delimited workspace-relative event/locator and plan-reference components; they omit absolute roots, dense IDs, and reached indexes. Sort by the stable semantic identity before pipeline limits.

For each sink, emit every reached meeting. If no meeting exists, emit one source-less endpoint whose reachability is `not_reached` only when the result is complete, otherwise `inconclusive`. A reached result remains reached even when incomplete, while its completion field states why the overall analysis is partial. Map unsupported, unknown, ambiguous, semantic-budget, semantic-cancellation, solver-budget, and solver-cancellation to explicit data and typed diagnostics. Never turn an incomplete empty result into a clean negative.

Define `CodeQueryFlowWitness` and step models by projecting `SummaryWitness`. `witness` produces rows only for reached endpoints with retained meetings. It invokes neither the provider nor the solver. Apply query `max_steps` and `max_bytes` as a contiguous-prefix reduction, downgrade witness completeness, and report omitted-step lower bounds and a truncation diagnostic.

Add `tests/code_query_value_flow.rs` using `tests/common/inline_project.rs` and existing structured semantic selectors. Prove JSON/RQL equality, exact and may meetings, ambiguous discovery, complete negatives, incomplete and budget outcomes, cancellation, stable checkout-root-independent IDs, duplicate-row solve reuse, set composition, pure witness projection, contiguous truncation, and `file_of`. Do not add a cross-language harness or adapter matrix.

### Milestone 4: Complete public transports and documentation

Extend `SearchToolsService` with bounded `register_query_value_flow_plan` and unregister methods. Prepared requests capture the flow registration snapshot alongside protocols. Workspace-generation rotation clears or stales live flow registrations consistently. Extend `CodeIntelligenceRuntime` and direct workspace execution with both registration sets while preserving existing protocol-only convenience entry points.

Add strict Python endpoint/witness models and union decoding. Extend LSP URI enrichment and VS Code result guards, labels, detail lines, navigation, and tests without inventing diagnostic severity. Update TextMate grammar for `value-flow`/`value_flow`, `plan-ref`/`plan_ref`, and the schema-generated option vocabulary. Update MCP tool descriptions and schema metadata from the declarative registry.

Update `docs/src/content/docs/code-query-json.md`, `code-querying.md`, `rune-query-language.md`, `rql-vscode.md`, and `python-client.md` for schema 6, host registration, the endpoint/witness algebra, orthogonal outcomes, finite budgets, and the policy-free boundary. Add executable examples and docs tests. Preserve explicit-version fixture files that intentionally pin schema 5; update compatible-head expectations to 6.

Acceptance is the Rust transport/LSP/docs tests, `bash scripts/test_python.sh`, and `npm --prefix editors/vscode test` passing.

### Milestone 5: Review and release-quality validation

Review the final diff against #1297 and this plan, focusing on stale-handle safety, stable identities, truthful completion, bounded retained memory, witness purity, Windows-safe paths, and absence of policy classification or #1205 harness work. Search for accidental hard-coded public vocabulary outside the schema and for exhaustive matches missed by new result domains.

Run from `/Users/dave/.codex/worktrees/e82b/bifrost`:

    cargo fmt
    git diff --check
    cargo test --test code_query_value_flow_context
    cargo test --test code_query_value_flow
    cargo test --test code_query_public_api
    cargo test --test structural_search_planner
    cargo test --test bifrost_lsp_server value_flow
    cargo test --test code_query_docs
    cargo test --test code_query_tutorials
    bash scripts/test_python.sh
    npm --prefix editors/vscode test
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Before completion, use the installed Bifrost policy tool to run the `bifrost.code-smells` pack and every repository executable policy root in one request with evaluation date `2026-07-29` and `fail_on: warning`. Treat `finding` as review work and `unreliable` as a failed validation result. Rerun the same selection after any fixes.

Update all living sections with exact evidence and write the final retrospective. Because this worktree is detached and the user did not request a branch or commit, do not create a branch, stage, commit, push, or open a pull request.

## Concrete Steps

Work only in `/Users/dave/.codex/worktrees/e82b/bifrost`. Before each milestone, inspect `git status --short --branch`, `git log -1 --oneline --decorate`, and `git diff --check`. Use `apply_patch` for edits and preserve unrelated files.

Use the existing typestate slice as the structural reference, but keep value-flow semantics native: `src/analyzer/structural/analysis_context.rs`, `src/analyzer/structural/search/typestate.rs`, `src/analyzer/structural/search/semantic.rs`, `src/analyzer/structural/search/results.rs`, `src/analyzer/structural/query/schema.rs`, `src/searchtools_service.rs`, and `tests/code_query_typestate.rs`. Read `src/analyzer/value_flow/{model.rs,plan.rs,client.rs,result.rs}` before adapting any output.

Implement milestones in order. After every focused test run, update `Progress`, `Surprises & Discoveries`, and `Decision Log` before moving on. The first user-visible smoke should contain one `result_type: "flow_endpoint"` item with `reachability: "reached"`, truthful may/must and completion fields, and a following `result_type: "flow_witness"` containing ordered source-backed steps.

## Validation and Acceptance

The feature is accepted when explicit schema versions 2 through 5 remain compatible, schema 6 JSON and RQL canonicalize to the same plan, a registered production plan returns equal typed endpoints through both syntaxes, every sink remains observable as reached/not-reached/inconclusive, budget/cancellation/unsupported/ambiguous states stay explicit, duplicate procedure rows cause one solve, witnesses are retained-evidence-only and bounded, all public transports decode the same fields, editor hover/completion/grammar derive from the declarative vocabulary, documentation examples execute, strict Clippy and the `nlp,python` suite pass, and the policy run is clean and reliable.

## Idempotence and Recovery

Registration and unregistration operations are bounded and idempotent. A failed registration must not mutate indexes or retained-byte counters. Prepared request snapshots remain valid after live alias removal but fail if their workspace generation or semantic artifact identities are stale. Focused tests can be rerun safely. Isolated Cargo builds must use `scripts/with-isolated-cargo-target.sh`; do not create manually named Cargo target directories. If interrupted, consult this plan's current `Progress` entry and `git diff` rather than discarding changes.

## Artifacts and Notes

GitHub issue: `https://github.com/BrokkAi/bifrost/issues/1297`.

The target public algebra is:

    structural_match -> procedure -> flow_endpoint -> flow_witness

The last arrow projects retained evidence. Only the `value_flow` arrow may invoke the existing solver.

## Interfaces and Dependencies

The final Rust surface must include a bounded `ValueFlowPlanRef`, `ValueFlowPlanRegistration`, `ValueFlowPlanRegistrationSet`, registration outcome/error types, and `SearchToolsService::{register_query_value_flow_plan, unregister_query_value_flow_plan}`. The IR must include `ValueFlowTraversal { plan_ref }`, `QueryStep::ValueFlow`, `QueryValueKind::{FlowEndpoint, FlowWitness}`, and schema version 6. Execution limits must include `CodeQueryValueFlowLimits`; profile work must include `CodeQueryValueFlowWork`. Public results must include `CodeQueryFlowEndpoint`, `CodeQueryFlowWitness`, strict supporting enums/step models, result references, detailed provenance, text rendering, and transport decoders.

No new external dependency is required. Use `ValueFlowPlan`, `solve_value_flow_with_witnesses`, `ValueFlowSummaryResult`, `ValueFlowSinkOutcome`, `SummaryWitness`, `WitnessRetentionLimits`, `WitnessReconstructionLimits`, `SolverBudget`, `SemanticBudget`, and `CancellationToken` from the existing repository.

Revision note (2026-07-29): created the initial self-contained plan after live issue creation and source inspection; fixed schema-v6, registration, endpoint-outcome, witness-purity, transport, #1205-boundary, and validation decisions before implementation. Reconciled every living section after implementation, adversarial review remediation, and final validation, including runtime semantic coverage, aggregate work limits, stable identity, shared witness projection, registration-lock behavior, policy reliability, toolchain-aligned strict Clippy, and the disk-limited full-feature test attempt.
