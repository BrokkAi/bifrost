# Complete model-backed taint conformance

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current. Maintain this document under `.agents/PLANS.md`.

## Purpose / Big Picture

Issue #1561 requires one deterministic gate for the complete model-backed taint route. After this work, a developer can run focused featureless tests and prove that semantic-model activation, exact summary binding, dependency selection, production propagation, retained evidence, and all public projections agree. The tests cover every supported boundary transfer, retain separate source origins, and prove that compatible demand uses one solve.

## Progress

- [x] (2026-08-04 11:42Z) Fetched the open issue and current remote state. Confirmed this issue branch equals `origin/master` at `4fb436a9121e4ce0d95d98b139735682c8589d79`.
- [x] (2026-08-04 11:42Z) Diagnosed the current production route and identified missing production conformance coverage.
- [x] (2026-08-04 11:42Z) Ran the two existing model-backed adapter tests and all five focused summary-binding tests. All passed.
- [x] (2026-08-04 11:42Z) Ran the baseline `bifrost.code-smells` policy selection. It completed with existing repository findings and no unreliable diagnostic.
- [x] (2026-08-04 11:58Z) Added production conformance fixtures for supported summary transfers, effects, and model-backed origin identity.
- [x] (2026-08-04 11:58Z) Added successful, recursive, and mutation-sensitive dependency-closure coverage.
- [x] (2026-08-04 11:58Z) Added reached and absent sink counts, retained/JSON/RQL parity, policy-origin parity, and one-solve multi-demand coverage.
- [x] (2026-08-04 11:58Z) Corrected the source-scenario identity collision exposed by two model-backed sources at one site.
- [x] (2026-08-04 12:19Z) Ran focused tests, strict featureless Clippy, formatting, diff checks, and the final policy gate.
- [x] (2026-08-04 12:27Z) Completed security, DRY, intent, operations, and architecture reviews.
- [x] (2026-08-04 13:12Z) Added exact meeting identities, canonical policy witness parity, ordered carrier continuity, and authored-order scenario stability.
- [x] (2026-08-04 13:12Z) Added executable parameter-input and receiver-input transfer cases. Asserted unbound receiver-output and exceptional-output cases as absent and typed partial.
- [x] (2026-08-04 13:12Z) Re-ran focused validation and specialist review. Architecture found no remaining issue. Intent retained one scope disagreement about unbound ports.

## Surprises & Discoveries

- Observation: The issue names the old policy module path.
  Evidence: PR #1548 moved production policy coordination to `crates/bifrost-policy/src/taint_policy.rs`.
- Observation: Binder tests already cover receiver, exceptional return, capture, heap, escape, and recursive effects.
  Evidence: `compiled_records_lower_every_supported_boundary_and_effect_honestly` in `tests/suite_semantic/semantic_model_summary_binding.rs` does not run the production route.
- Observation: The current successful production gate models only parameter zero to normal return.
  Evidence: `procedure_summary_pack_with_dependency` and `activated_java_parameter_to_return_summary_reaches_sensitive_sink_under_require_model` in `tests/suite_bench_policy/taint_policy_adapter.rs`.
- Observation: The current closure gate proves dependency traversal only through an expected missing-target failure.
  Evidence: `activated_java_summary_dependency_closure_selects_unobserved_relay` expects no retained result.
- Observation: Policy projection used only the semantic site for source-scenario identity.
  Evidence: Two logical model-backed sources at one call site preserved two public origins but initially produced `SourceScenarioIdentityCollision`.
- Observation: A dependency target descriptor that appears as another root call cannot prove closure selection by retained family size alone.
  Evidence: Removing the authored dependency edge still retained both summaries when both exact calls appeared in `run`; the existing missing-target case is the mutation-sensitive proof.
- Observation: The implemented transfer matrix proves retained binding data, but it does not execute every transfer through a checked sink.
  Evidence: The intent and architecture reviews both found this acceptance gap in `activated_java_summary_retains_every_supported_transfer_and_effect`.
- Observation: The multi-demand test checks reached and absent counts, but it does not bind each label to an exact stable sink identity.
  Evidence: The intent review showed that a label swap between two sinks can pass the current assertions.
- Observation: The production policy compiler does not install `ValueFlowSummaryLocationBinding` values.
  Evidence: Only the value-flow plan API and direct value-flow tests call `with_summary_location_bindings`; the policy compiler has no authored location-to-live-carrier mapping.
- Observation: Java external call rows did not expose a live receiver-output or exceptional-output path to later policy sinks.
  Evidence: Parameter-input to receiver-output and parameter-input to exceptional-return stayed absent. The retained run correctly reported partial evidence.

## Decision Log

- Decision: Keep this task test-first and change production only after a new minimized test fails.
  Rationale: Current evidence shows missing conformance coverage, not a known production defect.
  Date/Author: 2026-08-04 / Codex
- Decision: Put end-to-end cases in the existing consolidated adapter module.
  Rationale: `taint_policy_adapter.rs` already owns the production model-backed gate and its retained projection helpers.
  Date/Author: 2026-08-04 / Codex
- Decision: Compare stable carrier, origin, and symbol-site data, but omit projection-scoped identifiers.
  Rationale: The issue requires stable semantic identity without making local projection allocation part of the public contract.
  Date/Author: 2026-08-04 / Codex
- Decision: Use one small explicit dependency graph for successful, recursive, and removed-edge cases.
  Rationale: A shared fixture makes the mutation proof direct and keeps dependency behavior understandable.
  Date/Author: 2026-08-04 / Codex
- Decision: Include the stable source-event ordinal in policy scenario identity.
  Rationale: Public origin identity already distinguishes same-site logical source events by ordinal. Policy projection must preserve that distinction.
  Date/Author: 2026-08-04 / Codex
- Decision: Keep the existing missing-target closure test as the dependency-edge mutation proof.
  Rationale: Removing its authored call edge makes the expected failure disappear, while an independently selected target cannot prove closure causality.
  Date/Author: 2026-08-04 / Codex
- Decision: Treat unbound heap, capture, receiver-output, and exceptional-output ports as typed partial outcomes in this conformance gate.
  Rationale: The semantic pack identifies abstract locations, but the production policy surface cannot map them to live carriers. Inventing a text or name fallback would violate the issue non-goals.
  Date/Author: 2026-08-04 / Codex
- Decision: Compare policy witnesses through their public semantic subset.
  Rationale: Policy witnesses intentionally omit carrier facts and symbol identities. The gate now compares ordered step kinds, exact locations, truncation, and omitted counts.
  Date/Author: 2026-08-04 / Codex

## Outcomes & Retrospective

The first implementation milestone is complete. Nineteen adapter tests and five focused binder tests pass. Strict Clippy also passes.

The review follow-up is complete. The gate compares exact meeting identities and ordered witness paths across policy, retained, JSON, and RQL projections. It also proves scenario identity stability across authored source order.

Bindable parameter-input and receiver-input transfers reach their exact sinks. Abstract or unavailable output ports remain absent with partial evidence. This result preserves the structured production boundary. It does not invent a location binding that the semantic pack cannot define.

## Context and Orientation

A semantic-model pack contains authored procedure summaries for external calls. `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` activates compatible shards and finds summaries by language, path, symbol, receiver presence, and parameter count. `crates/bifrost-policy/src/taint_policy.rs` selects exact external targets, follows every declared call dependency, binds the selected family, compiles compatible policies, and runs propagation once. `crates/bifrost-analysis/src/analyzer/semantic_model/summary_binding.rs` lowers compiled transfers and effects into reusable semantic summaries. `crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs` converts the retained production report into stable public witnesses.

The main integration gate is `tests/suite_bench_policy/taint_policy_adapter.rs`. It already creates inline Java projects, registers ephemeral semantic packs, runs production policy evaluation, inspects retained results, executes JSON CodeQuery and RQL against the retained report, and compares public output. The focused binder tests live in `tests/suite_semantic/semantic_model_summary_binding.rs`. The parent lifecycle plan is `.agents/plans/issue-824-production-semantic-summary-taint-lifecycle.md`; it defines the same production route but measures it instead of completing semantic conformance.

In this plan, a carrier is a propagated taint fact. A meeting is a source label observed at a sink. An origin identifies the exact source event that created a fact. A dependency closure is every summary reached through declared call effects from selected root summaries. A recursive group is a strongly connected set of summaries that call each other.

## Plan of Work

First, extend the existing test builders in `tests/suite_bench_policy/taint_policy_adapter.rs`. Create one clear Java source fixture and one pack builder that can describe parameter, receiver, normal-return, exceptional-return, heap or named-location, and escape behavior. Reuse `InlineTestProject`, `SemanticPackCatalog`, and `evaluate_java_workspace_with_models`. Do not add a second compiler, binder, solver, report, or projection route.

Next, add canonical evidence helpers beside `assert_retained_taint_projection_matrix`. These helpers must compare complete reached and absent meeting sets, exact source origins, stable carrier identity, ordered source and origin symbols, typed fact kinds, and evidence completeness. They must remove only identifiers allocated by a projection instance. They must not remove stable carrier or symbol-site identity.

Add a model-backed two-origin case where two sources use the same propagation topology. Assert both origins in retained findings and every public projection. Add a transfer matrix that proves each supported input, exit, output, and effect form reaches only its intended sink. Each case must assert the expected meeting set and the complete absent set.

Replace the closure-only failure proof with a shared explicit dependency fixture. One case must bind and propagate through the complete closure. One must include a small recursive group. One mutation must remove a required dependency edge and cause the same gate to fail. Retain or strengthen the existing exact version, artifact near-miss, conflict, incomplete-summary, and materialized-body precedence cases.

Extend `assert_retained_taint_projection_matrix` so the direct retained projection, JSON CodeQuery, RQL, and policy projection use the same canonical evidence contract. Add compatible multiple-source and multiple-sink demand and assert one retained analysis plus one `taint.propagation_solves` metric.

If a production case fails, reduce it first. Change only the owning production module. Use `crates/bifrost-policy/src/taint_policy.rs` for selection or coordination defects, `summary_binding.rs` for binding defects, and `witness_projection.rs` for origin or identity defects. Add the minimized test before the correction.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/1ed3/bifrost` on the existing issue branch. After each milestone, update this plan and commit only the changed files with a multiline checkpoint message.

Run focused tests while developing:

    cargo test --locked --test suite_bench_policy --no-default-features -- taint_policy_adapter::<new-test-name>
    cargo test --locked --test suite_semantic --no-default-features -- semantic_model_summary_binding::

Run the complete issue validation after implementation:

    cargo test --locked --test suite_bench_policy --no-default-features -- taint_policy_adapter::
    cargo test --locked --test suite_semantic --no-default-features -- semantic_model_summary_binding::
    cargo test --locked -p brokk-bifrost-policy --lib --no-default-features -- projection::tests::
    cargo clippy --workspace --test suite_bench_policy --no-default-features -- -D warnings
    cargo fmt --all -- --check
    git diff --check

Run `bifrost.code-smells` and every explicitly named executable repository policy root through one MCP `run_policy` request. The repository names no executable policy roots at task start. Review each finding in changed files. Treat an unreliable result as a failed validation.

## Validation and Acceptance

The complete adapter module must pass without NLP. Its new tests must fail if two same-topology origins merge, if a required dependency edge disappears, or if any public projection changes semantic evidence. Every transfer case must state all reached and absent meetings, ordered witness symbols, fact types, and completeness. Exact model versions and artifacts must activate. Near misses must not activate. Conflicts must fail closed. Source bodies must take precedence. Compatible multiple-source and multiple-sink demand must report one propagation solve.

The focused binding module and analysis projection unit tests must pass. Featureless strict Clippy, formatting, and diff checks must pass. The final policy scan must not add a finding in a changed file.

## Idempotence and Recovery

All fixtures use ephemeral catalogs and inline temporary projects. Re-running tests does not change repository state. Cargo writes only to the normal worktree target. If a test fails, run its exact name again after the smallest correction. Do not delete caches, change branches, rebase, or create manual temporary target directories.

## Artifacts and Notes

Baseline test evidence:

    suite_bench_policy: 2 passed; 0 failed
    suite_semantic semantic_model_summary_binding: 5 passed; 0 failed

The baseline policy scan returned `finding`, not `unreliable`. Its findings are existing repository-wide prompts. Final comparison must focus on new or changed-file findings.

## Interfaces and Dependencies

Use existing public test interfaces: `InlineTestProject`, `SemanticPackCatalog`, `CompiledSemanticModelPack`, `PolicyBatchOutcome`, `ProductionTaintAnalysisResult`, `TaintResultRegistrationSet`, `CodeQuery::from_json`, and `CodeQuery::from_sexp`. Do not add a dependency. Do not enable `nlp`.

Revision note (2026-08-04): Created the self-contained issue #1561 plan after live issue inspection, Bifrost code navigation, baseline tests, and policy discovery.

Revision note (2026-08-04): Recorded the implemented conformance matrix, the source-scenario identity correction, dependency mutation evidence, and focused test results.

Revision note (2026-08-04): Recorded final validation and the specialist review gaps before the next implementation decision.

Revision note (2026-08-04): Closed the projection, meeting, carrier-order, and identity-stability gaps. Recorded the typed partial boundary for ports without live production carrier bindings.
