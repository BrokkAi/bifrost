# Deliver the production taint policy adapter and retained public projection

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, a loaded taint `.rqlp` policy can execute against the production semantic and taint engines instead of returning an unsupported result. A policy with several structured source and sink matches is compiled as a finite set-oriented analysis, compatible policies share one propagation run through `TaintBatchPlanner`, and one retained `TaintFindingReport` supplies both diagnostic-neutral public taint query data and the existing policy evidence/classification/reporting pipeline. Human, canonical JSON, SARIF, LSP, and VS Code policy views therefore describe the same analysis result without rerunning propagation.

The observable proof is an inline multi-source/multi-sink fixture. Its selectors bind exact return/receiver/argument semantic values, one compatible batch solves once, `collect_taint_findings` retains the sink meetings and bounded solver evidence, and all report formats retain the same finding identity, contributing labels, bounded origins, witness references, certainty, completeness, broad fallback classification, and scoring provenance. Changing only message, severity, finding combinations, classification, or CVSS presentation must not cause another propagation run. Changing sanitizer, transform, oracle/call-model, context, access-path, external-model, scope, or completeness-affecting semantics must partition or become an explicit incomplete/unsupported result.

## Progress

- [x] (2026-07-29 20:24Z) Verified a clean worktree at `eaada248`, fetched `origin`, confirmed `HEAD == origin/master`, and proved PR #1329 merge commit `24fb9291` is an ancestor.
- [x] (2026-07-29 20:24Z) Read issue #824, child #1297, PR #1329, `.agents/PLANS.md`, the production typestate adapter, and the current taint plan/finding/policy projection seams.
- [x] (2026-07-29 20:24Z) Confirmed that the current coordinator installs only `ProductionTypestatePolicyEvaluator`; the taint evaluator seam has no production implementation.
- [x] (2026-07-29 20:24Z) Confirmed that the Bifrost code-intelligence and policy MCP tools are not registered in this task even though their skills are installed.
- [x] (2026-07-29 20:27Z) Finished the independent guided-issue diagnosis; it confirmed the coordinator-wide architecture and identified endpoint-set equality plus discarded per-origin class/witness associations as prerequisites.
- [x] (2026-07-29 21:11Z) Milestone 1: implemented `TaintPolicyCompiler` over stored structured CodeQuery selectors, exact source-backed semantic call/value bindings, bounded semantic discovery, and set-oriented per-root source/sink plans.
- [x] (2026-07-29 21:11Z) Milestone 2: added coordinator-wide taint preparation, exact `TaintBatchPlanner` partitioning, one existing-client solve and one `collect_taint_findings` call per batch, plus observable solve/shared-membership work metrics.
- [x] (2026-07-29 21:11Z) Milestone 3: implemented and installed `ProductionTaintPolicyEvaluator`; it projects the retained report into the sealed pair-local taint DTOs while leaving classification, CVSS, evidence validation, and renderers authoritative.
- [x] (2026-07-29 21:11Z) Milestone 4: added the bounded sink-level `CodeQueryTaintFinding`/`CodeQueryTaintOrigin` envelope and the landed source-backed witness-step projection helper. The guided review later corrected witness ownership.
- [x] (2026-07-29 21:11Z) Milestone 5: extended retained-origin tests and added an inline two-source/two-sink, two-policy integration test proving one shared solve, broad fallback classification, and human/JSON/SARIF parity.
- [x] (2026-07-29 21:18Z) Completed formatting, strict featureless Clippy, the full policy and semantic integration binaries, and final diff review. Policy validation remains unavailable because tool discovery still exposes neither `list_policies` nor `run_policy`; no substitute result is claimed.
- [x] (2026-07-30 07:58Z) Synced and rebased the three implementation checkpoints onto current `origin/master`, then ran the requested five-perspective guided review and queued all twelve findings.
- [x] (2026-07-30 09:40Z) Reworked batching around endpoint-neutral propagation identity, unioned carrier/source/sink observations with dense ID rebinding, and added selected-procedure call-region discovery so caller/callee endpoints remain in one solve or fail inconclusively.
- [x] (2026-07-30 09:40Z) Changed `matched-value` to use direct source-backed point/value observations, including multiple path-specialized observations, and centralized shared selector quality, source-range, and semantic-limit projection used by typestate and taint.
- [x] (2026-07-30 09:40Z) Added request-wide solve, semantic, finding, witness-count, witness-step, expansion, and retained-byte budgets; retained each reconstructed witness once behind `Arc`; and made proof/completeness pair-local.
- [x] (2026-07-30 09:40Z) Added the production public query route on `PolicyBatchOutcome`, a `CodeQueryResultValue::TaintFinding` transport case, taint-owned witness envelopes that reuse `CodeQueryFlowWitnessStep`, and Rust/Python/LSP/VS Code model handling without fake flow plan references.
- [x] (2026-07-30 10:18Z) Closed all twelve guided-review findings and completed final task-scoped validation and diff review. The policy-pack gate remains unavailable because the installed skill exposes no callable `list_policies` or `run_policy`; the VS Code typecheck is likewise unavailable because this worktree has no installed `tsc`.
- [x] (2026-07-30 10:55Z) Rebased the PR onto current `origin/master` and fixed the LSP-discovered zero-match boundary: completely executed source or sink selectors with no matches now produce a clean complete policy run without constructing or solving an empty taint plan.

## Surprises & Discoveries

- Observation: the production source tree now lives under `crates/bifrost-analysis/src/`, while PR #1329's historical diff still names the pre-split `src/` paths.
  Evidence: the requested seams resolve under `crates/bifrost-analysis/src/analyzer/...` at `HEAD`, and `git show 24fb9291` shows their earlier `src/analyzer/...` names.

- Observation: `TaintBatchPlanner` originally unioned class bindings only after requiring equal value-flow event domains and propagation semantics.
  Evidence: the guided review showed that hashing the complete `ValueFlowPlan` made the union branch unreachable for different endpoint sets. `ValueFlowPlan::propagation_semantics_hash`, `has_same_propagation_semantics`, and `union_observations` now compare transfer structure by stable carrier keys, union observations, and densely rebind all client overlays once.

- Observation: a taint finding is not a registered value-flow endpoint, so embedding it in `CodeQueryFlowWitness` requires false `plan_ref` and `endpoint_id` values.
  Evidence: the original projector used `TaintUniverseHash` as `plan_ref` and the taint finding ID as `endpoint_id`. `CodeQueryTaintWitness` now owns `finding_id` while reusing the existing `CodeQueryFlowWitnessStep`; no duplicate witness-step model was introduced.

- Observation: selected source ranges can map to several legitimate path-specialized value observations.
  Evidence: the Python matched-value regression produces three structured observations for one selected name. Treating that as an ambiguous call is wrong; all bounded observations are now compiled directly and remain source-backed.

- Observation: `TaintFindingReport` retains both the diagnostic-neutral findings and the owning `TaintSummaryResult`, so witness projection can reconstruct bounded witnesses without another propagation run.
  Evidence: `crates/bifrost-analysis/src/analyzer/taint/finding.rs` stores `result` and `findings`, and `collect_taint_findings` reconstructs origins from retained summary witnesses.

- Observation: current origin reconstruction computes the exact class contribution for each source/witness and then discards that association.
  Evidence: `collect_taint_findings` calls `TaintFlowProblem::source_contribution(...).intersects(classes)` while retaining only `SourceEventKey` values and aggregate truncation flags. Projection must retain the contributed class set and witness association at collection time or it would need to re-derive evidence later.

- Observation: the existing policy layer already owns pair-local source facts, sink aggregation, finding-combination selection, broad/refined classification, CVSS reduction, evidence validation, and all renderers.
  Evidence: `TaintProjectionAuthority`, `TaintPolicyProjectionFacts`, `TaintPairProjection`, and `assemble_taint_projection_batch` reject incomplete adapter envelopes and perform the existing reducers after validation.

- Observation: the installed Bifrost navigation/policy skills do not prove their MCP tools are registered.
  Evidence: tool discovery did not expose `search_symbols`, `get_summaries`, `list_policies`, or `run_policy`; repository-local `rg` and Rust source inspection are the current fallback, and a final policy result must not be claimed unless `run_policy` becomes callable.

- Observation: unqualified `cargo clippy` selected Homebrew's `clippy-driver` while Cargo/rustc came from rustup; both report Rust 1.96.0 but use different LLVM patch releases and reject each other's crate metadata.
  Evidence: the initial shared and isolated-target runs failed with E0514. `/Users/dave/.cargo/bin/cargo-clippy clippy ...` selected rustup's matching driver and completed cleanly with `-D warnings`.

- Observation: the unselected sibling-callee fixture retains a diagnostic-neutral taint finding, but its deeper return/formal chain has partial Base evidence.
  Evidence: the compiler discovers the common caller and performs exactly one propagation solve; `PolicyBatchOutcome::taint_findings` retains the positive path, while the existing policy projection correctly reports `PartialDiscovery`, emits no scored policy finding, and never converts partial evidence into a complete negative.

- Observation: the PR's Rust matrix exposed two deterministic Scala definition regressions already present after rebasing onto current master.
  Evidence: the branch has no Scala or definition-resolver diff, but `scala_enclosing_terms_precede_implicit_companions_but_not_local_imports` and `scala_definition_api_preserves_parameterized_enum_case_source_identity` fail locally on the rebased tree with the same assertions as Linux and Windows CI. Fixing them would widen #824 into unrelated Scala resolver work.

## Decision Log

- Decision: stay on the already-created `dave/implement-production-taint-bridge` branch and do not create, switch, rebase, or open a pull request.
  Rationale: the worktree is clean and exactly at current `origin/master`; repository instructions prohibit branch operations or a PR without an explicit request.
  Date/Author: 2026-07-29 / Codex

- Decision: keep the existing `TaintFinding`, `TaintFindingReport`, `TaintBatchPlanner`, policy projection DTOs, classification reducer, CVSS reducer, and renderers authoritative.
  Rationale: issue #824 owns only the compiler/adapter/public evidence bridge. Replacing any of these seams would duplicate landed behavior and risk divergent policy/report semantics.
  Date/Author: 2026-07-29 / Codex

- Decision: compile selectors to exact source-backed semantic handles and `PolicyPort` bindings; never use callee text, regexes, source snippets, or name-only semantic guesses.
  Rationale: the loaded policy already retains canonical structured `CodeQuery` selectors, and the analyzer carries call, value, point, procedure, proof, and completeness identities.
  Date/Author: 2026-07-29 / Codex

- Decision: make batching a coordinator-owned preparation phase over all runnable taint policies, then make the per-policy evaluator a projection of retained prepared results.
  Rationale: the current `TaintPolicyEvaluator` callback sees one policy at a time and cannot discover later compatible policies. Preparing all taint policies first is the smallest way to let `TaintBatchPlanner` share propagation while preserving the existing per-policy assembly/classification path.
  Date/Author: 2026-07-29 / Codex

- Decision: retain one `TaintFindingReport` per executed batch/root and derive both public taint rows and `TaintProjectionPayload` from it.
  Rationale: this directly proves no second solver or policy-specific rerun exists. The report already owns the exact branded result needed for bounded origin and witness reconstruction.
  Date/Author: 2026-07-29 / Codex

- Decision: compatibility excludes source/sink observation subsets but includes normalized propagation rules, root, call behavior, summaries, sanitizers, transforms, oracle/context/access-path semantics, and completeness-affecting discovery state.
  Rationale: compatible policies must share propagation even when their endpoint subsets differ. The planner unions observations and remaps dense IDs, while exact normalized equality still rejects hash collisions or semantic drift.
  Date/Author: 2026-07-30 / Codex

- Decision: return an explicit capability-incomplete policy result for authored sanitizer, transform, external-model, or named-formal binding semantics not yet representable by the production lowering.
  Rationale: silently omitting these semantics could turn partial propagation into a complete clean negative. The current adapter either compiles exact structured support or misses safely; it does not substitute source-text matching or a weaker model.
  Date/Author: 2026-07-29 / Codex

- Decision: enrich retained internal origin evidence with the exact contributed class set and witness association during `collect_taint_findings`.
  Rationale: transforms can change which label an origin contributes at a sink. Recomputing or intersecting authored source labels downstream is incorrect, and rerunning witness analysis would violate the retained-result boundary.
  Date/Author: 2026-07-29 / Codex

- Decision: introduce taint-specific finding, origin, and witness ownership envelopes, while reusing `CodeQueryFlowWitnessStep` and the landed witness projection helper for every step.
  Rationale: taint adds sink aggregation, reached labels/classes, bounded origins, finding identity, and multiple witness references. Reusing `CodeQueryFlowWitness` itself would falsely claim a registered flow plan and endpoint; reusing its step type preserves the actual witness boundary without that false identity.
  Date/Author: 2026-07-30 / Codex

- Decision: expose diagnostic-neutral retained taint rows from `PolicyBatchOutcome` both as typed findings and `CodeQueryResultValue::TaintFinding` values.
  Rationale: the production coordinator already owns the single retained report. This is the smallest public route that proves query and `.rqlp` views derive from the same solve without creating a second taint plan registry or solver.
  Date/Author: 2026-07-30 / Codex

- Decision: treat selector, semantic, solver, origin, or witness incompleteness as explicit non-clean completion and leave Base CVSS unscored.
  Rationale: incomplete propagation is not a complete negative, and existing policy/CVSS code already applies the correct reduction once the adapter supplies honest proof/completeness.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

The production coordinator now prepares all runnable taint policies together, compiles exact structured endpoint matches into one set-oriented plan per root, partitions by the existing batch planner, invokes the existing taint client once per batch, and calls `collect_taint_findings` once on that result. Each participating policy consumes a retained projection from the same report. Work metrics make the shared solve observable in the canonical report.

`collect_taint_findings` now retains the exact per-origin contributing class set and its already-reconstructed bounded witnesses. The policy adapter aggregates sink fact rows conservatively, bounds origin and witness output, constructs the existing sealed projection DTOs, and leaves the existing broad/refined classification and CVSS reducers untouched. The public projection likewise aggregates by sink, exposes reached labels and bounded origins, and reuses `CodeQueryFlowWitnessStep`. Its taint witness envelope is finding-owned and therefore carries no fabricated value-flow plan or endpoint identity.

Validation is green: `cargo check -p brokk-bifrost --no-default-features`; `cargo fmt --all -- --check`; strict featureless `/Users/dave/.cargo/bin/cargo-clippy clippy -p brokk-bifrost --all-targets -- -D warnings`; all 196 policy integration tests (195 passed, one ignored); and the full semantic integration binary (500 passed, 23 intentionally ignored). The focused taint suite contributes 24 passing tests, and the end-to-end adapter tests prove compatible policies report `taint.propagation_solves = 1` and `taint.propagation_shared_memberships = 1`, caller/callee endpoints remain one region, matched values use direct observations, and an unselected common caller retains its partial diagnostic-neutral path without policy scoring.

The Python 3.13 schema-v6 transport model test passes. The VS Code typecheck could not start because `tsc` is not installed in this worktree; no dependency installation was performed solely for this validation.

The only unavailable gate is the repository policy pack: the installed policy skill has no registered `list_policies` or `run_policy` tool in this task. This is recorded as a validation-environment limitation, not a clean policy result.

## Context and Orientation

The public policy subsystem is in `crates/bifrost-analysis/src/analyzer/policy/`. `resolved.rs` stores each fully loaded `LoadedPolicy` and its `ResolvedTaintPolicySpec`. The resolved spec already contains stable source/sink endpoint identities and hashes, display/category/label metadata, structured selector paths, typed `PolicyPort` bindings, sanitizers, transforms, external models, catalog/manifests, and finding combinations. `LoadedPolicy.resolved_selectors()` stores each selector as canonical `CodeQuery`; the compiler must consume those values and must not reopen policy or endpoint files.

`evaluator.rs` defines the crate-private `TaintPolicyEvaluator` adapter seam. `DefaultPolicyEvaluator` creates `TaintProjectionAuthority`, asks the adapter for `TaintProjectionPayload`, seals and validates it, applies existing finding-combination precedence, classification, CVSS and risk reduction, constructs `TaintFindingEvidence`, and returns the canonical `PolicyRun`. `projection.rs` defines the exact private adapter DTOs. `future_evidence.rs` defines the existing public evidence contracts, including `TaintSourceProjectionFact`, `TaintPolicyProjectionFacts`, `TaintOriginEvidence`, `TaintFindingAnchor`, and `TaintFindingEvidence`. These types must be populated, not replaced.

`coordinator.rs` loads every requested policy into one `PolicyRegistry`, builds or accepts one immutable `WorkspaceAnalyzer`, creates one `ProductionTypestatePolicyEvaluator`, and currently evaluates policies one at a time through `DefaultPolicyEvaluator`. The production taint preparation phase must happen after registry loading and workspace creation but before this loop. It can inspect every runnable loaded taint policy, compile them under bounded per-policy authority, partition the compiled plans, execute each batch once, retain diagnostic-neutral reports, and build a map keyed by the exact policy and compiled-root identity. The normal evaluator loop then consumes those retained prepared outcomes and still owns all policy assembly and reporting.

The diagnostic-neutral taint engine is in `crates/bifrost-analysis/src/analyzer/taint/`. `plan.rs` defines `TaintAnalysisPlan`, `TaintPolicyPlan`, compatibility keys, projections, and `TaintBatchPlanner`. `client.rs` exposes the existing taint solve, including retained summary witnesses. `finding.rs` exposes `collect_taint_findings`, which returns `TaintFindingReport` containing both `TaintSummaryResult` and sink-level findings with reached classes, bounded origins, path quality, proof, and completeness. No new solver or pairwise source/sink loop is needed.

The structured semantic and value-flow layers are in `crates/bifrost-analysis/src/analyzer/semantic/` and `crates/bifrost-analysis/src/analyzer/value_flow/`. A compiled source or sink is a `ValueFlowSourceSpec` or `ValueFlowSinkSpec` bound to an exact `ProgramPointHandle`, `ValueFlowCarrier`, observation phase, proof, and completeness. A `ValueFlowPlan` combines procedure-local value-flow snapshots and exact call bindings under one root. The compiler must use `WorkspaceAnalyzer` semantic providers and bounded ICFG/oracle traversal to gather these structured inputs. A policy with several sources and sinks creates one set of source specs and one set of sink specs; it never creates a source-by-sink product.

The landed public flow result and witness types are in `crates/bifrost-analysis/src/analyzer/structural/search/results.rs`. `CodeQueryFlowEndpoint`, `CodeQueryFlowWitness`, and `CodeQueryFlowWitnessStep` already define stable source-backed transport shapes. `search/value_flow.rs` and `search/witness_projection.rs` contain stable locator hashing, quality mapping, bounded contiguous-prefix truncation, and witness step conversion. The taint public envelope must call or carefully generalize these helpers, not copy them or introduce `CodeQueryTaintWitnessStep`.

An analysis root is the exact procedure from which one taint solver run starts. A loaded policy can select endpoints in several procedures. The compiler may therefore return several `TaintPolicyPlan` values, one per exact compatible root, but each root plan contains all applicable sources and sinks in that root slice. Internal plan IDs may include a root fingerprint so `TaintBatchPlanner` never receives duplicate IDs; the retained projection map restores the exact loaded policy identity before policy assembly.

## Plan of Work

Milestone 1 implements production compilation without executing propagation. Add `crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs` and register it from `policy/mod.rs`. Define `TaintPolicyCompiler`, a bounded compilation error/failure type with truthful work accounting, and compiled metadata that maps dense value-flow source/sink IDs back to resolved endpoint identities, labels, hashes, origins, display data, and exact source-backed sites. Reuse or extract the typestate compiler's structured selector execution, source-span-to-call lookup, named argument resolution, semantic budget accounting, and `PolicyPort` binding logic where doing so avoids a second implementation. The shared helper must remain diagnostic-neutral and typed.

Execute each resolved source, sink, sanitizer, transform, and external-model selector by its stored `PolicySelectorPath`. Resolve `matched_value`, `receiver`, `return_value`, `argument_index`, and `argument_name` through semantic call/value handles. Build stable `ValueFlowEventKey` values from the exact selected point, deterministic endpoint/event ordinal, and event kind. Map `TaintLabel` values to canonical `SourceClassId` values and construct one `TaintUniverse` per compatible compilation group. Preserve selector proof/completeness. Reject empty compiled source or sink sides, ambiguous dangerous operands, conflicting same-site endpoints without a unique dominance winner, unsupported model/binding forms, changed sources, cancellation, and exhausted budgets as explicit failed or incomplete compilation outcomes.

For each exact root, gather bounded procedure value-flow snapshots and exact call bindings through the workspace semantic/ICFG providers, apply the authored `CallModelingSpec` through the existing `UnmodeledCallBehavior` and external-model APIs, and construct one `ValueFlowPlan`. Build the source/sink/sanitizer/transform bindings and one `TaintAnalysisPlan`, then wrap it in `TaintPolicyPlan` with a compatibility key that includes workspace snapshot, root/scope, universe, sanitizer/transform semantics, call/oracle/external-model semantics, access-path/context choices, and completeness-affecting budgets. Exclude message, severity, finding combinations, classification, CVSS, and render options.

Milestone 2 makes compatible policy work share propagation. Add a coordinator preparation entry point which receives all runnable `LoadedPolicy` values, the immutable workspace, cancellation, and per-policy budgets. Compile all taint policies before the ordinary evaluation loop. When policies share exact propagation semantics and root scope, build or normalize them against one common value-flow endpoint domain so the existing `TaintBatchPlanner` can union their source and sink bindings. Call `TaintBatchPlanner::partition`, run the existing taint client once per returned `TaintBatch`, and call `collect_taint_findings` exactly once for its `TaintSummaryResult`.

Retain the resulting `TaintFindingReport` and the batch's `TaintPolicyProjection` rows. Project meetings back only to policies whose source and sink subsets admit the meeting. A source or sink addition can share propagation only when the common plan preserves exact class/event identities and completion for every member; otherwise keep separate partitions. Do not run a source/sink Cartesian matrix. Record solve and reuse work metrics so tests can assert one batch solve and no extra run for presentation-only variants.

Milestone 3 implements `ProductionTaintPolicyEvaluator` over the prepared reports. It implements the sealed adapter marker and `TaintPolicyEvaluator`, looks up the exact prepared policy outcome, and constructs `TaintProjectionPayload` without invoking the solver. For each retained sink finding, intersect reached classes with the policy projection, group by resolved source endpoint, and construct complete `TaintSourceProjectionFact`, `TaintPolicyProjectionFacts`, `TaintPairProjection`, `TaintOriginProjection`, `AnalysisFindingId`, `TaintFindingAnchor`, `AnalysisEventRef`, `SourceScenarioId`, evidence reference/hash, proof, certainty, completeness, related locations, and bounded witnesses required by the existing projection validator.

Stable IDs and hashes must omit absolute workspace mounts and run-local dense IDs. Origins and witness references retain deterministic bounded prefixes and explicit omission lower bounds. Witnesses are reconstructed only from `TaintFindingReport.result()` retained solver evidence. Install one prepared `ProductionTaintPolicyEvaluator` beside the typestate evaluator in `coordinator.rs` and call `DefaultPolicyEvaluator::with_taint`. The normal evaluator continues to select broad/finding-combination presentation, reduce classification, keep Base CVSS unscored when incomplete, and construct one canonical report for every renderer.

Milestone 4 adds only the diagnostic-neutral taint fields absent from `CodeQueryFlowEndpoint`. Define a `CodeQueryTaintFinding` envelope in `structural/search/results.rs` with stable finding ID, sink-level identity/location, reached stable labels/classes, bounded origin records, proof/certainty, completeness, ambiguity, and finding-owned witness references. Do not define a taint witness step type. Extract or generalize the existing source-backed witness conversion so the public envelope and policy `BoundedWitness` projection consume the same retained solver witness and truncation decision.

Expose a bounded projection function which accepts the retained `TaintFindingReport` plus compiled metadata and returns public taint envelopes. The production evaluator calls that projection and then converts the same rows into the sealed policy DTOs. If the existing schema can expose this envelope without a new independently registered analysis plan, add the smallest schema-v7 `taint` transition and transport cases; otherwise keep the envelope on the production compiler/evaluator API and document why a second generation-scoped plan/result registration would violate this slice. Any new visible vocabulary must enter through `query/schema.rs` and receive parser, decoder, validator range, hover/completion, grammar, Rust/Python/LSP/VS Code model, and documentation coverage.

Milestone 5 proves behavior. Add an integration test under the existing policy/semantic suites using `tests/common/inline_project.rs`. The source should contain at least two selected sources, two sinks, one safe path, one reached path, and unrelated same-name calls. The policy fixtures should provide two presentation/classification variants with identical propagation semantics and one sanitizer/transform/call-model variant that must partition. Assert compilation creates one set-oriented plan per root with several source and sink bindings, compatible variants produce one solve, incompatible variants produce separate or explicit incomplete outcomes, and no pairwise solve count appears.

Serialize one retained diagnostic-neutral taint result and the corresponding canonical policy report. Assert public and policy views agree on sink identity, reached labels, bounded origins, witness IDs and steps, proof/certainty, completeness, and ambiguity. Render the same `PolicyReportDocument` as human, JSON, and SARIF and assert equivalent finding identity, contributing labels/classes, origin/witness membership, broad fallback classification when no refinement matches, scoring state/provenance, and incomplete Base evidence remaining unscored. Add cancellation, solver/query budget, origin/witness truncation, ambiguous dangerous operand, empty side, and external-model partition tests.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/d3ff/bifrost`.

After each implementation milestone, update this plan, run `cargo fmt --all`, run the smallest affected test target, inspect `git diff --check`, and commit only files changed for that milestone with a multiline message explaining the reason and validation. Do not use `git add -A`.

Useful focused commands will be refined as the new test target is chosen:

    cargo fmt --all
    cargo test -p brokk-bifrost taint
    cargo test -p brokk-bifrost policy::projection
    cargo test --test suite_semantic taint_client
    cargo test --test suite_bench_policy policy_match_evaluation
    cargo test --test code_query_value_flow
    git diff --check

Before the final handoff, run the task-scoped featureless Rust gates first:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost
    cargo test --test suite_semantic
    cargo test --test suite_bench_policy
    cargo clippy -p brokk-bifrost --all-targets -- -D warnings

Run Python/editor/docs checks only if their transport or documentation files change:

    bash scripts/test_python.sh
    (cd editors/vscode && npm test)
    (cd docs && npm run check && npm run build)

Do not enable `nlp` for ordinary milestone validation. If an actual pre-push or release gate is later requested, first check disk space and use `scripts/with-isolated-cargo-target.sh` for the required all-feature Clippy/test command.

Before completion, use one `run_policy` request for `bifrost.code-smells` plus every repository-named executable policy root if the MCP tools are registered. If `list_policies` or `run_policy` remains absent, record the plugin/MCP registration failure and do not substitute an LSP or CLI claim.

## Validation and Acceptance

The compiler acceptance test must show one resolved policy with several source and sink selector matches becoming set-oriented `TaintPolicyPlan` values grouped by root, never one plan per source/sink pair. Exact source/sink `PolicyPort` bindings must identify semantic values at source-backed program points. Same-name calls outside selector result spans must not become events.

The batching test must show compatible policies sharing one `TaintBatch` and one taint solve. Presentation, message, severity, finding-combination, classification, and CVSS-only differences must not affect the compatibility key or solve count. Sanitizer, transform, oracle/call behavior, context, access path, external-model, scope, and completeness-affecting differences must partition or become explicit incomplete outcomes.

The retained-result test must prove `collect_taint_findings` receives the exact `TaintSummaryResult` produced by the batch solve, and both public query projection and `TaintProjectionPayload` receive that same `TaintFindingReport`. Witness reconstruction may read retained summary evidence but must not call the solver or semantic provider.

The reporting test must prove one generic vulnerability remains when no narrow finding combination or taxonomy refinement applies. Human, JSON, and SARIF must preserve the same strong finding ID, source/sink endpoint identity, contributing labels/classes, bounded origin and witness memberships, certainty, completeness, broad/refined classifications, CVSS variants or unscored state, selected-display rationale, and metric provenance.

Cancelled, budget-exhausted, unsupported, ambiguous, truncated, or semantically partial compilation/propagation must produce explicit incomplete or failed results with truthful work. It must never become a complete clean negative, and incomplete Base evidence must remain unscored.

## Idempotence and Recovery

Compiler, solver, and projection operations are read-only over the analyzed workspace. Repeating one batch against the same immutable workspace and inputs must produce deterministic compatibility keys, plan/event identities, finding ordering, projection hashes, and report output.

Use repository-managed target storage. Do not create manually named `/tmp/bifrost-*` targets. Preserve unrelated user changes if any appear. Never use `git reset --hard`, broad checkout, or destructive cleanup. If a milestone fails, update `Progress` and `Surprises & Discoveries`, fix forward, and rerun its focused validation.

## Artifacts and Notes

Starting state:

    branch: dave/implement-production-taint-bridge
    HEAD: eaada248
    origin/master: eaada248
    PR #1329 merge ancestor: 24fb9291
    worktree: clean

The previous production typestate implementation in `crates/bifrost-analysis/src/analyzer/policy/typestate_policy.rs` is the primary pattern for bounded selector execution, semantic binding, compilation work accounting, retained witness projection, sealed evaluator integration, coordinator installation, and renderer parity. Reuse its architecture, but do not copy typestate-specific object/protocol semantics into taint.

## Interfaces and Dependencies

At the end of Milestone 1, `crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs` must contain a crate-private production compiler whose effective interface is:

    struct TaintPolicyCompiler<'a> { ... }

    impl<'a> TaintPolicyCompiler<'a> {
        fn new(
            workspace: &'a WorkspaceAnalyzer,
            query_limits: CodeQueryExecutionLimits,
            cancellation: &'a CancellationToken,
        ) -> Self;

        fn compile(
            self,
            policy: &LoadedPolicy,
            spec: &ResolvedTaintPolicySpec,
        ) -> Result<Vec<CompiledTaintPolicyPlan>, TaintPolicyCompileFailure>;
    }

`CompiledTaintPolicyPlan` contains one `TaintPolicyPlan`, its exact root, and stable source/sink/label/site metadata sufficient to project dense findings back to resolved policy endpoints. It contains no message, severity, classification, CVSS, or renderer fields.

At the end of Milestone 2, coordinator-owned preparation must return a retained batch object with one `TaintFindingReport` per executed batch/root and exact per-policy projection metadata. The solve API is the existing taint client; the finding API is exactly:

    collect_taint_findings(
        plan: &TaintAnalysisPlan,
        result: TaintSummaryResult,
        max_origins_per_finding: usize,
        witness_limits: WitnessReconstructionLimits,
    ) -> Result<TaintFindingReport, TaintFindingError>

At the end of Milestone 3:

    struct ProductionTaintPolicyEvaluator { ... }

must implement `policy::projection::sealed::TaintAdapter` and `policy::evaluator::TaintPolicyEvaluator`. Its `evaluate_taint` implementation performs lookup and projection only; it does not compile selectors or run propagation.

At the end of Milestone 4, `CodeQueryTaintFinding`, `CodeQueryTaintOrigin`, and the finding-owned `CodeQueryTaintWitness` carry only taint-specific aggregation and ownership. They reuse `CodeQueryFlowWitnessStep`; no `CodeQueryTaintWitnessStep` exists.

Revision note (2026-07-29): Created the initial self-contained execution plan after verifying current origin/master and mapping the landed value-flow, taint, policy, and witness seams. The plan chooses coordinator-wide preparation so the existing per-policy evaluator can consume shared retained propagation results.

Revision note (2026-07-29): Incorporated the independent diagnosis. It made endpoint-neutral value-flow union/rebinding and retention of per-origin contributed classes plus witness associations explicit prerequisites rather than leaving them as adapter implementation details.
