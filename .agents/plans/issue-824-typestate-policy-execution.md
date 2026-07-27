# Execute typestate policies through the production policy pipeline

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost already parses and composes typestate `.rqlp` policies, and it already has an internal finite-state protocol solver plus diagnostic-neutral typestate findings. The missing bridge means a user can author a resource-lifecycle policy but running it through the CLI or `bifrost/runPolicy` still reports `unsupported`. After this change, the existing resource-lifecycle policy can identify an acquired object that reaches the end of its enclosing procedure without the required close event. The same canonical `PolicyFinding` will appear through JSON, concise or verbose human output, SARIF, and the language-server policy endpoint.

This plan covers only the typestate policy vertical requested from issue #824: policy compilation, a production typestate evaluator, `.rqlp` execution, and canonical finding/rendering parity. It deliberately leaves the issue open for typed flow/taint query domains, `TaintPolicyCompiler`, and production taint evaluation.

## Progress

- [x] (2026-07-27 10:24 SAST) Reconciled live issue #824, closed dependencies #821/#823, current `origin/master`, and the existing query-local typestate slice.
- [x] (2026-07-27 10:24 SAST) Diagnosed the policy compiler/evaluator, semantic-capability, analysis-root, and rendering boundaries and received user approval for this plan.
- [x] (2026-07-27 14:03 SAST) Milestone 1: retained the full workspace semantic capability and implemented structured protocol, subject, event, terminal, and precedence lowering.
- [x] (2026-07-27 14:03 SAST) Milestone 2: added production summary evaluation, exact binding provenance, typed preparation failures, and canonical finding/location/witness projection.
- [x] (2026-07-27 14:03 SAST) Milestone 3: installed production execution in CLI and LSP paths and added JSON/human/SARIF identity-parity plus same-site dominance coverage.
- [x] (2026-07-27 16:29 SAST) Milestone 4: documentation, VS Code, focused and full Rust suites, strict all-feature Clippy, Python tests, and final P0/P1 specialist reviews are green.

## Surprises & Discoveries

- Observation: the policy execution coordinator constructs a `WorkspaceAnalyzer` for filesystem-backed runs but immediately erases it to `&dyn IAnalyzer`; live LSP execution similarly passes only `workspace.analyzer()`.
  Evidence: `src/analyzer/policy/coordinator.rs:322-357` and `src/lsp/server.rs:1229`.
- Observation: the existing typestate projection authority carries one protocol hash and one binding-plan hash for the entire policy. Multiple analysis roots therefore must share one global compiled binding plan rather than compiling unrelated plans per root.
  Evidence: `src/analyzer/policy/projection.rs:137-167` and `src/analyzer/policy/future_evidence.rs:1018-1069`.
- Observation: two narrow Bifrost structured-navigation calls stalled for more than one minute during diagnosis. Shell `rg` was used only for arbitrary text/call-site discovery after those calls were terminated.
  Evidence: diagnostic session before this ExecPlan; no code correctness conclusion was drawn from the timeouts.
- Observation: a subject acquired at a return continuation cannot be introduced solely by the zero fact's outgoing transfer, because the synthetic continuation may be reached only after the seed is needed. The summary solver needed a generic, root-validated point-seed input with reconstructable witness evidence.
  Evidence: the first production run had no reachable typestate subject; `SummaryPointSeed` now seeds the exact observation and the new `dataflow_summaries` tests cover success and foreign-root rejection.
- Observation: same-site policy semantics require two independent precedence reductions: endpoint precedence first, then event or expectation precedence. Endpoint provenance must remain keyed by the final dense binding ID after canonical plan sorting.
  Evidence: the CLI dominance fixture selects one call through two endpoint documents and retains exactly one event binding from the superseding endpoint.
- Observation: current TypeScript value/control semantic capabilities are intentionally partial. The production run therefore finds the violation with a proven witness but remains `inconclusive(partial_discovery)` and the finding remains possible/partial.
  Evidence: the CLI, LSP, human, and SARIF acceptance tests all preserve the same partial completion instead of promoting it to a complete negative or status zero.
- Observation: eagerly publishing a point seed makes a subject reachable even when control cannot reach its observation. Point seeds must be retained until the zero relation reaches their exact program point, and their witness quality must inherit that reachable zero path.
  Evidence: `point_seed_does_not_activate_at_an_unreachable_observation` fails against eager publication and passes with reachability-gated activation.
- Observation: a return-value observation can coincide with the analysis root's exit point. Since the summary solver processes exit points without an outgoing client callback, a seed first activated at that exit must receive same-point exit events and event-style terminal observations during activation.
  Evidence: `point_seed_at_exit_observes_the_exit_event_once` and `typestate_analysis_root_exit_event_executes_its_transition` cover the client and production CLI paths.
- Observation: uncertainty in subject discovery is conditional population uncertainty, not uncertainty that a separately proven authored semantic event occurs for the retained candidate. Treating it as event-row uncertainty silently suppressed the authored exit transition.
  Evidence: `proven_exit_event_transitions_a_partially_discovered_subject` distinguishes subject quality from event binding quality.
- Observation: policy selectors and direct semantic resolution initially received fresh limits per selector/root, multiplying the authored budget, and production work reported zero query effort. One shared residual structural/semantic budget is required across compilation and evaluation.
  Evidence: the compiler now charges selector execution, direct semantic materialization, range lookup traversal, and every root solve into one residual budget and exposes those rows through `PolicyExecutionWork` metrics.
- Observation: authored witness/origin limits are independently authoritative and must be intersected with host report bounds before projection authority validation.
  Evidence: `typestate_projection_honors_authored_report_caps_before_authority_validation` proves zero witnesses/origins and a one-step witness cap without relying on post-validation truncation.
- Observation: cold macOS debug codegen/linking for the library and CLI test binaries takes several minutes even after narrow source edits; subsequent focused executions are fast.
  Evidence: the first CLI link took 6m56s and the focused library unit-test link took 5m07s.
- Observation: semantic file and traversal limits cannot be enforced by filtering provider results after materialization. Nested dispatch can enter additional files and perform target/CFG traversal before returning a payload.
  Evidence: `SemanticExecutionBudget` now follows nested `SemanticRequest` values, file admission happens before source/cache work, dispatch targets charge before materialization, and ICFG exit/snapshot traversal charges before graph work.
- Observation: CodeQuery exposes the count of semantically materialized files but not their identities. Associating that count with final evidence paths is unsound for a branch that materializes one file while returning a row from another.
  Evidence: selector file counts are retained as anonymous conservative slots; direct provider materializations retain exact `ProjectFile` identities and can never be deduplicated against an unproven selector path.
- Observation: an incomplete compilation can perform substantial selector and semantic work before producing hashes. Returning a default work report made cancellation and exhaustion appear to cost zero through every transport.
  Evidence: `TypestatePolicyCompileFailure` snapshots `PolicyWorkReport`, and incomplete and failed evaluator paths preserve it in the canonical run.
- Observation: the default macOS `rustdoc` on this host cannot read the metadata emitted by the active Rust 1.96 compiler, even though every executable test binary passes.
  Evidence: the full `cargo test --features nlp` run completed all executable suites before the doctest metadata failure; rerunning the doctest gate with `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustdoc` passed.

## Decision Log

- Decision: keep this isolated worktree detached and fast-forward it to `origin/master`; do not create, switch, or rebase a branch.
  Rationale: repository instructions prohibit branch creation/switching unless explicitly requested. The worktree was already detached and the upstream delta was unrelated.
  Date/Author: 2026-07-27 / Codex
- Decision: derive an analysis root from the exact enclosing procedure of each resolved subject seed and compile all roots into one global binding plan.
  Rationale: the public authoring model intentionally does not add a second root selector. Enclosing-procedure ownership is structured and source-backed, while one global plan preserves the single binding-plan hash required by the sealed policy projection.
  Date/Author: 2026-07-27 / Codex
- Decision: preserve `PolicyFinding`, policy identity, messages, severity, classification, and SARIF ownership in the existing policy module.
  Rationale: issue #824 owns the adapter, not a second policy or reporting envelope. Diagnostic-neutral solver findings are inputs to the existing sealed projection authority.
  Date/Author: 2026-07-27 / Codex
- Decision: do not claim persisted or warm-cache protocol-summary reuse in this slice.
  Rationale: the requested outcome is production policy execution. The existing query-local summary solver is correctness-complete and bounded; reusable summary artifacts can be integrated only when a production semantic-summary projector is available without inventing a fallback or widening this slice.
  Date/Author: 2026-07-27 / Codex
- Decision: compile incomplete/cancelled/ambiguous semantic preparation into typed inconclusive policy runs, while malformed protocol/binding contracts remain typed failures.
  Rationale: a bounded or partial semantic result is not an internal invariant failure and must never be rendered as a clean negative. The evaluator needs this distinction before it has valid compilation hashes and a projection authority.
  Date/Author: 2026-07-27 / Codex
- Decision: finding identity excludes certainty and completeness labels.
  Rationale: certainty may improve as semantic coverage improves; the same semantic subject and violation must keep one finding identity across that evidence-quality change.
  Date/Author: 2026-07-27 / Codex
- Decision: keep point seeds in the generic summary kernel, but activate them only when the root's zero relation reaches their exact point; handle seed-at-exit observation ordering in the typestate client.
  Rationale: reachability is a generic solver invariant, while protocol event ordering is client semantics. Keeping those responsibilities separate avoids manufacturing paths or adding a typestate-specific kernel hook.
  Date/Author: 2026-07-27 / Codex
- Decision: carry CodeQuery proof/completeness into subject and endpoint binding quality, while applying a proven semantic event to an already-retained subject candidate even when subject population discovery is partial.
  Rationale: selector provenance must affect finding certainty and completion, but it must not turn an authored analysis-root exit event into a no-op for the candidate that is actually being analyzed.
  Date/Author: 2026-07-27 / Codex
- Decision: execute every selector and root against one decreasing policy budget and stop finding collection unless the solver reaches a fixed point.
  Rationale: per-selector/per-root fresh limits multiply authority, and collecting a partial fixed-point prefix risks presenting cancelled or exhausted analysis as real findings. Typed incomplete completion preserves the safe contract.
  Date/Author: 2026-07-27 / Codex
- Decision: enforce semantic file/traversal authority at the provider request boundary and treat selector materialization counts as anonymous.
  Rationale: post-hoc filtering cannot undo hidden work, while final selector evidence does not prove which files a semantic branch materialized. A conservative anonymous slot may stop early under a tiny cap but cannot exceed host authority.
  Date/Author: 2026-07-27 / Codex
- Decision: retain compilation work on both incomplete and failed typestate preparation.
  Rationale: work accounting is part of the canonical report contract and must remain truthful even when no projection authority or finding can be created.
  Date/Author: 2026-07-27 / Codex

## Outcomes & Retrospective

The typestate vertical now executes through CLI and LSP. Resolved selectors lower to one canonical protocol and binding plan, execute through the bounded summary solver, and produce diagnostic-neutral typestate findings that the existing policy authority converts into one canonical report model. JSON, verbose human, and SARIF retain the same strong finding ID, policy identity, primary and all bounded acquisition locations, bounded witness, certainty, and completeness. Same-site subject/event endpoint supersession reduces before dense binding construction; cancellation, semantic/provider failure, solver exhaustion, and incomplete compilation remain typed, non-clean, and work-accounted. Final architecture and reporting reviews found no P0/P1 blockers.

Validation finished with 119 focused policy/typestate tests, 39 semantic-oracle/ICFG tests, the full `nlp` executable Rust matrix, matching-toolchain doctests, strict all-target/all-feature Clippy, 59 Python tests, 72 VS Code tests, eight policy-document tests, and the rendered documentation build (57 pages and 5,395 checked links). `cargo fmt --check`, `cargo check --all-targets --all-features`, and `git diff --check` are clean. Flow/taint policy and query integration remains after this plan.

## Context and Orientation

The public policy model lives under `src/analyzer/policy/`. `src/analyzer/policy/source.rs` parses `.rqlp`; `src/analyzer/policy/registry.rs` resolves selector files, endpoint directories, precedence, and dependencies; `src/analyzer/policy/resolved.rs` stores a `LoadedPolicy` and its `ResolvedTypestatePolicySpec`. A resolved selector contains a canonical `CodeQuery`, schema resolution, stable policy path, and semantic hash. The compiler must consume these stored values and must not reopen selector files or scan source text.

`src/analyzer/policy/evaluator.rs` defines `DefaultPolicyEvaluator` and the crate-private `TypestatePolicyEvaluator` adapter seam. The default evaluator currently installs no adapter. It already owns `TypestateProjectionAuthority`, validates a sealed `TypestateProjectionBatch`, constructs `PolicyFinding`, applies policy-owned classification and optional CVSS/organizational-risk reduction, and returns a `PolicyRun`. `src/analyzer/policy/render/` accepts only the final `PolicyReportDocument`, so rendering parity should follow from correct canonical evidence rather than separate renderer-specific findings.

The internal typestate engine lives under `src/analyzer/typestate/`. `protocol.rs` defines the versioned `ProtocolSpec` and canonical `CompiledProtocol`. `binding.rs` defines exact `AbstractObject`, program-point, and call-site bindings plus the canonical `TypestateBindingPlan`. `client.rs` runs the existing bounded interprocedural solver, while `finding.rs` groups violations and retained witnesses. These types are diagnostic-neutral and contain no policy severity, message, classification, or SARIF fields.

The source-backed semantic intermediate representation lives under `src/analyzer/semantic/`. A `WorkspaceAnalyzer` selects a `ProgramSemanticsProvider` for a project file, materializes an immutable `SemanticArtifact`, and exposes exact `ProcedureHandle`, `ProgramPointHandle`, `CallSiteHandle`, value, object, CFG, and ICFG identities. A structured selector match must be mapped to these handles using byte ranges and semantic source mappings. A same-name call outside the selected structural match is not equivalent and must never become an event.

An analysis root is the procedure from which one solver run starts. For this policy adapter, the root is the exact enclosing procedure of a selected subject seed. If a policy selects subjects in several procedures, the compiler retains every distinct root in deterministic order, builds one binding plan containing every subject/event/terminal row, and the evaluator runs that plan once per root. Findings are then deduplicated by durable diagnostic-neutral identity.

## Plan of Work

Milestone 1 makes policy evaluation retain a `WorkspaceAnalyzer` when the host owns one. Add a workspace field or constructor to `PolicyEvaluationContext` without forcing fake adapter tests to implement semantic services. Change the coordinator's supplied-analyzer parameter to carry a `WorkspaceAnalyzer` and derive `&dyn IAnalyzer` from it for match policies. Change `evaluate_policy_source` and its LSP caller to pass the live workspace snapshot. A missing workspace for a typestate run is an explicit unavailable capability, not an empty result.

Create `src/analyzer/policy/typestate_policy.rs` and register it from `src/analyzer/policy/mod.rs`. Define a crate-private `TypestatePolicyCompiler` and a `CompiledTypestatePolicy` containing one `Arc<CompiledProtocol>`, one `Arc<TypestateBindingPlan>`, a deterministically ordered root list, and the exact resolved endpoint/scenario metadata needed for projection. Lower `ResolvedTypestateAutomatonSpec` into `ProtocolSpec` using existing identifier constructors and uncertainty semantics. Execute the `LoadedPolicy.resolved_selectors()` by their stored `PolicySelectorPath`; use existing CodeQuery execution, source ranges, `WorkspaceAnalyzer` providers, semantic artifacts, and oracle APIs to resolve subject roles and event roles. Do not use `split`, regex, source snippets, callee strings, or name-only semantic guesses.

Each selected subject produces a `BoundTypestateSubjectSpec` and an initial seed at its exact observation site in the protocol's initial state. Its enclosing procedure becomes a root. Event selectors produce `TypestateEventBindingSpec` values only for exact selected call/program-point sites and the authored observation phase. Analysis-root exit expectations produce terminal bindings for each applicable subject and the matching normal or exceptional root exit. Resolve supersession before building the plan; reject same-site incomparable conflicts and preserve incomplete/ambiguous results as typed compilation diagnostics. The compiler output is deterministic and hashes only canonical internal protocol/binding semantics, not display text or policy paths.

Milestone 2 changes the crate-private typestate seam so preparation happens once. `DefaultPolicyEvaluator` asks the adapter to compile/prepare, derives the sealed authority from the returned hashes, then asks the same adapter to evaluate the prepared value. Update fake adapter tests to construct the private prepared form. The production evaluator runs `solve_typestate_with_summaries` for each root with one shared finite semantic/dataflow budget and cancellation token, calls `collect_summary_findings_with_limits`, and maps every retained diagnostic-neutral finding to `TypestateProjectedFinding`.

Projection uses the exact resolved subject endpoint and its hashes/categories/display name. It constructs stable subject and violation-site identities from source-backed semantic locators, converts may/must/inconclusive status into `FindingCertainty`, carries solver and binding incompleteness into `FindingCompleteness`, and converts retained witness steps into policy `BoundedWitness` values under the effective policy/host limits. If `src/analyzer/structural/search/typestate.rs` already contains identical source-location or witness-step projection, extract only the adapter-neutral mapping into `src/analyzer/typestate/` and let CodeQuery and policy wrappers reuse it. Witness projection must never invoke the solver or provider again.

Milestone 3 installs one production typestate adapter per policy batch in `src/analyzer/policy/coordinator.rs`. CLI runs use the owned workspace; LSP `bifrost/runPolicy` uses the active workspace supplied to its cancellable worker. Taint remains uninstalled and explicitly unsupported. Create a small inline Python project with `open_resource`, `close`, one safe lifecycle, one violating lifecycle, and an unrelated same-name call. Prefer `tests/common/inline_project.rs` for source files and write only the small `.rqlp`/endpoint inputs that the policy loader requires.

Add compiler tests for deterministic hashes, receiver/return/argument binding, multiple roots, same-site dominance, unrelated same-name calls, ambiguous binding, cancellation, and budgets. Replace typestate-unsupported assertions in `tests/policy_rendering.rs`, `tests/bifrost_policy_cli.rs`, and `tests/bifrost_lsp_server.rs` with executable behavior while keeping taint-unsupported assertions. The report test must serialize one outcome as canonical JSON, human, and SARIF and assert the same policy ID, finding ID, primary/related locations, certainty, completeness, and witness identity/steps.

Milestone 4 updates `docs/src/content/docs/cli.md`, `docs/src/content/docs/static-analysis-policies.md`, `docs/src/content/docs/build-static-analysis-rule.md`, `docs/src/content/docs/agent-result-safety.md`, and `tests/policy_docs.rs`. Typestate becomes documented as executable; taint remains explicitly unsupported. Run formatting, focused tests, full all-feature Clippy and Rust tests, Python/editor suites, and rendered docs checks. Review the complete diff with the guided issue workflow's security, duplication, intent, operations, and architecture reviewers; resolve every confirmed critical/high finding and record other decisions here.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/d8e0/bifrost`.

After each milestone, run `cargo fmt`, the focused tests named by that milestone, inspect `git diff --check`, update this plan, and commit only files changed for the milestone with a multiline message explaining the rationale.

For isolated Rust validation use the repository helper rather than a manually named temporary target:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_typestate_execution
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_policy_cli
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_lsp_server

Before final review run (on macOS, split the executable Rust and Python extension gates so each uses its CI-native linker configuration):

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp
    RUSTDOC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustdoc cargo test --features nlp --doc
    bash scripts/test_python.sh
    (cd editors/vscode && npm test)
    (cd docs && npm run check && npm run build)

If doctests fail with Rust metadata error E0514 on macOS, rerun the doctest gate with the matching rustup toolchain:

    RUSTDOC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustdoc scripts/with-isolated-cargo-target.sh cargo test --all-features --doc

Expected end-to-end behavior is one typestate finding in canonical JSON, the same finding in human output, and one SARIF result with the same rule/finding identity, locations, bounded witness, and completion. With the current TypeScript semantic capability surface the fixture exits 2 and reports `inconclusive(partial_discovery)`; `--fail-on never` cannot erase that incomplete status. Invalid or incomplete semantic bindings produce a non-clean report with typed diagnostics rather than a clean empty run.

## Validation and Acceptance

Acceptance requires all of the following observable behavior:

The checked resource-lifecycle `.rqlp` document parses, compiles, and executes without an `unsupported` completion. A procedure that obtains but does not close a resource produces a typestate terminal-expectation finding. Selected event calls bind through structured call/value/object identities, and overlapping same-site endpoints honor explicit supersession instead of double-applying the event. A cancelled, budget-exhausted, or semantically partial run is explicitly incomplete and cannot become a complete negative.

Canonical JSON, concise/verbose human output, SARIF, and LSP all derive from one `PolicyReportDocument`. Tests prove that the finding ID, policy ID, primary path/range, related locations, witness membership, certainty, and completeness agree. The SARIF renderer may arrange these fields according to SARIF 2.1.0, but it must not lose their identities or silently upgrade incomplete evidence.

Every Rust target and feature passes strict Clippy. The full `nlp` executable and matching-toolchain doctest gates pass, while the Python feature is built and exercised through the repository's Maturin-based Python suite. Python and VS Code tests remain green, and docs pass type checking, build, and link validation. No test downloads an NLP model or starts semantic indexer threads.

## Idempotence and Recovery

Compiler and evaluator operations are read-only over the analyzed workspace. Repeating one policy run rebuilds only execution-scoped handles and produces deterministic canonical hashes and report ordering. Policy files remain confined to the workspace-rooted loader.

Use `scripts/with-isolated-cargo-target.sh` for build isolation; it removes its managed target on success, failure, or interruption. Preserve the unrelated untracked `.brokk/` directory. Do not use `git reset --hard`, checkout unrelated files, or sweep unrelated paths into milestone commits. If a milestone fails, fix forward from the current detached HEAD, update `Progress` and `Surprises & Discoveries`, and rerun its focused validation.

## Artifacts and Notes

The prior query-local typestate slice landed in commit `3270a588` and is the principal source of bounded solver, finding, registration, and witness-projection patterns. Reusable semantic/protocol summary artifacts landed in `a5262c1d`, but production warm-cache integration is not claimed by this plan.

At plan start the repository state is:

    HEAD (detached) at 970d9145
    origin/master at 970d9145
    unrelated untracked path: .brokk/

Final validation record:

    cargo fmt --all -- --check                                                PASS
    cargo check --all-targets --all-features                                  PASS
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
                                                                               PASS
    cargo test --features nlp (all executable suites)                          PASS
    RUSTDOC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustdoc cargo test --features nlp --doc
                                                                               PASS
    bash scripts/test_python.sh                                                PASS (59)
    editors/vscode npm test                                                    PASS (72)
    docs npm run check && npm run build                                        PASS (57 pages, 5,395 links)
    git diff --check                                                           PASS

## Interfaces and Dependencies

`src/analyzer/policy/typestate_policy.rs` must expose crate-private responsibilities equivalent to:

    pub(crate) trait TypestatePolicyCompiler {
        fn compile(
            &self,
            policy: &LoadedPolicy,
            spec: &ResolvedTypestatePolicySpec,
            context: &PolicyEvaluationContext<'_>,
            budget: &PolicyBudget,
        ) -> TypestateCompilationOutcome;
    }

    pub(crate) struct CompiledTypestatePolicy {
        protocol: Arc<CompiledProtocol>,
        bindings: Arc<TypestateBindingPlan>,
        roots: Box<[ProcedureHandle]>,
        // exact projection metadata keyed by internal subject identity
    }

The exact error/outcome names may follow existing policy diagnostic conventions, but compilation must distinguish failed, unsupported, cancelled, budget-exhausted, and incomplete outcomes. It must return exact `TypestateProtocolHash` and `TypestateBindingPlanHash` values from the compiled internal objects.

`PolicyEvaluationContext` must retain both the ordinary analyzer view and the optional full workspace capability, either directly or through accessors. `DefaultPolicyEvaluator` must prepare once, create `TypestateProjectionAuthority` from the prepared hashes, and evaluate that same prepared object. It must not compile twice or trust hashes detached from the value being evaluated.

The production evaluator depends only on existing in-repository modules: policy loading/resolution, CodeQuery execution, `WorkspaceAnalyzer` semantic providers, `ProtocolSpec`, `TypestateBindingPlan`, `solve_typestate_with_summaries`, `collect_summary_findings_with_limits`, sealed projection authority, and canonical policy renderers. No new external dependency is needed.

Revision note (2026-07-27 10:24 SAST / Codex): Created the initial self-contained ExecPlan after live issue/remote reconciliation, guided diagnosis and planning, and explicit user approval. The plan resolves the analysis-root and single-binding-hash questions and keeps flow/taint work outside this slice.
