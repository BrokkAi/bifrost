# Configurable semantics for unresolved and external calls

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as implementation proceeds.

This document follows `.agents/PLANS.md` and implements GitHub issue #1227.

## Purpose / Big Picture

Bifrost currently records unresolved, external, unmaterialized, and truncated call arms as incomplete dispatch evidence, but it usually emits no call-to-continuation edge for those arms. Data-flow clients therefore cannot apply any fallback semantics even though value-flow, taint, and typestate already have boundary callbacks. Mixed dispatch follows known targets and silently stops the residual unknown arm.

After this work, call continuation and call transfer policy are separate decisions. Every unmaterialized call arm can continue to its semantically available normal and exceptional destinations while preserving its boundary kind and incomplete proof. An analysis selects one explicit unmodeled-call profile: `paranoid` (the default), `optimistic`, or `require-model`. Policies can state that choice in `.rqlp`, the choice participates in semantic identity and cache compatibility, and exact bodies or summaries take precedence over fallback behavior. A query against a small Java or TypeScript project will demonstrate distinct, explainable results for all three modes without treating uncertainty as proof of safety.

This is intentionally staged. The control-flow invariant and shared fallback profiles are useful independently. Exact external-summary dispatch, structured heap/global effects, and operator modeling require new typed bridges and are later milestones rather than source-text approximations.

## Progress

- [x] (2026-07-28 09:45 SAST) Read issue #1227, fetched `origin`, and fast-forwarded the detached worktree to `origin/master` at `8eaa3d2a`.
- [x] (2026-07-28 09:53 SAST) Traced the ICFG, summary solver, value-flow, taint, typestate, policy schema, reusable-summary, and language-adapter paths; identified the missing continuation projection as the immediate root cause.
- [x] (2026-07-28 09:58 SAST) Wrote this living ExecPlan and separated the work into independently testable milestones.
- [x] Milestone 1: make unmodeled call continuation analysis-independent and add shared typed fallback profiles to value-flow, taint, and typestate plans.
  - [x] (2026-07-28 10:34 SAST) Made every retained call boundary continuation-capable and updated source-backed ICFG contracts for normal, exceptional, mixed known-plus-residual, external, and bodyless calls (`icfg_contract`: 25 passed).
  - [x] (2026-07-28 10:43 SAST) Added the shared paranoid-default profile, syntactic unresolved-call input binding, value-flow/taint behavior, typestate mapping, summary identity, and taint batch partitioning (`value_flow_client`: 10; `taint_client`: 26; `typestate_client`: 40; `dataflow_summaries`: 32 passed).
  - [x] (2026-07-28) Ran fresh-target strict all-feature clippy with the matching rustup `cargo-clippy`/`clippy-driver`; it passed in 3m59s. Checkpointed the milestone after formatting and diff validation.
- [x] Milestone 2: expose `:call-modeling (call-modeling :unmodeled ...)` through the declarative RQLP schema, canonical identity, validation, hover, grammar, and policy compilation.
  - [x] (2026-07-28 11:07 SAST) Added the declarative record/field/atom vocabulary, paranoid omission default, authored and resolved representations, canonical JSON and semantic hashing, mode-aware reusable-summary behavior identity, and typestate compilation.
  - [x] (2026-07-28 11:11 SAST) Added behavior-focused parser/default/hover/identity/execution/docs/editor coverage. Policy library (271), CLI (19), docs (8), loading (16), match evaluation (13), reusable summaries (16), and the focused LSP test all pass; fresh-target strict all-feature clippy passed in 3m55s.
- [x] Milestone 3: bind exact external reusable summaries and curated models to live call sites with explicit precedence and cache invalidation.
  - [x] (2026-07-28 12:04 SAST) Added a canonical, content-addressed external-summary set keyed by structured procedure locators, plus selector-bound curated models using `SummaryPort`, `SummaryTransfer`, and `SummaryEvidence`; value-flow applies exact summaries before curated models and either before fallback.
  - [x] (2026-07-28 12:04 SAST) Bound receiver, parameter, normal/exceptional result, and explicitly supplied heap/capture ports to live carriers. External content, curated model, location-binding, fallback-profile, and call-mode identities now participate in value-flow and downstream taint summary/cache compatibility (`reusable_summaries`: 17; focused exact/curated/heap value-flow tests pass).
- [x] Milestone 4: add structured mutable-receiver/argument, bounded heap/global, and operator effects through semantic adapters and the same typed summary pipeline.
  - [x] (2026-07-28 12:16 SAST) Built deterministic paranoid profiles from structured receiver/argument values, their addressable locations, and bounded static/type/module/external locations. Java primitives remain inputs rather than mutable outputs; one iterative union-find pass and a component-to-location index replace per-call graph searches and all-carrier scans.
  - [x] (2026-07-28 12:16 SAST) Java and TypeScript unary/binary lowering now emits `LanguageDefined` operand-to-result facts consumed by the neutral value-flow oracle. Source-backed tests cover normal and exceptional fallback results, receiver/argument-to-state flow in Java and TypeScript, bounded global and exact heap effects, unary/binary operations, and incomparable model-evidence alternatives (`value_flow_client`: 17 passed).
- [x] Milestone 5: run cross-language acceptance coverage, full formatting/clippy/tests, manual specialist review, and reconcile the issue checklist with implemented and follow-up scope.
  - [x] (2026-07-28 12:16 SAST) Manual correctness/performance review fixed undercounted nested fallback/location rows in retained-size and solver-work accounting, required one proven-and-complete summary evidence alternative rather than joining independent axes across alternatives, and removed the remaining call-times-carrier profile-construction scan.
  - [x] (2026-07-28 12:16 SAST) Broad no-feature library run executed 1,970 tests: 1,967 passed in the managed sandbox and the three blocked MCP subprocess tests passed when rerun outside it (five matching tests passed). The issue-focused matrix then passed: CLI 19, summaries 32, ICFG 25, docs 8, loading 16, match evaluation 13, reusable summaries 17, semantic IR 11, taint 26, typestate 40, and value-flow 17.
  - [x] (2026-07-28 12:19 SAST) Repeated fresh-target strict all-target/all-feature clippy after the post-review accounting and indexing fixes; it passed in 2m20s. Formatting and diff validation are clean.

## Surprises & Discoveries

- Observation: `WorkspaceIcfgProvider::call_transfers` preserves a residual boundary for unresolved, external, unmaterialized, and truncated dispatch, but assigns `model: None`. `project_call_boundary` returns no edges for `None`, making all client boundary callbacks unreachable for those arms.
  Evidence: `src/analyzer/semantic/icfg.rs` in `call_transfers` and `project_call_boundary`; `tests/icfg_contract.rs` currently asserts an empty successor set for a bodyless dynamic target.

- Observation: typestate already has the exact internal uncertainty behaviors needed by the requested modes: `ConservativeTransition`, `PreserveUncertainty`, and `Abstain`. The production RQLP compiler nevertheless hard-codes unknown and external calls to preservation.
  Evidence: `src/analyzer/typestate/protocol.rs`, `src/analyzer/typestate/client.rs`, and `src/analyzer/policy/typestate_policy.rs`.

- Observation: value-flow and taint recognize call inputs primarily from resolved `CallBindings`. An unresolved call has no candidate bindings, even though `SemanticCallSite` still records its receiver and argument values.
  Evidence: `src/analyzer/value_flow/plan.rs`, `src/analyzer/value_flow/client.rs`, and `src/analyzer/semantic/ir/model.rs`.

- Observation: reusable summaries already support typed ports, effects, external origins, content-addressed identity, and `SummaryBehaviorKey`, but summary application begins from a concrete `ProcedureHandle`. There is no selector-to-live-call binding path for an external boundary.
  Evidence: `src/analyzer/dataflow/reusable_summary.rs` and the reusable-summary entry points in the taint and typestate solvers.

- Observation: the semantic IR does not yet expose enough structured mutability/reachability information to distinguish Java primitive arguments from mutable referenced state or to bound global/heap effects. `ValueFlowRelationKind::LanguageDefined` exists, but production adapters do not yet emit operator flows.
  Evidence: `src/analyzer/semantic/ir/model.rs`, `src/analyzer/semantic/oracle/value_flow.rs`, and Java unary/binary lowering in `src/analyzer/java/semantic/control.rs`.

- Observation: during diagnosis, the Bifrost code-intelligence MCP surface disappeared from this session after earlier slow calls. Repository search remained fast with `rg`. This is additional evidence for the separately filed performance issue #1228 and does not change #1227's design.

- Observation: the first focused `--features nlp,python` test compiled the changed Rust library but failed while linking its `cdylib` because the host linker could not resolve Python C API symbols from PyO3. Focused behavioral tests therefore run without optional features until the Python link environment is repaired; all-feature `cargo check` and strict clippy remain useful compile gates.
  Evidence: `scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test icfg_contract ...` failed at `cc` with unresolved `_Py*` symbols on arm64 after compiling `brokk-bifrost`.

- Observation: the shell resolved rustup `cargo`/`rustc` from `~/.local/bin` but Homebrew `cargo-clippy`/`clippy-driver` from `/opt/homebrew/bin`. The binaries report the same 1.96 release but carry different compiler commit metadata, so both reused and fresh targets failed with Rust error E0514 until the rustup toolchain directory was placed first on `PATH`.
  Evidence: `which` and verbose version output showed rustup rustc commit `ac68faa20` alongside Homebrew clippy; `PATH=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin:... scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings` passed.

- Observation: projecting residual arms changed the independent repeated-scan summary oracle as well as production solving. Updating the oracle to replay typed boundary continuations restored four recursion/return differential tests and confirms the change is semantic rather than solver-specific.
  Evidence: `tests/common/dataflow_summary_reference.rs`; all 32 `dataflow_summaries` tests pass.

- Observation: the VS Code extension's dependencies are not installed in this worktree, so its TypeScript grammar test runner cannot start (`tsc: command not found`). The JSON grammar remains valid, and the repository's generic record/field TextMate rules already recognize the new declarative vocabulary; the fixture and scope assertions are checked in for the normal editor CI environment.
  Evidence: `npm test -- --runInBand rql-policy-grammar.test.ts` under `editors/vscode` stopped before compilation because `node_modules` is absent; `jq empty editors/vscode/syntaxes/bifrost-rql.tmLanguage.json` passes.

- Observation: conservative typestate can reach the authored terminal state and additional violating alternatives at the same site. Existing terminal projection attempted to serialize every reached state as a violation, including the expected state, and therefore failed once paranoid became the default.
  Evidence: `bifrost_policy_cli::typestate_same_site_endpoint_precedence_retains_only_the_dominant_binding` exposed the forged expected-state violation. Filtering expected states before constructing violation evidence restored all 19 policy CLI tests.

- Observation: the existing `TaintExternalModelSpec` is resolved and canonicalized, but the repository still has no production `TaintPolicyEvaluator`; only the sealed adapter seam and test doubles exist. This issue therefore supplies the neutral curated-model binding consumed by value-flow and taint plans, without pretending that policy selector evaluation or label-specific sanitize/transform execution is already production-wired.
  Evidence: `src/analyzer/policy/evaluator.rs` describes `TaintPolicyEvaluator` as the future taint compiler/solver adapter boundary; no production implementation exists under `src/`.

- Observation: the initial structured fallback prototype checked receiver/argument reachability by scanning every local rule for every location at every call site. That shape would make policy construction scale as calls times locations times relations.
  Evidence: the final implementation computes one iterative union-find component map over local rules, then performs bounded component lookups while constructing each call profile.

- Observation: Java's current fixture lowering did not expose a static memory-load carrier for the bounded-global test. The test therefore uses the same stable static locator and abstract-location vocabulary to supply a bounded global carrier when the adapter does not produce one; it proves fallback behavior, not Java static-field lowering.
  Evidence: `paranoid_fallback_models_bounded_globals_but_not_primitive_argument_mutation` constructs an `AccessPathRoot::Static` fallback only when no emitted static load exists.

- Observation: review found two validity/accounting pitfalls after semantics were passing. Retained-size and solver-work estimates counted fallback records but not their nested carrier keys, and summary evidence checked proven and complete axes independently across alternatives.
  Evidence: final accounting includes nested input/output/location keys and model-row work; modeled transfer quality now requires one alternative whose `PathQuality` is both proven and complete, with a regression test using incomparable alternatives.

## Decision Log

- Decision: Separate continuation from transfer semantics. An unmaterialized call arm projects every semantically available normal and exceptional continuation regardless of the client-selected fallback profile.
  Rationale: Control-flow reachability is a semantic fact; paranoid, optimistic, and require-model are analysis policies. Coupling the two caused the current disconnected implementation.
  Date/Author: 2026-07-28 / Codex

- Decision: Make `paranoid` the default shared profile, with `optimistic` and `require-model` explicit alternatives.
  Rationale: This matches issue #1227, prevents an unstated false-negative bias, and makes cache identity stable for callers that do not configure a mode.
  Date/Author: 2026-07-28 / Codex

- Decision: Keep boundary evidence incomplete in every fallback mode. `optimistic` means that the unseen body introduces no additional flow, not that the call was proven clean. `require-model` abstains at the unmodeled input-dependent transfer rather than converting absence into a negative result.
  Rationale: Completeness and propagation are independent dimensions. Losing the residual boundary would let incomplete analyses appear definitive.
  Date/Author: 2026-07-28 / Codex

- Decision: Preserve known call candidates and project a separate residual boundary arm for mixed dispatch.
  Rationale: A conservative residual must not discard precise known-body or exact-summary paths, and precise paths must not erase the unknown remainder.
  Date/Author: 2026-07-28 / Codex

- Decision: Use the precedence `materialized body > exact external reusable summary > curated/policy model > configured fallback`.
  Rationale: The most specific executable semantics should win, while fallback remains total when no model is available.
  Date/Author: 2026-07-28 / Codex

- Decision: Do not approximate mutable side effects or operator semantics with source scanning or blanket carrier mutation in Milestone 1. Add a typed semantic-adapter capability before claiming that coverage.
  Rationale: The current IR cannot make the necessary distinctions, and repository policy explicitly prohibits string-based substitutes for structured analysis.
  Date/Author: 2026-07-28 / Codex

- Decision: Keep working on the current detached commit and do not create a branch or PR.
  Rationale: Repository instructions forbid branch changes and PR creation unless the user asks. The detached worktree was safely fast-forwarded to the live remote before implementation.
  Date/Author: 2026-07-28 / Codex

- Decision: Remove the older public typestate `unknown-call inconclusive` control and retain only the orthogonal escape behavior alongside the shared `call-modeling` record.
  Rationale: Two public knobs for the same unresolved-call semantics would be contradictory. The new record is shared by taint and typestate, has one paranoid default, and participates in policy and summary identity.
  Date/Author: 2026-07-28 / Codex

- Decision: Match exact indexed summaries with mount, workspace-relative path, language, and declaration, but not source anchors.
  Rationale: indexed source coordinates can move without changing a library procedure's modeled interface. Artifact/model revisions and external content hashes remain in the selected summary identity and invalidate incompatible caches.
  Date/Author: 2026-07-28 / Codex

- Decision: Keep selector evaluation outside the neutral `CuratedCallModel`, and require adapters to bind a curated model to one validated live `CallSiteHandle`.
  Rationale: RQLP, built-in model packs, and future library indexes need one transfer vocabulary, while selector matching belongs to their owning adapter. The current production taint adapter does not yet exist, so embedding policy dependencies in value-flow would create the parallel mechanism the issue warns against.
  Date/Author: 2026-07-28 / Codex

- Decision: Precompute undirected local carrier components once when deriving paranoid side-effect profiles.
  Rationale: conservative alias/reachability needs structured transitive connectivity, but repeated graph searches in the plan-construction hot path would undermine the sub-five-second responsiveness goal tracked by #1228.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

Milestones 1 through 4 now cover the issue's runtime and authoring contract. Residual call arms reach normal and exceptional continuations while retaining incomplete boundary evidence. Value-flow and taint apply one shared paranoid-default profile without requiring resolved formal bindings, while typestate maps the same profile into its existing uncertainty transitions. `.rqlp` can override that profile with a typed `call-modeling` record, and the selected mode participates in canonical policy, semantic, summary, and batch identities.

Exact external procedure summaries and selector-bound curated models use the existing reusable-summary ports, transfers, evidence, completeness, origins, and content identities. Exact summaries precede curated models, which precede fallback. Paranoid fallback includes structured mutable receiver/argument state and bounded globals without treating Java primitives as out parameters. Java and TypeScript unary/binary expressions emit neutral `LanguageDefined` facts that flow through the same value-flow and reusable-summary machinery.

Final validation is green: the broad library surface passed apart from three sandbox-blocked subprocess tests that passed immediately outside the sandbox, the complete issue-focused matrix passed, and a fresh strict all-feature clippy run passed after review fixes. The implementation is ready for its Milestones 3-5 checkpoint on the current detached worktree. Production evaluation of authored taint external-model selectors remains the pre-existing future adapter gap; this issue does not claim that absent adapter.

## Context and Orientation

The shared interprocedural control-flow graph (ICFG) lives in `src/analyzer/semantic/icfg.rs`. `WorkspaceIcfgProvider::call_transfers` returns concrete call candidates plus residual `CallBoundary` records. The summary fixed-point engine in `src/analyzer/dataflow/summary.rs` retains boundary evidence for completeness, calls `project_call_boundary`, and dispatches each projected edge through the generic client hooks in `src/analyzer/dataflow/transfer.rs`.

A call boundary is an arm for which Bifrost cannot execute a concrete procedure body. Its `CallBoundaryKind` distinguishes unresolved dispatch, external targets, unmaterialized workspace bodies, deferred invocations, and candidate truncation. A call-to-continuation edge is not evidence that the call body was analyzed; it only represents the normal or exceptional continuation and carries the boundary evidence along with it.

Value-flow plans and clients are in `src/analyzer/value_flow/plan.rs` and `src/analyzer/value_flow/client.rs`. Taint wraps value-flow in `src/analyzer/taint/plan.rs` and adds its own client in `src/analyzer/taint/client.rs`. Typestate uncertainty is described by `ProtocolUncertaintyBehavior` in `src/analyzer/typestate/protocol.rs` and executed in `src/analyzer/typestate/client.rs`.

RQLP's public data model, parser, declarative schema, canonical representation, resolved policy, and semantic identity are under `src/analyzer/policy/`. All new syntax must enter through `src/analyzer/policy/schema.rs`; there must be no private parser-only or editor-only keyword table. The VS Code TextMate grammar is `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

Reusable summaries are defined in `src/analyzer/dataflow/reusable_summary.rs`. A summary contains stable ports, typed transfers/effects, an origin, dependencies, and a behavior key. External origins exist, but there is currently no production lookup that matches an unresolved call target and binds summary ports to the receiver, arguments, return, thrown value, or abstract locations at that live call site.

## Plan of Work

### Milestone 1: continuation invariant and internal profiles

First, change the ICFG contract so every residual boundary with a normal and/or exceptional continuation projects the corresponding `CallToNormalContinuation` and `CallToExceptionalContinuation` edges. Keep the boundary kind, proof, completeness, origin, and provenance on those edges. Update contract tests that currently expect an unresolved bodyless call to have no successors, and add mixed-dispatch coverage that proves known callees and the residual continuation coexist.

Introduce one shared `UnmodeledCallBehavior` value in the neutral data-flow layer with variants `Paranoid`, `Optimistic`, and `RequireModel`, defaulting to `Paranoid`. Carry it in value-flow plans; taint inherits the value-flow semantics and includes the value in its batch compatibility. Map it to typestate's existing internal uncertainty behavior.

For value-flow and taint, recognize syntactic receiver/argument inputs directly from `SemanticCallSite`, because unresolved calls do not have resolved bindings. Under `paranoid`, propagate those inputs to available return and thrown carriers and retain active facts. Under `optimistic`, preserve existing active facts but add no unseen-body transfer. Under `require-model`, abstain from input-dependent fallback transfer while retaining the boundary's incomplete evidence. Limit this milestone to carriers the current semantic model can justify; do not claim structured mutable heap/global side effects yet.

Focused validation for this milestone is `icfg_contract`, value-flow client, taint client, typestate client, and data-flow summary coverage with Java and TypeScript inline fixtures where possible.

### Milestone 2: public RQLP configuration and semantic identity

Add a declarative `call-modeling` record with an `unmodeled` field whose accepted atoms are `paranoid`, `optimistic`, and `require-model`. Allow it on taint and typestate analyses as:

    :call-modeling (call-modeling :unmodeled paranoid)

Default the omitted record to `paranoid`. Resolve the field into authored and resolved policy representations, canonical JSON, and semantic hashing. Compile typestate modes to conservative transition, preservation, and abstention. Ensure value-flow/taint plan construction receives the mode rather than reading policy data during transfer.

Include the mode in `SummaryBehaviorKey` construction and taint batch compatibility so changing it cannot reuse an incompatible summary or combine incompatible queries. Add parser, decoder, validation-range, hover, canonical round-trip, identity, execution, and TextMate grammar tests. Clean up the older typestate `unknown-call inconclusive` field rather than leaving two conflicting public knobs; keep escape handling separately modeled.

### Milestone 3: exact external and curated models

Add a boundary model resolver that runs before fallback selection. It must match an external reusable summary or curated/policy selector without requiring a materialized `ProcedureHandle`, then bind stable `SummaryPort`s to the live call site's receiver, parameters, normal result, thrown result, and supported abstract locations. The bound transfer must retain external origin, content hash, and dependency evidence.

Implement and test precedence: a materialized body wins over every model; an exact external semantic summary wins over curated/policy models; a curated/policy model wins over fallback. A mixed target set may execute a known body and a modeled or fallback residual arm together. External summary content and profile changes must invalidate the applicable summary repository/cache entries.

Connect the existing taint external-model authoring surface to this resolver rather than inventing a parallel evaluator-specific mechanism. If a selector cannot be represented without expanding the policy schema, extend the declarative registry and canonical identity in the same milestone.

### Milestone 4: structured side effects and operators

Extend language semantic adapters or the value-flow oracle with typed information sufficient to describe which receiver/argument locations may be mutated and which bounded heap/global locations a call can read or define. Use stable abstract locations and explicit effect records; avoid treating Java primitives as mutable references and avoid unbounded all-location fan-out.

Represent unary, binary, and native/stdlib operator behavior through the same typed transfer/summary vocabulary. Production Java and TypeScript lowering should emit `LanguageDefined` or a more precise typed relation that the value-flow plan consumes. Exact operator models take precedence over fallback just as call models do.

Validate normal return, exceptional flow, receiver mutation, argument mutation, bounded global/heap effects, and representative unary/binary operations in both languages.

### Milestone 5: acceptance, review, and issue reconciliation

Run formatting, focused test binaries, the policy/editor suites, strict all-target/all-feature clippy, and the full `nlp,python` test suite when practical. Review correctness, security, duplication, architecture, and intent. Fix confirmed findings and add minimized regression tests. Update this ExecPlan and issue #1227's checklist to distinguish delivered behavior from any deliberately extracted follow-up.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/ab80/bifrost`.

1. Inspect the current boundary contract and focused tests:

       rg -n "CallBoundary|project_call_boundary|CallToNormalContinuation|assert_successors" src/analyzer/semantic/icfg.rs tests/icfg_contract.rs tests/dataflow_summaries.rs

2. Implement and validate Milestone 1 incrementally:

       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test icfg_contract
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test dataflow_summaries
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test value_flow_client
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test taint_client
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test typestate_client

3. Implement the RQLP surface through the declarative schema, then run the policy/parser/editor-focused tests discovered from the changed modules. Record the exact binaries and results in `Progress`.

4. Implement external binding and structured adapter milestones with narrow tests before running broad validation.

5. Before a milestone checkpoint, run:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

6. Before final handoff, run the full suite with the required features when practical:

       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Expected focused-test output is a passing test binary with no ignored compilation error. A deliberately incomplete result must remain marked incomplete and retain the relevant call boundary in its evidence.

## Validation and Acceptance

The work is accepted when all of the following are demonstrated by behavior-focused tests and, where relevant, `.rqlp` execution:

- Java and TypeScript unresolved, external, unmaterialized, deferred, and candidate-truncated call arms reach every available normal and exceptional continuation while retaining their boundary evidence.
- Mixed dispatch executes known targets and a residual unknown arm; neither erases the other.
- Omitted configuration selects paranoid behavior.
- Paranoid propagates syntactic receiver/argument input facts to supported return, thrown, and modeled side-effect outputs.
- Optimistic introduces no unseen-body flow but leaves the analysis incomplete.
- Require-model abstains or produces an inconclusive/error result at an unmodeled boundary; it never converts missing semantics into a complete-clean finding.
- Typestate maps the three profiles to conservative transition, uncertainty preservation, and abstention.
- A materialized body, exact external summary, and curated policy model override fallback in that order.
- Profile and external-summary changes partition taint batches and invalidate incompatible reusable summaries.
- RQLP parser, validation range, hover, canonical JSON, semantic identity, editor grammar, and end-to-end execution cover the new vocabulary.
- Mutable receiver/argument, bounded heap/global, and unary/binary operator behavior is backed by structured semantic facts, not source-text scanning.
- `cargo fmt`, strict clippy, focused tests, and the applicable full-feature suite pass.

## Idempotence and Recovery

The focused test and validation commands are safe to rerun. `scripts/with-isolated-cargo-target.sh` owns and removes its temporary Cargo target. Do not create manually named target directories.

Policy schema and canonical changes should be made in one coherent slice so parser, decoder, validation, hover, and identity do not temporarily disagree. If a milestone fails, retain the ExecPlan and source diff, record the failing command and cause under `Surprises & Discoveries`, and fix forward. Do not reset unrelated user changes.

External summary repositories are content-addressed. Tests should create isolated repositories or in-memory fixtures and must not mutate a user's persistent cache. Re-running a model invalidation test must begin from its own temporary project/root.

## Artifacts and Notes

- GitHub issue: `https://github.com/BrokkAi/bifrost/issues/1227`
- Related performance issue: `https://github.com/BrokkAi/bifrost/issues/1228`
- Starting revision: `8eaa3d2a4d156455576a9b314294c0a7e19551d5` (detached, equal to `origin/master` when work began)
- Current public syntax proposal:

      (analysis
        :type taint
        :call-modeling (call-modeling :unmodeled paranoid)
        ...)

## Interfaces and Dependencies

Milestone 1 should leave a neutral, typed profile available to all clients, conceptually:

    pub enum UnmodeledCallBehavior {
        Paranoid,
        Optimistic,
        RequireModel,
    }

`Default` must return `Paranoid`. Value-flow plans must expose the selected behavior to their client. Taint batch compatibility must compare it. Typestate policy compilation must map it to `ProtocolUncertaintyBehavior` without duplicating string parsing.

The ICFG provider must return a continuation-capable boundary for every residual call arm with a continuation. The projected edge continues to carry `CallBoundaryKind`, `DispatchProof`, `Completeness`, origin, and provenance; it does not fabricate a callee.

The external model resolver introduced in Milestone 3 must consume stable selectors and typed summary ports. It must not depend on source substrings or require a fake workspace `ProcedureHandle`. The same bound-transfer form should be consumable by value-flow, taint, and typestate.

Revision note (2026-07-28): Initial plan created after live issue inspection and source diagnosis. It explicitly splits the immediately repairable call-continuation/profile work from external selector binding, structured side effects, and operator modeling because those capabilities do not yet exist in the semantic IR.

Revision note (2026-07-28): Milestone 2 completed the public RQLP surface and removed the conflicting legacy unknown-call knob. The default change uncovered and fixed terminal typestate reporting for sets containing both expected and violating states.

Revision note (2026-07-28): Milestones 3 and 4 completed exact external-summary selection, neutral curated-model binding, structured side-effect fallback, and Java/TypeScript operator flows. The plan records the absent production taint-policy adapter explicitly and replaces a repeated reachability scan with one iterative connectivity pass for performance.
