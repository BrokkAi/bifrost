# Add value-flow and set-oriented taint clients over the shared dataflow kernel

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost already has a language-neutral semantic value-flow oracle, a context-respecting summary solver, bounded witness reconstruction, and an IDE edge-function layer, but those pieces do not yet form a usable direct/indirect value-flow or taint analysis. After this work, an internal caller can provide already-resolved structured sources, sinks, sanitizers, and value-flow evidence, run one bounded analysis over helper calls and recursive summaries, and receive diagnostic-neutral flow meetings or taint findings with explicit proof, completeness, class identity, origin truncation, and witness truncation.

The change is deliberately split into two independently useful milestones. The first adds a policy-free value-flow plan and result contract over the fact-only summary solver. The second reuses that carrier topology through the IDE layer for finite taint-class sets and compatible multi-policy batches. Public CodeQuery/RQL selector compilation remains in issue #824, and reusable symbolic or persisted procedure summaries remain in issue #823.

The behavior is visible in new `tests/value_flow_client.rs` and `tests/taint_client.rs` integration suites. The value-flow suite follows local assignments, receiver/argument/return bindings, helper calls, recursion, and supported field locations without same-name guesses. The taint suite runs three sources and four sinks in one solver invocation, applies selective sanitization, partitions only semantically incompatible policies, aggregates bounded concrete origins, and agrees with a bounded per-pair reference union.

## Progress

- [x] (2026-07-26 14:05Z) Fetched `origin`, fast-forwarded the detached worktree from `257c1322` to `origin/master` at `4dceaf47`, and preserved the unrelated untracked `.brokk/` directory.
- [x] (2026-07-26 14:05Z) Read live issue #821 and its #816, #820, and #823 boundaries; confirmed #821 is unblocked and has no comments or existing production taint module.
- [x] (2026-07-26 14:05Z) Diagnosed the oracle-to-solver gap against the merged summary, witness, IDE, and typestate implementations and recorded the two-slice architecture in this ExecPlan.
- [x] (2026-07-26 15:20Z) Milestone 1: made oracle relations point-aware and implemented the policy-free direct/indirect value-flow plan, client, result, completeness, and witness contracts.
- [x] (2026-07-26 15:45Z) Milestone 1 review and validation: fixed exact event-identity validation, plan/result branding, context-sensitive-input rejection, and execution-discovery closure; passed the focused oracle, language, value-flow, and shared-kernel suites.
- [x] (2026-07-26 16:05Z) Milestone 2: implemented the stable taint universe, set-oriented affine-union IDE domain, compatible batch planner, selective/conservative sanitizer behavior, diagnostic-neutral findings, and witness-derived bounded origins.
- [x] (2026-07-26 16:08Z) Milestone 2 review and validation: fixed universe branding, sparse affine transfer algebra, ordered sanitizer/transform application, source-event validation, result branding, exact-class proof projection, stable finding keys, and independent origin/witness controls.
- [x] (2026-07-26 16:09Z) Final gates: `cargo fmt --all`, strict isolated all-target/all-feature Clippy, focused client/kernel tests, and the elevated isolated `cargo test --features nlp,python` suite all passed; both isolated Cargo targets were removed.

## Surprises & Discoveries

- Observation: the installed Bifrost 0.8.10 navigation plugin cannot bind this worktree even though the repository is healthy.
  Evidence: indexed tool calls report that `.brokk/bifrost_cache.db` has schema version 12 while the installed plugin accepts version 11. The user-owned `.brokk/` directory remains untouched; exact source, `rg`, and git history supplied the diagnosis.

- Observation: `DirectFlowProblem` is control reachability, not the direct value-flow client named by #821.
  Evidence: `src/analyzer/dataflow/direct.rs` has one zero fact and empty transfer callbacks, so it deliberately follows every ICFG edge without interpreting assignments, calls, or locations.

- Observation: the semantic oracle already computes the correct structured local relation but discards its execution site at publication.
  Evidence: `WorkspaceSemanticOracle::procedure_relations` iterates `ProgramPoint.events` while creating assignment, parameter, receiver, return, allocation, load, store, capture, and exceptional-return drafts, but `ValueFlowRelation` retains only kind, endpoints, proof, completeness, and provenance.

- Observation: the summary and IDE kernels already retain the exact interprocedural identities needed by both clients.
  Evidence: summary callbacks receive the exact `CallTransfer`; incoming-call and end-summary replay match normal and exceptional continuations; IDE values are keyed by `SummaryEntry`, point, and fact rather than by a point alone.

- Observation: client semantic quality can remain finite without widening the shared kernel contract.
  Evidence: value-flow and taint facts carry one semantic-uncertainty bit, while the existing path-quality frontier continues to carry ICFG evidence. This follows the landed typestate pattern, keeps certain and uncertain derivations separate, and prevents partial oracle rows from inflating a may proof or complete result.

- Observation: taint transfer functions were expensive when constructed inside IDE callbacks.
  Evidence: identity is a per-class relation, so rebuilding it for every `(point, fact)` callback was quadratic in universe bits. `TaintAnalysisPlan` now precomputes the identity and every sanitizer/transform phase function once.

- Observation: validation error precedence is part of the semantic-oracle contract.
  Evidence: validating event identity before endpoint ownership caused a deliberately cross-procedure capture relation to report `InvalidRelationIdentity` rather than `CrossProcedure`. `ValueFlowSnapshot::new` now rejects point/endpoint/capture ownership before checking the selected semantic event, restoring the stable structural error.

- Observation: sequentially applying sparse class overrides is not distributive when one overridden target is also an overridden source.
  Evidence: the relation `a -> b, b -> c` applied to `{a, b}` incorrectly produced only `{c}` because the second override erased the first output. The affine edge function now removes all overridden identity contributions first and then unions every matching target; the algebra test covers union and path order.

- Observation: three existing MCP-session tests require host OS permissions that the repository sandbox does not provide.
  Evidence: the sandboxed full suite passed 1,931 of 1,934 library tests and failed only those tests with `Operation not permitted`. Re-running the exact corrected suite elevated, with the established macOS dynamic-symbol flags and semantic indexing disabled, passed all library, integration, and doc tests.

## Decision Log

- Decision: make `ValueFlowRelation` carry its exact `ProgramPointHandle` and semantic event ordinal.
  Rationale: the oracle is the one authoritative structured interpretation of semantic events. A separate client-side scan of `SemanticEffect` would duplicate that interpretation, while source-text inference would violate the repository's no-mini-parser rule. Point plus ordinal also gives deterministic within-point transfer order without inventing source ranges or names.
  Date/Author: 2026-07-26 / Codex

- Decision: add a separately named `analyzer::value_flow` client instead of changing `DirectFlowProblem`.
  Rationale: existing direct ICFG reachability is a useful kernel regression. The new client needs finite carrier, source, sink, call-binding, result, and witness contracts that should not change ordinary fact-only callers.
  Date/Author: 2026-07-26 / Codex

- Decision: compile already-resolved `ValueFlowSnapshot` and `CallBindings` rows into a bounded immutable plan before solving.
  Rationale: local semantic facts and exact candidate-specific actual/formal/return mappings already exist. A pre-resolved plan keeps callbacks finite and repeatable, avoids provider work inside client algebra, and leaves public selector/policy compilation to #824.
  Date/Author: 2026-07-26 / Codex

- Decision: represent direct/indirect flow as a may analysis and expose must status explicitly as not established by this client.
  Rationale: IFDS reachability proves the existence or absence of a valid path under complete discovery; it does not by itself prove that every feasible path carries a value. The public result must never relabel a proven-complete may path as a must fact.
  Date/Author: 2026-07-26 / Codex

- Decision: keep positive reachability, complete negatives, and witness availability independent.
  Rationale: an incomplete oracle or exhausted solver may still support a positive partial meeting, but it cannot support complete-no-flow. Disabling or truncating witnesses must not change reachability or completeness.
  Date/Author: 2026-07-26 / Codex

- Decision: carry oracle-transfer uncertainty in finite client facts rather than adding an evidence-bearing emission API to every dataflow client.
  Rationale: a boolean semantic-quality component preserves separate certain and uncertain derivations, is bounded independently of path length, and lets result projection conjoin it with the existing path-quality frontier. It avoids a cross-kernel refactor that #821 does not require and matches the established typestate client boundary.
  Date/Author: 2026-07-26 / Codex

- Decision: use the existing IDE solver for taint classes with finite affine union edge functions.
  Rationale: a taint transfer maps an input class set through a finite per-class relation and unions finite generated classes. Identity, composition, pointwise meet, application, and value meet are all bounded and union-distributive, so another worklist engine is unnecessary.
  Date/Author: 2026-07-26 / Codex

- Decision: keep stable `SourceClassId` semantics separate from run-local dense bit positions.
  Rationale: bit positions are an execution optimization and may reorder. Persistent or diagnostic identities use stable source-class IDs plus a `TaintUniverseHash` computed from canonical class semantics.
  Date/Author: 2026-07-26 / Codex

- Decision: reconstruct concrete source origins after the fixed point from bounded witnesses and a source-event side table.
  Rationale: including every concrete `SourceEventKey` in the IDE value would grow the lattice with origin count and violate the issue's fixed-class-set design. Post-solve provenance can inspect retained witness steps, aggregate matching source events, and truncate independently while findings retain exact class identity.
  Date/Author: 2026-07-26 / Codex

- Decision: batch only on propagation-semantic compatibility.
  Rationale: workspace snapshot/scope, carrier plan, context/access-path precision, heap abstraction, external/unknown-call behavior, sanitizer/transform semantics, exceptional handling, and completeness-affecting budgets change the fixed point. Policy ID, message, CWE, CVSS, classification, and report limits do not.
  Date/Author: 2026-07-26 / Codex

## Outcomes & Retrospective

Both concern-separated clients are implemented and reviewed. The policy-free slice follows a real Java local assignment and an exact Java argument/formal/helper-return chain through `solve_with_summaries`; supports value, port, reference-location, call-result, and capture carriers; keeps uncertain input visible without promoting it to proven or complete; rejects context-sensitive oracle inputs rather than flattening them; and reconstructs bounded witnesses through the shared sidecar. Its direct focused tests cover local flow, helper bindings, uncertainty, discovery closure, context rejection, result branding, and witness independence. The existing summary/IDE/kernel suites retain coverage for recursion, matched normal and exceptional returns, cancellation, and solver budgets.

The taint slice carries three stable classes to four sinks in one IDE solve, removes only selected compatible classes through resolved sanitizers, preserves labels through unresolved sanitizers while marking the result incomplete, applies sanitizer and transform events in explicit order, partitions different propagation keys, and replays bounded concrete source origins outside the fixed point. Universe brands prevent same-width cross-plan class sets from mixing, analysis and finding results are plan-branded, and exact-class proof projection remains conservative when any contributing class or path is uncertain.

Final focused validation passed `semantic_oracle_contract` (41 tests), `semantic_value_language_contract` (18 tests), `value_flow_client` (10 tests), `taint_client` (13 tests), `dataflow_clients` (12 tests), `dataflow_ide` (23 tests), and `typestate_client` (28 tests). `cargo fmt --all`, isolated `cargo clippy --all-targets --all-features -- -D warnings`, and the complete isolated `cargo test --features nlp,python` suite also passed. The full suite used `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup'` and `BIFROST_SEMANTIC_INDEX=off` on macOS; its managed target was removed on success. No commit, branch, PR, public query syntax, persistence, or policy-rendering work was added.

## Context and Orientation

`src/analyzer/semantic/oracle/value_flow.rs` defines neutral value-flow relations. A `ValueFlowEndpoint` is a procedure-local value, a procedure port such as receiver/parameter/return, or a structured abstract location. A `ValueFlowRelation` connects one source endpoint to one target with a relation kind, proof status, completeness, and evidence-backed oracle identity. `src/analyzer/semantic/workspace_oracle/value_flow.rs` derives those rows from the normalized semantic IR rather than from source text.

`src/analyzer/semantic/oracle/call.rs` defines candidate-specific `CallBindings`. Receiver and argument rows map caller-side values or structured reference locations to callee ports. Normal and exceptional return rows map callee ports back to the exact caller result. Candidate and group coverage state whether all mappings were discovered.

`src/analyzer/dataflow/summary.rs` is the existing fact-only meet-over-valid-paths engine. A fact reaches points relative to one `SummaryEntry`; incoming-call rows and end summaries ensure a callee result returns only to the exact caller and continuation that invoked it. Recursion converges through iterative summary replay. `src/analyzer/dataflow/witness.rs` optionally retains a bounded predecessor sidecar, and `src/analyzer/dataflow/summary_result.rs` exposes deterministic facts, reached rows, path-quality frontiers, semantic coverage, solver termination, budgets, and reconstruction APIs.

`src/analyzer/dataflow/ide.rs` overlays a finite value and edge-function algebra on the same fact topology. It captures client transitions during the fact solve and then computes relative jump functions and entry-aware concrete values. Taint therefore uses the same call/return matching, recursion, cancellation, budgets, completeness, and witnesses as direct flow.

A carrier is the runtime entity whose value may flow: a semantic value, procedure port, or abstract location. A source binding says that one carrier becomes active at a structured event. A sink binding observes one carrier at a structured event. A meeting is a diagnostic-neutral result saying a source-derived carrier reached a sink scenario. Taint adds a finite set of propagation classes to the carrier fact. A class represents propagation and sanitization behavior, not a concrete source origin.

## Plan of Work

### Milestone 1: policy-free direct and indirect value flow

First, extend the oracle relation in `src/analyzer/semantic/oracle/value_flow.rs` with the exact `ProgramPointHandle` and zero-based event ordinal where the relation executes. Validate that the point belongs to the relation's procedure, that the ordinal exists, and that the retained evidence supports the selected event. Thread those fields through `FlowRelationDraft` and `materialize_flow_snapshot` in `src/analyzer/semantic/workspace_oracle/value_flow.rs`. Update oracle contract tests to prove that two same-shaped relations at different points remain distinct, ordering is deterministic, and every language fixture returns the expected point.

Create `src/analyzer/value_flow/mod.rs`, `model.rs`, `plan.rs`, `client.rs`, and `result.rs`, and export the module from `src/analyzer/mod.rs`. `model.rs` owns run-local carrier/event/source/sink IDs, live structured carriers, stable event and carrier keys for result identity, explicit observation phases, and proof/completeness carriers. IDs use the existing dense-ID helper; stable keys use semantic locators and structured roles rather than rendered names.

`plan.rs` accepts one root procedure, materialized `ValueFlowSnapshot` rows, exact `CallBindings`, resolved source bindings, resolved sink bindings, and the discovery status of each input. It validates one semantic-artifact generation, exact procedure/point ownership, call/callee agreement, structured endpoint compatibility, finite limits, and source/sink keys. It canonicalizes the input before assigning dense IDs and builds immutable indexes for local point transfers, exact call transfers, matched normal/exceptional returns, and structured boundary propagation. Incomplete or truncated oracle rows remain in the plan with explicit status; they never disappear into absence.

`client.rs` defines a finite `ValueFlowFact`: the distinguished zero fact, one active carrier, or one terminal sink meeting. `ValueFlowProblem` implements `DistributiveDataflowProblem`. Local callbacks preserve active carriers and apply point-ordered oracle relations; call callbacks map only exact receiver/argument bindings into the matched callee; return callbacks map only exact normal or exceptional ports back to that call's result; call-to-return callbacks apply the configured conservative structured unknown/external model; exceptional callbacks preserve exceptional control and apply exact exceptional events. Source bindings generate carriers from zero. Sink bindings emit non-propagating meeting facts at the configured phase. The implementation reuses shared bounded output helpers and remains iterative.

`solve_value_flow_with_summaries` invokes `solve_with_summaries` with opt-in witness retention and returns a branded `ValueFlowSummaryResult`. `result.rs` projects terminal meeting facts into `ValueFlowMeeting` values with a stable sink/scenario key, may status, explicitly unestablished must status, path-quality frontier, plan/discovery completeness, solver completeness, and bounded witnesses. A sink with no meeting is `NotReached` only when plan discovery and the solver are complete; otherwise it is `Inconclusive`.

Milestone 1 tests in `tests/value_flow_client.rs` use `InlineTestProject` and real semantic oracle snapshots/bindings. They cover local multi-hop assignments, exact actual/formal and receiver flow, helper and recursive return flow, normal versus exceptional returns, structured field load/store, same-name call and unresolved-field negatives, ambiguous dispatch, external/unknown calls, cancellation, every relevant budget, deterministic permutations, witness truncation independence, and complete-negative versus inconclusive outcomes. Add only small shared test helpers under `tests/common/` where they are genuinely reusable.

### Milestone 2: set-oriented taint over IDE

Create `src/analyzer/taint/mod.rs`, `model.rs`, `plan.rs`, `client.rs`, and `finding.rs`, and export the module from `src/analyzer/mod.rs`. `model.rs` defines validated stable `SourceClassId` semantics, a canonical `TaintUniverse` and `TaintUniverseHash`, run-local class IDs, finite `TaintClassSet` bitsets, source/sink/sanitizer/transform event keys, and the diagnostic-neutral scenario identity. Persisted forms mention only stable IDs and hashes; dense positions never escape without the universe remapping table.

`plan.rs` defines resolved taint source, sink, sanitizer, and transform bindings over the Milestone 1 carrier plan. `TaintAnalysisPlan` owns one canonical universe, finite event tables, origin-side-table limits, and exact propagation semantics. `TaintBatchPlanner` partitions submitted compiled policies by a `TaintBatchCompatibilityKey` containing every fixed-point-affecting input and excludes report-only metadata. Compatible policies union source seeds and sink observers once, retain projection membership, and do not duplicate solver runs.

`client.rs` defines `TaintEdgeFunction` as a canonical finite generated set plus per-input-class output relation. Applying a function maps every input bit through the relation and unions generated bits. Function meet unions outputs pointwise; composition follows path order; the identity maps each class to itself. `TaintFlowProblem` implements `IdeDataflowProblem` by reusing the value-flow transfer topology. Sources generate class sets, ordinary flow uses identity, transforms apply declared class mappings, and sanitizers remove only compatible classes. An unresolved sanitizer emits no killing transfer and marks discovery incomplete. Unknown/external calls apply the configured conservative structured model and never silently kill taint.

`solve_taint_batch_with_summaries` invokes `solve_ide_with_summaries` once per compatibility partition. `finding.rs` inspects terminal sink-meeting facts and entry-aware IDE values, intersects reached labels with each projected sink's accepted labels, and aggregates diagnostic-neutral `TaintFinding` values. `TaintFindingKey` contains the workspace/plan snapshot, stable sink event, and semantic carrier/context/access-path/exception/transform scenario, but excludes internal meeting nodes, concrete origins, witnesses, policy metadata, classification, and scoring.

`finding.rs` maintains a bounded `SourceEventKey` table outside the fixed point. Finding projection reconstructs retained witnesses, matches their structured steps against source bindings, aggregates equivalent origins, and reports origin and witness truncation independently. Missing witnesses or exhausted provenance budgets do not remove a finding or its source-class identity.

Milestone 2 tests in `tests/taint_client.rs` prove the finite algebra laws, deterministic dense-bit remapping, three-source/four-sink one-run equivalence to a bounded per-pair reference union, compatible batch union and incompatible partitioning, selective sanitization, conservative unresolved sanitization, helper/recursive call and return flow, origin aggregation, source and witness truncation independence, same-name and unresolved-field negatives, ambiguous/external calls, exceptional flow, cancellation, budgets, and inconclusive discovery. The test instrumentation counts calls to the public solve entry rather than asserting private registry order.

## Concrete Steps

All commands run from the repository root.

1. Confirm the refreshed baseline and preserve unrelated state:

       git status --short --branch
       scripts/with-isolated-cargo-target.sh cargo test --test dataflow_clients --test dataflow_ide --test typestate_client

2. Implement point-aware oracle relations and run:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo test --test semantic_oracle_contract --test semantic_value_language_contract

3. Implement the value-flow model, plan, fact client, result, and tests, then run:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo test --test value_flow_client --test dataflow_clients --test dataflow_summaries --test typestate_client

4. Review Milestone 1 for correctness, duplication, architecture, resource bounds, and operational concerns. Fix accepted findings, update this plan, and checkpoint only changed files.

5. Implement the taint model, batch plan, IDE client, findings, provenance, and tests, then run:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo test --test taint_client --test value_flow_client --test dataflow_ide --test typestate_client

6. Run final Rust gates:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

On macOS, if the full all-feature test link requires the repository's established dynamic Python-symbol flags, use the same environment already documented by the landed #822/#1172 plans. Keep `BIFROST_SEMANTIC_INDEX=off` so tests never download models or start real indexing.

## Validation and Acceptance

Milestone 1 is accepted when a real inline project proves local, helper, receiver, argument, return, recursive, exceptional, and supported field flow through `solve_with_summaries`; same-name and unresolved-field negatives do not become exact flow; witnesses come from the shared witness store; and incomplete discovery produces `Inconclusive` rather than complete-no-flow. Existing direct reachability, summary, IDE, and typestate tests must remain green.

Milestone 2 is accepted when one combined three-source/four-sink plan performs one IDE solve and produces the same diagnostic-neutral meetings as the bounded per-pair reference union; compatible policies share a batch while transfer-incompatible policies partition; class union/meet/composition laws hold; selective sanitizers remove only compatible classes; unresolved sanitizers and unknown calls remain conservative; dense bit reordering remaps through stable class IDs; concrete origins aggregate outside the fixed point; and witness/origin truncation does not alter class identity or solver completeness.

The implementation is complete only after formatting, strict all-target/all-feature Clippy, the focused feature suites, and `cargo test --features nlp,python` pass, with any environment-only reruns documented here. No regex/text fallback, duplicate worklist, public RQL syntax, reusable persisted summary, policy rendering, CWE/CVSS scoring, or broad vulnerability catalog may enter the diff.

## Idempotence and Recovery

All plan construction and solve operations are query-local and in-memory. Repeating a solve with the same canonical plan must produce byte-for-byte equivalent stable IDs, meetings, class mappings, termination, and budget accounting. Partial construction errors publish no usable plan. Solver cancellation and budget exhaustion return typed partial results without mutating semantic artifacts or caches.

Use `scripts/with-isolated-cargo-target.sh` for validation so temporary Cargo targets are deleted on success, failure, or interruption. Do not delete or rewrite the unrelated `.brokk/` directory. If a milestone fails midway, keep the plan's `Progress` and `Surprises & Discoveries` current, retain only additive compilable steps where possible, and resume from the exact focused test named above.

## Artifacts and Notes

Relevant landed commits are `b5b0dc3f` for the value/dispatch/heap oracle boundaries, `201770cd` for bounded fact tabulation, `3e94f809` for recursive summary fixed points, `c8df49d3` for bounded witnesses, `5d228346` for the typestate client pattern, and `4dceaf47` for IDE propagation.

The issue boundary is strict. `TaintTransferSummary`, cross-query or SQLite reuse, inferred/external summary provenance, SCC summary publication, and persistence validity keys belong to #823. Public CodeQuery/RQL source/sink selectors and policy compilation belong to #824. This plan consumes already-resolved diagnostic-neutral bindings and exposes internal analysis results for those downstream clients.

## Interfaces and Dependencies

In `src/analyzer/semantic/oracle/value_flow.rs`, extend the neutral relation with exact execution identity:

    pub struct ValueFlowRelation {
        point: ProgramPointHandle,
        event_index: u32,
        pub id: OracleRelationHandle,
        pub kind: ValueFlowRelationKind,
        pub source: ValueFlowEndpoint,
        pub target: ValueFlowEndpoint,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

Expose read-only accessors for `point` and `event_index`; keep construction validated through `ValueFlowSnapshot::new`.

In `src/analyzer/value_flow`, expose names in this shape, refining incidental signatures during implementation while preserving the responsibilities:

    pub enum ValueFlowCarrier { Value(ValueHandle), Port(ProcedurePortHandle), Location(AbstractLocation) }
    pub struct ValueFlowPlan;
    pub struct ValueFlowSourceSpec;
    pub struct ValueFlowSinkSpec;
    pub struct ValueFlowFact;
    pub struct ValueFlowProblem<'plan>;
    pub struct ValueFlowSummaryResult;
    pub struct ValueFlowMeeting;

    pub fn solve_value_flow_with_summaries<Provider>(
        root: &ProcedureHandle,
        provider: &Provider,
        plan: &ValueFlowPlan,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<ValueFlowSummaryResult, ValueFlowSolveError>
    where
        Provider: IcfgProvider + ?Sized;

The plan constructor consumes already materialized `ValueFlowSnapshot` and `CallBindings` values plus their discovery statuses. It must not import policy definitions or call a language-specific analyzer.

In `src/analyzer/taint`, expose names in this shape:

    pub struct SourceClassId;
    pub struct SourceEventKey;
    pub struct TaintUniverse;
    pub struct TaintUniverseHash;
    pub struct TaintClassSet;
    pub struct TaintEdgeFunction;
    pub struct TaintPolicyPlan;
    pub struct TaintAnalysisPlan;
    pub struct TaintBatchPlanner;
    pub struct TaintBatchCompatibilityKey;
    pub struct TaintFindingKey;
    pub struct TaintFinding;
    pub struct TaintFindingReport;

    pub fn solve_taint_batch_with_summaries<Provider>(
        root: &ProcedureHandle,
        provider: &Provider,
        plan: &TaintAnalysisPlan,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<TaintFindingReport, TaintSolveError>
    where
        Provider: IcfgProvider + ?Sized;

No external crate is required. Reuse the repository's dense-ID macro, canonical hashing, `HashMap`/`HashSet` aliases, semantic oracle types, summary/IDE result types, and witness limits.

Plan revision note (2026-07-26): Created after refreshing `origin/master`, reading the live issue and dependency boundaries, diagnosing the exact oracle-to-solver seam, and selecting the required policy-free value-flow then set-oriented taint milestone split.
