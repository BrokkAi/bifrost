# Add compositional semantic and client summaries for issue #823

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md`. It implements GitHub issue #823, “Add compositional semantic and protocol summaries with incremental caching.” The plan deliberately starts with reusable in-memory artifacts and admits a SQLite representation only after a fresh-process benchmark proves that an equivalent packed form is beneficial.

## Purpose / Big Picture

Bifrost can already solve bounded interprocedural data-flow queries, reuse query-local entry-to-exit rows while a solve is running, reconstruct bounded witnesses, propagate finite IDE edge functions, and execute a versioned typestate protocol. Those results cannot safely cross query or process boundaries: they contain run-local fact IDs, artifact-instance handles, witness ownership, request budgets, and other state whose meaning exists only inside one solve.

After this work, Bifrost clients can publish complete procedure effects under stable validity keys and reuse them across compatible callers and analyses. A typestate client can reuse a protocol-branded entry-state-to-exit-state relation without importing public policy or reporting types. Once issue #821 lands, the taint client can reuse a symbolic transfer summary even when only sink presentation, messages, CWE, CVSS, or report limits change. A user can observe the behavior through focused reuse and invalidation tests and, later, a retained lifecycle benchmark comparing rebuild, in-memory reuse, serialization, and fresh-process hydration.

The first working milestone does not add a database table. It defines the stable artifact, validation, algebra, provenance, and complete-only in-memory publication behavior that a later persistence experiment must preserve exactly.

## Progress

- [x] (2026-07-26 17:31Z) Refreshed `origin/master`, confirmed the detached worktree was current at `4dceaf47`, preserved the unrelated `.brokk/` directory, and created `dave/issue-823-compositional-summaries` from `origin/master` with explicit user authorization.
- [x] (2026-07-26 17:31Z) Read the live issue and dependency state: #817 and #822 are closed, #821 is open with implementation at `origin/agent/issue-821-value-flow-taint`, and #823 is unblocked for its semantic and protocol layers.
- [x] (2026-07-26 17:31Z) Audited query-local tabulation, IDE, typestate, semantic identity, store, and #817 lifecycle boundaries; confirmed no `SemanticProcedureSummary`, `ProtocolSummary`, `TaintTransferSummary`, or complete-summary repository exists on `origin/master`.
- [x] (2026-07-26 17:31Z) Wrote this issue-specific ExecPlan and selected stable in-memory contracts as Milestone 1.
- [x] (2026-07-26 19:04Z) Fetched and rebased onto `origin/master` commit `3a634356`, where #821 landed as PR #1180; restored the Milestone 1 work without conflict and kept `.brokk/` untouched.
- [x] (2026-07-26 20:17Z) Implemented Milestone 1: exact provenance, composition-root, and dependency-closure keys; typed boundary/effect/evidence contracts; deterministic full-summary composition and join; bounded byte-accounted in-memory reuse; and atomic publication from per-summary validated recursive topology.
- [x] (2026-07-26 20:52Z) Completed the guided security, duplication, intent, operations, and architecture review passes; fixed every Critical/High finding plus accepted boundedness/lifecycle findings, and completed delta re-reviews with no unresolved Critical or High issue.
- [x] (2026-07-26 21:08Z) Validated Milestone 1 with 15 reusable-summary tests, 27 query-local summary tests, 23 IDE tests, formatting/diff checks, and strict all-target/all-feature Clippy through the pinned Rust 1.96 toolchain.
- [x] (2026-07-26 21:11Z) Checkpointed the reviewed Milestone 1 implementation as commit `eb7370df` without staging or modifying the unrelated `.brokk/` cache.
- [ ] Implement and validate Milestone 2: protocol summary projection and reuse over the landed typestate client.
- [ ] Integrate Milestone 3 only after #821 lands: symbolic taint-transfer summaries and their split invalidation keys.
- [ ] Run Milestone 4 lifecycle measurements and record the promotion decision; implement packed SQLite persistence only if the evidence passes #817's predeclared gates.

## Surprises & Discoveries

- Observation: `TabulationEndSummary` documents its own exclusion from durable semantic and client summaries.
  Evidence: `src/analyzer/dataflow/summary_result.rs` describes it as a query-local correctness row and stores a run-local `FactId`, `Arc<IcfgExitProfile>`, witness alternatives, and result ownership.

- Observation: the IDE layer measures summary-function reuse but its result is still one solve's interned edge-function and value tables.
  Evidence: `src/analyzer/dataflow/ide_result.rs::IdeSummaryDataflowResult` owns boxed edge functions, values, optional dense function IDs, point values, request work, and termination.

- Observation: typestate already has the two durable hashes a protocol summary needs, but the result merely brands the query-local solve.
  Evidence: `src/analyzer/typestate/client.rs::TypestateSummaryResult` contains `TypestateProtocolHash`, `TypestateBindingPlanHash`, booleans, and `SummaryDataflowResult<TypestateFact>`.

- Observation: a source-facing `SemanticLocator` is explicitly not a cache-validity key.
  Evidence: `src/analyzer/semantic/ids.rs` distinguishes the remappable locator from `SemanticArtifactKey`, whose digest includes mount, portable path, exact source revision, adapter semantics, semantic IR version, configuration, and dependencies.

- Observation: #817 already measured the current exploded solver state and classified it as persistence-ineligible.
  Evidence: `.agents/docs/dataflow-lifecycle-benchmark-2026-07-24.md` records `ephemeral_not_eligible; persist reusable summaries only after #823 defines and measures them` and does not invoke the promotion gate without an equivalent artifact.

- Observation: at planning time, #821 had an implementation branch but was not yet on `origin/master`.
  Evidence: the initial baseline was `4dceaf47` while `origin/agent/issue-821-value-flow-taint` pointed to `b4267793`. That constraint ended when PR #1180 landed and this branch rebased to `3a634356`.

- Observation: #821 landed while Milestone 1 was under review, and the landed public contracts are now the only taint/value-flow baseline for this plan.
  Evidence: `origin/master` commit `3a634356` (“Add direct, indirect, and taint data-flow clients (#1180)”) adds `src/analyzer/value_flow/`, `src/analyzer/taint/`, and their behavior tests. The issue branch was rebased onto that commit before further summary integration.

- Observation: the initial Milestone 1 review exposed cache-safety gaps that ordinary compilation did not reveal.
  Evidence: independent security, intent, operations, duplication, and architecture passes converged on structural provenance keys, derived dependency closure, shared SCC invalidation, distinct alternative/sequential evidence operations, summary-level effect composition, and explicit work/retention budgets.

- Observation: dependency closure and recursive call topology are related but cannot be the same structure.
  Evidence: composition must flatten nested call effects and dependencies to remain associative, while SCC validation must retain the source-level strongly connected topology. `publish_scc` therefore validates an explicit topology against the flattened dependency closure and hashes that topology into every group member key.

- Observation: the shell resolves rustup's pinned `cargo`/`rustc` but Homebrew's `cargo-clippy`, and Rust 1.96 artifacts from those builds are metadata-incompatible despite sharing the same release number.
  Evidence: the ordinary strict command failed with `found crate cc compiled by an incompatible version of rustc`, identifying the current compiler as Homebrew. Running the gate through `rustup run 1.96.0 cargo-clippy` keeps Cargo, Clippy, and rustc on the pinned toolchain.

## Decision Log

- Decision: create durable summaries above, not inside, query-local tabulation.
  Rationale: `TabulationEndSummary` is required for fixed-point correctness and matched-return replay. Replacing it would couple persistence identity to run-local fact interning, witnesses, and request state. The reusable layer instead projects stable boundary relations and effects from a complete result.
  Date/Author: 2026-07-26 / Codex

- Decision: make stable procedure identity an exact `SemanticArtifactKey` plus a declaration identity, never an artifact-instance `ProcedureHandle` or remappable `SemanticLocator` alone.
  Rationale: handle equality includes `Arc` identity, while the locator intentionally omits cache validity. The artifact key supplies semantic validity and the declaration locator selects the callable within that artifact.
  Date/Author: 2026-07-26 / Codex

- Decision: admit only complete summaries to the reusable repository.
  Rationale: cancelled, budget-truncated, unresolved, stale, or corrupt work may support an explicitly partial current finding but cannot justify a complete negative or become a reusable complete entry.
  Date/Author: 2026-07-26 / Codex

- Decision: publish recursive strongly connected component members atomically after convergence.
  Rationale: exposing one member while mutually recursive peers are still changing can make order affect results and can allow an incomplete dependency set to masquerade as complete.
  Date/Author: 2026-07-26 / Codex

- Decision: keep recursive topology explicit and separate from the flattened retained dependency closure.
  Rationale: nested effects and dependencies must flatten for associative composition and invalidation, but using that transitive closure as the call graph invents SCC edges and makes valid recursive batches unpublishable. The declared topology is hashed into the shared group key, checked for strong connectivity, and required to be represented in each source member's retained dependencies.
  Date/Author: 2026-07-26 / Codex

- Decision: represent external provenance as a validated opaque model identity and content digest in this layer.
  Rationale: issue #1144 owns model-pack authoring, discovery, and packaging. #823 needs to distinguish inferred source from validated external semantics without creating a competing pack schema.
  Date/Author: 2026-07-26 / Codex

- Decision: do not add SQLite in the first milestone.
  Rationale: #817 requires an equivalent artifact, serialization/hydration path, stable identity, size, invalidation behavior, and measured warm benefit before promotion. None exists until the in-memory summary contract works.
  Date/Author: 2026-07-26 / Codex

- Decision: integrate Milestone 3 only against landed #821 commit `3a634356`.
  Rationale: the merged value-flow and taint modules now own the carrier, universe, event, plan, client, and finding contracts that a symbolic taint summary must reuse. The earlier implementation-branch snapshot is no longer authoritative.
  Date/Author: 2026-07-26 / Codex

## Outcomes & Retrospective

Milestone 1 now supplies the reusable semantic foundation without adding global state or persistence. Exact keys include semantic artifact validity, declaration, schema, execution semantics, context, behavior, origin, dependency closure, and the full recursive-group closure. Composition derives its own dependency identity, preserves effects from reachable non-returning callees, distinguishes alternative joins from sequential conjunction, and is deterministic across association for the complete semantic payload. The repository publishes only complete entries, validates exact dependencies, validates explicit recursive topology as a real SCC, preflights whole batches atomically, accounts retained bytes, and supports owner-driven generation rotation.

Focused `reusable_summaries` validation passes 15 behavior tests, including source/external/dependency invalidation, keyed composition-root identity, full-summary associativity, maximum-size idempotence, bounded composition work, non-returning effect preservation, complete-only publication, recursive closure invalidation, non-SCC rejection, composed SCC publication, byte capacity, and atomicity. The adjacent `dataflow_summaries` (27 tests) and `dataflow_ide` (23 tests) suites also pass. Strict `--all-targets --all-features` Clippy passes through the pinned Rust 1.96 toolchain, and the final specialist delta reviews found no unresolved Critical or High issue. Commit `eb7370df` is the reviewed Milestone 1 checkpoint; Milestone 2 begins from that stable foundation.

## Context and Orientation

`src/analyzer/semantic/ids.rs` owns durable semantic identity. `SemanticArtifactKey` identifies one mounted immutable source artifact and includes the exact source revision, adapter semantics, semantic IR version, configuration, and dependencies. `DeclarationLocator` identifies a callable declaration within an artifact. `SemanticLocator` is useful for source-facing remapping but is explicitly not sufficient as a validity key.

`src/analyzer/semantic/ir/artifact.rs` owns `SemanticArtifact` and `ProcedureHandle`. A handle pairs a run-time `Arc<SemanticArtifact>` with a dense `ProcedureId`; it is safe inside provider and oracle calls but is not durable across materializations. A reusable summary must therefore map between stable declaration/boundary identities and live handles at application time.

`src/analyzer/dataflow/summary.rs` is the correctness-critical meet-over-valid-paths solver. It interns client facts, tracks path edges and incoming calls, publishes query-local end summaries, replays those summaries to exact callers, converges through direct and mutual recursion, and optionally retains bounded predecessor evidence. `src/analyzer/dataflow/summary_result.rs` exposes the deterministic result plus coverage, termination, work, semantic work, metrics, and witness reconstruction. Those rows remain query-local.

`src/analyzer/dataflow/ide.rs` overlays finite values and edge functions on the same fact topology. `src/analyzer/dataflow/ide_result.rs` exposes relative jump functions and entry-aware values, again using one solve's interners. These functions provide the algebraic shape needed for client summaries, not a ready durable artifact.

`src/analyzer/typestate/protocol.rs` compiles a canonical versioned finite-state protocol. `src/analyzer/typestate/hash.rs` owns `TypestateProtocolHash` and `TypestateBindingPlanHash`. `src/analyzer/typestate/client.rs` runs the protocol through the shared summary solver and returns a branded query-local `TypestateSummaryResult`. `src/analyzer/typestate/finding.rs` projects violations and witnesses. Public policy loading, presentation, messages, severity, CWE, CVSS, and SARIF remain in `src/analyzer/policy/` and must not enter protocol-summary keys.

`src/analyzer/store/mod.rs` and `migrations/cache/` demonstrate the production SQLite lifecycle. Structural snapshots are versioned packed payloads tied to complete live parsed blobs; writes use an immediate transaction, account for payload cost, and cascade with parent data. That code is a later persistence pattern, not the first summary implementation.

`.agents/docs/semantic-artifact-lifecycle-matrix.md`, `.agents/docs/dataflow-lifecycle-benchmark-2026-07-24.md`, and `src/benchmark/artifact_lifecycle.rs` define #817's promotion process. A persistence candidate must preserve the same semantic fields and behavior, measure fresh-process reconstruction and hydration, retain exact provenance, and pass every predeclared gate.

In this plan, a summary is a stable, finite relation over procedure boundary identities and effects. A boundary identity is an entry, normal exit, exceptional exit, receiver, parameter, return, or supported heap/access-path port expressed without run-local dense numbering. Composition applies the first relation and then the second in execution order. Meet/join combines compatible alternatives monotonically and deterministically. A strongly connected component, or SCC, is a maximal mutually recursive group; none of its complete summaries becomes visible until all members converge.

## Plan of Work

### Milestone 1: stable semantic summary contracts and in-memory reuse

Create `src/analyzer/dataflow/reusable_summary.rs` and export its public contract from `src/analyzer/dataflow/mod.rs`. Keep `src/analyzer/dataflow/summary.rs` focused on query-local fixed-point execution.

Define strongly typed digest wrappers for the solver-summary schema, context/access-path abstraction, dependency closure, and external model content. Define `ProcedureSummaryKey` from an exact `SemanticArtifactKey`, callable `DeclarationLocator`, solver-summary version, context abstraction, exceptional/escape/unknown-call semantics, and callee or SCC dependency fingerprint. The artifact key already carries adapter, IR, source revision, configuration, and direct dependency identity; constructors must not accept redundant loosely related strings.

Define `SummaryOrigin` with `Inferred` and `External` variants. Inferred origin retains the exact source artifact/declaration identity. External origin retains a validated opaque model identity, model content digest, and contract version supplied by #1144-compatible model loading; it does not define files, manifests, precedence, or catalogs. Define `SummaryCompleteness` so only the complete variant can be published. Partial values retain canonical reasons for current-query reporting but fail repository admission. Reuse the semantic layer's `ProofStatus` and `EvidenceCompleteness` where they express edge evidence; do not import policy `ProofMetadata`, messages, or presentation types.

Define a finite `SemanticProcedureSummary` containing the stable key, origin, canonical boundary relation, exceptional and escape effects, unresolved/ambiguous-call effects, proof frontier, completeness, and ordered dependency keys. Its constructor validates ownership, uniqueness, canonical ordering, boundary compatibility, monotonic proof/completeness, dependency consistency, and finite size limits. Composition operates only on compatible identities and semantics, applies relations in path order, joins duplicate outputs monotonically, propagates exceptional/escape/unknown effects, and cannot upgrade proof or completeness.

Add an in-memory `CompleteSummaryRepository` whose lookup key is the full stable key. Publication validates completeness and dependency state. Single procedures publish as one entry; an SCC publication accepts a non-empty canonical batch, validates that every declared member is present and complete, and makes the batch visible atomically. Start with a simple bounded, lock-protected map only if concurrent use is needed by an actual caller; otherwise keep the repository single-owner and pass it explicitly. Do not add global state, SQLite, background work, or eager workspace hydration.

Create `tests/reusable_summaries.rs` using small constructed semantic identities. Prove deterministic keying and ordering; composition identity and associativity for representative finite relations; monotonic join; exact normal versus exceptional boundary behavior; inferred/external provenance preservation; complete-only admission; no publication after cancellation/truncation/partial evidence; source, adapter, IR, solver, configuration, context, and dependency invalidation; atomic two-member SCC publication; and stable equality under input permutation. Tests must prove behavior, not mirror private registry order.

### Milestone 2: protocol summary projection and reuse

Create `src/analyzer/typestate/summary.rs` and export it from `src/analyzer/typestate/mod.rs`. Define `ProtocolSummaryKey` from `ProcedureSummaryKey`, `TypestateProtocolHash`, `TypestateBindingPlanHash`, protocol-summary schema version, and the binding/context semantics that affect propagation. Exclude policy ID, source filenames used to load the policy, messages, severity, CWE, CVSS, report limits, witness limits, and rendering configuration.

Define `ProtocolSummary` as a canonical stable relation from entry subject/object/state identities to normal and exceptional exit identities/states plus terminal, escape, uncertainty, and violation effects. Run-local `TypestateSubjectId`, `ProtocolStateId`, and `TypestateFact` values must be converted through their canonical keys before publication and remapped through a validated live protocol/binding plan when reused.

Extend `solve_typestate_with_summaries` through a separate explicit entry point or optional repository parameter so the existing no-repository behavior remains correct. A hit applies the stable protocol relation to compatible incoming canonical states; a miss uses the current solver and projects a complete result only after termination and binding/execution completeness are proven. Recursive publication follows Milestone 1's SCC rule. Witnesses remain query-local and may be reconstructed from live source-backed execution; full witness paths are never stored in `ProtocolSummary`.

Extend `tests/typestate_client.rs` with two callers reusing one helper protocol summary, direct and mutual recursion, normal and exceptional exits, terminal findings, ambiguity/escape uncertainty, changed protocol and binding hashes, incomplete binding and budget/cancellation rejection, and parity between cached and uncached findings. Existing Java/TypeScript fixtures continue to use one protocol definition without language branches in the summary layer.

### Milestone 3: symbolic taint transfer after issue #821

Before this milestone, fetch and verify that #821 has landed on `origin/master`; integrate its final public internal contracts rather than relying on the current unmerged branch snapshot. Update this plan with the landed commit and any API differences.

Create `src/analyzer/taint/summary.rs`. Define `CarrierSummaryKey`, `TaintPropagationEventMatchKey`, `TaintSinkObserverMatchKey`, and `TaintTransferSummaryKey` using the exact split documented by #823. The transfer key includes carrier/ICFG/call-binding/oracle/context/access-path/exceptional/escape/unknown-call semantics, taint algebra and propagation model, propagation-relevant event matching when embedded, and callee/SCC dependencies. Sink-observer matching remains separate and never invalidates transfer.

Define `TaintTransferSummary` with symbolic boundary transfer, local source-generator ports, internal sink-observation ports, sanitizer/transform effects, exceptional/escape effects, proof, and completeness. Persisted or reusable class sets carry stable source-class identities and `TaintUniverseHash`, never run-local bit positions. Concrete source origins, witnesses, policy identity, messages, CWE, CVSS, scoring, and report limits stay outside the summary. A source and sink wholly inside a summarized callee remain observable through local/internal event ports.

Extend the #821 tests to prove reuse across sink-only and presentation-only changes; safe misses for source-generator, sanitizer/transform, oracle, context/access-path, unknown-call, and dependency changes; internal source-to-sink visibility; dense-bit remapping; exact SCC publication; and incomplete-summary rejection.

### Milestone 4: measurement and conditional persistence

Create `tests/measure_summary_lifecycle.rs`, `scripts/run-summary-lifecycle-benchmarks.sh`, and a dated report under `.agents/docs/`. Reuse the generated, inline Java/TypeScript, pinned VS Code, and pinned Spring PetClinic provenance discipline from the existing lifecycle runners. Measure rebuild, same-process complete-summary reuse, serialization, fresh-process hydration, retained bytes or RSS, serialized bytes, hit/miss status, invalidation, counts, completeness, and a canonical result checksum. Include semantic, protocol, and—after #821—taint summaries as separate candidates because their keys and reuse patterns differ.

Run the shared `evaluate_artifact_promotion` gate from `src/benchmark/artifact_lifecycle.rs`. Do not relax thresholds after observing results. Record one of three decisions per artifact: remain in-memory, promote to SQLite, or insufficient evidence. A candidate that lacks RSS, exact equivalence, stable invalidation, or a meaningful fresh-process warm benefit does not pass.

Only for candidates that pass, add a versioned migration and focused `AnalyzerStore` APIs. Use packed versioned DTOs, lazy hydration, corruption/version/staleness as misses, complete-generation validation, immediate write transactions when a read precedes replacement, payload-cost accounting, cascade cleanup, concurrent reader/writer tests, and overlay/source/dependency invalidation tests. Do not persist worklists, run-local dense IDs, whole witness paths, partial summaries, or implementation-internal maps.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/933f/bifrost`.

Confirm the attached issue branch and preserved unrelated state:

    git status --short --branch
    git rev-parse HEAD origin/master
    git rev-list --left-right --count HEAD...origin/master

Expected at plan creation: attached `dave/issue-823-compositional-summaries`, zero divergence, and only the pre-existing untracked `.brokk/` plus this plan.

After Milestone 1 implementation:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test reusable_summaries --test dataflow_summaries --test dataflow_ide
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Expect every focused test to pass and no generated `.brokk/` content or retained isolated Cargo target to enter the diff. Review the milestone, update this document, and checkpoint only the plan and files changed for Milestone 1.

After Milestone 2:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test reusable_summaries --test typestate_protocol --test typestate_binding --test typestate_client --test dataflow_summaries --test dataflow_ide
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Expect cached and uncached protocol runs to produce identical canonical facts/findings/completeness, with reuse counters demonstrating a hit only for exact keys.

After #821 integration and Milestone 3:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test reusable_summaries --test value_flow_client --test taint_client --test typestate_client --test dataflow_ide
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Run the lifecycle matrix only after all three equivalent in-memory artifacts exist. Use the exact external repository variables, revisions, sample count, and cleanup discipline recorded by the runner and report. If any candidate passes, implement and rerun its SQLite comparison before enabling persistence by default.

Before final publication run:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check
    git status --short

On macOS, if the complete feature-enabled suite requires the repository's established dynamic Python-symbol linker flags, record the exact rerun in `Surprises & Discoveries` and keep semantic indexing disabled. The helper must remove its managed target on success, failure, or interruption.

## Validation and Acceptance

Milestone 1 is accepted when two compatible callers can reuse one complete semantic procedure summary; deterministic composition and join laws pass; a changed source, adapter, IR, solver, configuration, context, or dependency key misses; incomplete work is rejected; inferred and external origins remain distinguishable; and mutually recursive entries become visible only as one converged batch.

Milestone 2 is accepted when a helper's protocol summary produces the same normal, exceptional, terminal, uncertainty, proof, completeness, and finding behavior as an uncached solve; protocol or binding changes miss; policy presentation changes are absent from the key; and bounded witnesses remain source-backed and query-local.

Milestone 3 is accepted when taint transfer reuse survives sink-only, message, CWE, CVSS, and report-limit changes; transfer-affecting changes miss; stable class identities survive dense-bit remapping; internal source-to-sink flows remain observable; and no incomplete transfer or SCC member is published as complete.

Milestone 4 is accepted when the retained report contains exact commit/corpus provenance, semantic counts, timings, memory, serialized size, cache status, invalidation, completeness, and checksums. SQLite is accepted only for a candidate that preserves equivalent behavior and passes every predeclared #817 gate. A measured no-go or in-memory-only decision still completes the milestone if it is reproducible and evidence-backed.

The issue is complete only when the implemented artifacts satisfy the live acceptance criteria, all focused tests pass, strict all-target/all-feature Clippy passes, the complete `nlp,python` suite passes, specialist review has no unresolved critical or high finding, the plan records final evidence, and unrelated `.brokk/` data remains untouched.

## Idempotence and Recovery

Key construction, validation, composition, lookup, and publication are deterministic and safe to repeat. Reapplying a complete SCC batch with identical keys and values is a no-op; applying a conflicting batch returns an error without partial publication. Cancellation or budget exhaustion leaves no reusable entry. External summary validation publishes nothing until the complete batch passes.

Use `scripts/with-isolated-cargo-target.sh` for every isolated Rust build so temporary targets are removed automatically. Do not create manually named `/tmp/bifrost-*` targets. Do not remove or rewrite `.brokk/`. If #821 changes before merge, update the plan first, then integrate the landed public contracts. If a future migration fails, treat its rows as cache misses, retain rebuild correctness, and keep the feature disabled until the equivalent-artifact tests pass again.

## Artifacts and Notes

The current baseline is `origin/master` commit `3a634356`, which lands #821 through PR #1180 on top of `5d228346` for the reusable typestate client and `4dceaf47` for bounded IDE propagation. The query-local recursive summary kernel landed in `3e94f809`, and bounded witnesses landed in `c8df49d3`. The earlier #821 branch snapshot at `b4267793` is historical only; all taint-summary work uses the landed contracts.

The existing lifecycle conclusion is intentionally narrow: exploded query-local results are persistence-ineligible, while reusable summary artifacts remain unmeasured. This plan must not misstate the earlier benchmark as either evidence for or against persistence of the new artifacts.

## Interfaces and Dependencies

Milestone 1 should expose responsibility-equivalent interfaces in `src/analyzer/dataflow/reusable_summary.rs`. Incidental names may be refined during implementation, but their semantic separation must remain:

    pub struct ProcedureSummaryKey;
    pub struct SummarySchemaVersion;
    pub struct SummaryContextKey;
    pub struct SummaryDependencyFingerprint;
    pub enum SummaryOrigin { Inferred(...), External(...) }
    pub enum SummaryCompleteness { Complete, Partial(...) }
    pub struct SemanticProcedureSummary;
    pub struct CompleteSummaryRepository;

    impl SemanticProcedureSummary {
        pub fn try_new(...) -> Result<Self, SummaryValidationError>;
        pub fn compose(...) -> Result<Self, SummaryCompositionError>;
        pub fn join(...) -> Result<Self, SummaryCompositionError>;
    }

    impl CompleteSummaryRepository {
        pub fn get(&self, key: &ProcedureSummaryKey) -> Option<&SemanticProcedureSummary>;
        pub fn publish(&mut self, summary: SemanticProcedureSummary) -> Result<(), SummaryPublicationError>;
        pub fn publish_scc(&mut self, members: Vec<SemanticProcedureSummary>) -> Result<(), SummaryPublicationError>;
    }

The final repository API may return borrowed or shared values according to its demonstrated ownership needs; do not introduce reference counting before a real concurrent consumer requires it. The solver remains correct without a repository.

Milestone 2 adds responsibility-equivalent interfaces in `src/analyzer/typestate/summary.rs`:

    pub struct ProtocolSummaryKey;
    pub struct ProtocolSummary;

    impl ProtocolSummary {
        pub fn try_from_complete_result(
            key: ProtocolSummaryKey,
            protocol: &CompiledProtocol,
            bindings: &TypestateBindingPlan,
            result: &TypestateSummaryResult,
        ) -> Result<Self, ProtocolSummaryError>;
    }

Milestone 3 adds `TaintTransferSummary` and its exact split keys in `src/analyzer/taint/summary.rs` after importing the landed #821 contracts. No new external dependency is expected. Reuse the existing canonical hashing, typed digests, semantic identities, dense-ID remapping patterns, proof/completeness types, `HashMap`/`HashSet` choices, benchmark gate, and SQLite infrastructure.

Plan revision note (2026-07-26): Created after live issue/dependency verification, Bifrost-backed code diagnosis, user approval of the implementation plan and branch, and refresh of `origin/master`. The plan begins with stable in-memory contracts, defers taint until #821 lands, and makes persistence conditional on #817's measured promotion gates.
