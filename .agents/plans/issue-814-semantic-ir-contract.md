# Define the language-neutral semantic IR contract

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation proceeds. Follow `.agents/PLANS.md` when revising it. The broader platform roadmap is checked in at `.agents/plans/language-agnostic-composable-typestate-platform.md`; this issue plan is self-contained and narrows that roadmap to GitHub issue #814.

## Purpose / Big Picture

Bifrost currently normalizes syntax, resolves declarations and calls, and answers bounded receiver questions, but it has no language-neutral representation of executable procedures. After this change, later TypeScript and Java adapters can describe procedures, blocks, program points, values, allocations, calls, memory actions, captures, normal and exceptional exits, and async boundaries through one Rust contract. A bounded renderer will make those facts reviewable before a CFG solver exists.

The observable result is an immutable `SemanticArtifact` API under `brokk_bifrost::analyzer::semantic`. Tests will construct equivalent TypeScript and Java semantic artifacts, render them deterministically, and prove that every missing or uncertain semantic fact is reported as typed ambiguity, unknown support, unsupported support, unproven evidence, or budget exhaustion rather than as a guessed edge. Tests will also prove that content changes, overlay snapshots, adapter changes, configuration changes, dependencies, parser dialects, workspace mounts, and mounted paths participate in artifact identity.

## Progress

- [x] (2026-07-16 14:39+02:00) Read issue #814, parent epic #813, downstream issues #815, #816, #817, #818, and #822, the merged durable roadmap, and the relevant existing source/storage contracts.
- [x] (2026-07-16 14:39+02:00) Diagnosed structural facts, Rune IR, call relations, receiver analysis, compact graph storage, analyzer providers, nested callable indexing, overlays, and source-range conventions.
- [x] (2026-07-16 14:39+02:00) Resolved the artifact and dense-ID scopes, nested procedure model, callable-reference model, capture model, and source-position convention in this plan.
- [x] (2026-07-16 15:32+02:00) Implemented durable and dense identities, total capabilities, typed outcomes, finite atomic budgets, and the standalone provider boundary.
- [x] (2026-07-16 15:32+02:00) Implemented the immutable semantic artifact/procedure/event contract and construction-time invariant validation.
- [x] (2026-07-16 15:32+02:00) Implemented the deterministic bounded semantic IR renderer with artifact/procedure selection and balanced truncation.
- [x] (2026-07-16 15:32+02:00) Added behavior-focused cross-language, nested callable, value/cell capture, method-reference, invalidation, uncertainty, validation, and renderer tests.
- [x] (2026-07-16 18:01+02:00) Ran formatting, focused tests, the full `nlp,python` feature suite, all-target/all-feature clippy, and parallel specialist plus final invariant audits; fixed every accepted finding and checkpointed the reviewed implementation as `296c1de1` after rebasing onto current `master`.
- [x] (2026-07-16 19:20+02:00) Ran the guided review against rebased `origin/master`, fixed all four findings in `1faf8b9b`, and revalidated 60 semantic tests, 9 Rune IR tests, 10 contract tests, all-feature clippy, and the complete `nlp,python` suite.

## Surprises & Discoveries

- Observation: `CodeUnit` is not an exhaustive executable-procedure identity. Java creates synthetic lambda `CodeUnit`s, but `CallRelationService` excludes synthetic units; most other adapters do not create an independent `CodeUnit` for every nested callable.
  Evidence: `src/analyzer/java/declarations.rs` creates lambda units, while `src/analyzer/usages/call_relations.rs::is_call_relation_unit` rejects `CodeUnit::is_synthetic()`.

- Observation: outgoing call discovery correctly skips nested callable bodies so their calls are not attributed to the outer callable, but a missing child procedure means those calls can disappear from the current call-relation surface.
  Evidence: `src/analyzer/usages/get_definition/call_sites.rs` prunes nested callable bodies during iterative traversal.

- Observation: the roadmap's original provider sketch made the artifact procedure-shaped while also declaring `ProcedureId` artifact-local, and `HeapOracle::locations` accepted an unscoped `ValueId`.
  Evidence: `.agents/plans/language-agnostic-composable-typestate-platform.md` originally specified `artifact_key(procedure)` followed by `procedure(key)` and a bare-value oracle signature.

- Observation: existing `Range` line numbering is not one uniform durable contract. Declaration and structural paths commonly store one-based lines, while call and receiver paths use raw zero-based tree-sitter rows.
  Evidence: `src/analyzer/tree_sitter_analyzer.rs`, `src/analyzer/structural/extract.rs`, and `src/analyzer/usages/get_definition/call_sites.rs` construct ranges differently.

- Observation: overlay state has no public revision token suitable for semantic identity. Analyzer storage generations are language-epoch guards, not overlay revisions.
  Evidence: `OverlayProject` exposes overlay presence and snapshotting, while liveness owns an internal generation counter.

- Observation: a capture destination cannot be creator-procedure-local. The nested body must own the capture slot that its load/store events address, while creation-site source values, source locations, callable values, and environment allocations remain creator-local.
  Evidence: the initial validation sketch made both `CaptureId` and its destination `MemoryLocationId` outer-local, which left the child body no legal procedure-local ID for the captured storage.

- Observation: removing a generic oracle-defined memory escape hatch exposed a required neutral case rather than a language-specific exception: mutable lexical captures need a creator-local lexical-cell location.
  Evidence: value snapshots can use `CaptureSource::Value`, but JavaScript/Python-style shared cells and Rust/C++ reference captures require `CaptureSource::Location` without pretending that a local binding is a field, static, or indexed location.

- Observation: capability discovery is only trustworthy if artifact construction rejects exact rows for unsupported features and rejects an unsupported gap for a feature advertised as complete.
  Evidence: treating the total capability table as advisory allowed internally contradictory artifacts even though proof/precision uncertainty already has separate gap and evidence dimensions.

- Observation: an optional call continuation cannot distinguish a semantically absent arm from an unknown, unsupported, unproven, or budget-exhausted arm.
  Evidence: review found that `Option<ProgramPointId>` would force adapters either to erase the reason or fabricate an edge; `ControlContinuation` now carries the exact state and validation requires matching gap/evidence rows.

- Observation: declared callable candidates and resolved runtime targets are different facts, and a same-artifact nested target can be known before its body is present in a partial materialization.
  Evidence: the reviewed contract separates `declared_targets` from target-resolution evidence and provides `CallableTarget::Unmaterialized(SemanticLocator)` only for an unpublished direct lexical child.

- Observation: limiting only top-level semantic rows does not bound retained payload or rendering work.
  Evidence: nested candidates, evidence, strings, events, and edge payload can dominate an artifact; construction now charges all retained payload atomically and rendering streams transactionally under an output budget.

- Observation: forward checks on continuation and gap rows are insufficient because unrelated extra edges and reverse contradictions can still make the graph lie.
  Evidence: the final audits added exact outgoing-topology ownership for invoke/suspend events and reverse validation from each gap/evidence row back to its precise subject.

## Decision Log

- Decision: one `SemanticArtifactKey` identifies one mounted source snapshot, normally one file, and `SemanticArtifact` owns every procedure extracted from it.
  Rationale: adapters already parse and normalize files as units; file-level artifacts make nested procedure identity exhaustive, avoid reparsing per callable, preserve mounted-path semantics, and give `ProcedureId` a real artifact-local scope.
  Date: 2026-07-16.

- Decision: `ProcedureId` is artifact-local. `BlockId`, `ProgramPointId`, `ValueId`, `AllocationId`, `CallSiteId`, `MemoryLocationId`, `CaptureId`, `SourceMappingId`, `EvidenceId`, and `SemanticGapId` are procedure-local. Raw dense IDs never cross provider boundaries without their owning artifact/procedure handle.
  Rationale: hot immutable rows remain compact `u32` values, while queries, oracles, storage, and solver setup cannot accidentally interpret an ID from a different artifact or procedure.
  Date: 2026-07-16.

- Decision: every nested function, local function, closure, or lambda body is a separate `ProcedureSemantics` row with an optional lexical parent; lexical nesting creates no control-flow edge into that child.
  Rationale: a callable body executes only when invoked. Treating its syntax as part of the outer CFG would fabricate reachability and misattribute calls.
  Date: 2026-07-16.

- Decision: callable creation/reference, capture binding, and invocation are distinct semantic events.
  Rationale: a lambda evaluation creates a callable/environment value, and a method reference may bind a receiver, but neither executes a target. Only an invocation owns a `CallSiteId` and can later produce ICFG edges.
  Date: 2026-07-16.

- Decision: capture sources are either values or abstract memory locations, and capture modes distinguish value snapshots/moves from shared or mutable cells and receiver capture.
  Rationale: hidden actual parameters alone cannot preserve mutation between closure creation and invocation, multiple environments for one body, closure escape, Java value capture, JavaScript lexical cells, or Rust/C++ reference and move modes.
  Date: 2026-07-16.

- Decision: semantic source positions use checked `u32` half-open byte spans as authoritative coordinates and carry explicit zero-based line and UTF-8-byte-column positions for display. They do not reuse `analyzer::Range` as durable identity.
  Rationale: bytes are unambiguous for tree-sitter and storage, fixed-width integers are portable, columns are required for exact anchors, and one explicit base avoids current line-number drift.
  Date: 2026-07-16.

- Decision: capture bindings are creator-local rows whose `(target, destination)` pair scopes the destination into the child procedure. Child-local capture slots name their lexical parent but do not back-reference one creation row.
  Rationale: one static body slot may be populated by several static callable-creation sites and by many runtime environment instances. The relation is many bindings to one child slot, not one outer binding to one globally reusable local ID.
  Date: 2026-07-16.

- Decision: represent promoted lexical storage explicitly as `LexicalCell` and keep it distinct from field, static, index, and child capture-slot memory.
  Rationale: location-backed captures need a principled abstract address for a local or parameter cell; encoding it as an indexed access or a language-defined string would hide the exact semantic distinction the neutral contract is meant to preserve.
  Date: 2026-07-16.

- Decision: validate artifact rows/events against the total capability table while keeping support independent from proof and precision.
  Rationale: unsupported features cannot emit exact-looking facts, but a completely supported feature may still produce ambiguity, unknown targets, unproven evidence, or budget exhaustion when the program itself or the bounded analysis prevents a unique answer.
  Date: 2026-07-16.

- Decision: #814 defines validated plain immutable topology and side-table contracts but does not choose CSR, CSC, persistence, adapter extraction, or ICFG topology.
  Rationale: #815 must measure concrete CFG construction and traversal before freezing a representation; #817 owns persistence promotion; #818 owns interprocedural edges.
  Date: 2026-07-16.

- Decision: represent every normal, exceptional, resume, and cancellation arm with `ControlContinuation::{Target, Absent, Unknown, Unsupported, Unproven, ExceededBudget}` and require exact per-arm and total outgoing topology.
  Rationale: the IR must preserve why control is unavailable without inventing reachability, and an invoke or suspend event must own all and only the edges its target arms declare.
  Date: 2026-07-16.

- Decision: keep provider operation failure outside semantic uncertainty as `Result<SemanticOutcome<T>, SemanticProviderError>`.
  Rationale: invalid input, I/O, and artifact-validation failure are not ambiguous program meaning and must not be cached or rendered as semantic partial results.
  Date: 2026-07-16.

- Decision: require exact subject-scoped gap/evidence correlations, structured work accounting for every retained payload, indexed linear validation, and transactional bounded rendering.
  Rationale: incomplete artifacts remain honest and resource limits remain enforceable even for adversarial nested payloads, without quadratic validation or partially emitted records.
  Date: 2026-07-16.

- Decision: compare procedure handles by artifact materialization identity as well as artifact key and local ID, and use the shared `LanguageDialect` plus portable workspace-relative paths.
  Rationale: distinct partial materializations of one key must not alias, and semantic/Rune identities must agree across platforms and TypeScript dialects.
  Date: 2026-07-16.

## Outcomes & Retrospective

Issue #814 is implemented in checkpoint `296c1de1`, with guided-review fixes in `1faf8b9b`. The public `analyzer::semantic` module now exposes durable artifact and locator identities, scoped dense IDs and handles, total capability declarations, typed semantic outcomes and operational errors, finite work budgets, immutable artifact/procedure/event topology, construction-time validation, and a deterministic bounded renderer. The file-level artifact with artifact-local procedures and procedure-local rows remained sufficient; no graph storage or persistence representation was frozen prematurely.

The TypeScript and Java fixtures deliberately construct equivalent neutral artifacts rather than claiming real language adapters. They prove the contract for straight-line flow, calls, nested callable bodies, value/cell/receiver captures, bound and unbound method references, partial targets, uncertainty, and rendering. #815 owns real adapter extraction and callable CFG construction; #816 owns dispatch/value/heap refinement and target oracles; #818 owns matched interprocedural call/return edges; #817 may promote storage only after those artifact shapes are measured.

Validation completed with 59 focused semantic unit tests and 10 cross-language contract tests, the full `cargo test --features nlp,python` suite, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt -- --check`, and `git diff --check`. Specialist review and four final invariant audits covered API/identity, nested callables and captures, uncertainty/capabilities, budget/render safety, exact continuation topology, reverse gap contradictions, partial local targets, and invoke/suspend edge ownership.

## Context and Orientation

`src/analyzer/structural/spec.rs`, `extract.rs`, and `facts.rs` normalize grammar-specific syntax into `FileFacts`. That representation intentionally describes containment, kinds, roles, names, and source spans rather than execution semantics. It must remain separate.

`src/analyzer/structural/rune_ir.rs` is the renderer pattern: bounded input and output, deterministic order, explicit truncation, safe string escaping, and iterative traversal. The semantic renderer will inspect already-built artifacts and will not parse source or expose RQL syntax.

`src/analyzer/usages/call_relations.rs` supplies source-backed caller/callee evidence, receiver ranges, arguments, proof tiers, and lazy formal binding. #818 will adapt it. #814 describes call sites and callable values without adding a second resolver.

`src/analyzer/usages/receiver_analysis.rs` supplies the existing `Precise`, `Ambiguous`, `Unknown`, `Unsupported`, and `ExceededBudget` vocabulary. The new outcome keeps these distinctions, adds explicit unproven partial results, and keeps candidate ambiguity independent from proof and completeness.

`src/compact_graph.rs` provides reusable compact storage mechanics. No new semantic type should make it the owner of semantic identity, and this issue does not select a frozen adjacency representation.

A semantic artifact is one immutable interpretation of one mounted source snapshot. Its key includes every input that can change that interpretation. A procedure is one executable body within the artifact. A program point is one normalized execution event within a procedure. An abstract memory location represents a field, static slot, indexed slot, capture cell/environment, or later oracle-provided heap location without claiming one concrete runtime address.

## Plan of Work

### Milestone 1: identity, capabilities, outcomes, and providers

Create `src/analyzer/semantic/mod.rs`, `ids.rs`, `capabilities.rs`, and `provider.rs`, and expose the module through `src/analyzer/mod.rs`.

In `ids.rs`, define typed fixed-width digest/version identities, `WorkspaceMountId`, validated UTF-8 `WorkspaceRelativePath`, `SemanticLanguage` with a distinct TypeScript-TSX dialect, `SourceRevision` with an opaque overlay snapshot token, `SemanticArtifactKey`, `SemanticLocator`, declaration segments, source anchors, and every dense ID. The artifact key must include mount, relative path, language/dialect, content revision, adapter-semantics fingerprint, semantic-IR version, semantic-configuration fingerprint, and dependency fingerprint. Its deterministic fingerprint uses length-delimited SHA-256 input.

In `capabilities.rs`, define a total `SemanticCapability` vocabulary and `CapabilitySupport` values `Complete`, `Partial`, and `Unsupported`. Lookup never returns `Option`; undeclared features are unsupported. Cover boundaries, blocks/points, normal and exceptional control, cleanup, assignments, values, allocations, local/parameter/receiver/return flow, field/static/index memory, calls and continuations, captures, callable references, and async suspend/resume.

In `provider.rs`, define `SemanticOutcome<T>` with explicit complete, ambiguous, unknown, unsupported, unproven, and budget-exceeded variants; partial candidates/results and work accounting remain available where meaningful. Define positive finite semantic budgets. Define `ProgramSemanticsProvider` as a standalone trait returning an artifact key for a `ProjectFile` and an immutable `Arc<SemanticArtifact>` for that key. Do not add semantic methods to the monolithic `IAnalyzer` in this issue.

This milestone is accepted when focused unit tests prove key invalidation for every field, duplicate mounted blobs stay distinct, TS and TSX differ, invalid paths are rejected, capabilities are total, and every outcome preserves its typed state and partial data.

### Milestone 2: immutable semantic IR and validation

Create `src/analyzer/semantic/ir.rs`. Define `SemanticArtifact`, `ProcedureSemantics`, `ProcedureHandle`, and procedure-scoped handles used at provider/oracle boundaries. Hot rows store only their local newtypes.

`SemanticArtifact` stores the key once, total capabilities, and a dense procedure array. Each procedure records its durable locator, optional lexical parent, kind/properties, values, allocation sites, abstract memory locations, capture bindings, call sites, source mappings, proof/completeness evidence, semantic gaps, basic blocks, program points/events, and intraprocedural control edges. Construction validates dense ordering, all local references, one entry plus normal and exceptional exit points, source scope, block membership, call continuations, capture targets, callable targets, async pairs, parent bounds, and an acyclic lexical-parent forest using iterative traversal.

Effects cover entry, normal/exceptional exit, assignment, typed value flow, allocation, field/static/index/capture load and store, callable creation/reference, capture binding, invocation, normal/exceptional call continuation, procedure return, throw, and async suspend/resume. Missing semantics are `SemanticGap` rows and gap events; they are not guessed control edges. Intraprocedural edge kinds do not include call-to-entry or exit-to-return edges.

Nested callable construction produces a callable value referencing a separate procedure row. Repeated runtime evaluations reuse the body `ProcedureId` while their creation/allocation sites distinguish abstract environments. Method references target existing procedures or durable external locators, optionally bind a receiver, and do not create a call site until invoked.

This milestone is accepted when invalid cross-scope references are rejected and fixtures prove separate nested bodies, explicit value-versus-location captures, bound/unbound method references, and the absence of a call event for an uninvoked callable value.

### Milestone 3: bounded rendering and conformance fixtures

Create `src/analyzer/semantic/render.rs` and `tests/semantic_ir_contract.rs`. The renderer consumes a validated artifact, iterates procedures/tables in dense order, prints the artifact scope before local IDs, escapes all source-derived strings, includes relative source mappings, proof, completeness, gaps, and capabilities, and never prints absolute roots. Limits bound procedures, rows/events, source-related entries, and output bytes. Truncation remains explicit and balanced.

Use `tests/common/inline_project.rs::InlineTestProject` for TypeScript and Java source fixtures. These tests manually build the neutral artifacts; actual AST extraction belongs to #815. Equivalent straight-line/call/return effects must compare equal across languages after identity/source metadata is separated. Additional fixtures cover a nested lambda, a captured value/cell, a callable created but not invoked, a bound and unbound method reference, an ambiguous callable target, unsupported exceptional/async semantics as gaps, and a deep synthetic artifact proving stack-safe bounded rendering.

This milestone is accepted when rendering is deterministic, bounded, explicitly truncated, and source-backed; semantic event equality does not contain solver facts, protocol states, RQL fields, or language-specific AST names.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/22bb/bifrost` on the existing issue branch. Do not switch, create, or rebase branches.

After Milestone 1, run:

    cargo fmt
    cargo test analyzer::semantic

Expect all identity, capability, and provider unit tests to pass. Commit only the plan and semantic contract files changed in this milestone with a multiline checkpoint message explaining the identity scopes.

After Milestone 2, run:

    cargo fmt
    cargo test analyzer::semantic

Expect the IR invariant and nested-callable tests to pass. Commit only the files changed for the milestone with a multiline checkpoint message explaining the event/capture model.

After Milestone 3, run:

    cargo fmt
    cargo test --test semantic_ir_contract
    cargo test analyzer::semantic

Expect equivalent TypeScript/Java event assertions, key invalidation, nested callable/capture/method-reference behavior, and renderer limits to pass.

For the final local gate, use the repository-managed isolated target helper:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Expect both commands to finish successfully. `cargo fmt -- --check` and `git diff --check` must also pass. Run specialist review on the complete diff, fix every accepted finding, update this plan, and create a final post-review checkpoint commit. Do not push or open a pull request unless explicitly asked.

## Validation and Acceptance

The implementation is accepted only if all of the following behaviors are demonstrated:

- A mounted artifact key changes for content, overlay snapshot, adapter semantics, IR version, semantic configuration, dependency fingerprint, language dialect, mount, or path changes.
- Identical content mounted at different paths or workspace mounts never shares a mounted semantic identity.
- Bare dense IDs are documented and API-scoped; provider/oracle boundary handles retain their owning artifact and procedure.
- Every nested executable body is a separate procedure and no lexical control edge enters it.
- Closure/callable creation, captures, receiver binding, and invocation are distinct events.
- A method reference without invocation has no `CallSiteId` event.
- Capture sources distinguish copied/moved values from shared/mutable memory locations.
- Entry, normal exit, exceptional exit, call continuation, memory, capture, and async effect contracts are representable without language or solver fields.
- Unknown, unsupported, ambiguous, unproven, and budget-exhausted semantics remain distinguishable and no absent fact becomes an exact-looking edge.
- Source mappings use portable, byte-authoritative coordinates and the renderer emits no absolute paths.
- Equivalent TypeScript and Java fixtures have equivalent neutral effect sequences where their semantics agree.
- Rendering is deterministic, bounded, explicit about truncation, and stack-safe.

## Idempotence and Recovery

All code generation is manual through ordinary source edits; rerunning formatting and tests is safe. Constructors reject invalid artifacts before any cache or global state is changed. No migration or persistent format is introduced, so a failed milestone can be repaired by editing only the new semantic modules and tests.

Use only the current branch. Stage explicit file paths, never `git add -A`. If a test or review reveals that an identity or event cannot serve #815/#816/#818, update the Decision Log before changing the public contract. Do not hide the mismatch with a language-specific fallback or source-text mini parser.

## Artifacts and Notes

Primary repository context:

- GitHub issue #814 and parent epic #813.
- `.agents/plans/language-agnostic-composable-typestate-platform.md`.
- `src/analyzer/structural/{spec,extract,facts,rune_ir,provider}.rs`.
- `src/analyzer/usages/{call_relations,receiver_analysis}.rs`.
- `src/compact_graph.rs`.
- `src/analyzer/store/epoch.rs` and overlay/liveness code.
- `tests/common/inline_project.rs`.

External semantic checks used to resolve nested callables are the classic IFDS supergraph model, Java lambda evaluation and method-reference evaluation rules, and Rust closure capture documentation. The required knowledge is embedded above: callable bodies are procedures; callable creation and invocation are distinct; bound receivers are evaluated at reference creation; capture environments carry values or locations.

## Interfaces and Dependencies

The implementation uses existing `sha2`, `serde` only where an existing public type already requires it, `std::sync::Arc` for immutable artifact handles, and repository-local hash collections. It adds no graph, solver, parser, or persistence dependency.

The provider boundary must have this shape, allowing naming refinements that preserve the same scopes:

    pub trait ProgramSemanticsProvider: Send + Sync {
        fn language(&self) -> SemanticLanguage;
        fn capabilities(&self) -> &SemanticCapabilities;
        fn artifact_key(
            &self,
            file: &ProjectFile,
            budget: &mut SemanticBudget,
        ) -> Result<SemanticOutcome<SemanticArtifactKey>, SemanticProviderError>;
        fn artifact(
            &self,
            key: &SemanticArtifactKey,
            budget: &mut SemanticBudget,
        ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>;
    }

`SemanticArtifact::procedure_handle` returns a `ProcedureHandle` that owns an `Arc<SemanticArtifact>` plus `ProcedureId`. Procedure-scoped value, point, call, and location handles add their raw local ID without copying the artifact key into hot IR rows.

Later oracle boundaries must therefore accept a `&ProcedureHandle` plus a local ID, or an equivalent scoped handle:

    fn locations(
        &self,
        procedure: &ProcedureHandle,
        value: ValueId,
        max_access_path: usize,
        budget: &mut SemanticBudget,
    ) -> SemanticOutcome<AbstractLocations>;

The artifact key, locator, and renderer use stable relative paths and digests; `ProjectFile`, `CodeUnit`, FQN, `Range`, and a bare dense ID are never sufficient durable semantic identity by themselves.

Plan revision note (2026-07-16): Initial issue plan written after live issue/roadmap review and parallel diagnosis of source, call, receiver, identity, storage, nested-callable, capture, and method-reference seams. It corrects the broader roadmap's procedure-shaped artifact sketch to a mounted source artifact with explicitly scoped dense IDs.

Plan revision note (2026-07-16): Closed the implementation milestone at checkpoint `648a9fec` after specialist review and final invariant audits. Review replaced optional continuations with typed states, made invoke/suspend topology exact, correlated gaps and proof evidence in both directions, constrained unmaterialized local targets, separated provider failures from semantic uncertainty, bounded all retained payload and streamed rendering, and scoped handles to materializations. Validation passed 59 focused semantic tests, 10 contract tests, the complete `nlp,python` suite, all-target/all-feature clippy with warnings denied, formatting, and diff checks.

Plan revision note (2026-07-16): After rebasing onto current `master`, guided review fixed four additional findings in `1faf8b9b`: normal/exceptional call and async arms may converge on one edge-typed join point; known callable creation survives unknown, unsupported, or pre-locator budget exhaustion; semantic and Rune IR share one transactional balanced writer; and semantic registries share one identifier-count macro. The corrected complete `nlp,python` suite and all-feature clippy passed.
