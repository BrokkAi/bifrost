# Expose procedure-local CFGs through typed CodeQuery and RQL

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It is the first independently useful slice of GitHub issue #824, “Expose CFG, data-flow, and typestate through typed CodeQuery/RQL.” It does not claim to complete #824. Later slices will add value-flow, taint, typestate, policy compilers, and witnesses after their owning analysis services exist.

## Purpose / Big Picture

After this change, a caller can start with an ordinary structural CodeQuery match, resolve the source-backed executable procedure that contains it, and inspect that procedure's entry, exits, and explicit control-flow edges through typed JSON or RQL. The response contains stable content-scoped IDs, workspace-relative paths, source ranges, control-flow kinds, evidence proof, completeness, and ordinary CodeQuery provenance. Callers never see the semantic IR's dense arena IDs.

For example, schema version 3 will accept this JSON pipeline:

    {
      "schema_version": 3,
      "languages": ["typescript"],
      "match": {"kind": "function", "name": "run"},
      "steps": [
        {"op": "procedure_of"},
        {"op": "cfg_entry"},
        {"op": "cfg_successor_edges"},
        {"op": "cfg_edge_target"}
      ]
    }

The corresponding RQL is:

    (cfg-edge-target
      (cfg-successor-edges
        (cfg-entry
          (procedure-of
            (language typescript
              (function :name "run"))))))

The terminal rows are typed `program_point` values. Their provenance contains a `procedure` step, the entry `program_point`, the traversed `control_edge`, and the target `program_point`. A separate `cfg-exits` query returns normal and exceptional exit points. Replacing `cfg_successor_edges` with `cfg_predecessor_edges` traverses the reverse edge index. Each edge operation is exactly one hop; the existing maximum query-step count and row budget keep composed traversals finite.

This slice is valuable on its own for CFG inspection, editor navigation, debugging language lowerers, and building later data-flow operators on an already tested public algebra.

## Progress

- [x] (2026-07-25 08:17Z) Inspected issue #824, its live dependencies, the existing umbrella plan, and the current CodeQuery, semantic artifact, policy, Python, LSP, and VS Code boundaries.
- [x] (2026-07-25 08:17Z) Chose the initial typed domains and exact one-hop CFG algebra described in this plan.
- [x] (2026-07-25 08:31Z) User approved implementation and requested checkpoint commits between milestones plus frequent synchronization with `origin/master`.
- [ ] Add schema-versioned query kinds and operations with parser, decoder, validator, canonical JSON, and RQL tooling coverage.
- [ ] Add source-backed public result types and deterministic wire identities without exposing dense semantic IR IDs.
- [ ] Implement the request-scoped CFG query adapter, semantic budgets, capability diagnostics, cancellation, and provenance.
- [ ] Integrate planning/explain/profile reporting and all Rust result rendering/evidence paths.
- [ ] Update the Python client, LSP/VS Code client, TextMate grammar, public docs, and executable examples.
- [ ] Run focused tests, formatting, clippy with all features, and the full `nlp,python` test gate; record results here.

## Surprises & Discoveries

- Observation: The semantic layer already exposes all procedure-local data needed by this slice. `WorkspaceAnalyzer::materialize_program_semantics` returns an immutable `SemanticArtifact`; each `ProcedureSemantics` exposes entry and exit point IDs plus indexed successor and predecessor control edges.
  Evidence: `src/analyzer/workspace.rs` contains `materialize_program_semantics`; `src/analyzer/semantic/ir/artifact.rs` contains `procedures`, `successor_edges`, `predecessor_edges`, `entry_point`, `normal_exit_point`, and `exceptional_exit_point`.

- Observation: Semantic IR IDs are deliberately dense and scoped to one artifact instance. They are safe internal handles but are not suitable wire identities.
  Evidence: `src/analyzer/semantic/ids.rs` defines dense `ProcedureId`, `ProgramPointId`, and `ControlEdgeId`; `SemanticArtifactKey::fingerprint` already provides a deterministic digest over the complete artifact validity identity.

- Observation: The older umbrella plan represented a traversed control edge only as provenance while the live issue explicitly requires `control_edge` as a value kind.
  Evidence: `.agents/plans/language-agnostic-composable-typestate-platform.md` specifies `cfg_successors` and `cfg_predecessors` as point-to-point operations, while issue #824 lists control edges among the explicit public value kinds.

- Observation: The normal workspace query path already carries an optional `WorkspaceAnalyzer` into pipeline execution, so the adapter can consume semantic services without moving solver logic into `CodeQuery`.
  Evidence: `src/analyzer/structural/search/mod.rs` passes the workspace through workspace request execution and currently uses the same seam for receiver analysis.

- Observation: Direct analyzer-only execution entry points do not have a workspace semantic provider.
  Evidence: `execute_request` and its analyzer-only variants accept `IAnalyzer`; semantic materialization is exposed by `WorkspaceAnalyzer`.

- Observation: CodeQuery's public schema version is currently 2, and policy fixtures deliberately pin version 2. Removing version 2 would cause unrelated policy identity churn.
  Evidence: `src/analyzer/structural/query/ir.rs` declares `SCHEMA_VERSION = 2`; checked `.rqlp` and normalized policy fixtures contain explicit version-2 selectors.

## Decision Log

- Decision: The first #824 slice exposes `procedure`, `program_point`, and `control_edge`, but not placeholder data-flow, taint, typestate, finding, or witness kinds.
  Rationale: Procedure-local CFG services are implemented and independently useful. Issues #822 and #823 remain open, so advertising their result domains now would either create dead API or pressure CodeQuery to fabricate analysis behavior.
  Date/Author: 2026-07-25 / Codex

- Decision: Control edges are first-class results. The initial operations are `procedure_of`, `cfg_entry`, `cfg_exits`, `cfg_successor_edges`, `cfg_predecessor_edges`, `cfg_edge_source`, and `cfg_edge_target`.
  Rationale: This satisfies the live issue's explicit `control_edge` domain and forms a small composable algebra. Point-to-point traversal is still expressible by composing an edge-producing operation with `cfg_edge_source` or `cfg_edge_target`. It also lets callers inspect conditional, exceptional, cleanup, loop-back, and async edge kinds directly.
  Date/Author: 2026-07-25 / Codex

- Decision: `cfg_successor_edges` and `cfg_predecessor_edges` are one-hop operations with no depth parameter.
  Rationale: One-hop operations have honest edge provenance and remain finite under the existing `MAX_QUERY_STEPS` and `max_pipeline_rows`. A future convenience traversal can lower a positive finite depth into repeated edge/endpoint operations without changing the foundational algebra.
  Date/Author: 2026-07-25 / Codex

- Decision: `procedure_of` accepts `structural_match` and `declaration`; `cfg_entry` and `cfg_exits` accept `procedure`; successor/predecessor edge operations accept `program_point`; edge source/target accept `control_edge`. `file_of` is extended to accept all three new source-backed domains.
  Rationale: These transitions provide one clear route into CFG data, preserve static validation, and let existing file-oriented compositions consume the new results.
  Date/Author: 2026-07-25 / Codex

- Decision: Schema version 3 introduces the new vocabulary. Version 2 remains an exact supported pin and rejects version-3-only operations at the precise operation range. Omitted versions resolve to compatible head version 3.
  Rationale: The new typed domains are a meaningful public schema expansion. Retaining version 2 avoids rewriting #709 policy fixtures and preserves their canonical identities, while explicit version gating prevents new syntax from silently changing the meaning of a version-2 document.
  Date/Author: 2026-07-25 / Codex

- Decision: Wire IDs are lowercase hexadecimal, domain-separated SHA-256 digests. A procedure ID hashes the artifact fingerprint and canonical `SemanticLocator`. A point or edge ID hashes the artifact fingerprint, owning procedure locator, domain tag, and the deterministic local ID. Every result also includes its source mapping and owning procedure ID.
  Rationale: This makes identities deterministic for one exact semantic artifact without serializing mount IDs, arena indexes, or artifact-instance pointers. The accompanying path/range/procedure relationship satisfies the issue's requirement that IDs remain source- and provenance-backed. IDs intentionally change when source, adapter semantics, configuration, or dependencies change.
  Date/Author: 2026-07-25 / Codex

- Decision: Semantic proof and completeness are diagnostic-neutral result metadata. They are represented by query-owned enums/records derived from semantic `Evidence`; they do not reuse `PolicyFinding` or attach policy severity, classification, CWE, CVSS, or messages.
  Rationale: Issue #709 owns the public diagnostic envelope. CFG inspection is analysis evidence, not a diagnostic.
  Date/Author: 2026-07-25 / Codex

- Decision: Semantic work receives a separate typed sub-budget within `CodeQueryExecutionLimits`, rather than being hidden inside the structural scan or pipeline-row counters.
  Rationale: Materializing one artifact can retain many semantic rows even when a query emits one result. A separate positive finite file/source/row budget makes that cost visible, testable, and reusable by future #824 domains.
  Date/Author: 2026-07-25 / Codex

- Decision: The workspace query APIs execute CFG operations. Analyzer-only APIs return an explicit incomplete `semantic_workspace_required` diagnostic for CFG steps instead of silently returning no rows.
  Rationale: The semantic provider belongs to `WorkspaceAnalyzer`. An explicit incomplete result preserves existing APIs without manufacturing a second provider path or allowing an empty result to masquerade as a complete negative.
  Date/Author: 2026-07-25 / Codex

- Decision: Commit after every independently verified milestone, refresh `origin/master` before the next milestone, and run the guided-review specialist workflow after the core Rust execution slice and again before final handoff when the later client/documentation diff materially changes the review surface.
  Rationale: The user explicitly requested frequent synchronization and reviewable checkpoint history. Reviewing after the core execution slice catches API and architecture mistakes before they spread across clients, while a final branch review covers integration drift.
  Date/Author: 2026-07-25 / User and Codex

## Outcomes & Retrospective

No implementation milestones are complete yet. The design phase established a narrow public contract that exercises real semantic services while leaving value flow, taint, typestate, policy compilation, and witnesses for later #824 plans. Update this section after each milestone with what worked, what changed, and what remains.

## Context and Orientation

CodeQuery is Bifrost's typed structural query language. JSON queries decode into `CodeQuery` and `QueryStep` in `src/analyzer/structural/query/`. RQL is the S-expression frontend in the same module. Both frontends share declarative operation and form registries in `src/analyzer/structural/query/schema.rs`. Static path validation uses `QueryValueKind` and `QueryStep::output_kind` in `src/analyzer/structural/query/ir.rs`.

The query executor is in `src/analyzer/structural/search/`. It carries intermediate rows as the private `PipelineValue` enum, deduplicates them with `PipelineKey`, advances provenance with `PipelineTraceValue`, and renders public tagged `CodeQueryResultValue` rows declared in `src/analyzer/structural/search/results.rs`. A “domain” in this plan means one `QueryValueKind` and its matching private and public result variants. A “program point” is one location in a procedure's control-flow graph where semantic events occur. A “control edge” is a directed relation between two program points, such as normal fallthrough, a true conditional branch, an exceptional transfer, or cleanup.

The semantic intermediate representation is in `src/analyzer/semantic/`. `SemanticArtifact` is one immutable, source-revision-specific artifact for one file. It owns `ProcedureSemantics` rows. Each procedure owns its points, edges, source mappings, evidence, and immutable control-flow indexes. `WorkspaceAnalyzer::materialize_program_semantics`, in `src/analyzer/workspace.rs`, is the public file-aware materialization seam. CodeQuery must consume this service and must not recreate CFG construction or become a data-flow solver.

`SemanticLocator` identifies source-backed semantic rows. `Evidence` contains `ProofStatus` and `EvidenceCompleteness`. “Proof” says whether the retained evidence establishes a fact. “Completeness” says whether the evidence covers all relevant semantics at that site. An unsupported or partial language capability must remain visible; absence of a row is not permission to infer that no row exists.

The normal transports all consume the canonical Rust result model. `src/lsp/server.rs` adds URI data for editor navigation. `bifrost_searchtools/models.py` supplies Python data classes and parsing. `editors/vscode/src/rql_query.ts` defines the TypeScript result union and list/tree presentation. The RQL TextMate grammar is `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`. Public documentation lives under `docs/src/content/docs/`.

Issue #709 already owns public policy loading and `PolicyFinding`. Its typestate projection seam is `TypestatePolicyEvaluator` in `src/analyzer/policy/evaluator.rs`. This plan does not change that ownership. Later #824 plans will compile #709's resolved policy definitions into the diagnostic-neutral engines from #821 through #823, then project their findings back through #709.

## Plan of Work

### Milestone 1: Freeze the typed schema and static API

Change `src/analyzer/structural/query/ir.rs` so `SCHEMA_VERSION` is 3 and `QueryValueKind` gains `Procedure`, `ProgramPoint`, and `ControlEdge`. Add the seven no-option `QueryStep` variants named in the Decision Log. Extend `QueryStep::op`, `from_label`, `output_kind`, expected-input diagnostics, canonical serialization, and every exhaustive match. Extend `FileOf` to accept the new domains. Set operations need no special implementation beyond ensuring their existing endpoint-kind validation recognizes the new enum variants.

Change the declarative registries in `src/analyzer/structural/query/schema.rs`. Each new JSON operation needs its label, value signature, description, and minimum schema version. Each RQL wrapper needs the kebab-case primary spelling and underscore alias:

    procedure-of / procedure_of
    cfg-entry / cfg_entry
    cfg-exits / cfg_exits
    cfg-successor-edges / cfg_successor_edges
    cfg-predecessor-edges / cfg_predecessor_edges
    cfg-edge-source / cfg_edge_source
    cfg-edge-target / cfg_edge_target

Extend the schema macros so version availability is declarative rather than maintained in a private list. Existing operations and forms are available since version 2; the seven new operations and forms are available since version 3. Register version 2 and compatible successor version 3 in `RQL_SCHEMA_VERSIONS`. JSON decoding and RQL lowering must reject a version-3-only operation under an explicit version-2 root at the operation's exact JSON path or RQL source range.

Update `src/analyzer/structural/query/decode.rs`, `json.rs`, `sexp.rs`, and their unit tests. Add behavior tests for JSON and RQL success, canonical round trips, hover/signature text, aliases, precise wrong-domain errors, precise version errors, `file_of` composition, and set plans whose branches end in the same new domain. Do not add a test that merely duplicates registry order.

This milestone is complete when typed queries parse and validate, but execution tests may still return the explicit not-yet-wired semantic diagnostic. Run:

    cargo test --lib analyzer::structural::query
    cargo test --test rql_diagnostics
    cargo test --test rql_tooling

Expect all selected tests to pass. Newly added tests must demonstrate that `cfg_entry` after a `declaration` fails at the exact step and that an explicit version-2 query cannot use `procedure_of`.

### Milestone 2: Define source-backed public result contracts

In `src/analyzer/structural/search/results.rs`, add public serializable types:

    pub struct CodeQueryProcedure {
        pub id: String,
        pub artifact_id: String,
        pub path: String,
        pub language: &'static str,
        pub procedure_kind: &'static str,
        pub range: CodeQueryRange,
        pub evidence: CodeQuerySemanticEvidence,
    }

    pub struct CodeQueryProgramPoint {
        pub id: String,
        pub procedure_id: String,
        pub path: String,
        pub language: &'static str,
        pub range: CodeQueryRange,
        pub boundary: Option<CodeQueryProgramPointBoundary>,
        pub event_count: usize,
        pub evidence: CodeQuerySemanticEvidence,
    }

    pub struct CodeQueryControlEdge {
        pub id: String,
        pub procedure_id: String,
        pub path: String,
        pub language: &'static str,
        pub range: CodeQueryRange,
        pub edge_kind: &'static str,
        pub source: CodeQueryProgramPointRef,
        pub target: CodeQueryProgramPointRef,
        pub evidence: CodeQuerySemanticEvidence,
    }

`CodeQueryProgramPointBoundary` is a snake-case enum with `Entry`, `NormalExit`, and `ExceptionalExit`. `CodeQueryProgramPointRef` is the compact, source-backed subset needed by edges: `id`, `procedure_id`, `path`, `range`, and optional `boundary`. `CodeQuerySemanticEvidence` contains typed proof and completeness values plus bounded reason strings. Use query-owned tagged or snake-case enums so callers do not parse prose to distinguish `proven` from `unproven` or `complete` from `partial`. Preserve the semantic evidence reason when one exists.

Add matching variants to `CodeQueryResultValue` and `CodeQueryResultRef`. Re-export all public types from `src/analyzer/structural/search/mod.rs` and `src/analyzer/structural/mod.rs`. Update text rendering so each row has a useful one-line label and the proof/completeness status is visible without inspecting JSON.

Do not serialize `ProcedureId`, `ProgramPointId`, `ControlEdgeId`, `WorkspaceMountId`, pointer identity, or raw `SemanticArtifactKey`. Put the domain-separated digest helpers beside the semantic query adapter, not in the general result model. Use `SemanticArtifactKey::fingerprint()` as the artifact component. Include `artifact_id` only on the owning procedure; descendants link through `procedure_id`.

Extend the private detailed evidence model in `results.rs` with the three domains. Their evidence file and byte span come from the semantic source mapping. Their stable owner is the query wire ID rather than an analyzer declaration guess. This lets result-detail, policy-safe evidence retention, and future finding identity code consume the rows without a string-search fallback.

This milestone is complete when hand-constructed new result values serialize, render, and retain detailed source evidence. Run:

    cargo test --lib analyzer::structural::search
    cargo test --test code_query_public_api

Expect tagged `result_type` values `procedure`, `program_point`, and `control_edge`, and expect compact provenance references to contain source-backed IDs and ranges.

### Milestone 3: Implement the request-scoped CFG query adapter

Create `src/analyzer/structural/search/semantic.rs`. Define a private `CfgQueryService<'a>` that borrows `WorkspaceAnalyzer`, the request cancellation token, diagnostics, limits, and profiling state. It owns a request-scoped cache from `ProjectFile` to the exact `SemanticOutcome<Arc<SemanticArtifact>>` or a normalized failure. Repeated branches and steps in one query must share the same artifact `Arc` and must not recharge materialization work.

Add a public nested limit type in `results.rs`:

    pub struct CodeQuerySemanticLimits {
        pub max_materialized_files: usize,
        pub max_source_bytes: usize,
        pub max_rows_per_dimension: usize,
    }

Add `semantic: CodeQuerySemanticLimits` to `CodeQueryExecutionLimits`. All values must be positive. Build one request-local `SemanticBudget` by setting its source and owned-text dimensions from `max_source_bytes` and every retained-row dimension from `max_rows_per_dimension`. Enforce `max_materialized_files` before calling the provider. Add a serializable `CodeQuerySemanticWork` to `CodeQueryExecutionWork` and to profile work, recording materialization attempts, unique materialized files, request-cache hits, source bytes, procedures, program points, control edges, and whether a semantic budget ended execution. Keep the full internal `SemanticWork` ledger authoritative even if the public summary reports only these relevant dimensions.

The service exposes operations that return existing `PipelineExpansion` values:

    procedure_of(PipelineValue) -> Vec<ProcedureHandle>
    cfg_entry(ProcedureHandle) -> ProgramPointHandle
    cfg_exits(ProcedureHandle) -> Vec<ProgramPointHandle>
    cfg_successor_edges(ProgramPointHandle) -> Vec<ControlEdgeHandle>
    cfg_predecessor_edges(ProgramPointHandle) -> Vec<ControlEdgeHandle>
    cfg_edge_source(ControlEdgeHandle) -> ProgramPointHandle
    cfg_edge_target(ControlEdgeHandle) -> ProgramPointHandle

The signatures above describe behavior, not necessarily standalone Rust functions. Keep handles inside private pipeline rows so artifact lifetime and scope remain correct. Add `Procedure`, `ProgramPoint`, and `ControlEdge` variants to `PipelineValue`, `PipelineKey`, `PipelineTraceValue`, terminal-source helpers, detailed evidence conversion, retained-memory accounting, and public rendering. Deduplicate by stable handle identity within the request. Never reconstruct an internal handle from a public digest.

For `procedure_of`, share or extract the structured source/range matching already implemented by `procedures_for_definition` in `src/analyzer/semantic/workspace_oracle/dispatch.rs`; do not copy it into a divergent second implementation. Add the parallel structural-match case using the structural fact's exact byte span and choose the unique smallest enclosing procedure locator. Exact declaration range matches win over containment. If there is no procedure, emit advisory `no_enclosing_procedure` and no row. If equally specific candidates remain, return deterministic candidates as unproven/partial and emit an incomplete ambiguity diagnostic rather than choosing by name.

For entry and exits, use the owning procedure's validated boundary IDs. Return normal then exceptional exit in that stable semantic order, deduplicating only if the IR ever proves the IDs equal. For edges, use `successor_edges` and `predecessor_edges`; never scan source or rebuild adjacency. Sort output by the semantic IR's deterministic edge ID before public-ID rendering. Resolve edge endpoints through the owning procedure handle.

Add diagnostic codes `SemanticWorkspaceRequired`, `NoEnclosingProcedure`, `SemanticCapabilityUnsupported`, `SemanticAnalysisPartial`, `SemanticBudgetExhausted`, and `SemanticProviderFailed` with stable snake-case labels. Use advisory impact only for the proven no-procedure case. Unsupported capability, ambiguity, partial provider outcomes, exhausted budget, and provider failure make completion incomplete. Reuse the existing cancellation diagnostic and cancellation completion. Partial artifacts may yield rows, but every affected row and the request completion must retain the partial reason.

Consult `SemanticCapabilities` before claiming completeness. `procedure_of` requires `Procedures`; entry and exits require their corresponding boundary and point capabilities; edge operations require program points plus the available control-flow capability for each retained edge kind. Unsupported exceptional or cleanup control flow must not suppress valid normal edges, but it must make a complete negative impossible. Never synthesize a missing edge.

Wire the service through `src/analyzer/structural/search/mod.rs` and, where it keeps the main module smaller, `expansions.rs`. Construct it only if the validated plan contains a semantic step. Explain mode must not construct it or materialize an artifact. Analyzer-only execution receives no service and emits `semantic_workspace_required` when it reaches a semantic step.

This milestone is complete when an inline TypeScript project can execute the example in Purpose / Big Picture and returns real target program points. Add behavior-focused tests to `tests/code_query_pipelines.rs` using `tests/common/inline_project.rs`. Include normal/conditional/exceptional edges, exits, reverse traversal, provenance, deterministic IDs across repeated requests, identity change after an overlay/source revision, set composition, `file_of`, missing procedure, analyzer-only execution, partial capabilities, tiny semantic budget, pipeline-row truncation, and cancellation.

Run:

    cargo test --test code_query_pipelines cfg_
    cargo test --test code_query_public_api
    cargo test --test semantic_provider_conformance

Expect real typed rows and explicit incomplete diagnostics for every non-complete path. A tiny semantic budget must never produce a complete empty result.

### Milestone 4: Make planning, profiling, and all result paths honest

In `src/analyzer/structural/execution/plan.rs`, annotate step nodes with the semantic facets they demand. Add a public serializable `CodeQuerySemanticRequest` with booleans or a stable list for `procedures`, `program_points`, and `control_edges`, and include it on `CodeQueryPhysicalNode` only when non-empty. `procedure_of` requests procedures; boundaries request procedures and points; edge traversal requests procedures, points, and control edges. Explain mode must display this request without execution.

In `src/analyzer/structural/execution/profile.rs`, publish the semantic work summary from Milestone 3. Attribute materialization and expansion time to the existing physical pipeline-step operator rather than pretending there is an independent solver operator. Record request-cache reuse. Ensure operator termination reports budget or cancellation consistently with the final typed diagnostics.

Audit every exhaustive result path in `src/analyzer/structural/search/results.rs`, `src/analyzer/structural/search/mod.rs`, `src/analyzer/policy/evaluator.rs`, and `src/lsp/server.rs`. The policy evaluator must treat the three new domains as diagnostic-neutral non-policy terminals unless a later analysis compiler explicitly requests them. It must not infer a policy finding from a control edge.

Add tests proving that explain mode reports demanded facets and performs no semantic materialization, while profile mode reports nonzero semantic work for the executed CFG query. Also prove compact and full result detail modes preserve usable source-backed terminal and provenance references.

Run:

    cargo test --test structural_search_planner
    cargo test --test code_query_pipelines explain
    cargo test --test code_query_pipelines profile
    cargo test --test policy_match_evaluation

Expect explain to remain planning-only and profile work to reconcile with the executed result.

### Milestone 5: Update clients, editor tooling, and documentation

In `bifrost_searchtools/models.py`, add frozen data classes for procedure, program point, point reference, control edge, semantic evidence, and provenance references. Extend `CodeQueryResultItem`, parsing, and text rendering exhaustively. Add Python tests that parse representative canonical Rust JSON for all three domains and reject malformed required fields.

In `editors/vscode/src/rql_query.ts`, extend `RqlQueryResultItem` and the label, description, tooltip, grouping, and navigation switches. Procedure rows navigate to their range. Program points navigate to their source mapping. Control edges navigate to the edge source mapping and show both endpoint IDs/ranges in the tooltip. Add tests in `editors/vscode/test/rql-query.test.ts`.

Update `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json` conservatively with the seven kebab-case forms and underscore aliases, and update `editors/vscode/test/rql-grammar.test.ts` and `rql-validation.test.ts`. Ordinary JSON must remain outside the RQL grammar unless the host identifies it as `bifrost-rql`.

Update `docs/src/content/docs/code-query-json.md`, `code-querying.md`, and `rune-query-language.md` with schema version 3, the exact typed signatures, one JSON example, one equivalent RQL example, result shapes, proof/completeness behavior, budget behavior, and the fact that this slice is procedure-local CFG rather than ICFG or data flow. Keep explicit version-2 policy examples unchanged where they intentionally pin the older query surface. Update executable doc tests in `tests/code_query_docs.rs` and `tests/code_query_tutorials.rs`.

Run:

    python -m unittest discover -s bifrost_searchtools/tests
    npm --prefix editors/vscode test
    cargo test --test code_query_docs
    cargo test --test code_query_tutorials

Expect client unions to be exhaustive, editor navigation to use the new ranges, grammar tests to recognize only RQL documents, and every published example to parse and execute.

### Milestone 6: Reconcile the roadmap and run release-quality validation

Update Milestone 7 and the Decision Log in `.agents/plans/language-agnostic-composable-typestate-platform.md` so the umbrella plan names the explicit edge algebra from this implemented slice. Preserve the future convenience meaning of `cfg_successors` and `cfg_predecessors` by describing them as optional bounded lowering over `cfg_successor_edges`/`cfg_predecessor_edges` plus endpoint projection. Do not mark #824 complete.

Run formatting and CI-equivalent checks from the repository root:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Tests must not download an NLP model or start semantic-index threads. Existing constructors and environment controls must remain in use. Expect formatting to make no further changes, clippy to finish with no warnings, and the full feature-enabled test suite to pass. Record exact command outcomes and any platform-specific exclusions in `Progress`, `Surprises & Discoveries`, and `Artifacts and Notes`.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/63a0/bifrost` on the already checked-out issue branch. Do not create or switch branches. Before each milestone, run:

    git status --short --branch
    git diff --check

Preserve unrelated user changes. During implementation, edit only the files named by the current milestone and any exhaustive compiler-directed call sites. Use `cargo fmt`, not manual formatting. Use `InlineTestProject` for the small CFG test programs.

After Milestone 1, demonstrate static typing with one accepted version-3 query and one rejected path:

    accepted: structural_match -> procedure -> program_point -> control_edge -> program_point
    rejected at steps[1]: procedure -> cfg_successor_edges

After Milestone 3, run the JSON example from Purpose / Big Picture through the same workspace request API used by MCP/LSP tests. A representative terminal row should have this shape, with real IDs and ranges substituted:

    {
      "result_type": "program_point",
      "id": "<64 lowercase hex characters>",
      "procedure_id": "<64 lowercase hex characters>",
      "path": "src/app.ts",
      "language": "typescript",
      "range": {
        "start_line": 2,
        "start_column": 3,
        "end_line": 2,
        "end_column": 14
      },
      "boundary": null,
      "event_count": 1,
      "evidence": {
        "proof": "proven",
        "completeness": "complete"
      },
      "provenance": [
        {
          "seed": {"result_type": "structural_match", "...": "..."},
          "steps": [
            {"op": "procedure_of", "result": {"result_type": "procedure", "...": "..."}},
            {"op": "cfg_entry", "result": {"result_type": "program_point", "...": "..."}},
            {"op": "cfg_successor_edges", "result": {"result_type": "control_edge", "...": "..."}},
            {"op": "cfg_edge_target", "result": {"result_type": "program_point", "...": "..."}}
          ]
        }
      ]
    }

The exact source range depends on the inline fixture. Tests should compare explicit expected ranges from that fixture, not use placeholders.

After every milestone, update this ExecPlan's progress and discoveries. If implementation changes a public name or shape, update the Decision Log, all examples, interfaces, and the revision note at the bottom in the same change.

## Validation and Acceptance

The initial #824 slice is accepted when all of the following are observable:

1. Version-3 JSON and RQL both parse the seven new operations into the same canonical `CodeQuery` plan. Version-2 documents reject those operations at the exact authored location while existing pinned version-2 policies still load unchanged.
2. Static validation accepts only the domain transitions in the Decision Log. Set operations accept compatible procedure, point, or edge branches and reject mixed endpoint kinds before execution.
3. A real workspace query over an inline supported-language function returns source-backed procedures, entry/exit points, and explicit control edges from `SemanticArtifact`. No result exposes a dense IR ID.
4. Repeating a query against the same artifact yields the same public IDs and deterministic ordering. Changing the source snapshot changes affected IDs. Every ID is accompanied by a workspace-relative path, range, and owning relationship.
5. Successor and predecessor edge queries agree: projecting a successor edge's target and querying that target's predecessor edges includes the original edge. Conditional and exceptional edge kinds survive serialization.
6. Proven/complete evidence remains distinct from unproven/partial evidence. Unsupported capabilities, ambiguity, provider failure, budget exhaustion, and cancellation cannot produce a falsely complete negative result.
7. Semantic work is lazy: a structural-only query and explain mode do not materialize semantic artifacts. A CFG query materializes only files reached by its pipeline rows, shares artifacts within the request, and stops at its separate finite semantic budget.
8. MCP/LSP JSON, Python models, VS Code result presentation/navigation, RQL hover/completion/validation, TextMate grammar, text rendering, and public docs agree on the same tagged result shapes and operation names.
9. The focused Rust tests, Python tests, VS Code tests, docs tests, `cargo fmt`, all-feature clippy, and the full `cargo test --features nlp,python` gate pass.
10. The umbrella plan records that explicit edge operations are the implemented foundation, and issue #824 remains open for flow endpoints, data-flow, taint, typestate, policy compilers, findings, and witnesses.

## Idempotence and Recovery

All implementation steps are source edits and repeatable test commands. Semantic materialization and query caches are request-scoped or existing workspace caches; tests must use temporary inline projects and must not leave `.brokk/bifrost_cache.db` in the repository. If a test creates that cache, remove only the generated untracked `.brokk` directory after verifying it contains no user-authored files.

If schema work partially lands, keep version 2 registered until version-3 parser, validator, canonical JSON, RQL, docs, and tooling tests all agree. Do not temporarily make version-3 operations available under version 2.

If semantic materialization fails after charging a staged budget, preserve the provider's atomic budget semantics and return an explicit incomplete diagnostic. Do not retry with a larger hidden budget, fall back to text search, or convert the failure into an empty complete result.

If public identity tests reveal nondeterministic local IDs for an unchanged artifact, stop and fix deterministic semantic lowering or derive a stronger locator/event key. Do not sort by rendered JSON as a workaround and do not publish raw source text as identity.

Use `scripts/with-isolated-cargo-target.sh` for isolated clippy and full-test targets. The helper removes its managed target on success, failure, or interruption. Do not create manually named Cargo target directories under `/tmp` or `/private/tmp`.

## Artifacts and Notes

The key architectural boundary is:

    CodeQuery seed and typed steps
        -> request-scoped CfgQueryService
        -> WorkspaceAnalyzer::materialize_program_semantics
        -> immutable SemanticArtifact / ProcedureSemantics
        -> source-backed typed query rows and provenance

CodeQuery does not construct CFGs, resolve calls, run data-flow, compile a policy, or classify a finding in this slice.

The explicit edge algebra is:

    structural_match | declaration
        --procedure_of--> procedure
        --cfg_entry | cfg_exits--> program_point
        --cfg_successor_edges | cfg_predecessor_edges--> control_edge
        --cfg_edge_source | cfg_edge_target--> program_point

`file_of` maps any of the three new domains back to `file`.

The remaining #824 roadmap starts after this plan:

    value / flow_endpoint + flows_to / flows_from
        -> taint_finding + typestate_finding
        -> bounded typed witnesses
        -> TaintPolicyCompiler / TypestatePolicyCompiler
        -> #709 PolicyFinding projection

Do not collapse those later stages into this CFG slice unless their owning service contracts have landed and this ExecPlan is deliberately revised.

## Interfaces and Dependencies

At the end of this plan, `src/analyzer/structural/query/ir.rs` must publicly expose these variants:

    pub enum QueryValueKind {
        // existing variants...
        Procedure,
        ProgramPoint,
        ControlEdge,
    }

    pub enum QueryStep {
        // existing variants...
        ProcedureOf,
        CfgEntry,
        CfgExits,
        CfgSuccessorEdges,
        CfgPredecessorEdges,
        CfgEdgeSource,
        CfgEdgeTarget,
    }

`src/analyzer/structural/search/results.rs` must expose and re-export `CodeQueryProcedure`, `CodeQueryProgramPoint`, `CodeQueryProgramPointBoundary`, `CodeQueryProgramPointRef`, `CodeQueryControlEdge`, `CodeQuerySemanticEvidence`, `CodeQuerySemanticLimits`, and `CodeQuerySemanticWork`, with the wire fields described in Milestones 2 and 3.

The private pipeline must retain semantic handles, not public DTOs:

    PipelineValue::Procedure(ProcedureHandle)
    PipelineValue::ProgramPoint(ProgramPointHandle)
    PipelineValue::ControlEdge(ControlEdgeHandle)

The implementation depends only on existing repository services and libraries:

- `WorkspaceAnalyzer::materialize_program_semantics` for file-aware semantic artifacts.
- `SemanticArtifact`, `ProcedureHandle`, `ProgramPointHandle`, and `ControlEdgeHandle` for correctly scoped immutable rows.
- `SemanticCapabilities`, `SemanticOutcome`, `SemanticBudget`, `SemanticWork`, and `CancellationToken` for honest availability, uncertainty, work, and cancellation.
- `SemanticArtifactKey::fingerprint`, `SemanticLocator`, and SHA-256 helpers already used by semantic identity code for deterministic content-scoped wire IDs.
- Existing `CodeQueryRange`, provenance, logical/physical planner, execution profile, LSP transport, Python package, and VS Code extension boundaries.

Do not add an external dependency. Do not add regex, substring, delimiter-scanning, or source-text fallback logic. Do not depend from structural/semantic query code back into `src/analyzer/policy`; #709 remains the outer diagnostic projection layer.

Revision note (2026-07-25 / Codex): Created the issue-specific ExecPlan after live issue and codebase diagnosis. The plan resolves the live issue's explicit `control_edge` requirement against the older umbrella plan, preserves pinned schema version 2, and limits the first implementation to real procedure-local CFG services.

Revision note (2026-07-25 / Codex): Recorded implementation approval, milestone checkpoint commits, frequent `origin/master` synchronization, and guided-review gates before source changes begin.
