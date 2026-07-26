# Expose query-local typestate findings and witnesses through CodeQuery/RQL

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It is the next independently useful slice of GitHub issue #824, “Expose CFG, data-flow, and typestate through typed CodeQuery/RQL.” It does not complete #824. Value flow and taint remain owned by #821, persisted or cross-query summaries remain owned by #823, and public `.rqlp` policy compilation and `PolicyFinding` projection remain a later #824 slice over #709's already-landed policy model.

## Purpose / Big Picture

After this change, an embedding that already has a compiled typestate protocol and a pre-resolved binding plan can register that pair under a namespaced reference, then run ordinary schema-version-4 JSON or RQL against a procedure. The query returns a diagnostic-neutral `typestate_finding`; a following `witness` step returns the bounded source-backed derivation already retained by the same solver run. The user can see the feature working by registering the checked resource-lifecycle protocol and binding plan, running equivalent JSON and RQL queries over an inline project with a use-after-close path, and observing equal typed results whose certainty, proof, completeness, truncation, protocol hash, binding-plan hash, source range, and witness steps agree.

This slice deliberately starts with the typed algebra `procedure -> typestate_finding -> typestate_witness`. The query obtains a procedure through the already-landed `procedure_of` step. It does not yet accept `bind` or `mode`: the registered `TypestateBindingPlan` already owns the exact subject, event, terminal, and object-role bindings, while `CompiledProtocol` already owns may-versus-must semantics. Pretending those options can be changed at query time would either invalidate the canonical hashes or duplicate the later endpoint-binding and policy compiler.

CodeQuery never loads a protocol, endpoint, or policy path. A host registers already-compiled in-memory values on `SearchToolsService` or passes an immutable registration snapshot to the direct Rust executor. Each execution creates a fresh `QueryAnalysisContext`, resolves only the references used by that query, and assigns execution-local dense handles. A missing registration, stale workspace generation, mismatched analysis root, exhausted budget, cancellation, or unsupported semantic capability remains an explicit incomplete outcome rather than an empty complete result.

## Progress

- [x] (2026-07-26 19:29 SAST) Fetched `origin`, verified that the clean current worktree is detached at current `origin/master` (`4dceaf47`), and read the live issue status and comments.
- [x] (2026-07-26 19:29 SAST) Traced the schema-v3 CFG pipeline, request-scoped `SemanticQueryContext`, #822 protocol/binding/client/finding APIs, and #709 evaluator seam. Confirmed that no `QueryAnalysisContext`, protocol registry, protocol handle, binding adapter, production `TypestatePolicyCompiler`, or production `TypestatePolicyEvaluator` exists.
- [x] (2026-07-26 19:29 SAST) Fixed the first-slice decisions: schema version 4, procedure input, in-memory pre-resolved registrations, one solver run, and a witness projection that never reruns analysis.
- [x] (2026-07-26 20:04 SAST) Attached the clean worktree to the user-selected fresh branch `dave/824-typed-codequery-typestate-surface` at verified `origin/master` commit `4dceaf47`; the older issue worktree remains untouched.
- [x] (2026-07-26 20:37 SAST) Milestone 1: added bounded protocol registration snapshots, downward-configurable hard limits, execution-scoped dense handles, exact workspace/root/hash checks, whole-plan artifact identity validation, and focused tests for conflicts, alias deduplication, every independent bound, unresolved references, stale files, generation mismatch, root mismatch, and cross-context handles. `cargo test --test code_query_typestate_context` passes 9 tests.
- [ ] Milestone 2: add the schema-v4 `typestate_finding` and `typestate_witness` domains plus `typestate` and `witness` operations across JSON/RQL parsing, canonical rendering, static validation, ranges, explain planning, and schema metadata.
- [ ] Milestone 3: adapt registered protocols and binding plans to the existing typestate client, retain findings in the typed pipeline, project witnesses without a second solve, and expose deterministic work and completion metadata.
- [ ] Milestone 4: update `SearchToolsService`, MCP/LSP transport behavior, Python models, VS Code rendering/navigation, TextMate grammar, public documentation, and executable examples.
- [ ] Milestone 5: run focused tests, full feature-enabled tests, strict Clippy, guided specialist review, and record exact evidence and any remediation here.

## Surprises & Discoveries

- Observation: schema version 3 is already a published compatibility point rather than an uncommitted draft.
  Evidence: commit `e7d33a11` landed `procedure`, `program_point`, and `control_edge` across Rust, MCP/LSP, Python, VS Code, and documentation; `src/analyzer/structural/query/ir.rs` currently declares `SCHEMA_VERSION` as 3.

- Observation: incrementing only `SCHEMA_VERSION` would accidentally erase explicit schema-version-3 resolution.
  Evidence: `src/analyzer/structural/query/schema.rs` currently constructs its lineage from version 2 and the current head. Schema 4 must therefore add explicit descriptors for 2, 3, and 4, with 3 inheriting from 2 and 4 inheriting from 3.

- Observation: #822 intentionally stops before query- or policy-facing binding compilation.
  Evidence: `TypestateBindingPlan::try_new` accepts already-resolved subjects, seeds, events, and terminal sites. All production-client tests build these values directly from semantic handles; no adapter constructs them from a `CodeQuery`, endpoint selector, or `ResolvedTypestatePolicySpec`.

- Observation: an internal `ProtocolSpec` alone cannot identify `use` and `close` call sites.
  Evidence: `ProtocolEventOccurrence::Endpoint` records an observation phase but deliberately does not contain a source name or public endpoint selector. Exact endpoint identity belongs in `TypestateBindingPlan`, so CodeQuery must consume a registered plan rather than scan names or invent a source-text matcher.

- Observation: the existing typestate client already has the required diagnostic-neutral evidence and bounded witness reconstruction.
  Evidence: `solve_typestate_with_summaries` returns `TypestateSummaryResult`; `collect_summary_findings_with_limits` emits may, must, and inconclusive `TypestateFinding` values with proof, completeness, uncertainty, abstention, bounded witnesses, and omission counts.

- Observation: one registered plan is analysis-root-specific when it contains analysis-root terminal expectations.
  Evidence: `TypestateFlowProblem::validate_analysis_root` rejects a root whose handle does not equal the root encoded by terminal binding sites. Registrations must therefore retain the expected root and a `typestate` step must require the exact matching `procedure` input.

- Observation: the ordinary MCP/LSP query cannot manufacture a pre-resolved binding plan from JSON.
  Evidence: binding plans contain scoped semantic handles that are intentionally not serializable. A host-facing in-memory registration API is required; remote JSON/RQL supplies only the validated `protocol_ref`.

- Observation: the workspace already had the exact non-lowering semantic-artifact identity check required by registrations, but it was compiled only for tests.
  Evidence: `WorkspaceAnalyzer::semantic_artifact_key_is_current` derives the current complete key through `ProgramSemanticsProvider::current_artifact_key`. Milestone 1 made that helper available to crate code and reused it rather than rematerializing IR.

- Observation: validating only observation sites would miss semantic artifacts retained through subject objects and bounded call contexts.
  Evidence: `AbstractObject` can retain value, call-result, procedure-port, allocation, lexical-cell, or scoped-locator roots, while observation and call-result contexts retain additional call handles. `TypestateBindingPlan::for_each_retained_artifact_key` now walks all of these structured handles.

## Decision Log

- Decision: introduce CodeQuery schema version 4 and retain exact versions 2 and 3 in the compatibility lineage.
  Rationale: adding typestate terms to the already-published version 3 would make an explicit version pin change meaning. Version 4 permits exact range diagnostics for v3 documents while omitted versions advance to the compatible head.
  Date/Author: 2026-07-26 / Codex

- Decision: the first typed operation is `typestate: procedure -> typestate_finding`.
  Rationale: a procedure is an exact source-backed `ProcedureHandle` and the registered plan identifies its subjects and observations. Accepting structural matches, call sites, expressions, or flow endpoints immediately would require the endpoint/bind compiler that this slice deliberately does not implement. Callers can still start with a structural match and apply `procedure_of` first.
  Date/Author: 2026-07-26 / Codex

- Decision: schema-v4 `typestate` requires only `protocol_ref`; it does not accept `bind` or `mode`.
  Rationale: binding roles are part of `TypestateBindingPlanHash`, and analysis mode is part of `TypestateProtocolHash`. Query-time overrides would make the registered canonical pair dishonest. The later `TypestatePolicyCompiler` may expose richer authoring inputs while still lowering them to this same execution contract.
  Date/Author: 2026-07-26 / Codex

- Decision: separate host registrations from execution-local handles.
  Rationale: `SearchToolsService` needs a bounded, in-memory way for embeddings and tests to install a `ProtocolRef`, root, `CompiledProtocol`, and `TypestateBindingPlan`. Every query then snapshots compatible registrations into a fresh `QueryAnalysisContext`, which deduplicates equal hash pairs into dense slots. This supports real MCP/LSP execution on a configured host without accepting file paths or serializing semantic handles.
  Date/Author: 2026-07-26 / Codex

- Decision: a registration is branded by workspace generation and exact analysis root in addition to the protocol and binding-plan hashes.
  Rationale: equal dense IDs from a stale artifact cannot be trusted after a workspace reload. Registration and execution must validate the current generation and root before the solver starts, returning an explicit stale or root-mismatch outcome when they differ.
  Date/Author: 2026-07-26 / Codex

- Decision: registering the same reference and same registration is idempotent; registering the same reference with different root or hashes is an error; different references may reuse one registration.
  Rationale: this preserves human-readable aliases without allowing a name to silently change meaning. Reusing one immutable registration for multiple aliases avoids duplicate retained protocols and plans.
  Date/Author: 2026-07-26 / Codex

- Decision: registration limits may be tightened per host but can never exceed the public hard maxima.
  Rationale: this keeps the default store finite while making each resource dimension independently enforceable and testable. A failed reference, registration-count, protocol-byte, or binding-byte charge leaves both indexes and retained-byte counters unchanged.
  Date/Author: 2026-07-26 / Codex

- Decision: `ProtocolHandle` contains a context generation, dense slot, protocol hash, and binding-plan hash, but only the two hashes and authored reference may appear in results.
  Rationale: the generation and slot exist only to reject cross-context or stale lookup. They are neither durable identity nor a persistence key.
  Date/Author: 2026-07-26 / Codex

- Decision: `witness: typestate_finding -> typestate_witness` projects retained evidence and never invokes the solver or finding collector.
  Rationale: a witness is a bounded view of the same diagnostic-neutral finding. A second run could observe a different workspace generation, double work, or produce inconsistent proof metadata.
  Date/Author: 2026-07-26 / Codex

- Decision: witness options may only reduce the registered query limits.
  Rationale: `collect_summary_findings_with_limits` already bounds reconstruction. `max_steps` and `max_bytes` on the `witness` step can truncate that retained value further, but cannot request a larger hidden reconstruction or alter finding certainty.
  Date/Author: 2026-07-26 / Codex

- Decision: keep `TypestatePolicyCompiler`, `.rqlp` loading, presentation, classification, human rendering, and SARIF projection out of this ExecPlan.
  Rationale: #709 owns loaded public policy and `PolicyFinding` models. This slice proves the diagnostic-neutral execution contract that the later compiler/evaluator will consume; it must not create a second policy envelope or context-free finding-to-diagnostic conversion.
  Date/Author: 2026-07-26 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. The host-side ownership and safety boundary now exists independently of the query grammar: protocol aliases are bounded wire values, registrations retain exact immutable roots/protocols/plans, identical aliases share one allocation, and execution-local handles cannot be reused across contexts or workspace generations. The next milestone introduces schema-v4 typed operations without yet running the solver. At completion, summarize the exact JSON/RQL behavior delivered, the protocol registration and stale-generation guarantees, focused and full validation results, any review remediation, and the remaining #824 work for richer binding inputs, policy compilation, value flow, taint, and summary persistence.

## Context and Orientation

CodeQuery is Bifrost's typed structural and semantic query pipeline. JSON decodes in `src/analyzer/structural/query/decode.rs`; RQL, the S-expression frontend, decodes in `src/analyzer/structural/query/sexp.rs`. Both frontends lower to `CodeQuery`, `CodeQueryPlan`, and `QueryStep` in `src/analyzer/structural/query/ir.rs`. `QueryValueKind` names the value at each point in a pipeline, and `QueryStep::output_kind` rejects invalid compositions before workspace execution. Public operation names, RQL forms, JSON fields, RQL properties, value shapes, signatures, descriptions, minimum schema versions, and semantic facets belong in `src/analyzer/structural/query/schema.rs`.

The executor lives under `src/analyzer/structural/search/`. `PipelineValue` and `PipelineKey` carry and deduplicate private intermediate rows. `apply_pipeline_step` applies one validated `QueryStep`. `SemanticQueryContext` in `src/analyzer/structural/search/semantic.rs` owns one request's `SemanticBudget`, cancellation token, materialized-artifact cache, diagnostics, and semantic work counters. The already-landed `CfgQueryAdapter` maps source-backed structural or declaration rows to procedure handles, points, and control edges. The typestate adapter must be another narrow consumer of this shared context, not a second query engine and not a replacement solver.

A protocol is a finite state machine describing states, events, transitions, terminal expectations, and uncertainty behavior. `src/analyzer/typestate/protocol.rs` defines the diagnostic-neutral `ProtocolSpec`, compiled `CompiledProtocol`, and stable `TypestateProtocolHash`. Compilation assigns dense state/event IDs only after producing a deterministic canonical representation. Those dense IDs are private execution details.

A binding plan connects a compiled protocol to exact program semantics. `src/analyzer/typestate/binding.rs` defines `TypestateBindingPlan`, subjects, initial seeds, event observations, terminal observations, object roles, exact semantic sites, proof/completeness quality, and stable `TypestateBindingPlanHash`. The plan contains scoped handles into immutable semantic artifacts. It is therefore an in-memory analysis value, not a JSON wire document.

`src/analyzer/typestate/client.rs` runs a bound protocol through the summary data-flow solver. `solve_typestate_with_summaries` consumes an exact root `ProcedureHandle`, `WorkspaceIcfgProvider`, `CompiledProtocol`, `TypestateBindingPlan`, `SemanticBudget`, `SolverBudget`, and `CancellationToken`. It returns `TypestateSummaryResult`. `src/analyzer/typestate/finding.rs` then aggregates that result into `TypestateFindingReport` with deterministic may/must/inconclusive findings and bounded `TypestateFindingWitness` values.

In this plan, a `ProtocolRef` is a bounded validated human-readable alias such as `embedding:bifrost.test.resource-lifecycle`. A host registration pairs that alias with one current workspace generation, one analysis root, one compiled protocol, and one binding plan. A `ProtocolHandle` is an opaque capability issued inside one `QueryAnalysisContext`; it proves that the reference resolved to the exact registered pair for that execution. A `typestate_finding` is a diagnostic-neutral analysis result. It has no severity, message, CWE, CVSS assessment, policy identity, or SARIF shape. A `typestate_witness` is a bounded source-backed derivation retained by that finding.

`src/searchtools_service.rs` owns the transport-facing service and prepares queries against an immutable `WorkspaceQueryScope`. `src/mcp_common.rs` advertises tool schemas and executes prepared calls. `src/lsp/server.rs` attaches editor-navigation URIs to source-backed results. Python response models live in `bifrost_searchtools/models.py`; VS Code RQL result presentation lives in `editors/vscode/src/rql_query.ts`; the conservative RQL TextMate grammar is `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

## Plan of Work

### Milestone 1: Define safe host registrations and execution-local handles

Create `src/analyzer/structural/analysis_context.rs` and export its public host-facing types from `src/analyzer/structural/mod.rs`. Define a bounded `ProtocolRef` parser with an explicit namespace and local identifier, maximum byte lengths, stable display/serialization, and no acceptance of paths or unnamespaced strings. The parser is a wire-identifier parser, not a source-language parser. Add errors for empty/invalid namespace or name, oversize input, and forbidden characters.

Define `ProtocolRegistration` as an immutable value containing the workspace generation captured at registration, expected root `ProcedureHandle`, `Arc<CompiledProtocol>`, and `Arc<TypestateBindingPlan>`. Its constructor must reject a plan whose `protocol_hash()` differs from `protocol.hash()`. Add the smallest read-only traversal API needed in `src/analyzer/typestate/binding.rs` to enumerate the semantic artifact keys retained by subjects and observation sites. Registration or execution must verify those artifacts against the current workspace snapshot; do not validate only the root while silently accepting stale helper-procedure handles.

Define a bounded `ProtocolRegistrationSet`. It maps `ProtocolRef` to immutable registrations, maintains a secondary hash-pair/root index for reuse, and charges count and retained canonical bytes before mutation. Registration is transactional. Same reference plus same generation/root/hashes is idempotent. Same reference plus a different registration returns `ReferenceConflict`. Different references with the same registration share the same `Arc`. Establish finite constants for references, registrations, retained protocol bytes, and retained binding-plan bytes; unit tests must exercise every bound.

Define opaque `ProtocolHandle` and private `ProtocolRegistry`. `QueryAnalysisContext::new` receives the current workspace generation and an immutable registration snapshot, allocates a fresh monotonically unique nonzero context generation, and imports only references requested by the decoded query. Handle lookup checks context generation, slot bounds, protocol hash, binding-plan hash, registration workspace generation, expected root, and current artifact identities. A handle from another or earlier context returns `StaleHandle`, even if its dense slot happens to exist.

Extend `SearchToolsService` with a bounded in-memory registration store and explicit host methods such as `register_query_protocol` and `unregister_query_protocol`. These methods accept in-memory compiled values only; do not expose MCP tools that accept protocol files, binding-plan JSON, or arbitrary workspace paths. `PreparedQueryCode` captures an immutable registration snapshot together with its existing `WorkspaceQueryScope`, so a concurrent registration change cannot alter a prepared request. Workspace generation changes make older registrations explicitly stale until the host re-registers them.

Add focused unit tests in `src/analyzer/structural/analysis_context.rs` and service lifecycle tests in `src/searchtools_service.rs`. Prove idempotence, same-reference conflict, different-reference reuse, context-local slots, stale handles, stale workspace generations, artifact mismatch, finite registration bounds, transactional failure, and concurrent prepare/register snapshot isolation.

At the end of this milestone, run:

    cargo test analyzer::structural::analysis_context
    cargo test searchtools_service::tests --lib
    cargo fmt --check
    git diff --check

Expect every conflict and stale condition to have a deterministic typed error and the worktree to contain no `.brokk/bifrost_cache.db` generated by tests.

### Milestone 2: Publish schema-v4 typed domains and operations

Change `SCHEMA_VERSION` in `src/analyzer/structural/query/ir.rs` to 4. In `src/analyzer/structural/query/schema.rs`, replace the two-entry computed lineage with explicit compatible descriptors for versions 2, 3, and 4. Version 3 remains an exact accepted pin. Version 4 inherits from 3 and becomes the omitted-version head.

Extend `QueryValueKind` with `TypestateFinding` and `TypestateWitness`. Extend `QueryStep` with a typed `TypestateTraversal` carrying one `ProtocolRef`, and a `WitnessTraversal` carrying optional positive `max_steps` and `max_bytes` reductions. The first static signatures are:

    procedure --typestate(protocol_ref)--> typestate_finding
    typestate_finding --witness(max_steps?, max_bytes?)--> typestate_witness

Extend `file_of` to map both new source-backed domains to `file`. Set operations may combine branches only when both terminate in the same new domain. Preserve the existing path-specific validation error behavior for every rejected input.

Enter every new term through `src/analyzer/structural/query/schema.rs`. Add `ProtocolRef` and witness-limit value shapes, `protocol_ref`, `max_steps`, and `max_bytes` JSON step fields, RQL properties with kebab-case primary spelling and underscore aliases where the existing public style requires them, schema-v4 operation entries, exact signatures, descriptions, and semantic facets. Extend the declarative step metadata so each operation declares its accepted option fields; do not add another private keyword list beside the registry. Existing hierarchy, reference, call, call-site, and receiver option handling should migrate to or delegate through the same metadata where necessary to make the new rule genuinely exhaustive.

Teach `decode.rs`, `json.rs`, `sexp.rs`, `source.rs`, and exhaustive IR matches to parse and render:

    {
      "schema_version": 4,
      "match": {"kind": "function", "name": "lifecycle"},
      "steps": [
        {"op": "procedure_of"},
        {"op": "typestate", "protocol_ref": "embedding:bifrost.test.resource-lifecycle"},
        {"op": "witness", "max_steps": 32, "max_bytes": 16384}
      ]
    }

and the equivalent RQL:

    (witness :max-steps 32 :max-bytes 16384
      (typestate :protocol-ref "embedding:bifrost.test.resource-lifecycle"
        (procedure-of
          (function :name "lifecycle"))))

Parsing validates the reference's syntax but does not resolve it. Before execution, `QueryAnalysisContext` resolves every referenced protocol against the prepared registration snapshot. Explain mode may report the required typestate facets and authored reference without touching registrations or workspace data; results/profile mode must resolve before the first typestate operator runs.

Update physical-plan semantic demand in `src/analyzer/structural/execution/plan.rs` and profiling types so `TypestateFindings` and `TypestateWitnesses` are explicit facets. Cheap structural matching and `procedure_of` remain before the solver operator. Explain output must not materialize a protocol, semantic artifact, ICFG, or solver state.

Extend `src/analyzer/structural/query/tests.rs`, `source.rs` range tests, and `tests/structural_search_planner.rs`. Prove JSON/RQL canonical equivalence, schema-v4 defaulting, exact v2/v3 rejection at the authored operation/property range, missing/duplicate/unknown property diagnostics, positive finite witness limits, invalid domain composition, compatible and incompatible set branches, `file_of`, hover/signature metadata, and planning-only explain behavior.

At the end of this milestone, run:

    cargo test analyzer::structural::query --lib
    cargo test --test structural_search_planner
    cargo test --test code_query_public_api
    cargo fmt --check
    git diff --check

Expect explicit schema versions 2 and 3 to retain their old canonical meaning while omitted and explicit version 4 accept the new algebra.

### Milestone 3: Execute typestate once and retain typed findings and witnesses

Create `src/analyzer/structural/search/typestate.rs` as a narrow adapter over `QueryAnalysisContext`, `WorkspaceIcfgProvider`, `solve_typestate_with_summaries`, and `collect_summary_findings_with_limits`. Do not add protocol state or solver worklists to the structural executor. The adapter takes one `SemanticProcedureValue` plus a resolved `ProtocolHandle`, validates that the procedure is the registration's exact root and that every retained artifact generation is current, then runs the existing client with the shared request cancellation token and semantic budget.

Add `CodeQueryTypestateLimits` under `src/analyzer/structural/search/results.rs` and include it in `CodeQueryExecutionLimits`. It must contain positive finite solver limits and finding/witness reconstruction limits. Construct `SolverBudget` and `TypestateFindingLimits` from those values; do not silently use an unbounded or larger hidden budget. Reuse the `SemanticBudget` already owned by `SemanticQueryContext` so CFG/ICFG provider work and typestate work share one request's semantic accounting. Invalid zero or over-maximum limits fail before execution.

Cache one request's completed or incomplete analysis by exact root, protocol hash, and binding-plan hash. Duplicate input rows or aliases must not rerun the solver. Do not persist this cache and do not claim #823 summary reuse. Record typestate solve count, reached rows, retained findings, retained/omitted witnesses, witness steps, solver termination, and budget exhaustion in `CodeQuerySemanticWork` and the profile surface.

Extend private pipeline values, keys, traces, detailed evidence, rendering, and public result types in `src/analyzer/structural/search/mod.rs` and `results.rs`. A `SemanticTypestateFindingValue` retains the authored reference, canonical hashes, exact root, diagnostic-neutral `TypestateFinding`, and its already-materialized bounded witnesses. Its stable pipeline key includes the canonical hashes, subject identity, source site, finding kind, and certainty; never use a dense protocol, state, subject, or witness slot alone.

The public `CodeQueryTypestateFinding` must include at least `protocol_ref`, 64-lowercase-hex `protocol_hash`, 64-lowercase-hex `binding_plan_hash`, subject identity, finding kind, certainty, source path/range, proof, completeness, uncertainty causes, abstention, retained witness count, omitted witness count, and stable source-backed result identity. It must not contain a policy ID, severity, message, classification, CWE, CVSS assessment, or SARIF fields.

The `witness` step expands each retained finding into deterministic `CodeQueryTypestateWitness` rows without calling the provider, solver, or finding collector. Each row contains the same protocol/binding/finding identity, optional observed state, bounded ordered source-backed steps, completeness/truncation, and omitted-step or omitted-byte lower bounds. Query-level `max_steps` and `max_bytes` can trim the retained witness and downgrade only witness completeness. They cannot change finding certainty, solver completeness, or request analysis work.

Map failures into new typed `CodeQueryDiagnosticCode` values: unresolved protocol reference, conflicting/stale registration, stale handle, root mismatch, unsupported semantic capability, provider failure, solver budget exhaustion, finding budget exhaustion, witness truncation, and cancellation. Preserve the existing rule that an incomplete empty result is never reported as a clean complete negative. Sort findings and witnesses by stable semantic keys before applying the pipeline result limit.

Add `tests/code_query_typestate.rs` using `tests/common/inline_project.rs`. Build a small TypeScript project and a pre-resolved plan from exact semantic handles; do not find `open`, `use`, or `close` by regex or substring in production code. The test should register the resource-lifecycle protocol, execute equivalent JSON and RQL through the real workspace executor, and compare canonical results for a use-after-close finding and its witness. Add behavior-focused cases for a complete no-finding path, a terminal-expectation finding, may/must/inconclusive evidence, ambiguous/incomplete binding, unresolved reference, wrong root, stale generation, deterministic repeated output, duplicate rows with one solver run, set composition, cancellation, each budget family, witness trimming, and `file_of`.

At the end of this milestone, run:

    cargo test --test code_query_typestate
    cargo test --test code_query_pipelines typestate
    cargo test --test structural_search_planner typestate
    cargo fmt --check
    git diff --check

Expect JSON and RQL to return byte-for-byte equivalent canonical result values, profile work to report one solve, and the witness step to add no solver work.

### Milestone 4: Carry the schema and results through every public transport

Update `src/searchtools_service.rs` so prepared results/profile requests build a `QueryAnalysisContext` from the exact workspace and registration snapshots captured at preparation. Explain requests remain registration- and workspace-free. Extend `src/mcp_common.rs` schema metadata with version 4, the new operations, fields, signatures, and result descriptions. Add a real service test that registers a plan in memory, prepares an MCP query, mutates registrations afterward, and proves execution uses the prepared snapshot. An unconfigured service must return the explicit unresolved-reference diagnostic rather than hiding the operation or accepting a protocol path.

Update `src/lsp/server.rs` to attach navigable URIs to the primary finding range and every retained witness step while preserving workspace-relative paths in canonical data. Add focused tests in `tests/bifrost_lsp_server.rs` for finding and witness navigation and stale/unresolved diagnostics.

In `bifrost_searchtools/models.py`, add strict frozen models for typestate finding kind, certainty, evidence, uncertainty, witness step, `CodeQueryTypestateFinding`, and `CodeQueryTypestateWitness`. Extend the result union, canonical parser, text rendering, and required-field rejection. The Python client sends only `protocol_ref`; documentation must state that the connected host must pre-register it. Add representative positive and malformed cases to `python_tests/test_searchtools_client.py` and keep all older result models unchanged.

In `editors/vscode/src/rql_query.ts`, extend the result union, guards, labels, descriptions, tooltips, grouping, icons, and navigation. A finding opens its primary violation/terminal site. A witness item exposes its ordered source-backed steps and opens the selected step. Show certainty, proof/completeness, protocol reference, protocol hash prefix, witness completeness, and omission metadata without inventing severity. Add tests in `editors/vscode/test/rql-query.test.ts`.

Update `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json` conservatively with `typestate`, `witness`, `protocol-ref`/`protocol_ref`, `max-steps`/`max_steps`, and `max-bytes`/`max_bytes`. Update grammar, completion, hover, validation-range, formatting, and execution tests. Ordinary JSON remains outside the RQL editor integration unless the host has identified the document as `bifrost-rql`.

Update `docs/src/content/docs/code-query-json.md`, `code-querying.md`, `rune-query-language.md`, `rql-vscode.md`, and `python-client.md`. Explain schema version 4, host registration, the exact two-step algebra, diagnostic-neutrality, proof/completeness, finite budgets, stale references, and why `bind`, `mode`, policy loading, persisted summaries, flow, and taint are not in this slice. Include one executable JSON/RQL pair and representative finding/witness output with the fixture's real hashes. Update `tests/code_query_docs.rs` and `tests/code_query_tutorials.rs` so published examples parse and execute against an in-memory registration.

Run:

    python -m unittest discover -s bifrost_searchtools/tests
    python -m unittest python_tests.test_searchtools_client
    npm --prefix editors/vscode test
    cargo test --test bifrost_lsp_server typestate
    cargo test --test code_query_docs
    cargo test --test code_query_tutorials

Expect every public consumer to accept the same required fields and use the same source ranges. A host without the reference must produce the same typed unresolved-reference outcome across direct Rust, MCP, LSP, Python, and VS Code presentation.

### Milestone 5: Reconcile the roadmap, review, and run release-quality validation

Update `.agents/plans/language-agnostic-composable-typestate-platform.md` so Milestone 7 records schema-v4 `procedure -> typestate_finding -> typestate_witness` as the implemented query-local checkpoint and retains structural/call/expression `bind` forms as later compiler-backed extensions. Do not rewrite #709's public policy model and do not mark #824 complete.

Review the final branch diff against the issue and this ExecPlan. Run the guided specialist reviewers required by the guided-issue workflow: security, duplication, intent/senior-development, DevOps/operations, and architecture. Resolve every confirmed critical or high finding before proceeding. Record medium/low decisions and all code-changing remediation in `Progress`, `Surprises & Discoveries`, and `Decision Log`.

From the repository root, run:

    cargo fmt
    git diff --check
    cargo test --test code_query_typestate
    cargo test --test code_query_pipelines
    cargo test --test code_query_public_api
    cargo test --test structural_search_planner
    cargo test --test bifrost_lsp_server
    cargo test --test code_query_docs
    cargo test --test code_query_tutorials
    python -m unittest discover -s bifrost_searchtools/tests
    python -m unittest python_tests.test_searchtools_client
    npm --prefix editors/vscode test
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The isolated helper must remove its target on success, failure, or interruption. Tests must not download an NLP model or start semantic-index threads; use the repository's existing no-semantic-index constructors and environment controls. If the full suite exposes a platform-specific external dependency, record the exact failure and run the closest authoritative CI-equivalent command rather than weakening or ignoring the test.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/942c/bifrost` after the user explicitly selects or attaches the intended branch. This ExecPlan does not authorize creating, switching, or rebasing a branch. Before every milestone, run:

    git status --short --branch
    git log -3 --oneline --decorate
    git diff --check

Read the current implementation before editing because this is a living codebase. Start with:

    sed -n '1,360p' src/analyzer/structural/query/schema.rs
    sed -n '1,360p' src/analyzer/structural/query/ir.rs
    sed -n '1120,1510p' src/analyzer/structural/search/mod.rs
    sed -n '5010,5260p' src/analyzer/structural/search/mod.rs
    sed -n '1,940p' src/analyzer/structural/search/semantic.rs
    sed -n '1,1120p' src/analyzer/structural/search/results.rs
    sed -n '1,1220p' src/analyzer/typestate/protocol.rs
    sed -n '600,1120p' src/analyzer/typestate/binding.rs
    sed -n '340,1230p' src/analyzer/typestate/client.rs
    sed -n '1,860p' src/analyzer/typestate/finding.rs
    sed -n '780,940p' src/searchtools_service.rs

Implement milestones in order. After each milestone, update this plan's living sections with the exact timestamp, changes, tests, and discoveries. In an ExecPlan session, create the required multiline checkpoint commit on the user-selected current branch after focused validation and after any post-milestone review fixes. Stage only files changed for this issue; never use `git add -A`.

The first user-visible smoke should use a registered in-memory fixture and produce a result structurally like:

    {
      "result_type": "typestate_finding",
      "protocol_ref": "embedding:bifrost.test.resource-lifecycle",
      "protocol_hash": "<64 lowercase hex>",
      "binding_plan_hash": "<64 lowercase hex>",
      "certainty": "may",
      "finding_kind": "error_transition",
      "path": "src/resource.ts",
      "range": {"start_line": 12, "start_column": 3, "end_line": 12, "end_column": 17},
      "evidence": {
        "path_proven": true,
        "path_complete": true,
        "analysis_complete": true,
        "uncertainty": [],
        "abstained": false
      },
      "retained_witnesses": 1,
      "omitted_witnesses": 0
    }

Applying `witness` should yield the matching `typestate_witness`, retain the same hashes and source identity, include bounded acquire/close/use steps, and leave the profile's typestate solve count at one.

## Validation and Acceptance

The implementation is accepted when all of the following behavior is observable.

1. Explicit schema versions 2 and 3 parse exactly as before and reject `typestate`, `witness`, and their properties at the authored range. Omitted and explicit schema version 4 accept the new terms and canonicalize equivalent JSON/RQL identically.
2. Static validation accepts only `procedure -> typestate_finding -> typestate_witness` plus `file_of` from either result domain. Invalid set branches and domain compositions fail before workspace or solver work.
3. Same-reference/same-registration is idempotent; same-reference/different-root-or-hash fails deterministically; different references may share one immutable registration; every store bound is enforced transactionally.
4. A handle from another execution, an old workspace generation, an old artifact, or a different root cannot resolve. No serialized result, cache key, profile, diagnostic, or document contains a dense handle generation or slot.
5. One configured host executes equivalent JSON and RQL over an inline use-after-close project and returns equal source-backed diagnostic-neutral findings. A complete safe path returns a complete empty result; incomplete analysis cannot masquerade as that result.
6. `witness` uses the retained finding and performs zero additional solves or semantic-provider materializations. Its limits can only shorten the witness and must preserve the finding's certainty and analysis completeness.
7. Results distinguish may, must, and inconclusive certainty; proven/unproven and complete/incomplete evidence; uncertainty and abstention; witness/result truncation; unsupported capability; budget exhaustion; cancellation; root mismatch; and stale/unresolved registration.
8. Repeated execution against the same workspace generation is deterministic in identity and order. Source or workspace generation changes invalidate the old registration instead of reusing stale handles.
9. Explain mode reports semantic demand but performs no registration lookup, source materialization, ICFG construction, or solver work. Profile mode reconciles its work counters with the returned result and never reports more than one solve per exact registration/root.
10. MCP/LSP, Python, VS Code, TextMate grammar, canonical text rendering, and public documentation agree on the exact schema-v4 vocabulary and result shapes. Ordinary JSON outside a `bifrost-rql` document remains unaffected by the editor grammar.
11. No production path searches source text, method names, or rendered semantic identities to construct bindings. The query consumes the registered structured plan and the existing semantic/ICFG services.
12. Focused tests, Python tests, VS Code tests, documentation tests, strict all-feature Clippy, and the full `nlp,python` test gate all pass without leaving unmanaged Cargo targets or `.brokk` caches.

## Idempotence and Recovery

All source edits and test commands are repeatable. Host registration is explicitly idempotent for the same reference and exact registration. A failed registration does not partially mutate aliases, retained-byte accounting, or the hash-pair index. A failed or cancelled query may return cancellation-safe partial results and diagnostics, but it never publishes them as complete and never mutates the registration snapshot.

If schema work partially lands, keep explicit descriptors for versions 2 and 3 and do not advertise version 4 through MCP/editor/docs until JSON, RQL, validation, ranges, and canonical rendering agree. Never make the new operations available under explicit schema version 3 as a temporary shortcut.

If stale-artifact validation reveals that `TypestateBindingPlan` does not expose enough structured handles, add a read-only iterator or validation helper inside `src/analyzer/typestate/binding.rs`. Do not parse canonical rendering, debug text, or serialized hashes to recover handles.

If the executor cannot borrow the shared semantic budget safely while using the typestate adapter, refactor `SemanticQueryContext` to expose one narrow closure-based method that lends the workspace provider, budget, and cancellation together. Do not create a hidden independent semantic budget or use interior mutability merely to bypass the borrow checker.

If witness projection needs a smaller cap than the retained witness, copy only the bounded public step values and mark the projected witness incomplete with omission metadata. Never rerun analysis to satisfy a larger `witness` request.

Use `scripts/with-isolated-cargo-target.sh` for isolated Clippy and full-test targets. Do not create manually named Cargo targets under `/tmp` or `/private/tmp`. If Bifrost navigation or a test creates an untracked `.brokk/bifrost_cache.db`, first verify that `.brokk` contains only generated cache files, then remove those exact files and the empty directory.

## Artifacts and Notes

The core ownership boundary is:

    host-resolved ProtocolRegistration
        -> immutable registration snapshot
        -> execution-local QueryAnalysisContext / ProtocolHandle
        -> typestate QueryStep over an exact procedure
        -> existing solve_typestate_with_summaries
        -> existing collect_summary_findings_with_limits
        -> CodeQueryTypestateFinding
        -> witness projection without a rerun

The compatibility lineage after Milestone 2 is:

    schema 2: structural/query navigation before typed CFG
        -> schema 3: procedure, program_point, control_edge
        -> schema 4: typestate_finding, typestate_witness

The remaining #824 work after this plan is deliberately separate:

    structural/call/expression/flow inputs plus bind selectors
        -> TypestatePolicyCompiler over ResolvedTypestatePolicySpec
        -> #709 PolicyFinding projection and human/SARIF parity
        -> #821 flow/taint query domains and TaintPolicyCompiler
        -> #823 reusable cross-query/persisted summaries

Revision note (2026-07-26 19:29 SAST / Codex): Created the plan after live issue, repository, schema, typestate-client, and policy-seam diagnosis. Chose schema v4 and a deliberately narrow procedure-rooted query contract so the first implementation is executable without smuggling in the later binding or policy compiler.

## Interfaces and Dependencies

At the end of Milestone 1, `src/analyzer/structural/analysis_context.rs` must expose an API equivalent in responsibility to:

    pub struct ProtocolRef { /* validated namespaced wire identity */ }

    pub struct ProtocolRegistration { /* generation, root, protocol, bindings */ }

    pub struct ProtocolRegistrationSet { /* bounded immutable snapshot source */ }

    pub struct ProtocolHandle { /* opaque context generation, slot, hashes */ }

    pub struct QueryAnalysisContext { /* one execution's resolved registrations */ }

Exact constructor names may follow neighboring Rust conventions, but the ownership and validation laws in this plan are mandatory. `ProtocolRegistrationSet` may use `HashMap` plus a separately sorted result view; do not pay for `BTreeMap` ordering unless ordering is semantically required at insertion.

At the end of Milestone 2, `src/analyzer/structural/query/ir.rs` must expose responsibilities equivalent to:

    pub enum QueryValueKind {
        // existing variants
        TypestateFinding,
        TypestateWitness,
    }

    pub struct TypestateTraversal {
        pub protocol_ref: ProtocolRef,
    }

    pub struct WitnessTraversal {
        pub max_steps: Option<usize>,
        pub max_bytes: Option<usize>,
    }

    pub enum QueryStep {
        // existing variants
        Typestate(TypestateTraversal),
        Witness(WitnessTraversal),
    }

At the end of Milestone 3, `src/analyzer/structural/search/results.rs` must expose `CodeQueryTypestateFinding`, `CodeQueryTypestateWitness`, their typed evidence and kind structures, and finite `CodeQueryTypestateLimits`. The structural search executor depends on `analyzer::typestate` and `analyzer::semantic`; neither of those modules may depend on `analyzer::structural` or `analyzer::policy` as a result of this work.

`SearchToolsService` is the host boundary for configured MCP/LSP execution. Its registration methods accept compiled Rust values, not bytes or paths. `ProtocolSpec::from_json` may still be used by an embedding before registration, but CodeQuery itself never calls it and never opens a protocol file. The later policy compiler may build the same `ProtocolRegistration` from #709's already-loaded `ResolvedTypestatePolicySpec`; it must not require changes to the schema-v4 finding or witness shapes.
