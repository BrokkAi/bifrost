# Add bounded receiver, points-to, and member-target traversal

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, `query_code` can ask what object or type a JavaScript or TypeScript expression may denote and which exact member declaration a receiver-qualified access targets. The query result preserves precise, ambiguous, unknown, unsupported, and budget-exceeded outcomes instead of turning uncertainty into an empty result or a same-name guess. Users can demonstrate the behavior with JSON or RQL recipes that follow constructor and factory values, distinguish unrelated same-name members, and compose with existing reference-site and call-input rows.

This is a bounded, demand-driven exposure of Bifrost's existing receiver facts. It is not a control-flow graph, whole-program pointer analysis, general alias-set engine, taint engine, or source-text fallback.

## Progress

- [x] (2026-07-15 11:46Z) Refreshed origin and rebased the clean issue branch onto `origin/master` at `ddd16b4d`.
- [x] (2026-07-15 11:46Z) Verified the pre-change baseline: 13 receiver-analysis tests and all 57 `code_query_pipelines` tests pass.
- [x] (2026-07-15 11:46Z) Inspected the typed query IR/executor, declarative schema, public result consumers, receiver provider, get-definition member resolution, documentation harness, and current capability claims.
- [x] (2026-07-15 11:46Z) Created this implementation plan and fixed the public names, typed domains, capture semantics, explicit outcome model, provider scope, and validation contract.
- [ ] Milestone 1: add the analyzer-owned receiver query service, work reporting, and focused JS/TS provider tests.
- [ ] Milestone 2: add JSON/RQL steps, the receiver-analysis pipeline/result domain, consumers, and end-to-end tests.
- [ ] Milestone 3: add the executable cookbook and update every relevant public capability/query document.
- [ ] Milestone 4: review the complete diff, repair findings, and run the full repository validation bundle.

## Surprises & Discoveries

- Observation: The Bifrost MCP navigation endpoints named by the installed skills are not exposed in this Codex task.
  Evidence: the active tool catalog contains no `search_symbols`, `get_symbol_sources`, `scan_usages_by_location`, or `most_relevant_files` endpoint, so exploration uses the skills' prescribed targeted `rg` and exact-source fallback.

- Observation: The issue branch was clean but `origin/master` had advanced by two commits, including a docs social preview change and a C++ receiver fix.
  Evidence: `git rebase origin/master` completed without conflicts and placed the branch at `ddd16b4d`.

- Observation: The shared receiver outcome/provider exists, but only the JS/TS implementation exposes allocation, alias, and factory-return values through the provider trait.
  Evidence: `src/analyzer/usages/receiver_analysis.rs` defines the shared model and `src/analyzer/usages/js_ts_graph/receiver_analysis.rs` is the sole `ReceiverFactProvider` implementation beyond the no-op provider.

- Observation: Structural captures retain exact spans, while call-input rows and reference-site rows already retain exact expression/reference ranges.
  Evidence: `FactMatch.captures`, `ExpressionSiteValue`, and `ReferenceSiteValue` in the structural matcher/executor provide the three input surfaces required by this issue without reparsing source strings.

- Observation: Both docs and the MCP description currently make blanket statements that `query_code` does not perform points-to or receiver-value analysis.
  Evidence: repository search finds those statements in `docs/src/content/docs/` and `src/mcp_extended.rs`; they must be narrowed to distinguish this bounded JS/TS capability from unsupported whole-program analysis.

## Decision Log

- Decision: Keep schema version 2 and name the operations `receiver_targets`, `points_to`, and `member_targets`, with hyphenated RQL wrappers.
  Rationale: These are additive typed pipeline steps and match the issue vocabulary without overloading structural roles.
  Date/Author: 2026-07-15 / user and Codex

- Decision: Return one explicit `receiver_analysis` row per analyzed input.
  Rationale: Unknown, unsupported, and budget-exceeded outcomes must remain observable even when they contain no candidates; diagnostics alone would make multi-row queries hard to attribute safely.
  Date/Author: 2026-07-15 / user and Codex

- Decision: Store receiver values and member declarations inside the analysis result rather than promoting them to ordinary declaration rows.
  Rationale: The enclosing outcome applies to the candidate set. Flattening candidates would lose ambiguity and make an unknown analysis indistinguishable from no match. `file_of` remains the only downstream step and maps to the analyzed source site.
  Date/Author: 2026-07-15 / user and Codex

- Decision: Support JavaScript and TypeScript precisely; every other language returns `unsupported` plus a capability diagnostic.
  Rationale: Only JS/TS has the reusable shared provider required by the issue. Widening language-specific graph heuristics into a parallel query type system would violate the requested architecture.
  Date/Author: 2026-07-15 / user and Codex

- Decision: The optional `capture` selector is legal only on a structural-match input and must name a declared positive capture.
  Rationale: Captures already have exact spans. Reusing them avoids a new general capture-projection step while preventing runtime typos and ambiguous domain behavior.
  Date/Author: 2026-07-15 / user and Codex

- Decision: Provider work is reported and charged to the existing request budget; a test-only receiver-budget override proves deterministic budget exits.
  Rationale: Receiver analysis must not create an unmetered nested traversal, and budget tests must not depend on timing or source size accidents.
  Date/Author: 2026-07-15 / user and Codex

## Outcomes & Retrospective

Implementation has not started. The branch is synchronized, the existing focused baselines are green, and the public/implementation contracts are fixed below.

## Context and Orientation

The public query language lives under `src/analyzer/structural/query/`. `ir.rs` defines query value domains and legal step transitions. `schema.rs` is the only authority for visible step names, RQL forms, fields, signatures, descriptions, and constrained values. The decoder, JSON renderer, RQL lowering, and source-analysis modules consume that metadata. Visible RQL vocabulary must also be recognized by the conservative VS Code TextMate grammar.

`src/analyzer/structural/search.rs` scans structural seeds and executes semantic steps. Internal rows retain exact `CodeUnit`, `ProjectFile`, and source-range identities, deduplicate deterministic values, preserve bounded provenance, and charge global file/source/fact/pipeline budgets. Public terminal values are tagged variants and are mirrored by the Rust REPL, LSP navigation wrapper, VS Code query runner, and Python client.

The receiver model lives in `src/analyzer/usages/receiver_analysis.rs`. `ReceiverAnalysisOutcome<T>` distinguishes `Precise`, `Ambiguous`, `Unknown`, `Unsupported`, and `ExceededBudget`. `ReceiverValue` preserves allocation sites, exact type/object declarations, current receivers, and recursive factory-return provenance. `JsTsReceiverFactProvider` in the JS/TS graph module resolves expressions and exact member targets through structured tree-sitter nodes, imports, aliases, and the analyzer definition index. Existing get-definition and usage-graph code already consume that provider and must continue to share it.

A receiver analysis row describes one source expression or receiver-qualified site. `receiver_targets` analyzes the receiver extracted from a structural call/field, call site, receiver expression site, or reference site. `points_to` analyzes a structural expression/capture, an assignment's normalized right-hand side, a reference site, or a call-input expression. `member_targets` analyzes a receiver-qualified structural match or reference site and returns exact indexed member declarations. The result outcome describes the complete candidate set; it is not a proof tier on an individual flattened edge.

## Plan of Work

Milestone 1 adds an analyzer-owned query service under `src/analyzer/usages/`. Define a source-site input containing file, range, source kind, optional capture label, and optional member name. Construct `JsTsReceiverFactProvider` from analyzer-indexed source, the language parse tree, structured import binder, and global definition index. Expose service methods for expression values, extracted receiver values, and exact member targets. Unsupported languages and unsupported input shapes return explicit outcomes rather than empty vectors.

Extend receiver budget tracking with observable scope-node and summary-expansion counts. Add a report containing the outcome, work, and candidate-truncation state. Keep existing provider wrappers for get-definition/usage consumers, but implement them through the report-producing path so query traversal and existing consumers cannot drift. Cancellation is checked before and after each bounded provider request.

Milestone 2 extends the schema-v2 pipeline. Add `ReceiverAnalysis` to `QueryValueKind`, `PipelineValue`, keys, traces, public values, and provenance refs. Add step filters carrying an optional capture name. Validate the exact input domains and ensure capture selectors appear only on structural matches and refer to a capture declared in the positive query patterns. RQL accepts option/value pairs before the nested query and canonicalizes to the same JSON step object.

The public `CodeQueryReceiverAnalysis` contains `analysis_kind`, path, language, exact range, bounded text, input kind, optional capture, outcome, receiver values, member targets, optional unsupported reason, and optional exceeded limit. Receiver values serialize recursively: allocation sites include their exact type declaration and source location; direct object/type variants include their exact declaration; factory returns include the exact factory declaration and nested returned value. Compact/full detail follows existing declaration/range identity rules. Empty candidate fields are omitted, but the enclosing analysis row is never omitted.

Derive the provider budget component-wise from the default receiver budget, any test override, and the remaining CodeQuery fact/pipeline work. Charge actual scope nodes and summary expansions back to the request. Charge bounded candidates as pipeline work. Ordinary ambiguity with a complete candidate set is not truncation. Candidate-cap truncation or `ExceededBudget` sets the top-level `truncated` flag and emits a limit-specific diagnostic. Unsupported providers emit one aggregated language/operation diagnostic while preserving each unsupported row. Cancellation keeps the existing no-partial-results contract.

Update every exhaustive consumer: Rust public reexports and REPL rendering, LSP path/navigation selection, MCP schema/help, Python recursive models and result union, VS Code result types/rendering/navigation, query-source live validation/hover/completions, JSON canonicalization, and the TextMate grammar.

Milestone 3 adds `docs/src/content/docs/code-query-tutorials/receiver-traversal.md`, links it from the tutorial index, TypeScript page, and docs sidebar, and marks every fixture/RQL/JSON/expected block for the executable tutorial harness. Recipes prove constructor/factory provenance, exact same-name member selection, branch ambiguity, `call_input -> points_to`, and `references_of -> member_targets`.

Update the query overview, JSON reference, RQL guide, capability matrix, Python client, rule-building guide, overview/selection guidance, evaluation evidence, agent safety page, and reference tutorial boundary. State positively that JS/TS supports bounded demand-driven receiver/value provenance, while whole-program points-to, general alias sets, path-sensitive control flow, taint, and unbounded data flow remain unsupported. Update terminal-result counts and result-consumer tables from six to seven variants.

Milestone 4 reviews the complete diff for duplicated parsing, name-only guesses, lost outcomes, uncharged work, invalid domain transitions, stale public unions, imprecise docs, and cross-platform path/range handling. Repair all findings, run the full validation bundle, update the living sections, and commit the reviewed result.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/c2c4/bifrost` on the existing issue branch. Do not create or switch branches, push, or open a pull request. Stage only files changed for the current milestone and make multiline checkpoint commits explaining the behavior and rationale.

Before implementation, the branch was synchronized with:

    git fetch origin
    git rebase origin/master

Focused Rust validation during Milestones 1 and 2:

    cargo test --lib receiver_analysis
    cargo test --test code_query_pipelines
    cargo test analyzer::structural::query
    cargo test --test bifrost_tool_cli
    cargo test --test bifrost_lsp_server

Public consumer and documentation validation:

    bash scripts/test_python.sh
    npm --prefix editors/vscode test
    cargo test --test code_query_docs --test code_query_tutorials
    npm --prefix docs run check
    npm --prefix docs run build

The worktree initially lacks `docs/node_modules` and `editors/vscode/node_modules`. Reuse `/Users/dave/Workspace/BrokkAi/bifrost/docs/node_modules` for docs validation, and install VS Code dependencies from `editors/vscode/package-lock.json` with `npm --prefix editors/vscode ci` if no reusable installation exists.

Final repository gates:

    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python
    bash scripts/test_python.sh
    npm --prefix editors/vscode test
    npm --prefix docs run check
    npm --prefix docs run build
    git diff --check

Run a fresh docs development server on an unused port and inspect the receiver tutorial, capability matrix, query reference, sidebar, and deployment-base links. Do not trust an older Astro daemon.

## Validation and Acceptance

JSON and RQL must canonicalize the three new steps identically. Unknown step fields, invalid capture names, capture selectors after a non-structural domain, missing declared captures, and illegal input domains must report the exact `steps[i]` path. Source diagnostics, hover, completion, MCP schema generation, and the TextMate grammar must all derive or agree with the schema registry.

An allocation/factory fixture must return `precise` with a recursive factory-return value terminating at the exact `Service` allocation site. A same-name fixture containing unrelated `Service.run` and `Other.run` declarations must return only `Service.run` when the receiver is precise. A conditional or alias fixture must return `ambiguous` with every bounded candidate and must not upgrade either candidate to precise.

An unsupported Python input must return an `unsupported` analysis row and a Python capability diagnostic. A supported-but-unresolved JS/TS expression must return an `unknown` row. A tiny receiver budget must return `exceeded_budget`, identify the exact receiver limit, and set top-level `truncated`. Candidate-cap truncation must retain the bounded candidates, identify `max_targets`, and also mark truncation.

`call_sites_to -> call_input -> points_to` must analyze the exact bound argument expression. `references_of -> member_targets` must locate the containing receiver-qualified site and reuse exact provider member resolution. `file_of` after any receiver-analysis result must return the analyzed input file. Provenance deduplication, trace caps, terminal result limits, intermediate budget behavior, and cancellation must preserve the existing query invariants.

The executable docs page must compare complete exact JSON output for all advertised recipes. The docs must no longer claim that all receiver-value or points-to analysis is absent, and must not imply that bounded JS/TS facts provide whole-program completeness.

## Idempotence and Recovery

All query/service tests use temporary inline projects and are safe to repeat. Receiver queries read analyzer snapshots and do not mutate source workspaces. Dependency installations affect ignored build directories only. If a provider shape cannot be supported from existing tree-sitter facts, retain an explicit unsupported outcome and diagnostic; do not add source-text parsing or same-name recovery. If a milestone fails, keep the working tree, update this plan with the discovery, and repair the root cause without resetting unrelated changes.

## Artifacts and Notes

Canonical operations and domains:

    structural_match | reference_site | call_site | expression_site
        --receiver_targets--> receiver_analysis

    structural_match | reference_site | expression_site
        --points_to---------> receiver_analysis

    structural_match | reference_site
        --member_targets----> receiver_analysis

    receiver_analysis --file_of--> file

Canonical outcome labels:

    precise, ambiguous, unknown, unsupported, exceeded_budget

Revision note (2026-07-15): Created the implementation-ready ExecPlan after rebasing onto current master, verifying focused baselines, and fixing the public outcome, domain, provider, budget, consumer, documentation, and validation contracts.

## Interfaces and Dependencies

The query IR adds conceptually:

    pub struct ReceiverTraversalOptions {
        pub capture: Option<String>,
    }

    pub enum QueryStep {
        ReceiverTargets(ReceiverTraversalOptions),
        PointsTo(ReceiverTraversalOptions),
        MemberTargets(ReceiverTraversalOptions),
        // existing variants remain
    }

The public result model adds conceptually:

    pub struct CodeQueryReceiverAnalysis {
        pub analysis_kind: &'static str,
        pub path: String,
        pub language: &'static str,
        pub range: CodeQueryRange,
        pub text: String,
        pub input_kind: &'static str,
        pub capture: Option<String>,
        pub outcome: &'static str,
        pub values: Vec<CodeQueryReceiverValue>,
        pub member_targets: Vec<CodeQueryDeclaration>,
        pub reason: Option<&'static str>,
        pub limit: Option<&'static str>,
    }

`CodeQueryReceiverValue` is a recursively tagged enum matching `ReceiverValue`. `CodeQueryResultValue` and `CodeQueryResultRef` gain `ReceiverAnalysis`. Python and TypeScript expose equivalent tagged/recursive models. No new third-party Rust dependency is required.
