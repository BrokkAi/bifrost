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
- [x] (2026-07-15 12:34Z) Milestone 1: added the analyzer-owned receiver query service, shared member-site resolution, exact factory provenance, work/truncation reports, cancellation, and focused JS/TS tests.
- [x] (2026-07-15) Milestone 2: added JSON/RQL steps, the receiver-analysis pipeline/result domain, public consumers, live help, grammar support, and end-to-end tests.
- [x] (2026-07-15) Milestone 3: added the executable receiver cookbook, updated public capability/query/safety documentation, and inspected fresh development and production-base renders.
- [x] (2026-07-15) Milestone 4: reviewed the complete diff, repaired exported and static factory receiver regressions, and ran the full repository validation bundle.
- [x] (2026-07-15) Post-milestone guided review: queued and repaired all seven confirmed findings covering prepared-context reuse, terminal-limit short-circuiting, nonhalting receiver truncation, complete text rendering, schema-owned capture bounds, exact factory association, `file_of` metadata, and shared member-site extraction.
- [ ] (2026-07-15) Re-run the complete publish gate, push the reviewed branch, and open the user-authorized ready-for-review pull request.

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

- Observation: `ReceiverValue::FactoryReturn` existed in the shared model but no provider path constructed it.
  Evidence: the first service provenance test returned the allocation directly; wrapping local, imported, and static factory summaries with their exact indexed `CodeUnit` made the recursive public contract real instead of merely serializable.

- Observation: Cargo's non-test library build reports the new service as dead code until Milestone 2 wires it into structural traversal.
  Evidence: the receiver and pipeline tests pass, while the integration-test build warns on the not-yet-consumed service types. This is an expected transient milestone state and will be eliminated by the query executor integration rather than suppressed.

- Observation: Receiver traversal needs to distinguish an exact receiver expression from a containing call/member site.
  Evidence: treating both as the same service input could analyze an unsupported structural shape directly. The service now accepts an explicit input mode, and the pipeline test proves a class match returns `unsupported` with `receiver_site_without_receiver`.

- Observation: Semantic capture diagnostics already map through `steps[i].capture` to the exact JSON string value.
  Evidence: live-source tests assert the range is precisely `"service"` for a missing declared capture and for a capture used after a reference-site stage.

- Observation: The issue worktree had no VS Code dependencies, while the main checkout only had reusable docs dependencies.
  Evidence: `npm ci` under `editors/vscode` installed 340 locked packages; lint, compilation, grammar tests, and all 54 extension unit tests pass.

- Observation: Reusing the main checkout's docs `node_modules` as a symlink made Vite try to update the main checkout's `.vite` cache outside the worktree sandbox.
  Evidence: the first docs check failed with `EPERM` while unlinking a main-checkout cache entry. A copy-on-write clone of the existing dependency tree kept the installed packages reusable while giving this worktree a writable cache; check and build then passed.

- Observation: Adding receiver support as an eighth column made the already dense capability matrix visually cramped.
  Evidence: the fresh browser preview showed narrow wrapped columns. Moving receiver-provider support into a focused two-column table restored the existing matrix layout while keeping every language's supported/unsupported result explicit.

- Observation: The production-base link checker caught an extra slash at the end of the new reference-tutorial fragment.
  Evidence: the first build reported one broken internal link. Removing the trailing fragment slash yielded 3,993 checked links with no failures, and the production preview preserved `/bifrost` on sidebar, safety, stylesheet, and social-card URLs.

- Observation: Exact factory provenance initially rejected exported factory declarations because analyzer ranges include the `export` wrapper while tree-sitter function nodes begin at `function`.
  Evidence: the all-feature suite exposed missing usage-graph edges for exported local factories. Matching same-file, same-name function declarations by overlapping structured ranges restores the exact `CodeUnit` without a name-only fallback.

- Observation: Static factory methods use the analyzer's `$static` member identity and must be selected from the receiver-value variant rather than from the owner declaration alone.
  Evidence: `Service.create()` resolved as a class/static receiver but plain `Service.create` lookup produced no factory summary. Receiver-aware member selection now chooses `Service.create$static`, while factory-return values still unwrap to ordinary instance members such as `Service.run`.

- Observation: This machine exposes distinct Homebrew and rustup compiler identities with the same Rust version string, and macOS Python extension tests require dynamic symbol lookup.
  Evidence: a mixed-toolchain doctest invocation rejected cached rlibs with E0514 after every test binary passed. Pinning the rustup toolchain in `PATH`, setting `PYO3_PYTHON=.venv/bin/python`, adding macOS `dynamic_lookup` linker flags, and using the managed isolated-target helper avoids both toolchain contamination and retained temporary targets.

- Observation: The first query integration reused the JS/TS provider but rebuilt its tree-sitter declaration index and materialized a definition context for every receiver row.
  Evidence: the guided review traced `ReceiverQueryService::new` from the per-range expansion loop. The executor now owns one service per receiver step, each source file is parsed and indexed once, bounded forward-definition lookup replaces the workspace-wide index, cancellation covers setup traversal, and setup nodes are charged once to the CodeQuery fact budget.

- Observation: Receiver-local limits were incorrectly treated as fatal shared execution-budget exhaustion.
  Evidence: candidate truncation and deterministic tiny budgets set `row_exhausted`, which stopped later receiver rows and cleared intermediate receiver rows before `file_of`. Receiver truncation now marks the top-level result and emits its diagnostic without halting the typed pipeline; only cancellation or exhausted shared CodeQuery limits stop execution.

- Observation: Analyzer declaration ranges can enclose nested same-name syntax that is not itself indexed as a `CodeUnit`.
  Evidence: overlap-only factory selection could attribute the enclosing function to a nested same-name factory. Each candidate analyzer range is now associated with its nearest same-name tree-sitter declaration range before it may represent the requested factory node; unavailable nested declarations return unknown instead of false provenance.

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

- Decision: Wrap every summarized local, imported, or static factory result at the provider boundary with the exact indexed factory declaration.
  Rationale: Reconstructing factory provenance in a renderer would be impossible and would let get-definition, usage analysis, and query traversal disagree about the underlying value.
  Date/Author: 2026-07-15 / Codex

- Decision: Treat receiver candidate caps and provider budget exits as nonhalting truncation metadata, distinct from the shared CodeQuery execution budget.
  Rationale: Every receiver input still has a valid explicit analysis row, and that row must remain composable with `file_of`; stopping the entire pipeline loses typed results and suppresses unrelated bounded inputs.
  Date/Author: 2026-07-15 / Codex guided-review repair

- Decision: Reuse one prepared receiver context per file and receiver step, backed by bounded forward-definition queries.
  Rationale: Parsing and declaration indexing are file setup work rather than per-site analysis, and demand-driven lookup avoids silently constructing an unmetered whole-workspace index.
  Date/Author: 2026-07-15 / Codex guided-review repair

## Outcomes & Retrospective

Milestones 1 and 2 are complete. The analyzer-owned service accepts an exact file/range, operation, and expression-versus-containing-site mode; checks cancellation; uses indexed JS/TS source and tree-sitter nodes; and returns explicit supported or unsupported reports. Provider reports expose actual scope-node and summary-expansion work and candidate truncation. Member-site extraction is shared with get-definition, and factory summaries retain exact recursive provenance.

Schema version 2 now exposes all three typed receiver steps through JSON, RQL, MCP help, live diagnostics/hover, and the TextMate grammar. The executor preserves receiver analysis as a terminal domain, supports `file_of`, charges provider work, retains bounded ambiguity, and renders explicit unknown, unsupported, candidate-cap, and budget outcomes. Rust, Python, LSP, CLI, and VS Code result consumers include the recursive result variant. The 13 receiver baseline, 4 focused service tests, 66 query/schema tests, 61 query-pipeline tests, and all 54 VS Code tests pass.

Milestone 3 adds an executable six-case TypeScript receiver cookbook covering allocation, recursive factory provenance, exact same-name member selection, ambiguity, reference-site composition, and call-input composition. The docs overview, CodeQuery/RQL references, capability matrix, Python client, rule guide, evaluation/safety guidance, language index, TypeScript page, and former blanket no-points-to claims now distinguish bounded JS/TS receiver evidence from unsupported whole-program/general analyses. All 20 executable tutorial tests and 3 query-doc contract tests pass. Astro reports zero diagnostics; the production build checks 3,993 base-aware links across 50 pages. Fresh browser inspection verified the tutorial, sidebar, revised capability layout, and `/bifrost` deployment links.

Milestone 4 repaired two integration defects found only by the complete suite: exported factory declarations now match their exact analyzer units across wrapper-range differences, and static factory summaries select `$static` member identities while returned instances continue to select ordinary members. All 17 JS/TS usage-graph tests, the 13 receiver tests, 61 query-pipeline tests, clippy with every target/feature, Python's 41 tests, VS Code's 54 tests, docs checks/build, formatting, and diff checks pass. The all-feature Rust run passed 842 library tests (3 ignored) and every integration-test binary; its first final doctest phase was invalidated solely by the host's mixed Homebrew/rustup artifact identities, so the gate was repeated with a pinned toolchain in the repository's self-cleaning isolated target.

The guided-review repair keeps the public contract intact while closing seven implementation and consumer gaps. Receiver steps now reuse prepared per-file syntax/import contexts and bounded definition lookup, charge setup work, and stop preparing rows once the terminal output cap is satisfied. Candidate caps and provider budget exits remain explicit, diagnostic, top-level truncation states but no longer discard later rows or prevent `file_of`. Rust, REPL, Python, and VS Code presentations expose recursive values plus member, reason, and limit details. Capture bounds and `file_of` help come from the declarative schema. Factory-to-`CodeUnit` association and member-site extraction now each have one structured implementation path. Focused validation passes 31 receiver-related unit tests, 23 query-source tests, all 61 query-pipeline tests, Python's 41 tests, and all 54 VS Code tests; the complete publish gate remains the final step before the authorized pull request.

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

All commands run from `/Users/dave/.codex/worktrees/c2c4/bifrost` on the existing issue branch. Do not create or switch branches. Stage only files changed for the current milestone and make multiline checkpoint commits explaining the behavior and rationale. The user subsequently authorized pushing this branch and opening a non-draft pull request after the guided-review repairs and publish gate pass.

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

Revision note (2026-07-15): Completed Milestone 1 with a shared analyzer service, real work/truncation reports, exact factory wrapping, cancellation, unsupported-language results, and focused regression coverage.

Revision note (2026-07-15): Completed Milestone 2 with schema-v2 JSON/RQL operations, exact capture validation, a budgeted receiver-analysis terminal domain, all public result unions, editor/MCP metadata, and end-to-end JS/TS outcome/composition coverage. A review repair added explicit expression-versus-containing-site selection so unsupported shapes cannot be mistaken for receiver expressions.

Revision note (2026-07-15): Completed Milestone 3 with six exact executable receiver recipes, capability/query/client/safety documentation, a readable receiver-provider capability table, base-aware link validation, and fresh visual inspection of development and production builds.

Revision note (2026-07-15): Completed Milestone 4 by repairing exported-range and static-member factory regressions found by the full suite, then validating with a pinned Rust toolchain and the repository-managed isolated-target workflow.

Revision note (2026-07-15): Applied every confirmed guided-review finding: reusable and metered receiver setup, terminal-limit short-circuiting, nonhalting receiver truncation, complete recursive renderers, schema-driven capture validation and `file_of` metadata, exact factory association, and one shared member-site walk. Focused Rust, Python, and VS Code regressions pass; final publish validation is pending.

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
