# Add arbitrary-symbol reference traversal to query_code

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, a `query_code` structural match can be projected to an exact indexed declaration and traversed through source references. A user can return each exact reference site with its target, enclosing semantic user, proof, usage-surface classification, and reference kind; collapse those sites to the declarations that use the target; or traverse from a declaration to the exact indexed declarations it uses. Reference rows compose with `file_of`, so reference traversal can feed the existing direct import traversal.

The public operations are `references_of`, `used_by`, and `uses`. JSON and RQL lower to one schema-version-2 typed IR. Existing `scan_usages`, LSP references, rename, dead-code, and whole-workspace `usage_graph` behavior must remain unchanged. The implementation must use the existing tree-sitter/analyzer resolver structures and must not add regex, substring, delimiter-scanning, points-to, or name-only source fallbacks.

## Progress

- [x] (2026-07-14 15:00Z) Confirmed the issue branch is clean and exactly matches current `origin/master` at `9ce0857f` with issues #715 and #716 present.
- [x] (2026-07-14 15:00Z) Inspected the typed query IR/executor, schema-driven JSON/RQL help, result/provenance models, usage finder, targeted resolvers, inverted edge builders, clients, editor, and executable cookbook harness.
- [x] (2026-07-14 15:00Z) Created this implementation ExecPlan and fixed the public syntax, domains, result shape, exact-user semantics, language scope, and documentation shape.
- [x] (2026-07-14 17:10Z) Milestone 1: implemented the public reference-step IR, operation-specific schema, JSON/RQL parsing, `reference_site` result domain, provenance `via`, MCP/TextMate vocabulary, CLI/LSP routing, and Python consumer models.
- [x] (2026-07-14 19:05Z) Milestone 2: implemented cached exact inbound/outbound traversal across all eleven adapters, structured proof/surface/kind filtering, deterministic site identity and provenance, bounded partial-result semantics, reference-scan budget accounting, and focused cross-language/classification/failure tests without changing the legacy usage graph.
- [ ] Milestone 3: add the executable cross-language reference-traversal cookbook and update public documentation.
- [ ] Milestone 4: run focused and complete validation, review the full diff, fix findings, and record the final outcome.

## Surprises & Discoveries

- Observation: The Bifrost MCP code-navigation endpoints named by the installed skills are not exposed in this Codex task.
  Evidence: The active tool catalog contains no `search_symbols`, `get_symbol_sources`, or related Bifrost endpoint, so exploration uses the skills' prescribed targeted `rg` and exact-source fallback.

- Observation: `ReferenceKind`, `ReferenceHit`, and candidate types already exist in `src/analyzer/usages/model.rs`, but no current language resolver constructs a `ReferenceHit`.
  Evidence: repository-wide `rg ReferenceHit` finds only the type definition and re-export; targeted scanners directly construct `UsageHit`, while inverted scanners collapse resolved locations into `UsageEdges`.

- Observation: issue #716 has already made exact member/owner traversal available across every cookbook language.
  Evidence: current `QueryStep` contains hierarchy/member variants and every language tutorial is required by `tests/code_query_tutorials.rs` to execute `supertypes`, `subtypes`, `members`, and `owner`.

- Observation: The existing `get_definition` batch resolver is already a structured, tree-sitter-backed outbound reference resolver for all eleven languages and returns exact reference focus ranges plus exact `CodeUnit` candidates.
  Evidence: `parse_tree_for_language` dispatches every supported adapter and `resolve_definition_batch_with_source` preserves `Resolved`, `Ambiguous`, unsupported, and unresolved outcomes without source-text guessing.

- Observation: The requested all-feature focused test command currently fails to link the Python extension on this macOS environment because the linker cannot resolve Python symbols. Featureless focused Rust tests link and run successfully, while `cargo check --features nlp,python` succeeds.
  Evidence: `cargo test --features nlp,python --test code_query_pipelines` reached the dylib link and failed on `_Py*` symbols; the same pipeline tests without features pass.

- Observation: Java field access records its structured qualifier under `Role::Object`, while method calls use `Role::Receiver`.
  Evidence: the normalized Java extractor attaches `field_access.object` as `Role::Object`; using the operation-appropriate role makes `Base.FLAG` classify as `static_reference` without parsing source text.

- Observation: Reference traversal performs analyzer work beyond the structural seed scan and therefore must consume the same workspace limits even when its results deduplicate to few rows.
  Evidence: inbound candidate sets now charge files/source bytes and resolved candidates; outbound per-file scans charge files/source bytes/named leaves once at cache fill. A focused intermediate-domain test proves exhaustion returns no `reference_site` rows from a file-terminal query.

## Decision Log

- Decision: Keep CodeQuery schema version 2.
  Rationale: Reference traversal is an additive continuation of the typed pipeline; existing version-2 queries remain valid.
  Date/Author: 2026-07-14 / user and Codex

- Decision: Add `ReferenceSite` as a fourth pipeline domain. `references_of` maps declaration to reference site; `used_by` and `uses` map declaration to declaration; `file_of` additionally accepts reference sites.
  Rationale: This preserves explicit domains and lets exact sites compose with the existing inter-file query steps.
  Date/Author: 2026-07-14 / user and Codex

- Decision: `uses` selects only hits whose smallest exact enclosing declaration is the input declaration.
  Rationale: This makes `A uses B` and `B used_by A` inverse relations under the same filters. A caller can compose `members` then `uses` to include member bodies without recursively attributing nested declarations to an outer type.
  Date/Author: 2026-07-14 / user and Codex

- Decision: Every reference step accepts optional `reference_kinds`, `proof`, and `surface`; absent kind/proof means no filter, and absent surface means `external_usages`.
  Rationale: Existing external-usage behavior stays the quiet default while callers can explicitly request editor-visible imports/self receivers or one proof/kind tier.
  Date/Author: 2026-07-14 / user and Codex

- Decision: Add optional `via` to provenance steps.
  Rationale: `used_by` and `uses` terminate in declarations but must retain the exact reference site that proves the semantic edge.
  Date/Author: 2026-07-14 / user and Codex

- Decision: Deliver the first implementation for all eleven current usage analyzers and centralize full recipes in one cross-language Reference Traversal page.
  Rationale: A single query vocabulary should not silently vary by language; explicit capability diagnostics cover genuinely unsupported target shapes. Centralized recipes avoid duplicating large exact outputs across every language page.
  Date/Author: 2026-07-14 / user and Codex

- Decision: Implement outbound `uses` by batching the existing structured `get_definition` resolver over named tree-sitter leaf nodes once per file, then filter the cached exact hits by `enclosing_code_unit` identity.
  Rationale: This reuses the target resolver already maintained for every language, preserves exact `CodeUnit` identity and ambiguity, avoids a second language-specific resolution stack, and satisfies the required one-scan-per-file cache. The legacy graph builders remain unchanged and continue deriving their narrower class/callable edges independently.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

Milestones 1 and 2 are implemented. JSON and RQL canonicalize configured reference steps; reference sites serialize exact ranges, targets, optional exact enclosing declarations, proof, usage surface kind, and optional classification. Declaration-returning steps retain the exact site under `via`. The pipeline resolves exact inbound and outbound edges across Python, Java, JavaScript, TypeScript, Go, C/C++, Rust, PHP, Scala, C#, and Ruby. Focused Java cases prove all eight reference kinds, inverse `uses`/`used_by`, `file_of` composition, surfaces, proof tiers, and same-name-owner isolation. Reference scans are cached and charged to existing workspace/pipeline budgets; legacy `usage_graph` construction remains unchanged. Documentation and final full-suite validation remain.

## Context and Orientation

The public query IR lives under `src/analyzer/structural/query/`. `ir.rs` defines `CodeQuery`, `QueryStep`, and typed input/output validation. `schema.rs` is the only authority for visible query fields, forms, operations, spellings, signatures, descriptions, and constrained values. `decode.rs`, `json.rs`, and `sexp.rs` implement JSON decoding, canonical serialization, and RQL lowering. `source.rs` drives live validation, hover, and suggestions. Visible RQL vocabulary must also be recognized by `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

`src/analyzer/structural/search.rs` executes the syntax seed and typed steps. Internal rows currently hold structural matches, exact declaration/range pairs, or files plus bounded provenance. Terminal results are tagged `structural_match`, `declaration`, or `file`. This work adds an exact reference-site row and result. A `CodeUnit` is Bifrost's exact indexed declaration identity; FQN strings are display values and must never be serialized and resolved back into identities during execution.

The usage subsystem is under `src/analyzer/usages/`. `finder.rs` chooses candidate files and dispatches exact target queries. Each language has a targeted resolver/extractor used by `scan_usages` and an inverted scanner used by `usage_graph`. `model.rs` defines `UsageHit`, `UsageProof`, `UsageHitKind`, `UsageHitSurface`, `ReferenceKind`, and the currently unused `ReferenceHit`. Existing consumers expect `UsageHit` snippets and current surface filtering; structured reference traversal must adapt to that output rather than changing consumer behavior.

Documentation lives under `docs/src/content/docs/code-query-tutorials/`. `tests/code_query_tutorials.rs` turns marked fixture/RQL/JSON/expected blocks into an `InlineTestProject`, proves both syntaxes canonicalize identically, executes them, and compares complete serialized output. `import-traversal.md` is the existing cross-language model for the new `reference-traversal.md` page.

## Plan of Work

Milestone 1 adds the public contract and one Java vertical slice. Extend `QueryValueKind`, `QueryStep`, and canonical validation with `ReferenceTraversalFilter`. Add declarative operation-specific allowed fields and constrained values for reference kinds, proof, and surface. JSON uses `references_of`, `used_by`, `uses`, `reference_kinds`, `proof`, and `surface`; RQL uses their hyphenated spellings with options in any order before the nested query. Add the `reference_site` tagged result, exact range and declaration references, and optional provenance `via`. Update MCP schema/help, source diagnostics, TextMate grammar, CLI/REPL rendering, LSP/VS Code result unions, and Python models. Implement Java end to end to prove the internal design before widening it.

Milestone 2 establishes the analyzer-owned structured seam and widens it. Targeted inbound scans continue to use each language's exact target-aware resolver but produce structured hits before converting once to legacy `UsageHit` output. Outbound scans reuse each language's structured inverted resolution to return exact targets and site metadata before deriving the existing class/callable-only usage edges. Migrate Java/C#/Scala, then JavaScript/TypeScript/Python/Ruby, then Go/Rust/C++/PHP, committing after each verified cluster if the work is too large for one checkpoint. Cache inbound work by exact target and outbound work by file; filter outbound hits by exact enclosing `CodeUnit` for `uses`.

Reference-site identity is `(file, range, exact target, exact enclosing unit, proof, usage kind, optional reference kind)`. Filter first by the requested `UsageHitSurface`, then proof and reference kind. An absent kind filter includes unclassified hits; a supplied kind filter excludes them. Ambiguous candidates may be emitted only as `unproven` with a diagnostic. Unsupported, unresolved-without-an-exact-target, cancelled, candidate-truncated, and too-many-callsite outcomes remain distinct internally and become deterministic diagnostics/truncation behavior. Cancellation returns no partial edges. Terminal truncation may return a bounded terminal set; truncation before later steps must not serialize a value of the wrong domain.

Milestone 3 adds `reference-traversal.md` with executable cases for all field/property usages, field writes, declarations used by a selected method, `members -> uses`, external versus editor surfaces, reference-to-file/import composition, and same-name unrelated-owner negatives. Include a cross-language support matrix covering all eleven adapters, add a focused test for the page, link it from the tutorial index and language pages, update Import Traversal's former future boundary, and revise the reference docs, READMEs, MCP/Python-client docs, and installed skills.

Milestone 4 runs the complete validation bundle and reviews the diff for text parsing, fallback guesses, exact-identity loss, incorrect proof promotion, unbounded scans, duplicate schema vocabulary, stale public unions, and changed legacy usage surfaces. Fix every finding, update this plan, and commit the reviewed result.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/b010/bifrost`. Keep the current branch; do not create or switch branches. Stage only files changed in the milestone and make multiline checkpoint commits explaining behavior and rationale.

Focused implementation checks should include:

    cargo fmt
    cargo test --features nlp,python --test code_query_pipelines --test code_query_tutorials --test code_query_docs --test bifrost_tool_cli
    npm --prefix editors/vscode test
    bash scripts/test_python.sh
    git diff --check

Final validation is:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python
    bash scripts/test_python.sh
    npm --prefix editors/vscode test
    npm --prefix docs run check
    npm --prefix docs run build
    git diff --check

## Validation and Acceptance

Parser and source-analysis tests must prove JSON/RQL equivalence, option ordering, duplicate and unknown fields, all constrained values, invalid domains, canonical output, exact diagnostic ranges, hover/suggestions, MCP exhaustiveness, and grammar coverage.

Pipeline tests must prove every transition, exact reference-site serialization, `via` provenance, `file_of` composition, deterministic deduplication, trace caps, exact semantic-user behavior, `members -> uses`, field read/write filtering, proof filtering, external/editor surfaces, same-name unrelated-owner negatives, exact module-scoped identities, mixed languages, unsupported targets, ambiguity, truncation, budgets, and cancellation.

Every language adapter must have at least one exact inbound and outbound reference test. Across the suite, cover method and constructor calls, field reads and writes, type/static/super/inheritance references where analyzers expose them, overloads, imports, self receivers, and unproven candidates. Existing `scan_usages`, LSP references, rename, dead-code, and `usage_graph` regressions must remain green.

The new cookbook page must execute every marked JSON and RQL query and compare complete exact output. Astro check/build and a fresh rendered preview must pass.

## Idempotence and Recovery

Tests use temporary inline projects and are safe to rerun. Query execution reads analyzer snapshots and does not mutate source workspaces. Keep the ExecPlan current at every stop. If a language exposes a real structured capability gap, record the exact evidence and emit a capability diagnostic; do not hide it with text search. If a checkpoint fails, retain the working tree and repair the root cause rather than resetting unrelated changes.

## Interfaces and Dependencies

The public IR adds conceptually:

    pub struct ReferenceTraversalFilter {
        pub reference_kinds: Vec<ReferenceKind>,
        pub proof: Option<UsageProof>,
        pub surface: UsageHitSurface,
    }

    pub enum QueryStep {
        ReferencesOf(ReferenceTraversalFilter),
        UsedBy(ReferenceTraversalFilter),
        Uses(ReferenceTraversalFilter),
        // existing variants remain
    }

`CodeQueryResultValue` and `CodeQueryResultRef` gain `ReferenceSite`. `CodeQueryProvenanceStep` gains an optional `via: CodeQueryResultRef`. No new external dependency is required.

Revision note (2026-07-14): Created the implementation-ready ExecPlan from issue #717, the accepted plan, current issue-715/716 implementation, usage-analysis architecture, and cookbook harness.

Revision note (2026-07-14): Recorded the completed public-contract and all-adapter traversal milestones, the structured outbound-resolver decision, classification details, budget behavior, and the macOS Python-linker limitation discovered during focused validation.
