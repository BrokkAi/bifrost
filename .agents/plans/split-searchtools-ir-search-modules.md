# Split searchtools.rs, semantic/ir.rs, and structural/search.rs along their real module boundaries

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Three of the repository's largest source files each contain more than one genuine abstraction cohabiting for historical reasons, and their size is now a tax on every edit (the #1057 work touched two of them). After this change, each file becomes a module directory whose children mirror the boundaries that already exist in the code, with the parent `mod.rs` re-exporting the exact previous public surface so that **no file outside the split module changes**. This is a pure code-motion refactor: no behavior change, no API change, no logic edits. Success is observable as: the same test suites pass before and after, `cargo clippy --all-targets --all-features -- -D warnings` stays clean, and no consumer file appears in the diff.

The three targets and their real seams:

1. `src/searchtools.rs` (9,056 lines) — several independent MCP tool families (scan_usages, symbol sources, summaries, definitions-by-reference, search/navigation) plus a shared selector-resolution core, all in one file with repo-wide fan-in.
2. `src/analyzer/semantic/ir.rs` (6,643 lines) — the semantic IR type contract, a `validate_*` checker family that is an algorithm *over* that contract, and 2.1k lines of inline tests.
3. `src/analyzer/structural/search.rs` (11,001 lines) — the CodeQuery result/diagnostic contract consumed by rendering and policy layers, the query execution engine, and 2.9k lines of inline tests.

## Progress

- [x] M1 — Split `src/searchtools.rs` into `src/searchtools/` by tool family plus a shared resolution core. Not yet committed (commit pending explicit request per repo convention). Final shape: `mod.rs` (473L: imports, constants, module declarations, internal cross-family hoists, the explicit `pub`/`pub(crate)` re-export list, and the handful of genuinely cross-family items — `RefreshParams`/`ActivateWorkspaceParams`/`GetActiveWorkspaceParams`/`RefreshResult`/`ActiveWorkspaceResult`/`refresh_result`, `resolve_file_patterns` + friends, `primary_range`, `code_unit_kind_name`, `line_count`, `default_limit`, `is_glob_pattern`), `scan_usages.rs` (3227L), `navigation.rs` (1608L), `selectors.rs` (1101L), `summaries.rs` (1080L), `sources.rs` (727L), `definitions.rs` (354L), `tests.rs` (722L, unwrapped per the `structural/query/tests.rs` precedent). Validation green: `cargo fmt` clean, `cargo clippy --all-targets --all-features -- -D warnings` clean, all 7 required suites pass (959 tests total, 1 pre-existing `--ignored` smoke test), `git status --short` shows only the searchtools move plus this plan file.
- [ ] M2 — Split `src/analyzer/semantic/ir.rs` into `src/analyzer/semantic/ir/` (contract / validate / tests); commit.
- [ ] M3 — Split `src/analyzer/structural/search.rs` into `src/analyzer/structural/search/` (results contract / engine / expansions / tests); commit.
- [ ] Final: merge `origin/master` into local, re-validate, push to `origin/master`.

## Surprises & Discoveries

- Observation: the receiving side of two splits already follows the target conventions, so the refactor extends existing patterns rather than inventing them.
  Evidence: `src/analyzer/semantic/mod.rs:23` is `pub use ir::*;` (the ir surface is already glob-re-exported, so an `ir/mod.rs` that re-exports its children changes nothing for the ~15 consumer files); `src/analyzer/structural/query/` already contains a dedicated `tests.rs` child module.

- Observation (M1): a handful of "definition candidate" rendering primitives (`DefinitionCandidateRenderCache`, `definition_candidate`/`definition_candidates`/`*_with_cache`, `definition_candidate_from_range`, `definition_candidate_key`, `declaration_kind_name`, `lexical_definition_candidate`, plus `DefinitionCandidate`/`DefinitionCandidateKey`/`DefinitionOutcomeKey`/`DefinitionDiagnostic`) are called from **both** `navigation.rs` (the by-location renderers `render_definition_lookup`/`render_type_lookup`) and `definitions.rs` (the by-reference renderer `render_definition_reference_lookup`/`semantic_outcome_key`) — they are not family-specific despite living textually between the two call sites in the original file. Placed in `selectors.rs` (see Decision Log). Verified precisely by cross-referencing which bucket's generated file textually invoked which other bucket's names (build script + `\b`-boundary regex over a string/comment-aware lexer, to rule out doc-comment mentions), not by guesswork.
- Observation (M1): converting a directly-declared `pub(crate)` item into a `pub(crate) use child::Item;` re-export can newly trip `unused_imports` in a `cargo clippy --all-targets` "lib-only" (non-test) sub-compilation, even though the item compiled warning-free at its original definition site. Rust's `dead_code` lint is exempt for any item with `pub`/`pub(crate)`/`pub(super)` visibility (assumed reachable from outside the current translation unit), but `unused_imports` is not exempt for `pub(crate) use` specifically, since the compiler can fully verify crate-wide reachability. `ScanUsagesSurface` hit this: its only real consumer is the moved `#[cfg(test)] mod tests`, which the "lib" sub-target compiles without `cfg(test)`. Fixed with a scoped, commented `#[allow(unused_imports)]` on that one re-export line rather than dropping the re-export (dropping it would violate the "identical previous surface" contract).
- Observation (M1): struct/enum field privacy does not travel with a blanket item-level `pub(super)` widening. Two structs (`SummaryTargets`, `UsageHitRow`) had private fields that the moved test module constructs via struct-literal syntax from a sibling child module; Rust's field privacy is independent of the struct's own visibility, so each field needed its own `pub(super)` bump (enum variant fields do not have this problem — variant fields always share the enum's own visibility).

## Decision Log

- Decision: hard review contract for all three milestones — the diff must contain **zero changes outside the split module's directory** (plus the deleted original file). Every consumer keeps compiling against the same paths because the new `mod.rs` re-exports the previous public surface verbatim.
  Rationale: this is what makes a 9–11k-line move reviewable at all: the reviewer checks the re-export list and the compile/test gates instead of re-reading moved code. Fan-in is large (`searchtools::` is imported by ~20+ files across src/ and tests/).
  Date/Author: 2026-07-22 / Claude (approved scope by Jonathan: these three files, in this order)

- Decision: pure move only — no renames, no signature changes, no visibility narrowing, no drive-by cleanups. Visibility may only be *widened* where the move requires it (`pub(super)`/`pub(crate)` on items that were file-private and are now referenced across sibling child modules), and each such widening should be the minimum that compiles.
  Rationale: mixing refactor-by-motion with refactor-by-edit destroys the reviewability property above and turns a safe change into a risky one.
  Date/Author: 2026-07-22 / Claude

- Decision: inline `#[cfg(test)] mod tests` blocks move to a child `tests.rs` (`#[cfg(test)] mod tests;`) inside the new directory, not to `tests/`.
  Rationale: these are unit tests exercising private items; a child module keeps `super::*` access working unchanged. `structural/query/tests.rs` is the in-repo precedent.
  Date/Author: 2026-07-22 / Claude

- Decision (M1): `tests.rs`'s content is the *unwrapped* body of the original `mod tests { ... }` block (attribute moved to the `#[cfg(test)] mod tests;` declaration in `mod.rs`, braces and one level of indentation removed), not the block re-wrapped inside the file.
  Rationale: `mod tests;` in `mod.rs` already establishes the `tests` module from the file's contents; keeping an inner `mod tests { ... }` would nest it twice (`searchtools::tests::tests`) and break every `super::` reference in the test body. Matches the `structural/query/tests.rs` precedent exactly (no wrapper there either).
  Date/Author: 2026-07-22 / Claude

- Decision (M1): the shared "definition candidate" rendering core (see Surprises) goes into `selectors.rs` alongside the selector-resolution functions, not into `navigation.rs` or `definitions.rs`.
  Rationale: it is consumed by both families; `selectors.rs` is the designated shared-resolution-core file per the plan's target shape, and splitting a `CodeUnit -> DefinitionCandidate` renderer from the `CodeUnit` resolution it operates on would force one consumer to depend on the other's file for no benefit.
  Date/Author: 2026-07-22 / Claude

- Decision (M1): `most_relevant_files`/`list_symbols`/`skim_files_for_files` and their param/result types, plus `classify_test_files` and its supporting types, are treated as "satellites" of `summaries.rs` and `scan_usages.rs` respectively (not split into their own files), per the plan's explicit allowance for family membership judgment calls.
  Rationale: `most_relevant_files`/`list_symbols` operate on the same file-skim/relevance machinery as `get_summaries` and sit textually and functionally alongside it; `classify_test_files` (`TestFileKind`, `classify_resolved_test_file`, `is_generated_like_path`) exists to support `scan_usages`'s `excluded_test_files`, its only production caller.
  Date/Author: 2026-07-22 / Claude

- Decision (M1): cross-family production code reaches a sibling child via a glob `use super::<sibling>::*;` at the top of each child file (in addition to `use super::*;` for the parent's own imports/constants), rather than curated per-function explicit import lists.
  Rationale: every one of the ~365 moved top-level names is guaranteed unique (they all lived in one flat namespace before the split), so glob imports cannot collide; this keeps the six child files simple and avoids hand-maintaining large explicit lists that would need updating on every future addition. `mod.rs` itself still uses **explicit, one-name-per-line** `pub use` / `pub(crate) use` statements for the true external (previous file-level) surface, per the hard rule 3 in the Decision Log above — the glob convenience only applies to the new internal sibling-to-sibling wiring this split introduces.
  Date/Author: 2026-07-22 / Claude

- Decision (M1): `mod.rs` additionally carries a small `#[cfg(test)]`-gated block of plain (non-`pub`) `use child::{...};` imports, purely so the moved, textually-unedited `tests.rs` keeps resolving the handful of names it reaches via a bare `super::name` path (mirroring how those names were reachable from the nested `mod tests` in the original flat file). This is separate from, and additional to, the external `pub`/`pub(crate)` re-export list.
  Rationale: rule 2 requires `tests.rs`'s moved content to be byte-identical text; satisfying its existing `super::name` references without editing them requires `mod.rs` to re-expose those specific names in its own namespace. Gating the block behind `#[cfg(test)]` avoids `unused_imports` in non-test builds, since these names have no other consumer through `crate::searchtools::`.
  Date/Author: 2026-07-22 / Claude

## Outcomes & Retrospective

Nothing yet recorded. Fill in per milestone.

## Context and Orientation

All paths are relative to the repository root. Rust module facts this plan relies on: (a) converting `foo.rs` into `foo/mod.rs` plus child files is invisible to consumers as long as `mod.rs` declares the children and re-exports the same names; (b) child modules can access the parent module's private items via `super::`, so unit tests moved into a child `tests.rs` keep working; (c) items moved into one child and used by a sibling child need at least `pub(super)` visibility — this is the only category of edit allowed beyond pure motion.

The three files' internal structure (measured 2026-07-22 with the `get_summaries` tool):

`src/searchtools.rs`: 116 top-level types, 230 free functions, 732-line inline test module. The tool families and their anchors: scan_usages (`scan_usages_backend` ~385L, `usage_graph`, `resolve_scan_usages_target`, types `ScanUsagesEntry`/`SymbolUsages`/`AmbiguousUsageSymbol`/`UsageLocation`/`ScanUsagesWorkEntry`, `filter_and_dedupe_hits`, `ambiguous_usage_symbol_from_groups`); symbol sources (`get_symbol_sources`, `resolve_file_anchored_symbol_sources`, `SourceLookupOutcome`, `SymbolSourcesResult`); summaries (`get_summaries`, `route_summary_targets`, `summarize_symbol_targets`, `SummaryTargets`, `ContainerListing*`, `SummaryResult`); definitions-by-reference (`resolve_definition_context_symbol`, `group_definition_context_symbols`, `resolve_definition_context_query`, `DefinitionDiagnostic`, the `DefinitionByReference*` types); search/navigation (`search_symbols`, `get_navigation_by_location`, `get_type_by_location`); and the shared resolution core that #1057 just worked in (`split_definition_selector`, `split_path_qualified_definition_selector`, `resolve_selectable_definitions`, `distinct_definitions`, `definition_selector`, `file_anchored_definition_selector`, `code_unit_match_names`, `exact_codeunit_resolution`, `exact_then_fuzzy_codeunit_resolution`, `anchor_scoped_codeunit_resolution`, `AmbiguousSymbol`, `prefer_exact_lookup_matches`, the not-found input builders). Some helpers are genuinely cross-family (limits/constants, path/file-pattern resolution, rendering glue consumed by `searchtools_render.rs`); a `common.rs` (or keeping them in `mod.rs`) is acceptable — cohesion over forced symmetry. Consumers to keep untouched include `src/searchtools_service.rs`, `src/searchtools_render.rs`, `src/mcp_core.rs`, `src/mcp_property_fuzzer/`, `src/nlp/`, `src/commit_analysis.rs`, bins, and ~15 test files.

`src/analyzer/semantic/ir.rs`: 48 types (the IR contract: `SemanticEffect`, `ProcedureSemantics`, `SemanticCallSite`, `CaptureBinding`, error kinds, etc.), a `validate_*` free-function family (~2.5kL: `validate_events` 395L, `validate_gap_subject`, `validate_procedure`, `validate_callable_value`, `validate_capture_row`, `measure_artifact_work`, ...), and a 2.1kL test module. `src/analyzer/semantic/mod.rs` re-exports `pub use ir::*;` already.

`src/analyzer/structural/search.rs`: 77 mostly-small types (the CodeQuery result/diagnostic contract: `CodeQueryResult*`, `CodeQueryMatch`, `CodeQueryDiagnosticCode`, `CodeQueryReceiver*`, `DetailedCodeQueryKey`, ...), the execution engine (`execute_plan` 408L, `execute_seed`, `execute_parallel_seed_union`, `apply_pipeline_step` 515L, `apply_plan_step`, `execute_internal_with_strategy`, `QueryExecutionState`), graph-traversal expansion primitives (`inbound_reference_expansions` 299L, `scan_outbound_reference_hits`, `call_declaration_expansions`), and a 2.9kL test module. External consumers: `src/lsp/server.rs` (`execute_request_with_cancellation`), `src/analyzer/policy/evaluator.rs`, `src/analyzer/structural/execution/benchmark.rs`, plus siblings in `structural/`.

## Plan of Work

### M1 — `src/searchtools.rs` → `src/searchtools/`

Create `src/searchtools/mod.rs` (start as a `git mv` of the original for history), then extract child modules along the family boundaries above; suggested shape (the implementer may adjust membership where cohesion demands, recording deviations): `scan_usages.rs`, `sources.rs`, `summaries.rs`, `definitions.rs` (the by-reference surface), `navigation.rs` (search_symbols + location navigation), `selectors.rs` (the shared resolution core), `tests.rs`. `mod.rs` keeps: module declarations, the re-export block reproducing the previous public/pub(crate) surface, and whatever genuinely-shared small items don't belong to any family. Widen visibility only as needed for cross-child references. Zero edits outside `src/searchtools/`.

Validation: `cargo fmt`; `cargo clippy --all-targets --all-features -- -D warnings`; `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --test searchtools_definition_selectors --test searchtools_service --test searchtools_summary_ranges --test searchtools_fuzzy_symbol_lookup --test searchtools_list_symbols --test get_definition_test --test mcp_property_fuzzer_service`. Confirm `git status` shows only `src/searchtools.rs` → `src/searchtools/*`.

### M2 — `src/analyzer/semantic/ir.rs` → `src/analyzer/semantic/ir/`

`ir/mod.rs` = the type contract (types, their impls, ids/serde glue), re-exporting `validate` items so `semantic::ir::validate_*` paths and the existing `pub use ir::*` in `semantic/mod.rs` keep resolving; `ir/validate.rs` = the `validate_*`/`measure_*` family; `ir/tests.rs` = the moved test module. Zero edits outside `src/analyzer/semantic/ir/`.

Validation: fmt, clippy as above; `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --test semantic_language_conformance` plus `cargo test --features nlp,python --lib semantic` (unit tests moved with the module) and any suite grep finds importing `semantic::ir`.

### M3 — `src/analyzer/structural/search.rs` → `src/analyzer/structural/search/`

`search/mod.rs` = the engine (plan execution + pipeline steps + entry points, kept together — they are one algorithm) plus module declarations and re-exports; `search/results.rs` = the result/diagnostic type contract; `search/expansions.rs` = the reference-expansion traversal primitives; `search/tests.rs` = the moved test module. Zero edits outside `src/analyzer/structural/search/`.

Validation: fmt, clippy as above; run the CodeQuery/structural suites (locate via `rg -l "structural::search|execute_request" tests/`) plus `--test searchtools_service` (the query tools route through this) and the policy evaluator's consuming tests.

### Final

Merge `origin/master` into local, re-run clippy plus the union of the suites above on the merged tree, push to `origin/master`.

## Idempotence and Recovery

Each milestone is a self-contained commit; if a milestone's gates fail, fix forward within the module directory or revert that single commit. Never rewrite pushed history. If `origin/master` moves under us mid-work, merge (do not rebase) and re-validate.

## Interfaces and Dependencies

No new dependencies. No public-surface changes: for each split module, the set of names reachable at the old paths (`crate::searchtools::X`, `crate::analyzer::semantic::ir::X`, `crate::analyzer::structural::search::X`) must be identical before and after — that identity, enforced by zero-consumer-edits plus green compile, is the acceptance contract.
