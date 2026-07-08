# Improve Ranking for Noisy Broad Symbol Searches

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](../../.agents/PLANS.md).

## Purpose / Big Picture

After this change, `search_symbols` should stop surfacing weak or noisy matches ahead of the likely target when the query is broad, short, or repeated across many files. A user should be able to search for `ffDetectBootmgr` or `Bootmgr` and see the implementation file and the most actionable declarations first, instead of bouncing through broad utility files, headers, tests, or generated output. The proof is a focused C/C++ fixture suite plus service-level tests that show exact matches beat partial matches, implementation files beat prototypes, and recent git activity only breaks ties.

## Progress

- [x] (2026-06-09T23:33:00Z) Re-read `.agents/PLANS.md`, inspected the current `search_symbols` pipeline in `src/searchtools.rs`, the service wrapper in `src/searchtools_service.rs`, and the persisted symbol query path in `src/analyzer/persistence/storage.rs`.
- [x] (2026-06-09T23:33:00Z) Confirmed that persisted FTS rank is discarded today because `search_definitions` results are materialized into `BTreeSet<CodeUnit>`, so relevance ranking must be rebuilt in `searchtools`.
- [x] (2026-06-10T00:12:00Z) Added an internal ranking layer for `search_symbols` candidate and file ordering, keeping the public request and response shapes unchanged.
- [x] (2026-06-10T00:12:00Z) Added focused ranking tests with `InlineTestProject`, plus a service-level test proving exact relevance beats a hotter partial-match file while keeping the git tie-break path intact.
- [x] (2026-06-10T00:12:00Z) Ran `cargo test --test searchtools_fuzzy_symbol_lookup --test searchtools_service`, `cargo test --lib search_symbols_renders_markdown_with_structured_fields`, `cargo fmt --all`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Cut the checkpoint commit with a multiline rationale covering the new ranking tiers, the path/test heuristics, and the git tie-break role.

## Surprises & Discoveries

- Observation: the current `search_symbols` implementation does not rank by symbol relevance at all after collecting matches; it groups by file, then truncates by `most_important_project_files`, which is driven by recent git activity rather than match strength.
  Evidence: `src/searchtools.rs::search_symbols` currently calls `select_files_for_display(...)` after grouping raw matches and before rendering.

- Observation: the persisted FTS query already has a rank in SQLite, but that order is lost before `search_symbols` sees it.
  Evidence: `src/analyzer/persistence/storage.rs::search_symbols_inner` orders SQL rows by `rank`, while `src/analyzer/tree_sitter_analyzer.rs::search_definitions_persisted` inserts the hits into a `BTreeSet<CodeUnit>`, which reorders them by package, name, kind, file, and signature.

- Observation: request-context file boosting is not available in the current service path.
  Evidence: `src/searchtools_service.rs::decode_render_and_run` deserializes only tool params and passes `&WorkspaceAnalyzer` plus those params to `search_symbols`; there is no prompt or recent-tool-call context object in that path.

- Observation: a plain lowercase substring check is not enough for short identifier ranking because it loses camel-case boundaries such as `ffDetectBootmgr`.
  Evidence: the first ranking implementation still let `BootmgrSupportName` outrank `ffDetectBootmgr` for the `Bootmgr` query until the scorer switched to camel-case-aware component matching.

- Observation: relying only on analyzer-driven `contains_tests` misses some clearly test-scoped files, so path heuristics are needed for symbol-search filtering and ranking.
  Evidence: the first test fixture with `tests/bootmgr_test.cpp` still appeared in `include_tests=false` results until `search_symbols` added a file-path-based test heuristic.

## Decision Log

- Decision: implement ranking entirely inside `src/searchtools.rs` for this change.
  Rationale: it is the smallest place that has both the full match set and the tool-specific output grouping. Changing the analyzer storage path alone would not survive the `BTreeSet<CodeUnit>` boundary.
  Date/Author: 2026-06-09 / Codex

- Decision: keep the `search_symbols` JSON shape stable and change only result ordering.
  Rationale: the user asked for better ranking, not a new interface, and the existing grouped `SearchSymbolsFile` structure is already consumed by render tests and service/MCP boundaries.
  Date/Author: 2026-06-09 / Codex

- Decision: defer prompt/recent-call file boosting even though it would be useful.
  Rationale: the current service path does not expose that context, so adding it would be a separate additive API plumbing change that is larger than the ranking fix requested here.
  Date/Author: 2026-06-09 / Codex

- Decision: keep candidate ranking entirely post-retrieval and use the existing analyzer search as the recall layer.
  Rationale: changing retrieval was unnecessary for the requested behavior, and the scorer can reorder broad result sets without affecting other analyzer callers.
  Date/Author: 2026-06-10 / Codex

- Decision: supplement `analyzer.contains_tests(file)` with a path-based test heuristic inside `search_symbols`.
  Rationale: symbol search needs predictable source-vs-test behavior even when a file lacks test framework syntax but clearly lives under `tests/` or has a `_test`/`spec` style filename.
  Date/Author: 2026-06-10 / Codex

- Decision: use a bounded path-affinity boost and camel-case-aware component matching for broad identifier queries.
  Rationale: this lets `Bootmgr` favor symbols in the Bootmgr feature area and treat `ffDetectBootmgr` as a meaningful component match, without letting file paths overpower exact symbol-name matches.
  Date/Author: 2026-06-10 / Codex

## Outcomes & Retrospective

Implementation outcome 2026-06-10T00:12:00Z: `search_symbols` now ranks by symbol relevance first and uses recent git activity only as a later tie-breaker. Exact and component-level identifier matches beat weaker substring hits, C/C++ implementation definitions beat prototypes, normal source beats test/generated paths, and broad utility files no longer displace a focused feature file simply because they contain many noisy matches. The public JSON shape did not change; only result ordering and the render note changed.

## Context and Orientation

`search_symbols` lives in `src/searchtools.rs`. It currently strips empty patterns, unions `analyzer.search_definitions(pattern, false)` results into a `BTreeSet<CodeUnit>`, filters out test files when `include_tests=false`, groups the remaining declarations by source file, then calls `select_files_for_display(...)` to keep only the requested limit. `select_files_for_display(...)` delegates to `most_important_project_files(...)` in `src/relevance.rs`, which uses recent git history to score files. That behavior is useful as a tie-breaker, but it is not symbol relevance.

`SearchSymbolsResult`, `SearchSymbolsFile`, and `SearchSymbolHit` are the public response types. They are rendered into markdown by `src/searchtools_render.rs`, which currently tells the user that truncated results are selected by recent activity and displayed alphabetically. That text must be updated to match the new ranking behavior.

The analyzer model is defined in `src/analyzer/model.rs`. `CodeUnit` exposes `identifier()`, `short_name()`, `fq_name()`, `kind()`, `signature()`, `is_synthetic()`, and the source `ProjectFile`. Those fields are sufficient to implement ranking without changing the analyzer API. For C/C++, display signatures already distinguish definitions from declarations by ending function definitions with `{...}` and declarations/prototypes with `;`, which makes implementation-vs-prototype ranking available in `searchtools` without another analyzer change.

Tests already cover symbol search and fuzzy lookup in `tests/searchtools_fuzzy_symbol_lookup.rs`, render behavior in `src/searchtools_render.rs`, and service-level tool behavior in `tests/searchtools_service.rs`. Small ad hoc fixtures should use `tests/common/inline_project.rs`.

## Plan of Work

Start in `src/searchtools.rs` by introducing internal ranking helpers. Add a query classifier that distinguishes literal identifiers, literal qualified names, and regex-like patterns. For each `CodeUnit` candidate that survives the existing pattern search and test filtering, compute a best-match score across all requested patterns. The score should prefer exact identifier matches, then exact short-name matches, then exact fully qualified matches, then prefix and token/component matches, and finally weaker substring/regex-only matches. Add path-quality tie-breakers so normal source files beat tests and generated/vendor/build-output files. Add implementation-quality tie-breakers so C/C++ definitions in source files beat prototypes in headers when both match the same query. Keep non-synthetic declarations ahead of synthetic ones.

Once candidates are ranked, group them by file without losing that candidate order. Replace the current `select_files_for_display(...)` call in `search_symbols` with file ranking derived from the top few candidates in each file. File ranking should use the best three candidate scores, a cohesion bonus when those top hits are near each other in line space, a penalty for broad utility files with many weak matches, and recent git importance only as a later tie-breaker. After sorting files by that score, truncate to the requested limit. Within each file, build the existing `classes`, `functions`, `fields`, `modules`, and `macros` buckets by walking the already ranked candidates, not by sorting signatures alphabetically.

Update `src/searchtools_render.rs` so the truncation note says results are relevance-ranked and that recent activity is only used as a tie-breaker when available. Leave the rest of the render shape alone.

Finish by adding tests. In `tests/searchtools_fuzzy_symbol_lookup.rs`, add a C/C++ fixture with a real implementation file, a header prototype, partial-name noise, a test file, and a generated-path file. Assert that `search_symbols(["ffDetectBootmgr"])` ranks the implementation file first and that `search_symbols(["Bootmgr"])` favors concrete declarations over generic mentions. In `tests/searchtools_service.rs`, keep one service test proving git history still wins when search relevance is otherwise equal, and add another proving an exact symbol match beats a hotter but only partial-match file.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, implement and validate the change with:

    cargo test --test searchtools_fuzzy_symbol_lookup --test searchtools_service
    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings

Expected signs of success:

    search_symbols(["ffDetectBootmgr"]) returns `src/detection/bootmgr/bootmgr_apple.c` before `src/detection/bootmgr/bootmgr.h`
    search_symbols(["Bootmgr"]) ranks files with real Bootmgr declarations ahead of broad utility or generated files
    the service-layer truncation note no longer claims files are selected only by recent activity
    the existing git tie-break test still passes for an intentionally relevance-tied query

This section will be updated with actual command transcripts after the implementation is complete.

Actual results recorded 2026-06-10T00:12:00Z:

    cargo test --test searchtools_fuzzy_symbol_lookup --test searchtools_service
    test result: ok. 15 passed ... in searchtools_fuzzy_symbol_lookup
    test result: ok. 33 passed ... in searchtools_service

    cargo test --lib search_symbols_renders_markdown_with_structured_fields
    test result: ok. 1 passed; 0 failed

    cargo fmt --all
    <no output; completed successfully>

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile ... target(s) in 21.37s

## Validation and Acceptance

Acceptance is behavioral. A human should be able to run the focused searchtools and service tests and see that broad searches converge on the likely target instead of surfacing weak textual matches first. The new tests should fail before the ranking change and pass after it. For exact `ffDetectBootmgr`, the implementation file must outrank the header prototype and any partial/noisy matches. For broad `Bootmgr`, concrete declarations and definitions must outrank generic utility names or generated-path matches. When the limit truncates otherwise equal candidates, recent git activity may still break ties.

## Idempotence and Recovery

These are source-only edits and are safe to reapply. If the ranking change causes unexpected file order in unrelated tests, inspect whether the new comparator is using unstable iteration order from a hash collection and add an explicit stable path or line tie-breaker. If the git-based tie-break test becomes flaky outside a git repository, keep it on a temporary repo fixture as the existing service test already does. Do not revert unrelated working-tree changes.

## Artifacts and Notes

The key implementation evidence to preserve is:

    `src/searchtools.rs::search_symbols` no longer calls `select_files_for_display(...)` for its primary ranking path
    file ranking uses candidate relevance first and git history only later
    the new C/C++ fixture shows the implementation file beating the header prototype for `ffDetectBootmgr`

The focused tests should stay small and inline so ranking failures are easy to inspect in the assertion output.

## Interfaces and Dependencies

No public interface changes are required for this change. At the end of the implementation:

    pub struct SearchSymbolsResult {
        pub patterns: Vec<String>,
        pub truncated: bool,
        pub total_files: usize,
        pub files: Vec<SearchSymbolsFile>,
    }

and:

    pub struct SearchSymbolsFile {
        pub path: String,
        pub loc: usize,
        pub classes: Vec<SearchSymbolHit>,
        pub functions: Vec<SearchSymbolHit>,
        pub fields: Vec<SearchSymbolHit>,
        pub modules: Vec<SearchSymbolHit>,
        pub macros: Vec<SearchSymbolHit>,
    }

must remain unchanged. The new ranking data should stay internal to `src/searchtools.rs`.

Revision note 2026-06-09T23:33:00Z: Created this ExecPlan before implementation because the change affects search ranking semantics, service render text, and acceptance tests without altering the public result shape.
Revision note 2026-06-10T00:12:00Z: Updated the ExecPlan after implementation and validation to record the final ranking heuristics, the added test/path heuristics, the camel-case component fix, and the passing command evidence.
