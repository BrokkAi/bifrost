# Fix C/C++ Empty Symbol Views with Macro Indexing and Summary Fallback

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](../../.agents/PLANS.md).

## Purpose / Big Picture

After this change, exact C and C++ file targets stop looking empty when they contain useful navigation structure that the analyzer previously skipped. A user can point `list_symbols`, `get_symbol_sources`, and `get_summaries` at small `.c` and `.h` files and see function definitions, prototypes, typedef-like declarations, and macros. If a requested file genuinely has no indexed declarations, `get_summaries` still returns something useful: first top-level includes, and then the first twenty lines of the file if there are no includes either.

The proof is a focused inline C/C++ fixture suite. `list_symbols` should surface source-file functions and header macros, `get_symbol_sources(["ffDetectBootmgr"])` should return the function body, `get_symbol_locations(["FF_CODEC_UNKNOWN"])` should resolve to the macro definition line, and `get_summaries(["only_includes.h"])` should return fallback include or excerpt elements instead of `summaries: []`.

## Progress

- [x] (2026-06-09T22:40:00Z) Read `.agents/PLANS.md`, reviewed the current C++ declaration walker, persistence encoding, searchtools summary path, and existing analyzer/searchtools tests.
- [x] (2026-06-09T23:14:00Z) Added `CodeUnitType::Macro`, wired the new kind through persistence, autocomplete ordering, file-tool labels, LSP symbol/completion mappings, and created this ExecPlan.
- [x] (2026-06-09T23:14:00Z) Extended `src/analyzer/cpp/declarations.rs` so pointer-returning function definitions and prototypes classify as functions, typedef/alias declarations are indexed, and `preproc_def` / `preproc_function_def` become macro declarations.
- [x] (2026-06-09T23:14:00Z) Taught searchtools to group and render macros, added `fallback_reason` to file summaries, and implemented `declarations -> includes -> first 20 lines` fallback for exact file targets with no indexed declarations.
- [x] (2026-06-09T23:14:00Z) Added focused analyzer/searchtools/service tests with `InlineTestProject`, ran `cargo test --test searchtools_list_symbols --test cpp_analyzer_test --test searchtools_fuzzy_symbol_lookup --test searchtools_summary_ranges --test searchtools_service`, `cargo fmt --all`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Cut the checkpoint commit with a multiline rationale covering the analyzer classification change, macro indexing, and file-summary fallback behavior.

## Surprises & Discoveries

- Observation: the current C++ declaration walker explicitly skips `type_definition` and `alias_declaration`, so type-only headers can vanish from file summaries even when the parser recognized the syntax.
  Evidence: `src/analyzer/cpp/declarations.rs` currently matches `\"type_definition\" | \"alias_declaration\" => {}` in `visit_node`.

- Observation: include fallback can be built from data the analyzer already records today; there is no need to index includes as declarations.
  Evidence: `visit_include` in `src/analyzer/cpp/declarations.rs` already fills `parsed.import_statements` and `parsed.imports`, and `IAnalyzer` exposes `import_statements(&ProjectFile)`.

- Observation: the existing persistence epoch helper only has one global version salt, not a per-language override hook, so the quickest safe invalidation path is to bump the shared epoch salt.
  Evidence: `src/analyzer/persistence/epoch.rs` hashes `bifrost-analyzer-epoch-v1\n` once inside `epoch_cell`, before any language-specific inputs are added.

- Observation: function-like macros and source definitions worked with the existing source extraction path as soon as the analyzer started emitting them as ordinary declarations with real ranges.
  Evidence: `tests/searchtools_fuzzy_symbol_lookup.rs::cpp_macro_and_function_lookup_supports_locations_sources_and_search` passes without adding a macro-specific branch in `get_symbol_sources`.

## Decision Log

- Decision: make macros first-class `CodeUnitType::Macro` declarations instead of encoding them as fields or leaving them out.
  Rationale: the user explicitly asked for navigable macro definitions across symbol tools, and a dedicated kind keeps rendering, search, and future LSP behavior honest.
  Date/Author: 2026-06-09 / Codex

- Decision: scope the empty-summary fallback to `get_summaries` file/glob targets only, with fallback order `declarations -> includes -> first 20 lines`.
  Rationale: broad symbol search should stay focused on declarations, but exact file inspection must not silently report an existing file as empty.
  Date/Author: 2026-06-09 / Codex

- Decision: defer the line-width-aware excerpt renderer and use the existing summary text rendering path for the first-twenty-lines fallback in this change.
  Rationale: the user explicitly split that renderer work into a follow-up change, so this implementation should keep scope tight and ship the behavioral fix first.
  Date/Author: 2026-06-09 / Codex

- Decision: bump the shared analyzer epoch salt from `v1` to `v2` instead of inventing a one-off C++ override path during this change.
  Rationale: the existing persistence hook is global, and a simple salt bump guarantees stale rows are invalidated now without widening the implementation into persistence architecture work.
  Date/Author: 2026-06-09 / Codex

## Outcomes & Retrospective

Implementation outcome 2026-06-09T23:14:00Z: the analyzer/searchtools milestones are complete. C/C++ declarations now include macros and named aliases, pointer-returning prototypes stop degrading into malformed fields, and exact file summaries no longer silently disappear when a file contains only includes or only raw text. The remaining step is bookkeeping: capture the rationale in a checkpoint commit.

## Context and Orientation

The C and C++ analyzer lives under `src/analyzer/cpp/`. The file `src/analyzer/cpp/declarations.rs` walks tree-sitter syntax nodes and converts them into `CodeUnit` declarations stored by the generic tree-sitter analyzer. A `CodeUnit` is the repository’s cross-language symbol record, defined in `src/analyzer/model.rs`, with a `CodeUnitType` such as class, function, field, or module plus the file, package, name, signatures, and ranges used by searchtools and LSP features.

The persistence layer under `src/analyzer/persistence/` stores analyzed declarations on disk so analyzer warm starts do not need to reparse every file. `src/analyzer/persistence/reconcile.rs` encodes `CodeUnitType` into stable strings, and `src/analyzer/persistence/epoch.rs` computes a per-language invalidation hash. Because this change alters how C/C++ declarations are classified and adds a new declaration kind, the C++ epoch must change so old persisted rows do not survive with empty data.

The user-facing symbol tools live in `src/searchtools.rs` and `src/searchtools_render.rs`. `list_symbols` groups declarations per file, `get_symbol_locations` and `get_symbol_sources` resolve names back to declarations and ranges, and `get_summaries` produces compact file or type summaries. `SummaryBlock` is the file-or-symbol summary result, and `SummaryElement` is the per-declaration snippet inside it. The include and first-20-lines fallback belongs here, not in the analyzer, because it is a presentation behavior for exact file inspection.

Tests already cover analyzer behavior in `tests/cpp_analyzer_test.rs` and searchtools behavior in files such as `tests/searchtools_summary_ranges.rs`, `tests/searchtools_fuzzy_symbol_lookup.rs`, and `tests/searchtools_service.rs`. For new small ad hoc projects, repository policy prefers the shared inline harness in `tests/common/inline_project.rs`.

## Plan of Work

Start by extending the shared symbol model. Add `CodeUnitType::Macro` in `src/analyzer/model.rs`, update user-facing labels and helper predicates there, then wire the new kind through persistence encoding in `src/analyzer/persistence/reconcile.rs`, autocomplete ordering in `src/analyzer/i_analyzer.rs`, and the existing LSP and file-tool kind mappings. In `src/analyzer/persistence/epoch.rs`, change the analyzer epoch salt so persisted C++ rows rebuild under the new classification rules.

Next, update `src/analyzer/cpp/declarations.rs`. The current declaration walker only recognizes a small subset of function declarators and skips type aliases entirely. Add a recursive declarator classifier that can unwrap pointer, reference, parenthesized, array, and initializer wrappers until it can decide whether a declaration is a function or a variable. Reuse that helper for both `function_definition` and `declaration` so pointer-returning definitions and prototypes become `Function` code units. Add handlers for `type_definition` and `alias_declaration` so named typedef and alias declarations index as class-like declarations with useful signatures. Add handlers for `preproc_def` and `preproc_function_def` so object-like and function-like macros index as `Macro` code units whose ranges cover the full definition text, including continuation lines.

Then update `src/searchtools.rs` and `src/searchtools_render.rs`. Add a `macros` bucket to `SearchSymbolsFile`, teach the grouping and render helpers to display it, and allow `code_unit_kind_name` and fallback signatures to emit `macro`. `get_symbol_locations` and `get_symbol_sources` should work automatically once macros are indexed, but verify that the existing source block path returns the full raw macro text. Extend `SummaryBlock` with an optional `fallback_reason`. In `summarize_files`, when an exact matched file yields no normal summary elements, synthesize include elements from top-level import/include statements; if those are also absent, synthesize one excerpt element containing the first twenty raw lines of the file and set the appropriate fallback reason.

Finish by adding focused tests. Use `InlineTestProject` fixtures for a source file with real functions, a header with macros plus a prototype, an include-only header, and a header with neither declarations nor includes so the excerpt fallback is exercised. Validate direct analyzer declarations, searchtools summary behavior, service rendering, and any MCP-visible JSON expectations that depend on the new fields or kinds.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, implement and validate the change with:

    cargo test --test searchtools_list_symbols --test cpp_analyzer_test --test searchtools_fuzzy_symbol_lookup --test searchtools_summary_ranges --test searchtools_service
    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings

Expected signs of success:

    list_symbols on a C/C++ fixture file shows functions and macros instead of an empty `lines: []` body
    get_symbol_locations for a macro name returns the definition line
    get_symbol_sources for a macro name returns the full `#define` text, including continuation lines
    get_summaries for an include-only file returns fallback include elements with a fallback reason
    get_summaries for a file with no declarations and no includes returns one excerpt element covering lines 1 through 20

Actual results recorded 2026-06-09T23:14:00Z:

    cargo test --test searchtools_list_symbols --test cpp_analyzer_test --test searchtools_fuzzy_symbol_lookup --test searchtools_summary_ranges --test searchtools_service
    Finished `test` profile ...
    test result: ok. 28 passed ... in cpp_analyzer_test
    test result: ok. 11 passed ... in searchtools_fuzzy_symbol_lookup
    test result: ok. 3 passed ... in searchtools_list_symbols
    test result: ok. 31 passed ... in searchtools_service
    test result: ok. 14 passed ... in searchtools_summary_ranges

    cargo fmt --all
    <no output; completed successfully>

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile ... target(s) in 5.79s

## Validation and Acceptance

Acceptance is behavioral. A human should be able to inspect the new tests and see that a `.c` file containing `const char* ffDetectBootmgr(...)` no longer appears symbol-empty, and that headers containing `#define FF_CODEC_UNKNOWN 0` or `#define FF_CODEC_NAME(x) ...` expose those macros to symbol lookup and source retrieval. Exact file targets to `get_summaries` must never silently disappear just because the analyzer found no declarations; they must either show declarations, show include fallback, or show the first twenty lines.

Run the focused tests above plus `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`. The new tests should fail before the implementation and pass after it. Keep the existing searchtools file-path fallback behavior intact while broadening C/C++ declaration coverage.

## Idempotence and Recovery

These are source-only edits and can be applied repeatedly. If a partial implementation leaves persistence unable to decode old rows, rerun the focused tests after verifying `code_unit_kind_str` and `parse_kind` stay in sync. If searchtools render new macro kinds but the analyzer still does not emit them, inspect `tests/cpp_analyzer_test.rs` first; it is the fastest signal for declaration classification bugs. Do not revert unrelated working-tree changes.

## Artifacts and Notes

The most important implementation evidence to preserve is:

    src/analyzer/cpp/declarations.rs previously skipped type aliases and macros
    src/searchtools.rs previously returned `None` for existing files with zero summary elements
    src/analyzer/persistence/epoch.rs must change so persisted C++ payloads refresh under the new declaration classification

The new tests should use small inline fixtures so the failure modes stay obvious and isolated from the larger fixture corpus.

## Interfaces and Dependencies

At the end of this change, `src/analyzer/model.rs` must define:

    pub enum CodeUnitType {
        Class,
        Function,
        Field,
        Module,
        Macro,
    }

`src/searchtools.rs` must extend:

    pub struct SearchSymbolsFile {
        pub path: String,
        pub loc: usize,
        pub classes: Vec<SearchSymbolHit>,
        pub functions: Vec<SearchSymbolHit>,
        pub fields: Vec<SearchSymbolHit>,
        pub modules: Vec<SearchSymbolHit>,
        pub macros: Vec<SearchSymbolHit>,
    }

and:

    pub struct SummaryBlock {
        pub label: String,
        pub path: String,
        pub preamble: String,
        pub fallback_reason: Option<String>,
        pub elements: Vec<SummaryElement>,
    }

The new summary fallback excerpt should use a `SummaryElement` whose `kind` is `excerpt`, whose `symbol` is the project-relative path, and whose `text` is the raw first-twenty-lines slice.

Revision note 2026-06-09T22:40:00Z: Created this ExecPlan before implementation because the requested fix crosses the C++ analyzer, persisted declaration schema, searchtools grouping, and file-summary fallback behavior.
Revision note 2026-06-09T23:14:00Z: Updated the ExecPlan after implementation and validation to record the final shape, the shared epoch-salt decision, the focused test evidence, and the remaining checkpoint-commit task.
