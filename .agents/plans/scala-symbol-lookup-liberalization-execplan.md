# Liberalize Scala Symbol Lookup and Remove Searchtools Kind Filters

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](../../.agents/PLANS.md).

## Purpose / Big Picture

After this change, Bifrost accepts idiomatic Scala symbol names and JVM-style `$` encodings interchangeably across symbol lookup tools, instead of forcing callers to match the repository’s current internal rendering. A user can ask for `ai.brokk.ir.PrimOp.AsClockOp`, `ai.brokk.ir$.PrimOp$.AsClockOp`, or mixed delimiter forms and get the same result. At the same time, `get_symbol_sources`, `get_symbol_locations`, and `get_symbol_ancestors` stop requiring or advertising `kind_filter`, which removes a brittle caller-side choice that GPT traces keep getting wrong.

The visible proof is a focused Scala fixture with nested objects and case objects. `list_symbols` and `get_summaries` should present idiomatic Scala names, `get_symbol_sources` and `get_symbol_locations` should resolve both idiomatic and `$`-encoded spellings, and `get_symbol_ancestors` should reject non-type requests with a clear invalid-params error instead of quietly misclassifying them.

## Progress

- [x] (2026-06-09T20:23:58Z) Read `.agents/PLANS.md`, reviewed the existing Scala/C# lookup tests, and confirmed that commit `2831057` only covered simple trailing-`$` companion-object cases.
- [x] (2026-06-09T20:23:58Z) Inspected `src/analyzer/symbol_lookup.rs`, `src/analyzer/model.rs`, `src/analyzer/scala/declarations.rs`, `src/searchtools.rs`, `src/searchtools_service.rs`, `src/mcp_common.rs`, and MCP tests to pin down the current resolver, schema, and service boundaries.
- [x] (2026-06-09T20:53:45Z) Implemented Scala-aware display helpers, updated `list_symbols`, searchtools outputs, and LSP label/name surfaces to render idiomatic Scala names while keeping internal canonical names unchanged.
- [x] (2026-06-09T20:53:45Z) Removed `kind_filter` from `get_symbol_sources`, `get_symbol_locations`, and `get_symbol_ancestors`, including MCP schemas and legacy compatibility stripping in the service layer.
- [x] (2026-06-09T20:53:45Z) Added `get_symbol_ancestors` invalid-params behavior for non-type targets and kept provider-unavailable behavior unchanged for valid type-like symbols in unsupported languages.
- [x] (2026-06-09T20:53:45Z) Added focused Scala regression tests, updated MCP/service expectations, and ran focused searchtools/MCP tests, `cargo fmt --all`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-06-09T20:53:45Z) Cut a checkpoint commit for the Scala/API work, then start the follow-on C# display-only normalization pass.
- [x] (2026-06-09T21:18:42Z) Normalized C# nested-type display names at the same user-facing display helper boundary, updated the delimiter regression expectation, and reran focused tests plus `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`.

## Surprises & Discoveries

- Observation: Scala `object` declarations are currently stored as `CodeUnitType::Class`, not `CodeUnitType::Module`, with `$` appended in `src/analyzer/scala/declarations.rs`.
  Evidence: `visit_type_declaration(...)` in `src/analyzer/scala/declarations.rs` builds `format!("{raw_name}$")` and still constructs `CodeUnitType::Class`.

- Observation: The current fix in `CodeUnit::identifier()` only preserves trailing `$`; it still strips internal `$` segments for non-function/non-field identifiers, which matches the new trace failures for names like `ir$.PrimOp$`.
  Evidence: `src/analyzer/model.rs` now returns `member_name.rsplit('$').next().unwrap_or(member_name)` for non-trailing internal `$`.

- Observation: `get_symbol_ancestors` already differs from the other two tools because it should surface service-level invalid-params errors for non-type targets rather than just another `not_found` list entry.
  Evidence: `src/searchtools_service.rs` only has success-returning `decode_render_and_run(...)` today, so ancestor validation needs a new result-aware decode path.

- Observation: the nested Scala trace failures did not require a wholesale parser rewrite in `symbol_lookup.rs`; once `kind_filter` was removed from the affected tools, the existing path normalization already handled the observed `$` object/member spellings well enough for the new regression fixture.
  Evidence: the focused Scala fixture passes for both `ai.brokk.ir.PrimOp.AsClockOp` and `ai.brokk.ir$.PrimOp$.AsClockOp` after the API/display changes, without adding a new Scala-only path parser.

- Observation: C# user-facing nested-type names can be normalized cleanly at the same display helper boundary used for Scala, without changing lookup aliases or canonical storage.
  Evidence: replacing `$` with `.` per path segment in `display_symbol_name(Language::CSharp, ...)` updates rendered labels while the existing `N.Outer+Inner.Method` lookup test still passes.

## Decision Log

- Decision: Keep internal analyzer canonical names unchanged and solve Scala liberalization in shared lookup aliases plus searchtools display formatting.
  Rationale: The repo already keys exact definitions on JVM-ish `$` names. Changing canonical storage would widen the blast radius across analyzers, usages, and caches, while the observed failures are at the lookup and presentation boundaries.
  Date/Author: 2026-06-09 / Codex

- Decision: Do not globally retag Scala `object` declarations from `Class` to `Module`.
  Rationale: The traces that passed `kind_filter="module"` are better handled by removing the filter from the affected tools than by changing Scala declaration typing across the whole analyzer stack.
  Date/Author: 2026-06-09 / Codex

- Decision: `get_symbol_ancestors` will become explicitly type-only and return invalid params for non-type requests once `kind_filter` is removed.
  Rationale: The user called out that ancestors only make sense against classes, and the tool is semantically different from source/location lookup because it is not just “best effort resolution.”
  Date/Author: 2026-06-09 / Codex

- Decision: Extend the same user-facing display helper boundary to C# nested types so searchtools and LSP labels render `Outer.Inner` while lookup continues accepting `$`, `.`, and `+`.
  Rationale: This improves displayed output for the other major internal-name outlier without widening the blast radius into analyzer storage or resolver semantics.
  Date/Author: 2026-06-09 / Codex

## Outcomes & Retrospective

Midpoint outcome 2026-06-09: the Scala/API milestone is complete. Bifrost now accepts the traced Scala `$` spellings without caller-supplied kind filters, renders idiomatic Scala names in searchtools and LSP labels, and rejects non-type ancestor requests with invalid params. The next follow-on task is explicit C# display-only normalization, which should stay separate from canonical storage and lookup semantics.

Update 2026-06-09T21:18:42Z: the C# follow-on is complete. User-facing nested-type names now render idiomatically as `Outer.Inner` in the same surfaces that were switched to Scala-aware display helpers, while lookup semantics and canonical internal names remain unchanged.

## Context and Orientation

The relevant logic is split across four layers. `src/analyzer/scala/declarations.rs` turns Scala syntax trees into `CodeUnit` declarations; this is where `object Foo` becomes the stored short name `Foo$`. `src/analyzer/model.rs` defines helpers such as `CodeUnit::identifier()`, which many renderers use to display a short symbol name. `src/analyzer/symbol_lookup.rs` contains the shared fuzzy resolver for symbol tools. It builds path aliases from a symbol’s fully qualified name, short name, and identifier, then accepts a set of “reasonable delimiter” spellings such as `.`, `/`, `\`, `::`, and `+`.

The user-facing tools live in `src/searchtools.rs`. `get_symbol_sources`, `get_symbol_locations`, and `get_symbol_ancestors` currently share `SymbolNamesParams`, which includes both `symbols` and `kind_filter`. `src/mcp_common.rs` exposes the same schema to MCP clients. `src/searchtools_service.rs` is the JSON and rendered-text boundary used by direct MCP calls and the Python wrapper tests. That service currently assumes these tools can be decoded with a simple success-only helper.

Scala support today is inconsistent. Commit `2831057` fixed simple trailing-`$` cases such as `Baz$` and `Baz$.test3`, but nested object names like `ir$.PrimOp$` still lose information because internal `$` separators are treated too aggressively in identifier/display logic and not all alias variants are tried symmetrically. Existing tests in `tests/searchtools_list_symbols.rs`, `tests/searchtools_summary_ranges.rs`, and `tests/searchtools_fuzzy_symbol_lookup.rs` cover only the simple cases.

## Plan of Work

Start in `src/analyzer/symbol_lookup.rs`. Add a Scala-specific path-variant builder that accepts both idiomatic object/member spellings and JVM-style `$`-encoded spellings for each segment, rather than only trimming trailing `$` or splitting blindly on every `$`. The implementation should preserve the existing cross-language delimiter behavior and keep C# nested-type matching intact. The goal is that a single Scala declaration yields alias paths for raw canonical storage, idiomatic display-style names, and mixed variants where one object segment is JVM-ish and another is idiomatic.

Then update `src/analyzer/model.rs` and the searchtools display path in `src/searchtools.rs` so Scala-facing output becomes idiomatic. `CodeUnit::identifier()` should stop dropping internal Scala object names. Add a dedicated searchtools display helper that converts canonical Scala names like `ir$.PrimOp$.AsClockOp$` into idiomatic user-facing labels like `ir.PrimOp.AsClockOp` without changing the stored FQNs used for exact definition lookup. Apply that helper where searchtools build labels, signatures, summary elements, and source headings.

Next, split the parameter structs in `src/searchtools.rs`. Keep `SymbolNamesParams` only for tools that still need filtering. Introduce new symbol-list parameter structs with `symbols: Vec<String>` for `get_symbol_sources`, `get_symbol_locations`, and `get_symbol_ancestors`. Change `get_symbol_sources` and `get_symbol_locations` to resolve with `CodeUnitKindFilter::Any`. `get_symbol_locations` should return every concrete resolved location, not just the first match surviving a filter. `get_symbol_sources` should also return every concrete match. For object-like targets, reuse the existing `sources` field but produce synthetic file-list entries instead of dumping full source bodies.

After that, extend `src/searchtools_service.rs` with a helper that decodes arguments, runs a handler returning `Result<R, SearchToolsServiceError>`, and still renders structured text on success. Use that path for `get_symbol_ancestors`, which should resolve symbols liberally but then validate that each resolved target is type-like before asking the hierarchy provider for ancestors. A non-type request must raise `InvalidParams`. If the analyzer has no type-hierarchy provider, preserve the existing unsupported-language behavior for type-like symbols.

Finally, update MCP schemas and tests. Replace the shared `symbol_names_schema()` usage for the three edited tools with a symbols-only schema in `src/mcp_common.rs` and `src/mcp_core.rs`. Update service, MCP, and direct Rust tests to remove `kind_filter` from current requests while adding compatibility coverage showing that a legacy extra field is ignored for sources and locations. Add the nested Scala fixture tests for idiomatic and `$`-encoded input forms, and keep one explicit C# nested-type regression to prove the Scala liberalization did not change that behavior.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, implement and validate the change with:

    cargo test --test searchtools_list_symbols --test searchtools_summary_ranges --test searchtools_fuzzy_symbol_lookup --test searchtools_service --test bifrost_mcp_server
    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings

Expected signs of success:

    nested Scala object lookups such as ai.brokk.ir.PrimOp.AsClockOp and ai.brokk.ir$.PrimOp$.AsClockOp resolve identically
    get_symbol_sources/get_symbol_locations/get_symbol_ancestors requests no longer advertise or require kind_filter
    get_symbol_ancestors returns Invalid tool arguments (or the equivalent service invalid-params payload) for non-type symbols
    existing C# nested-type lookup tests still pass

This section must be updated with actual command results as implementation proceeds.

## Validation and Acceptance

Acceptance is behavioral. A human should be able to look at the new focused Scala fixture tests and see that Bifrost accepts both idiomatic Scala and JVM-ish `$` forms for nested objects and case objects. `list_symbols` and `get_summaries` must present readable Scala names without dropped object identifiers. `get_symbol_sources` must return file listings for object-like requests and source excerpts for member requests. `get_symbol_locations` must stop depending on caller-supplied kind filters. `get_symbol_ancestors` must reject non-type requests with a clear invalid-params error.

Run the focused Rust suites above and expect them all to pass. The new nested Scala tests must fail against the current pre-change implementation and pass after the edits. Run `cargo clippy --all-targets --all-features -- -D warnings` before stopping because repo policy requires the same core Rust checks as CI.

## Idempotence and Recovery

These are source-only edits and can be reapplied safely. If a partial implementation leaves the MCP schema and tool handlers out of sync, rerun the focused service and MCP tests first; they are the fastest signal for stale request shapes. If Scala output formatting and canonical lookup disagree, keep internal names canonical and adjust only the display helper and alias builder rather than rewriting stored declarations. Do not revert unrelated working-tree changes.

## Artifacts and Notes

Key evidence points to preserve while editing:

    commit 2831057 fixed simple Baz$/Baz$.test3 cases only
    src/analyzer/scala/declarations.rs stores Scala object declarations with trailing $
    src/analyzer/symbol_lookup.rs currently trims trailing $ and blindly splits internal $, which is too lossy for nested Scala object paths

The new tests should include both idiomatic and raw `$` spellings for the same target so future regressions are obvious.

## Interfaces and Dependencies

At the end of this work, `src/searchtools.rs` must expose distinct parameter types so these three tools no longer deserialize a `kind_filter` field:

    pub struct SymbolLookupParams {
        pub symbols: Vec<String>,
    }

`get_symbol_sources` and `get_symbol_locations` should take `SymbolLookupParams` and resolve with no kind restriction. `get_symbol_ancestors` should also take `SymbolLookupParams`, but return:

    pub fn get_symbol_ancestors(
        analyzer: &dyn IAnalyzer,
        params: SymbolLookupParams,
    ) -> Result<SymbolAncestorsResult, SearchToolsServiceError>

or an equivalent service-level result path that can surface `InvalidParams` for non-type targets. The MCP schema functions in `src/mcp_common.rs` must provide a symbols-only schema for these three tools, while any remaining filter-using tools can continue to use the existing `SymbolNamesParams`-style schema.

Revision note 2026-06-09: Created this ExecPlan before implementation because the requested change spans shared symbol resolution, public searchtools APIs, service error handling, and Scala-specific display behavior.
Revision note 2026-06-09T20:53:45Z: Updated the ExecPlan after completing the Scala/API milestone, recording the final implementation shape, focused test evidence, and the discovery that removing kind filters solved the observed nested Scala trace failures without a larger resolver rewrite.
