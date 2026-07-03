# Simplify get_summaries While Preserving MCP Compatibility

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](../../.agent/PLANS.md).

## Purpose / Big Picture

After this change, the Rust-level `get_summaries` API becomes a simpler file-and-symbol summary function with one job: return summary blocks plus `not_found` and `ambiguous`. Directory symbol inventory remains available to MCP and Python callers exactly where they expect it today, so `SearchToolsClient.get_summaries(...)` and direct MCP `tools/call` responses keep supporting mixed file, symbol, and directory inputs.

The user-visible proof is that Rust tests for `get_summaries` stop expecting `directory_symbols`, while service and Python tests still show directory inventory coming back through the MCP boundary. `list_symbols` remains backed by `analyzer.list_symbols(...)`, preserving its current nested outline and package-header behavior.

## Progress

- [x] (2026-06-02 15:27Z) Read `.agent/PLANS.md`, inspected the current `searchtools`/service/Python wrapper contract, and confirmed the working tree already contains unrelated edits in the same files.
- [x] (2026-06-02 15:42Z) Refactored `src/searchtools.rs` so `SummaryResult` no longer contains `directory_symbols` and direct Rust `get_summaries` reports directory targets in `not_found`.
- [x] (2026-06-02 15:45Z) Added service-only `get_summaries` composition so MCP/Python callers still receive optional `directory_symbols`, including mixed directory plus non-directory calls.
- [x] (2026-06-02 15:52Z) Updated renderers, README, and focused Rust/Python tests for the split contract.
- [x] (2026-06-02 15:53Z) Ran `cargo fmt`, focused Rust tests, `cargo clippy --all-targets --all-features -- -D warnings`, and the Python wrapper tests via `uv run --python 3.12 --with maturin python -m unittest python_tests.test_searchtools_client`.
- [ ] (2026-06-02 15:53Z) Full `cargo test` rerun remains blocked by pre-existing `get_symbol_ancestors` MCP registry/test drift in unrelated dirty files (`src/mcp_core.rs`, `src/mcp_registry.rs`, `tests/bifrost_mcp_server.rs` expectations).

## Surprises & Discoveries

- Observation: The working tree is already dirty in `src/searchtools.rs`, `src/searchtools_render.rs`, `src/searchtools_service.rs`, and Python wrapper files because unrelated `get_symbol_ancestors` work is in progress.
  Evidence: `git diff -- src/searchtools.rs src/searchtools_render.rs src/searchtools_service.rs bifrost_searchtools/client.py bifrost_searchtools/models.py python_tests/test_searchtools_client.py`

- Observation: I did not find real external directory-target calls to `get_summaries` in `../anvil` or `../brokkbench/localizer`; those callers use file or symbol inputs only.
  Evidence: `rg -n "get_summaries\\(\\[.*\\]|call_tool\\(\\s*\\\"get_summaries\\\"" /home/jonathan/Projects/anvil /home/jonathan/Projects/brokkbench/localizer`

## Decision Log

- Decision: Keep MCP/Python `get_summaries` response shape compatible, including optional `directory_symbols`, while simplifying only the Rust core result type.
  Rationale: This removes the main Rust-level tech debt without forcing external callers onto a new union contract.
  Date/Author: 2026-06-02 / Codex

- Decision: Keep `list_symbols` implemented via `analyzer.list_symbols(...)` instead of rebuilding it from summary elements.
  Rationale: Existing tests prove that `list_symbols` preserves Brokk-style nesting and package headers that would otherwise need lossy reconstruction.
  Date/Author: 2026-06-02 / Codex

## Outcomes & Retrospective

The core goal landed cleanly: Rust `get_summaries` is now a narrower summary-only API, and the service layer owns the compatibility behavior for directory inventory. The direct tests now make that split visible instead of overloading one result type with two jobs.

The main remaining gap is unrelated to this refactor. A full `cargo test` run still fails in `tests/bifrost_mcp_server.rs` because the dirty working tree already includes `get_symbol_ancestors` in the published MCP tool lists while those end-to-end expectations have not yet been updated. That drift predates this ExecPlan and did not block the focused summary/searchtools validation.

## Context and Orientation

The summary/searchtools pipeline lives in three layers. The Rust core logic in `src/searchtools.rs` defines request/result types and the pure query functions such as `get_summaries` and `list_symbols`. The MCP/Python service layer in `src/searchtools_service.rs` converts JSON arguments into Rust calls, renders human-readable preview text, and emits JSON payloads to callers. The Python wrapper models in `bifrost_searchtools/models.py` and client methods in `bifrost_searchtools/client.py` deserialize those payloads into Python data classes used by external scripts such as `../brokkbench/localizer/localize_sft_core.py`.

Today, `SummaryResult` in `src/searchtools.rs` carries both `summaries` and optional `directory_symbols`, even though directory handling is a separate concern from file/class summaries. The helper `route_summary_targets(...)` already distinguishes file targets, directory targets, symbol targets, and unmatched file-like targets. That makes it possible to keep the target-routing knowledge while moving directory composition out of the Rust core result type.

The renderer in `src/searchtools_render.rs` currently assumes `SummaryResult` may contain `directory_symbols`. The service uses `decode_render_and_run(...)` for `get_summaries`, which is convenient when a tool maps directly to one Rust result type but no longer fits once the service needs to merge a Rust `SummaryResult` with directory inventory for compatibility.

## Plan of Work

First, update `src/searchtools.rs` so `SummaryResult` only contains `summaries`, `not_found`, and `ambiguous`. Keep `route_summary_targets(...)` as the shared classifier. Change direct Rust `get_summaries(...)` to ignore the classified directory targets when building summaries and instead append those original directory-like inputs to `not_found`. Preserve sorting and mixed file-plus-symbol behavior.

Next, extend `src/searchtools_service.rs` with a small MCP-only result type for `get_summaries`, likely a serializable struct with the old fields: `summaries`, optional `directory_symbols`, `not_found`, and `ambiguous`. Add a dedicated `handle_get_summaries(...)` path instead of `decode_render_and_run(...)`. That handler should parse `SummariesParams`, classify targets with the same routing helper, call Rust `get_summaries(...)` on file/symbol/unmatched inputs, call the existing skim/list-symbols helper for directory targets, then merge the pieces into the compatibility payload and render text using the existing summary-plus-skim formatting.

Then, adjust `src/searchtools_render.rs` so `SummaryResult` only renders summaries, not directory symbols, and add rendering support for the new MCP-only compatibility payload if a separate type is introduced. Update Python wrapper models only as needed to keep `directory_symbols` available for service payloads while avoiding any assumption that the Rust core result still contains it.

Finally, update the tests and docs. Rust tests that call `get_summaries(...)` directly must stop expecting `directory_symbols` and instead assert the directory targets end up in `not_found`. Service tests and Python wrapper tests must continue to show directory inventory on the external contract. README examples or prose that describe directory behavior should say that MCP/Python `get_summaries` still accepts directories for compatibility, while Rust `get_summaries` is file/symbol-oriented.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, inspect and modify the summary core, service boundary, and tests. The main validation commands after editing are:

    cargo test --test searchtools_service --test searchtools_summary_ranges --test searchtools_list_symbols
    cargo test
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    uv run python -m pytest python_tests/test_searchtools_client.py

Expected signs of success:

    tests/searchtools_summary_ranges.rs passes with directory-target assertions moved from `directory_symbols` to `not_found`
    tests/searchtools_service.rs still passes directory-target `get_summaries` assertions via the service payload
    python_tests/test_searchtools_client.py still passes and `SymbolSummariesResult.directory_symbols` remains populated for directory requests through the wrapper

This section must be updated with real command results as implementation proceeds.

## Validation and Acceptance

Acceptance requires both contracts to be visible. At the Rust level, running the summary-range tests must prove that `get_summaries(...)` no longer returns `directory_symbols`; directory-only targets should now be visible as unsupported in `not_found`. At the service level, running the service tests must prove that a JSON `get_summaries` call with `"targets":["."]` still returns structured `directory_symbols`, and a mixed call still returns summary blocks plus directory inventory in one payload.

For the Python boundary, run `uv run python -m pytest python_tests/test_searchtools_client.py` and confirm that the wrapper still deserializes `get_summaries` responses and exposes directory inventory through `SymbolSummariesResult.directory_symbols`.

## Idempotence and Recovery

These edits are source-only and can be re-applied safely. If a partial patch leaves the service and core out of sync, rerun the focused Rust tests listed above; they cover the direct/core split and will show which boundary still expects the old shape. Do not revert unrelated dirty changes in the working tree; restrict recovery to the summary/searchtools hunks touched by this ExecPlan.

## Artifacts and Notes

Useful existing evidence to preserve during implementation:

    list_symbols_uses_fast_literal_resolution
    get_summaries_accepts_directory_targets
    get_summaries_accepts_workspace_root_directory_target
    get_summaries_directory_target_returns_skim_symbol_inventory

The first should keep passing unchanged. The latter three should split into Rust-core expectations versus service-compatibility expectations.

## Interfaces and Dependencies

At the end of this work, `src/searchtools.rs` must expose:

    pub struct SummaryResult {
        pub summaries: Vec<SummaryBlock>,
        pub not_found: Vec<String>,
        pub ambiguous: Vec<AmbiguousSymbol>,
    }

`src/searchtools.rs` should continue to expose `pub fn get_summaries(analyzer: &dyn IAnalyzer, params: SummariesParams) -> SummaryResult` and `pub fn list_symbols(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult`.

`src/searchtools_service.rs` must define a serializable compatibility payload for MCP/Python `get_summaries` that restores:

    summaries
    optional directory_symbols
    not_found
    ambiguous

It may be a dedicated service-layer struct if that keeps the Rust core clean. The Python data class `bifrost_searchtools.models.SymbolSummariesResult` should remain compatible with the service payload.

Revision note: created this ExecPlan because `AGENTS.md` requires an ExecPlan for significant refactors, and this change intentionally splits the Rust-core and MCP-level contracts.

Revision note: updated the plan after implementation to record the shipped contract split, the exact validation commands that passed, and the unrelated full-suite MCP tool-list failure caused by existing dirty `get_symbol_ancestors` work.
