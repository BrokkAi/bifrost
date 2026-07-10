# Split usage scanning by selector type and hide byte offsets

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently exposes one `scan_usages` tool that mixes symbolic and location selectors, and several public tool APIs expose UTF-8 byte offsets that are useful to tree-sitter but inappropriate for model-facing callers. After this change, callers with visible line numbers use `scan_usages_by_location`, callers without reliable line numbers use `scan_usages_by_reference`, and all MCP, CLI-tool, and Python surfaces use line/column coordinates rather than byte offsets. The analyzers continue using byte ranges internally.

The change is observable by listing MCP tools in normal and `--no-line-numbers` modes, exercising both direct service calls and Python methods, and inspecting structured results from rename and full-detail structural query calls. Downstream P2T and Anvil callers use the new reference name.

## Progress

- [x] (2026-07-10 00:00Z) Created `/home/jonathan/Projects/bifrost-scan-usages-api-split` on `codex/scan-usages-api-split` from committed Bifrost `HEAD`.
- [x] (2026-07-10) Split the public scan-usage request and MCP/Python surfaces while retaining one backend.
- [x] (2026-07-10) Removed byte offsets from external request and response shapes; diagnostic and schema audits remain part of final validation.
- [x] (2026-07-10) Updated Bifrost documentation, generated plugin copies, benchmark routing, and behavior-focused tests.
- [x] (2026-07-10) Validated Bifrost with formatting, focused and full feature-enabled Rust suites, the Python suite, plugin manifest checks, and `cargo clippy-no-cuda`; committed the completed changeset on the worktree branch.
- [x] (2026-07-10) Updated, validated, and committed Brokkbench on its existing master branch (`7878e08e91`).
- [x] (2026-07-10) Updated, validated, and committed Anvil on its existing master branch (`fdb72e3`).
- [x] (2026-07-10) Updated, validated, and committed Usagebench on its existing main branch (`e8911d5`).

## Surprises & Discoveries

- Observation: Anvil pins Bifrost 0.7.4 while its managed server always uses `--no-line-numbers`.
  Evidence: `src/mcp.rs` defines `BUNDLED_BIFROST_VERSION` as `0.7.4` and includes `--no-line-numbers` in `default_bifrost_args`.

- Observation: Brokkbench has extensive unrelated working-tree changes, including existing result-shape changes near some scan-usage test doubles.
  Evidence: `git status --short` lists many unrelated files; task-owned staging must be inspected hunk by hunk.

- Observation: Issue #607 is the same boundary being refactored: location selectors could match a declaration in another file, or treat an arbitrary line inside a declaration body as the declaration target.
  Evidence: https://github.com/BrokkAi/bifrost/issues/607 and new service regressions covering cross-file Java declarations and arbitrary JavaScript body lines.

- Observation: A benchmark process cannot call both the location-only and reference-only MCP surfaces in one server mode.
  Evidence: symbol tool descriptors intentionally advertise only one scan variant based on `--no-line-numbers`; reference benchmark scenarios therefore require a separate no-line MCP session.

- Observation: Removing byte selectors exposed a location-selection gap for symbolic operator references such as Scala `!`.
  Evidence: the old byte-range path accepted the explicit operator span while the line/column path only recognized identifier characters; location resolution now admits one non-whitespace Unicode character and leaves semantic validation to the structured resolver.

## Decision Log

- Decision: Preserve `symbols` for the reference API and `targets` for the location API.
  Rationale: These are the two existing selector forms, so callers need only change the tool or method name.
  Date/Author: 2026-07-10 / Codex

- Decision: Remove the old public Bifrost `scan_usages` name without an alias.
  Rationale: Backward compatibility is not required and retaining the combined surface would defeat the explicit split.
  Date/Author: 2026-07-10 / Codex

- Decision: “External” means MCP/CLI tool schemas and structured results plus Python methods and models. Native analyzer ranges and resolver requests remain byte-based.
  Rationale: Byte coordinates are required for tree-sitter correctness but should not be supplied or interpreted by model-facing clients.
  Date/Author: 2026-07-10 / Codex

- Decision: Anvil temporarily recognizes both the pinned legacy name and the new reference name, but all new guidance prefers the new name.
  Rationale: Anvil master must remain compatible with its bundled 0.7.4 binary until the release pin is bumped.
  Date/Author: 2026-07-10 / Codex

- Decision: Location selectors match only structured declaration-name ranges in the explicitly requested file.
  Rationale: This fixes issue #607 at the resolver boundary without text-search fallbacks, preserves optional-column line selection, and prevents body lines or cross-file members from becoming accidental targets.
  Date/Author: 2026-07-10 / Codex

- Decision: Usagebench uses `scan_usages_by_location` because its declaration-to-usages contract begins with a source location and its shared default MCP session advertises the line-number surface.
  Rationale: Converting the existing zero-based declaration coordinates to Bifrost's one-based line/character target preserves the benchmark contract and avoids opening a second no-line-number server solely for usage scans.
  Date/Author: 2026-07-10 / Codex

## Outcomes & Retrospective

The implementation and downstream migrations are complete. Core service and MCP tests cover both entry points, Unicode character columns and symbolic operators, byte-free rename/query ranges, mode-specific listings and failures, and issue #607's same-file declaration-name resolution. The full `nlp,python` Rust suite, 38 Python tests, focused service/MCP/benchmark suites, plugin manifest validation, and `cargo clippy-no-cuda` pass. Brokkbench, Anvil, and Usagebench are committed independently; Bifrost is ready for its worktree commit.

## Context and Orientation

Public tool request and result types and the shared usage implementation live in `src/searchtools.rs`. MCP schemas live in `src/mcp_core.rs`; service dispatch lives in `src/searchtools_service.rs`; workspace path normalization lives in `src/tool_arguments.rs`; text rendering lives in `src/searchtools_render.rs`. The Python wrapper is `bifrost_searchtools/client.py` with result models in `bifrost_searchtools/models.py`. Structural query ranges are serialized from `src/analyzer/structural/search.rs`. Benchmark selector configuration lives under `src/benchmark/`.

Normal MCP mode renders line numbers and must advertise the location scan and location definition tools. `--no-line-numbers` must advertise the reference variants. Direct service and Python clients expose both variants for programmatic callers.

## Plan of Work

First, replace the combined public scan parameter type with reference and location parameter types. Add two public functions that construct homogeneous requests and invoke a private backend carrying a surface enum. Use that enum throughout ambiguity, failure, truncation, and rendering guidance so every retry names the current public tool and uses supported arguments.

Second, make all public selectors line/column-only. Remove byte fields from definition, type, rename, and scan location requests; remove them from rename edit results, structural-query serialized ranges, Python models, and benchmark manifests. Keep byte conversion and ranges behind these boundaries. Replace byte-oriented public diagnostics with line/column guidance.

Third, update MCP mode selection, service dispatch, CLI normalization, Python methods, benchmark routing, docs, plugin skill copies, and behavior-focused tests. Normal mode must list only `scan_usages_by_location`; no-line mode must list only `scan_usages_by_reference`; the old name and omitted variant must be rejected by MCP.

Fourth, update Brokkbench’s active P2T and root Python callers to the reference method/name, while preserving historical extraction support for archived names. Update Anvil’s active guidance, metadata, tests, and bundled agents, retaining only narrow legacy recognition for the pinned release. Update Usagebench’s declaration-to-usages call and fixtures to the location name.

## Concrete Steps

Work in `/home/jonathan/Projects/bifrost-scan-usages-api-split` for Bifrost. Run focused Rust tests, `scripts/test_python.sh`, `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python`, `cargo fmt`, and `cargo clippy-no-cuda`. Commit only files changed in this worktree.

Work directly in `/home/jonathan/Projects/brokkbench` and `/home/jonathan/Projects/anvil` on their existing master branches, and `/home/jonathan/Projects/usagebench` on its existing main branch. In Brokkbench, use targeted `uv run pytest` and Ruff commands and inspect the staged diff because the tree is dirty. In Anvil, run targeted tests, then `cargo test`, `cargo fmt`, and `cargo clippy --all-targets -- -D warnings`; run the MCP handshake with `BROKK_BIFROST_BINARY` pointing to the new Bifrost binary. In Usagebench, run Cargo tests and case validation.

## Validation and Acceptance

Acceptance requires both scan variants to return the same usage semantics for equivalent declarations, with mode-specific validation and recovery text. MCP listings must select the correct variant and reject the old or hidden name. Serialized MCP/Python tool inputs and results must contain no `start_byte` or `end_byte` fields, including rename edits and full-detail structural-query ranges. Unicode line/column selection must remain correct. Bifrost, targeted Brokkbench, and Anvil tests and linters must pass.

## Idempotence and Recovery

The worktree creation is complete and should not be repeated. All source edits and tests are repeatable. No push, merge, rebase, or pull request is permitted. If downstream dirty files overlap task edits, stage only a hand-inspected task patch and leave all pre-existing hunks unstaged.

## Artifacts and Notes

The Bifrost worktree began at commit `da2660233672e02d98da060ec775297862e837c5`. The primary Bifrost worktree remains dirty and untouched.

## Interfaces and Dependencies

At completion, Rust searchtools exposes `scan_usages_by_reference(analyzer, ScanUsagesByReferenceParams)` and `scan_usages_by_location(analyzer, ScanUsagesByLocationParams)`. The Python client exposes methods with those names. Reference parameters contain `symbols`, `include_tests`, and optional `paths`; location parameters contain `targets` made of `path`, required `line`, optional `column`, plus the same scope controls. No new dependencies are required.
