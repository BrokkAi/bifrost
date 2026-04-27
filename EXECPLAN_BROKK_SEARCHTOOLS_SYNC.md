# Port Brokk searchtools surface into Bifrost

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` in this repository.

## Purpose / Big Picture

Bifrost is the Rust implementation of analyzer-backed search tools used by downstream clients. Brokk recently changed its searchtools API and behavior in commits `a44ba8337e1d7008b78fab0cab2624340f0bfc9a`, `df8f3ab50b2bf2ead8ed44b7cecafec217bc6079`, and `d1cc95399ebcabc9834d9db4e09bf306ea5ec60c`. After this work, Bifrost keeps its snake_case tool naming but adopts the revised surface area: callers use `get_summaries` for both file and class-style summaries, and `get_file_summaries` is no longer advertised as a public tool. Search symbol results become more useful by returning display signatures with line numbers, and limited file result sets choose the most relevant files before rendering them in stable alphabetical order.

## Progress

- [x] (2026-04-27T16:56Z) Inspected the three Brokk commits and the existing Bifrost searchtools, MCP, Python client, and tests.
- [x] (2026-04-27T16:56Z) Created this ExecPlan before implementation.
- [x] (2026-04-27T17:04Z) Implemented `get_summaries` target routing and relaxed symbol lookup.
- [x] (2026-04-27T17:04Z) Updated `search_symbols` output and limited-result sorting.
- [x] (2026-04-27T17:04Z) Updated MCP, service, Python client, README, and tests from `get_file_summaries` to `get_summaries`.
- [x] (2026-04-27T17:04Z) Ran focused Rust validation and Python client validation. Full `cargo test` still reaches pre-existing external Brokk parity harness failures because the Brokk CLI/Gradle task is unavailable in this environment.

## Surprises & Discoveries

- Observation: Bifrost already has structured summary blocks with source ranges, so the Brokk text output should guide behavior, not replace the Rust wire format.
  Evidence: `src/searchtools.rs` returns `SummaryResult`, `SummaryBlock`, and `SummaryElement` with line ranges.

- Observation: Exact method source lookups can return overloads, so relaxed lookup must preserve all exact definitions rather than collapsing to one result.
  Evidence: Python client coverage for `A.method2` expects two source blocks.

- Observation: The broad Rust suite is blocked by the existing external Brokk reference harness, not by this searchtools change.
  Evidence: `cargo test` fails in `tests/most_relevant_files.rs` with `ClassNotFoundException: ai.brokk.tools.MostRelevantFilesCli` and missing Gradle task `:app:runMostRelevantFiles`.

## Decision Log

- Decision: Keep Bifrost snake_case tool names while replacing `get_file_summaries` with `get_summaries`.
  Rationale: The user clarified that Bifrost should not move to Brokk camelCase, only the revised Brokk surface area.
  Date/Author: 2026-04-27 / Codex

- Decision: Use Bifrost's existing `most_relevant_project_files` machinery for the `d1cc953` selection behavior.
  Rationale: This repo already has the Rust relevance implementation and parity tests; reusing it keeps behavior consistent with the current architecture.
  Date/Author: 2026-04-27 / Codex

## Outcomes & Retrospective

Implemented the revised Bifrost searchtools surface. `get_summaries` is now the public mixed target summary tool; `get_file_summaries` is no longer advertised by the MCP/service/Python surface. Search symbol results now return structured display signatures with line numbers, and limited file displays select by Git importance before stable alphabetical rendering. Focused Rust tests and Python client tests pass. Full `cargo test` remains blocked by the known external Brokk most-relevant-files parity harness dependency.

## Context and Orientation

The public searchtools functions live in `src/searchtools.rs`. `src/searchtools_service.rs` maps tool names to those functions for both Python and MCP callers. `src/mcp_server.rs` publishes tool descriptors and schemas to MCP clients. The Python package in `bifrost_searchtools/` exposes the native Rust service to Python callers and renders structured results.

Brokk's new `getSummaries` accepts mixed targets: file paths, globs, and class names in one call. In Bifrost this will be named `get_summaries` and will accept `targets`. A file-like target means an input that is clearly a path, glob, dotfile, `.` directory target, or has a common source/document extension. Other targets are resolved as symbols, with exact lookup first and relaxed lookup second.

The limited-result sorting change from `d1cc953` means that when more files match than the caller's limit, the implementation selects the most important files according to relevance ranking, then sorts those selected files alphabetically for deterministic rendering. If the number of files is within the limit, the output remains alphabetical.

## Plan of Work

First, add `SummaryTargets`, file-target detection, and relaxed lookup helpers in `src/searchtools.rs`. Replace `get_file_summaries` with `get_summaries`, keeping the existing summary block result shape and reusing the current file summary logic for file targets. For symbol targets, resolve definitions using the relaxed lookup helper and summarize the matching code unit.

Second, update `search_symbols` result types so each kind contains display entries with `line`, `signature`, and `symbol` fields instead of bare fully qualified names. Add a default display signature helper that normalizes analyzer signatures to single-line display text and falls back to simple class/function/field/module names.

Third, add a file-selection helper for limited outputs. It should return alphabetical files when no truncation is needed. When truncation is needed, call `most_relevant_project_files` using all candidate files as seeds, take the limit, fill any gap alphabetically, and sort the selected set alphabetically before rendering. Apply this helper to `search_symbols` and `summarize_symbols`/`skim_files`.

Fourth, update the public boundary: `src/searchtools_service.rs`, `src/mcp_server.rs`, `bifrost_searchtools/client.py`, `bifrost_searchtools/models.py`, README examples, and tests should advertise and call `get_summaries`, not `get_file_summaries`.

## Concrete Steps

Run implementation from `/home/jonathan/Projects/bifrost`.

After editing, run:

    cargo test --test searchtools_service --test bifrost_mcp_server --test searchtools_summary_ranges

Then run:

    cargo test

If the native Python module is available in the environment, run:

    uv run pytest python_tests

## Validation and Acceptance

Acceptance is that MCP `tools/list` includes `get_summaries` and omits `get_file_summaries`; service and Python calls to `get_summaries` return the existing structured summary blocks for file and class targets; ambiguous relaxed symbol lookups are reported instead of silently picking one; `search_symbols` includes display signatures and line numbers; and a Git-backed truncation test proves relevance-based selection with alphabetical rendering.

## Idempotence and Recovery

All code edits are ordinary tracked-file changes and can be rerun safely. The validation commands write only build artifacts and caches. If a validation step fails, inspect the failing test, update this plan's `Surprises & Discoveries` and `Progress`, then continue from the failed subsystem.

## Artifacts and Notes

The source Brokk commits are:

    a44ba8337e1d7008b78fab0cab2624340f0bfc9a Search tools improvements (#3286)
    df8f3ab50b2bf2ead8ed44b7cecafec217bc6079 fix: remove old getClassSkeletons that has been superceded by getSummaries
    d1cc95399ebcabc9834d9db4e09bf306ea5ec60c feat: selectFilesForDisplay prioritizes more-important files as determined by our relevance code

## Interfaces and Dependencies

In `src/searchtools.rs`, define:

    pub struct SummariesParams {
        pub targets: Vec<String>,
    }

Expose:

    pub fn get_summaries(analyzer: &dyn IAnalyzer, params: SummariesParams) -> SummaryResult

Keep existing `SummaryResult`, `SummaryBlock`, and `SummaryElement` as the response model.

At the service boundary, route the tool name `get_summaries`. Do not route `get_file_summaries`.
