# Port Brokk summarizeSymbols into bifrost searchtools

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [`.agent/PLANS.md`](.agent/PLANS.md).

## Purpose / Big Picture

After this change, bifrost will render compact symbol skims with the same recursive nesting and package grouping behavior that Brokk’s Java `IAnalyzer.summarizeSymbols(...)` already uses. A caller will be able to reach that output through the analyzer trait and through the searchtools surface, instead of getting the current one-level skim that drops nested inner members. The proof is a Rust analyzer test that shows nested classes recurse correctly, plus searchtools-facing tests that show packaged files render with `# package.name` headers and that the new searchtools entry point returns the same structure as `skim_files`.

## Progress

- [x] (2026-04-04T11:40Z) Read `.agent/PLANS.md`, the current Rust analyzer/searchtools surfaces, and Brokk’s `IAnalyzer.java` implementation to scope the port.
- [x] (2026-04-04T11:49Z) Ported recursive `summarize_symbols` behavior into `src/analyzer/i_analyzer.rs`, including top-level package grouping and nested child rendering.
- [x] (2026-04-04T11:50Z) Exposed `summarize_symbols` through `src/searchtools.rs`, `src/searchtools_service.rs`, `src/mcp_server.rs`, and the Python client while keeping `skim_files` as a compatibility alias.
- [x] (2026-04-04T11:55Z) Added and ran focused Rust and Python regression tests for recursion, package grouping, JSON service behavior, MCP exposure, and the Python client entry point.

## Surprises & Discoveries

- Observation: bifrost already had a method named `summarize_symbols`, but it only rendered one level of children and did not group top-level declarations by package/module prefix.
  Evidence: `src/analyzer/i_analyzer.rs` rendered top-level declarations and one child level directly; Brokk’s `IAnalyzer.java` recurses through `getDirectChildren(...)` and emits `# package.name` headings at indent zero.

- Observation: the Java analyzer fixture for `Packaged.java` includes a constructor-like child entry for `Foo`, so exact packaged-file skim output is analyzer-specific beyond the Brokk-style grouping/header behavior.
  Evidence: the first version of `tests/searchtools_summarize_symbols.rs` failed because the returned lines were `["# io.github.jbellis.brokk", "- Foo", "  - bar", "  - Foo"]`.

- Observation: this shell does not provide a `python` binary, but `python3` runs the Python client suite successfully.
  Evidence: `python -m unittest ...` failed with `/bin/bash: python: command not found`, and `python3 -m unittest python_tests.test_searchtools_client` passed.

## Decision Log

- Decision: keep `skim_files` as a backward-compatible alias and add an explicit `summarize_symbols` searchtools entry point instead of replacing the old tool.
  Rationale: existing clients and tests already depend on `skim_files`, but the user explicitly asked for `summarizeSymbols` to be exposed in searchtools.
  Date/Author: 2026-04-04 / Codex

## Outcomes & Retrospective

The port is complete. bifrost now has Brokk-style recursive symbol skims in the analyzer trait, an explicitly named `summarize_symbols` searchtools entry point, unchanged backward compatibility for `skim_files`, and regression coverage across Rust, MCP, and Python boundaries. The main lesson from validation is that the method-level port and analyzer child inventories are separate concerns: the new tests should lock the recursive/package-grouping behavior without assuming identical constructor or synthetic-child modeling across implementations.

## Context and Orientation

The Rust analyzer trait lives in `src/analyzer/i_analyzer.rs`. Every language analyzer implements that trait either directly or through wrappers over `TreeSitterAnalyzer`, so a default trait method is the correct place to port shared behavior from Brokk. The current searchtools layer lives in `src/searchtools.rs`; it defines serde parameter/result types and the Rust functions used by both the shared service (`src/searchtools_service.rs`) and the stdio MCP server (`src/mcp_server.rs`). The Python API in `bifrost_searchtools/client.py` talks to the same shared service through the PyO3 native module in `src/python_module.rs`.

In this repository, `skim_files` is the closest existing public operation to Brokk’s `summarizeSymbols(ProjectFile)`: it expands file globs, reads each matched file’s line count, and returns the analyzer’s compact symbol skim as `lines`. That public tool currently inherits the simplified Rust analyzer implementation. The port therefore needs two parts: improve the analyzer default method so every caller gets the richer output, and add an explicitly named searchtools entry point so callers can ask for `summarize_symbols` directly.

## Plan of Work

First, update `src/analyzer/i_analyzer.rs` to match the Brokk algorithm more closely. Keep `summarize_symbols(&ProjectFile)` as the simple public entry point, but route it through new helper methods that accept a set of included `CodeUnitType` values and an indentation level. At indent zero, group non-module, non-anonymous top-level declarations by the prefix of their fully qualified name before the last `.` and emit `# prefix` headings when the prefix is non-empty. For every rendered symbol, recurse through direct children filtered by the allowed kinds so nested classes such as `AInner.AInnerInner.method7` stay visible in the skim output.

Next, update `src/searchtools.rs` to expose a new `summarize_symbols(...)` function over file patterns. Reuse the existing compact result shape used by `skim_files` so the change stays additive. Then wire that function into `src/searchtools_service.rs`, add the new MCP tool descriptor in `src/mcp_server.rs`, and add a matching method in `bifrost_searchtools/client.py`. The Python result model can stay unchanged because the new operation returns the same `SkimFilesResult` structure.

Finally, add focused tests. One Rust analyzer test should prove recursive nesting for the existing Java fixture. A second Rust searchtools test should prove package headers appear for packaged Java files and that the new `summarize_symbols` tool returns the same file-based structure as `skim_files`. The service, MCP, and Python surfaces each need one small regression assertion that the new tool name is accepted and returns structured data.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`:

1. Edit `src/analyzer/i_analyzer.rs`, `src/searchtools.rs`, `src/searchtools_service.rs`, `src/mcp_server.rs`, and `bifrost_searchtools/client.py`.
2. Add focused tests in existing Rust and Python test files.
3. Run:

       cargo test summarize_symbols
       cargo test searchtools_service
       cargo test bifrost_searchtools_server_speaks_mcp_stdio
       python3 -m unittest python_tests.test_searchtools_client

Expected high-signal results:

       test nested_java_symbols_recurse_in_summary ... ok
       test python_boundary_returns_summarize_symbols_json ... ok
       test bifrost_searchtools_server_speaks_mcp_stdio ... ok
       OK

## Validation and Acceptance

Acceptance is behavioral. `IAnalyzer::summarize_symbols(&A.java)` must include nested lines for `AInner`, `AInnerInner`, and `method7` instead of flattening only one child level. `searchtools::summarize_symbols(...)` and `skim_files(...)` must both return file records whose `lines` contain package headers such as `# io.github.jbellis.brokk` for packaged files. `SearchToolsService::call_tool_json("summarize_symbols", ...)`, the MCP `tools/list` response, and `SearchToolsClient.summarize_symbols(...)` must all accept the new tool name and return structured JSON or typed models without breaking the existing `skim_files` tool.

## Idempotence and Recovery

All planned edits are additive and safe to repeat. If a validation command fails, inspect the changed files, fix the bug, and rerun the same command. The new searchtools entry point is additive, so a partial implementation can be retried without cleanup as long as the build is restored before finishing.

## Artifacts and Notes

Expected recursive skim excerpt for `tests/fixtures/testcode-java/A.java`:

    - A
      - method1
      - method2
      - method2
      - method3
      - method4
      - method5
      - method6
      - AInner
        - AInnerInner
          - method7
      - AInnerStatic
      - usesInnerClass

Expected packaged skim excerpt for `tests/fixtures/testcode-java/Packaged.java`:

    # io.github.jbellis.brokk
    - Foo
      - bar

## Interfaces and Dependencies

At the end of this work, these public interfaces must exist:

    src/analyzer/i_analyzer.rs
    fn summarize_symbols(&self, file: &ProjectFile) -> String;

    src/searchtools.rs
    pub fn summarize_symbols(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult;

    src/searchtools_service.rs
    SearchToolsService::call_tool_value("summarize_symbols", ...)

    bifrost_searchtools/client.py
    def summarize_symbols(self, file_patterns: list[str]) -> SkimFilesResult

Revision note: created this focused ExecPlan so the summarizeSymbols port can be implemented under the repository’s ExecPlan requirement without rewriting the broader searchtools plans.
Revision note: updated progress, discoveries, validation, and retrospective after implementation and test execution so the plan now reflects the finished state of the work.
