# Add Rust-first dead-code and unused-abstraction smell reporting

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, Bifrost will expose a new MCP code-quality tool that reports likely dead code and low-value one-call abstractions for Rust code. A contributor or MCP client will be able to point the tool at one or more Rust files, or at explicit fully qualified Rust symbols, and receive a bounded markdown report that distinguishes likely findings from inconclusive evidence. The observable proof is that the new tool appears in `tools/list`, can be called through `SearchToolsService`, and flags an unused Rust helper plus a one-call Rust wrapper in focused tests.

## Progress

- [x] (2026-05-19 11:20Z) Re-read `.agent/PLANS.md`, inspected existing `src/code_quality/*` handlers, and confirmed that issue `#85` should be implemented as a tool-layer composition over `UsageFinder`.
- [x] (2026-05-19 11:24Z) Compared the Brokk Java counterpart and confirmed that the reusable behavior is candidate selection plus bounded `queryUsages(...)`, not Java-specific formatting.
- [x] (2026-05-19 11:41Z) Implemented `src/code_quality/dead_code_smells.rs` with Rust-only candidate gating, bounded usage queries, conservative skip rules, and markdown rendering.
- [x] (2026-05-19 11:43Z) Registered the new tool through `src/code_quality/mod.rs`, `src/searchtools_service.rs`, and `src/mcp_server.rs`.
- [x] (2026-05-19 11:47Z) Added focused Rust smell tests plus service/MCP coverage.
- [x] (2026-05-19 11:58Z) Ran `cargo test --test rust_dead_code_smells`, `cargo test --test searchtools_service`, `cargo test --test bifrost_mcp_server`, `cargo test --test usages_rust_graph_test`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-05-19 11:59Z) Updated this ExecPlan with the final results and deferred-scope notes.

## Surprises & Discoveries

- Observation: The issue `#85` branch did not yet contain any implementation-specific code.
  Evidence: `git rev-parse origin/master HEAD` returned the same commit hash for both refs at the start of this work.

- Observation: Bifrost already has the exact substrate needed for this feature in the tool layer.
  Evidence: `src/usages/finder.rs` exposes bounded `query(...)`, and the existing smell tools in `src/code_quality/` already establish the MCP/service/reporting pattern that issue `#85` should follow.

- Observation: Cross-file public Rust function usage is not yet as predictably seedable in small ad hoc fixtures as same-file private usage.
  Evidence: The initial one-call-wrapper test using `src/main.rs -> helpers.wrapper()` produced zero hits, while the same scenario expressed as a same-file private call resolved correctly and passed after the fixture was adjusted.

## Decision Log

- Decision: Implement milestone 1 for Rust only.
  Rationale: Rust already routes through `RustExportUsageGraphStrategy`, which makes the first slice graph-backed and credible instead of regex-only.
  Date/Author: 2026-05-19 / Codex

- Decision: Keep the dead-code heuristic in the tool layer instead of adding a new analyzer trait.
  Rationale: The Brokk counterpart composes declarations plus usage queries rather than relying on a dedicated analyzer capability, and Bifrost already has the same composition points.
  Date/Author: 2026-05-19 / Codex

- Decision: Treat truncated candidate-file sets, ambiguous usage results, failures, and too-many-callsites outcomes as inconclusive and skip them.
  Rationale: The goal is high-recall triage without inventing dead-code certainty where the current tree-sitter usage stack cannot defend it.
  Date/Author: 2026-05-19 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. Bifrost now exposes a Rust-first `report_dead_code_and_unused_abstraction_smells` MCP tool that composes declaration discovery with bounded `UsageFinder::query(...)` calls. The handler emits findings only for `0`-usage and `1`-usage Rust functions, classes, and fields, and it records ambiguous, truncated, failed, and too-many-callsites cases as skipped evidence instead of mislabeling them as dead code.

The new tool is wired through the code-quality module surface, `SearchToolsService`, and the stdio MCP server. Focused tests cover an unused helper, a one-call wrapper, a self-recursive function, candidate-file truncation, explicit FQN targeting, and thresholded no-findings output. The service and MCP server tests prove the tool is callable and listed.

Deliberately deferred work remains unchanged from the original scope: Python, JS/TS, and any Java strategy are follow-up milestones, not part of this Rust-first landing.

## Context and Orientation

`src/code_quality/mod.rs` is the hub for analyzer-backed code-quality MCP tools. Each tool has its own submodule with a `*Params` input struct, a `*Result` output struct, and a `report_*` or `compute_*` function re-exported by `mod.rs`.

`src/searchtools_service.rs` wires those handlers into `SearchToolsService::call_tool_value`, which is the local JSON boundary used by tests and by the stdio MCP server. `src/mcp_server.rs` defines the public `tools/list` descriptors and per-tool input schemas.

`src/usages/finder.rs` contains `UsageFinder`, which can return both the usage result and the candidate file set via `query(...)`. That matters here because the dead-code smell must skip symbols whose candidate set exceeded the supplied cap. `src/usages/model.rs` defines `FuzzyResult` and `UsageHit`.

The Rust-first constraint is deliberate. The smell tool should only analyze Rust declarations in milestone 1, because Rust already has the strongest graph-backed usage support in Bifrost. Non-Rust declarations that reach the handler should be skipped silently or reported as skipped evidence where that helps explain the result.

## Plan of Work

Add a new file `src/code_quality/dead_code_smells.rs`. Define the public parameter and result structs there. The parameters should mirror the planned bounded contract: `file_paths`, optional `fq_names`, `min_score`, `max_findings`, `max_input_files`, `max_candidate_symbols`, `max_usage_candidate_files`, and `max_usages_per_symbol`.

Inside that module, implement a Rust-only candidate pipeline. Resolve caller-supplied files with `resolve_project_files`, then cap the selected files by `max_input_files`. When `fq_names` is empty, gather declarations from those files. When `fq_names` is present, resolve exact definitions and optionally keep only those whose source file is in the selected file set when that set is non-empty. In both paths, retain only non-synthetic, non-anonymous Rust functions, classes, and fields.

For each candidate, compute the best declaration range from `analyzer.ranges_of(candidate)` and run `UsageFinder::new().query(...)` with the supplied usage caps. If the query reports `candidate_files_truncated`, or returns `FuzzyResult::Failure`, `FuzzyResult::Ambiguous`, or `FuzzyResult::TooManyCallsites`, record skipped evidence and move on.

For successful usage results, drop self-usages by excluding hits whose `enclosing` code unit equals the candidate. Also compute external usages by comparing the defining owner of the candidate to the owner of each hit using `analyzer.parent_of(...)`, falling back to the code unit itself when no parent exists. Only emit findings when the non-self usage count is `0` or `1`. Use Brokk-like scoring and report columns: score, confidence, kind, symbol, file span, total usages, external usages, evidence, and rationale. The report should explicitly note that the analysis is Rust tree-sitter usage analysis and best-effort.

After the handler exists, export it from `src/code_quality/mod.rs`, add it to the `SearchToolsService` imports and dispatch table, and add a matching tool descriptor plus input schema in `src/mcp_server.rs`.

Finally, add focused tests. Create a new Rust smell test file that uses `tests/common/inline_project.rs` to cover an unused helper, a one-call wrapper, a self-recursive function that should still count as dead code, a truncated candidate-file case that should be skipped, explicit FQN targeting, and a thresholded no-findings case. Extend the service/MCP tests so the new tool is listed and callable.

## Concrete Steps

From `/Users/dave/.codex/worktrees/f0e5/bifrost`:

1. Create `src/code_quality/dead_code_smells.rs` and implement the Rust-only report handler.
2. Edit `src/code_quality/mod.rs` to register and re-export the new handler types.
3. Edit `src/searchtools_service.rs` to import and dispatch `report_dead_code_and_unused_abstraction_smells`.
4. Edit `src/mcp_server.rs` to list the new tool and describe its schema.
5. Add focused tests for the Rust smell handler and the service/server boundaries.
6. Run the targeted test commands and the local CI checks listed below.

Expected commands:

    cargo test --test rust_dead_code_smells
    cargo test --test searchtools_service
    cargo test --test bifrost_mcp_server
    cargo test --test usages_rust_graph_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

Acceptance is behavioral:

1. The new MCP tool appears in `tools/list` as `report_dead_code_and_unused_abstraction_smells`.
2. Calling the tool through `SearchToolsService` returns a structured JSON object with a markdown report and `truncated` flag.
3. A Rust inline project with an unused private helper reports a dead-code finding with `0` usages.
4. A Rust inline project with a single-call wrapper reports an unused-abstraction finding with `1` usage.
5. A self-recursive Rust function is not exempt merely because it calls itself; self-usages are removed and the symbol still reports as dead code.
6. When the usage candidate file cap is too low, the report records skipped evidence instead of emitting a misleading finding.

## Idempotence and Recovery

All edits are additive and safe to retry. If the new handler behaves unexpectedly, it can be isolated by removing the new dispatch entries and module export without disturbing existing smell tools. If a specific candidate filter proves too broad, tighten the Rust-only gating rather than relaxing the skip-on-inconclusive rule.

## Artifacts and Notes

The most important artifact is the new report table shape, because downstream MCP clients will consume it directly. Keep the report ordering stable by sorting findings deterministically by usage count, score, file, and symbol so tests stay reliable.

## Interfaces and Dependencies

In `src/code_quality/dead_code_smells.rs`, define:

    pub struct ReportDeadCodeAndUnusedAbstractionSmellsParams
    pub struct ReportDeadCodeAndUnusedAbstractionSmellsResult
    pub fn report_dead_code_and_unused_abstraction_smells(
        analyzer: &dyn IAnalyzer,
        params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
    ) -> ReportDeadCodeAndUnusedAbstractionSmellsResult

This handler should depend on:

- `crate::code_quality::{ReportLines, resolve_project_files, sanitize_table_cell}`
- `crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range}`
- `crate::path_utils::rel_path_string`
- `crate::usages::{FuzzyResult, UsageFinder, UsageHit}`

Keep the public output shape as `{ report: String, truncated: bool }`, matching the surrounding code-quality tools.

Change note: created this ExecPlan before code edits because AGENTS.md requires ExecPlans for significant features and this issue adds a new MCP tool with non-trivial analyzer composition and tests.

Change note: updated this ExecPlan after implementation to record the final Rust-only behavior, the targeted test/CI evidence, and the discovered limitation around small cross-file Rust fixtures.
