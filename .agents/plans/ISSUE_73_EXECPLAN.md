# Extract Shared Usage Graph Core For Issue 73

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, `bifrost` will no longer keep the exported-symbol usage graph logic trapped inside one JS/TS-only file. The reusable graph pieces will live in shared `src/usages` modules so future Python and Rust strategies can plug in their own parsing and scanning logic without copy-pasting the graph traversal and seed/re-export/import bookkeeping. The immediate proof is that the existing JS/TS usage-finding tests still pass while the code is reorganized around a language-neutral core.

## Progress

- [x] (2026-05-18T10:20Z) Read issue `#73`, `.agent/PLANS.md`, `src/usages/js_ts_graph.rs`, `src/usages/model.rs`, and the matching Brokk shared-engine classes.
- [x] (2026-05-18T10:20Z) Decided to keep this issue scoped to shared graph IR and traversal extraction, while leaving JS/TS-specific AST parsing and hit scanning behind a JS/TS adapter.
- [x] (2026-05-18T10:31Z) Added `src/usages/graph_core.rs` with shared import-edge IR plus reusable project-graph construction, seed expansion, importer lookup, and importer-edge matching logic.
- [x] (2026-05-18T10:31Z) Re-layered `JsTsExportUsageGraphStrategy` so `src/usages/js_ts_graph.rs` now builds JS/TS parses and extractors, then delegates graph bookkeeping to the shared core.
- [x] (2026-05-18T10:31Z) Kept validation behavior-focused by preserving the existing JS/TS graph tests rather than introducing a large mock adapter harness.
- [x] (2026-05-18T10:35Z) Ran `cargo fmt`, `cargo test --test usages_js_ts_graph_test`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`; all passed.

## Surprises & Discoveries

- Observation: `bifrost` already had a language-neutral graph kernel, but it was buried inside `src/usages/js_ts_graph.rs`.
  Evidence: `ProjectGraph`, `ImportEdge`, re-export BFS, and importer reverse-index construction were all broader than JS/TS-specific AST parsing.

- Observation: Brokk’s Java implementation split the system at the same seam this issue calls for: a shared engine plus thin language adapters.
  Evidence: `ExportUsageReferenceGraphEngine.java`, `ExportUsageGraphLanguageAdapter.java`, and `JsTsExportUsageGraphAdapter.java` in `brokk-shared`.

- Observation: the existing `tests/usages_js_ts_graph_test.rs` file was sufficient acceptance coverage for this extraction once the public `UsageFinder` and JS/TS strategy behavior stayed unchanged.
  Evidence: after the refactor, all three focused tests passed without needing new fixture setup or mock analyzers.

## Decision Log

- Decision: extract only the reusable graph bookkeeping and traversal core in this issue, not the full Brokk multi-language adapter surface.
  Rationale: `bifrost` does not yet have Python/Rust graph strategies to plug in, so the highest-value change is to establish the shared module boundary without inflating the public API prematurely.
  Date/Author: 2026-05-18 / Codex

- Decision: keep `ExportIndex` and `ImportBinder` in `src/usages/model.rs` for now, and add separate shared graph-core modules instead of moving every IR type at once.
  Rationale: those types are already language-neutral and already shared by other `usages` code; the main refactor pressure is on the graph engine, not on renaming existing models.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

The issue’s enabling refactor is now in place. `src/usages/graph_core.rs` owns the reusable graph bookkeeping, while `src/usages/js_ts_graph.rs` is reduced to the JS/TS-specific responsibilities of parsing files, extracting exports/import binders, and scanning syntax trees for `UsageHit` records. This matches the architectural seam described in issue `#73` and makes future Python/Rust graph strategies a matter of supplying their own extraction and scanning layers instead of copy-pasting the graph traversal.

What remains for the broader backlog is to add those new language strategies. This issue did not attempt to design the full multi-language adapter surface used in Brokk’s Java code, because `bifrost` does not yet have Python/Rust graph implementations ready to plug in. The current extraction is intentionally the smallest shared core that reduces duplication pressure now while preserving JS/TS behavior.

## Context and Orientation

The current exported-symbol usage graph lives in `src/usages/js_ts_graph.rs`. That file currently does four jobs at once: it chooses whether JS/TS can handle a query, builds project-wide export/import/re-export indices, walks those graph indices to infer seeds and importers, and scans JS/TS syntax trees to record `UsageHit` values. The public entry points are `src/usages/finder.rs`, which routes JS/TS targets into `JsTsExportUsageGraphStrategy`, and `src/usages/mod.rs`, which exports the strategy.

The reusable concepts already exist in the current code. `ExportIndex` and `ImportBinder` in `src/usages/model.rs` are language-neutral representations of what a file exports and which local names an import introduces. `ProjectGraph`, `ImportEdge`, and the seed/re-export/import traversal logic in `src/usages/js_ts_graph.rs` are also language-neutral except for one dependency: module resolution currently goes through `resolve_js_ts_module_specifier`, which is JS/TS-specific and should stay behind the JS/TS adapter layer.

Brokk’s reference implementation lives outside this repo in `/Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/`. The most relevant files are `ExportUsageReferenceGraphEngine.java`, `ExportUsageGraphLanguageAdapter.java`, and `JsTsExportUsageGraphAdapter.java`. They show the target architectural seam: the shared engine owns graph orchestration while the language adapter owns file parsing, binding extraction, module resolution, and candidate scanning.

## Plan of Work

First, add a new shared graph-core module under `src/usages/` to hold the reusable graph data and traversal helpers that currently sit inside `src/usages/js_ts_graph.rs`. This module should define the graph-side IR for resolved import edges and the project graph structure that stores parsed per-file export/import data, reverse re-export edges, star re-exports, seed lookup tables, and reverse importer edges. The build path should be parameterized by a small resolver callback so the shared core can ask the JS/TS layer how to resolve a module specifier without directly depending on JS/TS code.

Next, update `src/usages/js_ts_graph.rs` so it becomes a JS/TS adapter and scanner layered on top of that shared core. JS/TS-specific responsibilities should remain here: target-language detection, parser setup, AST export extraction, AST import-binder extraction, and AST scanning for `UsageHit` values. The strategy should create the shared graph, request seeds and importer files from it, and then reuse the existing scan pipeline against the narrowed file set.

Then, update `src/usages/mod.rs` to expose the new shared module only as an internal implementation detail unless a public export is clearly needed. Keep `UsageFinder` behavior unchanged: JS/TS still routes through `JsTsExportUsageGraphStrategy`, and non-JS/TS still falls back to regex.

Finally, keep validation behavior-centered. The existing `tests/usages_js_ts_graph_test.rs` file already exercises the JS/TS strategy through in-file references and `UsageFinder` routing. If the extraction needs more coverage, add focused tests around the shared graph boundary through the existing public JS/TS strategy rather than inventing a large mock-only test harness.

## Concrete Steps

From `/Users/dave/.codex/worktrees/3976/bifrost`:

1. Edit `src/usages/` to add shared graph-core modules and rewire `js_ts_graph.rs`.
2. Run:

       cargo fmt

3. Run focused tests:

       cargo test --test usages_js_ts_graph_test

4. Run CI-style Rust checks:

       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings

If focused tests expose unrelated breakage in the broader suite, capture that in `Surprises & Discoveries` and then run the smallest additional command needed to prove the refactor is sound.

## Validation and Acceptance

Acceptance is behavioral, not structural.

Run `cargo test --test usages_js_ts_graph_test` and expect the existing JS/TS graph tests to pass. That proves `UsageFinder` still routes JS/TS targets through the graph path and that the graph still finds the same in-file references after the extraction.

Run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` and expect both to pass. That proves the refactor kept the Rust codebase in the same quality state expected by CI.

## Idempotence and Recovery

This refactor is source-only. Re-running `cargo fmt` and the test commands is safe. If a partial extraction leaves compilation broken, the safe recovery path is to finish moving the remaining shared helpers into the new module rather than reverting unrelated code. No generated files or persistent state are involved.

## Artifacts and Notes

The key architectural references for this issue are:

    src/usages/js_ts_graph.rs
    src/usages/model.rs
    src/usages/finder.rs
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/ExportUsageReferenceGraphEngine.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/JsTsExportUsageGraphAdapter.java

## Interfaces and Dependencies

The shared Rust core should end this issue with stable internal interfaces under `src/usages/` for:

    a project-graph type that can return seed exports for a target, importer files for a seed set, and matching import edges for a candidate importer;

    a resolver callback shape that takes `(importing_file, module_specifier)` and returns resolved `ProjectFile` targets for that adapter;

    graph-edge IR that records the importer file, the local binding name, the resolved target file, and whether the import was named, default, or namespace.

`JsTsExportUsageGraphStrategy` should remain the public façade that implements `crate::usages::traits::UsageAnalyzer`.

Revision note: created this issue-specific ExecPlan after reading the issue and current implementation so the extraction can proceed against a written architecture and validation plan.

Revision note: updated after implementation to record the new shared `graph_core` module, the JS/TS relayering, and the exact validation commands that passed.
