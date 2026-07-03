# Add `--sources` Subset Workspaces for One-Shot `--tool`

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Today `bifrost --tool ...` always builds a full-root workspace, which is unnecessarily expensive for small one-shot queries such as `get_symbol_sources` on a small set of files. After this change, a user can pass repeatable `--sources PATH` arguments to restrict one-shot workspace construction to an explicit subset of files, directories, and glob expansions. They should be able to see it working by running `bifrost --tool get_symbol_sources --sources src --args '{"symbols":["src/main.rs"]}'` and observing that symbols outside the selected source set are not visible.

## Progress

- [x] (2026-06-28T00:00:00Z) Inspected the current `--tool` CLI flow, `SearchToolsService`, `FileSetProject`, watcher behavior, and persistence reconcile logic.
- [x] (2026-06-28T00:35:00Z) Implemented `FileSetProject` persistence opt-out and exposed the shared ignore-aware workspace file enumerator for CLI source-set expansion.
- [x] (2026-06-28T00:40:00Z) Added a manual `SearchToolsService::new_manual_for_project(...)` constructor and switched subset one-shot runs to it.
- [x] (2026-06-28T00:50:00Z) Added `--sources PATH` parsing, file/directory/glob resolution, and subset workspace construction in `src/bin/bifrost.rs`.
- [x] (2026-06-28T01:05:00Z) Added CLI and unit coverage, updated help/README text, and validated with `cargo fmt`, `cargo test --test bifrost_tool_cli`, `cargo test fileset_project_disables_persistence`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## Surprises & Discoveries

- Observation: `FileSetProject` already exists and already models the exact subset-workspace semantics needed for one-shot `--tool`.
  Evidence: `src/analyzer/project.rs` defines `FileSetProject { root, files, languages }` with `all_files()` and `analyzable_files()` limited to the provided set.

- Observation: persisted analyzer startup would treat a subset workspace as authoritative for deletes unless persistence is disabled at the project boundary.
  Evidence: `src/analyzer/persistence/reconcile.rs` computes `deletes` as every baseline row whose path is not present in `workspace_files`.

- Observation: even a manual subset analyzer would still get whole-root side effects if it reused the normal service constructor because watchers are rooted at `project.root()`.
  Evidence: `ProjectChangeWatcher::start` in `src/project_watcher.rs` always calls `watch(project.root(), RecursiveMode::Recursive)`.

## Decision Log

- Decision: implement subset workspaces only for one-shot `--tool`, not MCP or LSP.
  Rationale: the user explicitly asked for one-shot `get_symbol_sources` acceleration, and long-lived server modes need full-root semantics plus watchers.
  Date/Author: 2026-06-28 / Codex

- Decision: make `FileSetProject` itself return `None` from `persistence_root()`.
  Rationale: disabling persistence at the project boundary prevents every caller from accidentally reconciling a subset against the full-root analyzer cache.
  Date/Author: 2026-06-28 / Codex

- Decision: `--sources` accepts literal files, literal directories, and glob patterns.
  Rationale: the requested UX was `path*`, followed by an explicit request to expand directories.
  Date/Author: 2026-06-28 / Codex

## Outcomes & Retrospective

Implementation outcome 2026-06-28: one-shot `bifrost --tool` invocations can now accept repeatable `--sources PATH` selectors and build an exact subset workspace from file literals, directory recursion, and glob expansion instead of indexing the entire repo. The subset path is manual-only, does not start watchers or semantic indexing, and cannot poison the analyzer persistence DB because `FileSetProject` now disables persistence at the project boundary.

Follow-up requested after this commit: tighten `ProjectChangeWatcher` so long-lived services watch only directories that contain analyzed files instead of recursively watching the entire project root.

## Context and Orientation

The top-level CLI entrypoint lives in `src/bin/bifrost.rs`. Today its `run_tool` path canonicalizes `--root`, normalizes tool arguments, constructs `SearchToolsService::new(root)`, and dispatches the tool against a full `FilesystemProject`. The reusable analyzer project abstractions live in `src/analyzer/project.rs`; that file already contains `FilesystemProject` for full-root directory walks and `FileSetProject` for exact file subsets. The service layer lives in `src/searchtools_service.rs`; it owns analyzer construction, watcher startup, and tool dispatch.

The key constraint is analyzer persistence. `WorkspaceAnalyzer::build_persisted(...)` reuses a per-root SQLite cache and removes persisted rows for files missing from the current workspace. That behavior is correct for full-root workspaces and incorrect for subset workspaces, so subset runs must never persist. The second constraint is watcher scope. One-shot subset tool runs should not watch the whole repo or start semantic indexing because they exit immediately after printing one result.

## Plan of Work

First, update `src/analyzer/project.rs` so `FileSetProject` overrides `persistence_root()` to return `None`. While in that file, expose a shared ignore-aware file enumeration helper that the CLI can reuse for directory and glob expansion without re-implementing the repository walk in the binary.

Next, update `src/searchtools_service.rs` with a constructor that accepts an `Arc<dyn Project>`, builds a `WorkspaceAnalyzer` with `WorkspaceAnalyzer::build(...)`, and installs it with `UpdateStrategy::Manual` and semantic indexing disabled. This keeps the normal tool dispatch path intact while ensuring one-shot subset runs do not start watchers or persistence.

Then, extend `src/bin/bifrost.rs` to parse repeatable `--sources PATH`. When the flag is present alongside `--tool`, resolve each input relative to `--root` into a deduplicated set of project-relative files: file literals include one file, directory literals recurse, and glob patterns expand against the ignore-aware workspace file inventory. Fail fast for missing literals, outside-workspace paths, empty glob matches, and an empty final subset. Construct a `FileSetProject` from the resolved set, build a manual `SearchToolsService` from it, and otherwise keep argument normalization, rendering, and output handling unchanged.

Finally, update `tests/bifrost_tool_cli.rs`, add focused unit tests near the source expansion helper and `FileSetProject`, update help text and `README.md`, then run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and targeted tests for the new behavior.

## Concrete Steps

Work from the repository root:

    cd /home/jonathan/Projects/bifrost

Validation commands:

    cargo fmt
    cargo test --test bifrost_tool_cli
    cargo clippy --all-targets --all-features -- -D warnings

If those pass, run targeted unit tests that cover the new subset resolver and project behavior.

## Validation and Acceptance

Acceptance is behavioral. A one-shot command such as:

    cargo run --bin bifrost -- --root tests/fixtures/testcode-java --tool get_symbol_sources --sources A.java --args '{"symbols":["A.java"]}'

must succeed without building a watcher-backed full-root session. A symbol or file outside the selected subset must resolve as not found even if it exists under the same `--root`. Passing a directory in `--sources` must recursively add files under that directory, and passing a glob in `--sources` must expand it against the ignore-aware workspace inventory. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and the updated CLI test suite must pass.

## Idempotence and Recovery

These are source-only changes and are safe to reapply. If work stops midway, recover by ensuring the new manual-project `SearchToolsService` constructor exists before wiring `--sources` parsing, because the CLI subset path depends on that constructor. Do not revert unrelated worktree files; the observed untracked `.so.bak-stale-0014` file is unrelated and must remain untouched.

## Artifacts and Notes

The most important pre-change artifact is the current `run_tool` implementation in `src/bin/bifrost.rs`: it always calls `SearchToolsService::new(root)` and therefore always builds a full-root workspace with the standard service defaults. The subset feature intentionally changes only that workspace-construction step while leaving tool dispatch and rendering behavior unchanged.

## Interfaces and Dependencies

`src/searchtools_service.rs` must expose a manual custom-project constructor with this shape:

    pub fn new_manual_for_project(project: Arc<dyn Project>) -> Result<Self, String>;

`src/analyzer/project.rs` must make `FileSetProject` opt out of persistence by overriding:

    fn persistence_root(&self) -> Option<&Path> {
        None
    }

The CLI source resolver may live in `src/bin/bifrost.rs` or a shared library helper, but it must consume `--sources` strings and return project-relative file paths suitable for:

    FileSetProject::new(root.clone(), rel_paths)

Revision note: 2026-06-28 / Codex. Created this ExecPlan before implementation because `AGENTS.md` requires an ExecPlan for significant features and this change alters public CLI behavior plus analyzer construction semantics.
Revision note: 2026-06-28 / Codex. Updated progress and outcomes after finishing the `--sources` subset-workspace implementation and validation so the next contributor can begin directly from the watcher-scope follow-up.
