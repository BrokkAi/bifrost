# Generalize usage-analysis file inventory

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This repository’s canonical ExecPlan instructions are in `.agents/PLANS.md`; this document follows those instructions.

## Purpose / Big Picture

Large repositories should not become CPU-bound because usage-analysis code repeatedly walks the filesystem. After this change, `usage_graph` and `scan_usages` paths will derive file sets from the already-built analyzer state instead of repeatedly calling `Project::all_files()` or `Project::analyzable_files()`. The improvement is visible on `libgit2/libgit2@267479dad5bfc8b028965e54a2625f3960f9d319`: path-scoped C++ `usage_graph` should complete in about 1-2 seconds instead of about 70 seconds while returning the same graph counts.

## Progress

- [x] (2026-07-06) Reproduced issue #511 on `libgit2/libgit2@267479dad5bfc8b028965e54a2625f3960f9d319`; warmed `usage_graph(paths=[src/libgit2/transports/http.c, src/libgit2/transports/winhttp.c, tests/libgit2/online/fetch.c])` took about 71.4 seconds.
- [x] (2026-07-06) Profiled the warmed call and found the C++ phase dominated by repeated workspace file enumeration through include fallback resolution.
- [x] (2026-07-06) Confirmed recent commits `049776e` and `2111bf7` indexed C++ reverse include references for `referencing_files_of`, but did not route C++ usage-graph visibility through the same indexed shape.
- [x] (2026-07-06) Added a shared C++ `IncludeTargetIndex` and routed C++ usage-graph include traversal through an indexed resolver.
- [x] (2026-07-06) Replaced usage-analysis `Project::analyzable_files()` calls with a shared helper that reads the analyzer’s in-memory file inventory.
- [x] (2026-07-06) Moved C++ import, hierarchy, usage visibility, and get-definition include-boundary checks onto the analyzer-owned include target index.
- [x] (2026-07-06) Validated with targeted tests, `cargo clippy-no-cuda`, and the libgit2 repro timing.

## Surprises & Discoveries

- Observation: The recent include-index commits were real but only part of the answer.
  Evidence: `049776e Index C++ include references` added `CppAnalyzer::reverse_include_index`, and `2111bf7 Share reverse file index construction` shared reverse-map construction. The profiled C++ usage-graph path still called `resolve_include_targets_with_unique_fallback`, whose fallback calls `project.all_files()`.

- Observation: The pathological wall time was not workspace construction.
  Evidence: With `BIFROST_TIMING=1`, `WorkspaceAnalyzer::build` was about 1.7 seconds, while `usage_graph::resolve_cpp` was about 66.8 seconds before the indexed include resolver.

- Observation: A narrow C++ indexed include resolver removes the measured hot spot but is not the right stopping point.
  Evidence: After the first fix, `usage_graph::resolve_cpp` dropped to about 1.1 seconds and total warmed `usage_graph` dropped to about 1.65 seconds. Remaining code still has several usage-analysis calls to `project().analyzable_files(...)`.

- Observation: Python repro runs must load the rebuilt local extension, not just the freshly built `target/debug` cdylib.
  Evidence: `uv run python` imported `/home/jonathan/Projects/bifrost/bifrost_searchtools/_native.abi3.so`, which was older than `target/debug/libbrokk_bifrost.so`. After copying the rebuilt cdylib over the local extension for measurement, the new code path ran and the repro dropped below one second warmed.

- Observation: `cpp_unresolved_include_boundary` was another C++ usage-side include check that still used the filesystem-aware resolver.
  Evidence: Static search found `resolve_include_targets(analyzer.project(), file, include)` in `src/analyzer/usages/get_definition/cpp.rs`; perf still showed `collect_workspace_files` while `usage_graph::resolve_cpp` was slow. Routing it through `CppAnalyzer::include_target_index()` removed the remaining project enumeration from that path.

## Decision Log

- Decision: Generalize the rule at the usage-analysis boundary: hot usage paths should use analyzer-owned file inventory rather than live project enumeration.
  Rationale: The analyzer has already paid to enumerate and parse relevant files. Re-walking the filesystem from resolvers is both redundant and vulnerable to the same bug across languages.
  Date/Author: 2026-07-06 / Codex

- Decision: Keep direct include resolution behavior, but make fallback include resolution use a prebuilt target index.
  Rationale: Direct relative includes can be resolved from the source file and project root without enumeration. The expensive part is suffix fallback for unresolved includes; indexing preserves behavior while avoiding one full scan per include.
  Date/Author: 2026-07-06 / Codex

- Decision: For hot C++ analyzer paths, indexed include resolution should answer source-relative, project-relative, and unique suffix fallback from analyzed-file inventory.
  Rationale: Visibility, import analysis, hierarchy, and C++ get-definition checks only need targets that the analyzer has indexed. Calling filesystem `exists()` or `Project::all_files()` in these loops repeats work already completed during analyzer construction.
  Date/Author: 2026-07-06 / Codex

## Outcomes & Retrospective

Implemented a usage-analysis-wide inventory boundary. Edge resolvers and candidate providers now get language file sets from `analyzer.analyzed_files()` through `analyzed_files_for_language`, so the hot path no longer re-enters `Project::analyzable_files()`.

Implemented a reusable C++ `IncludeTargetIndex` owned by `CppAnalyzer`. C++ import analysis, reverse include indexing, type hierarchy, usage visibility, and get-definition include-boundary checks now share indexed include resolution. The old `resolve_include_targets_with_unique_fallback` API was removed so new hot callers cannot accidentally reintroduce `Project::all_files()` fallback.

Final libgit2 repro with the rebuilt local Python extension:

    usage_graph[0] 2.724s nodes=11277 edges=362 truncated=None
    usage_graph[1] 0.983s nodes=11277 edges=362 truncated=None
    [bifrost-timing] END usage_graph::resolve_cpp (819.8 ms)

## Context and Orientation

`Project` in `src/analyzer/project.rs` represents a source tree. `FilesystemProject::all_files()` performs a live ignored filesystem walk through `collect_workspace_files`; `FilesystemProject::analyzable_files(language)` calls `all_files()` and filters by extension. These are correct for cold project construction but too expensive inside hot usage-analysis loops.

`IAnalyzer` in `src/analyzer/i_analyzer.rs` represents an already-built analyzer. Its `analyzed_files()` method returns files already known to the analyzer. For `MultiAnalyzer` in `src/analyzer/multi_analyzer.rs`, `analyzed_files()` merges the file sets from all language delegates. This in-memory inventory is the correct source for usage-graph builders and scan-usages candidate logic after workspace construction.

Usage-analysis code lives under `src/analyzer/usages/`. Edge resolvers for several languages currently call `analyzer.project().analyzable_files(Language::X)`, which can re-enter live filesystem enumeration. C++ usage-graph visibility in `src/analyzer/usages/cpp_graph/resolver.rs` also used the standalone C++ include fallback resolver from `src/analyzer/cpp/imports.rs`, whose fallback calls `project.all_files()`.

## Plan of Work

First, add or use a single shared helper in `src/analyzer/usages/common.rs` that returns a deterministic `Vec<ProjectFile>` for a language by filtering `analyzer.analyzed_files()` with `language_for_file`. This helper must not call `Project::analyzable_files()`.

Next, migrate usage-analysis edge resolvers that currently call `analyzer.project().analyzable_files(Language::X)` to this helper. This includes Go, Java, C#, PHP, Scala, C++, and JavaScript/TypeScript usage-graph resolver setup. This is a single usage subsystem migration, not separate language-specific fixes.

Then, adjust C++ include indexing so hot analyzer paths use `CppAnalyzer::include_target_index()`. The indexed resolver should preserve source-relative, project-relative, and unique suffix fallback resolution against analyzed files without filesystem enumeration.

Finally, validate both behavior and performance. The C++ usage graph tests must still pass, the indexed include fallback unit test must pass, `cargo clippy-no-cuda` must pass, and the libgit2 warmed `usage_graph` repro must stay around 1-2 seconds with the same node/edge/truncation counts as before the fix.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Run:

    cargo fmt
    cargo check
    cargo test indexed_include_resolution_uses_unique_suffix_fallback
    cargo test --test usage_graph_cpp_test
    cargo clippy-no-cuda

For the performance validation, build the Python-enabled debug library:

    cargo build --features python

For the local Python package import path used by `uv run python`, copy the rebuilt cdylib over the local extension before measuring:

    cp target/debug/libbrokk_bifrost.so bifrost_searchtools/_native.abi3.so

Then run the libgit2 repro script against `/tmp/bifrost-issue511-libgit2`:

    BIFROST_TIMING=1 uv run python - <<'PY'
    import time
    from bifrost_searchtools import SearchToolsClient
    root = '/tmp/bifrost-issue511-libgit2'
    paths = ['src/libgit2/transports/http.c','src/libgit2/transports/winhttp.c','tests/libgit2/online/fetch.c']
    client = SearchToolsClient(root=root, manual=True)
    for i in range(2):
        t = time.perf_counter()
        g = client.usage_graph(paths=paths)
        print(f'usage_graph[{i}] {time.perf_counter() - t:.3f}s nodes={len(g.nodes)} edges={len(g.edges)} truncated={getattr(g, "truncated", None)}', flush=True)
    PY

Expected output after the fix is approximately:

    usage_graph[0] 2-3s nodes=11277 edges=362 truncated=None
    usage_graph[1] <1.5s nodes=11277 edges=362 truncated=None

## Validation and Acceptance

Acceptance is met when no hot usage-analysis resolver calls `Project::analyzable_files()` for language file sets, C++ hot include checks use analyzer inventory, tests and clippy pass, and the libgit2 repro stays below 2 seconds warmed on this machine with the same output counts.

## Idempotence and Recovery

The edits are source-only and safe to rerun. If a helper migration breaks a resolver, run `rg -n "project\\(\\)\\.analyzable_files|\\.all_files\\(\\)" src/analyzer/usages src/analyzer/cpp src/searchtools.rs` to find the remaining live filesystem enumeration call, then decide whether it belongs in cold project construction or hot usage analysis. Keep `Project::analyzable_files()` itself intact for cold construction and project-level APIs.

## Artifacts and Notes

Before the indexed include resolver:

    usage_graph[0] 71.389s nodes=11277 edges=362 truncated=0
    usage_graph[1] 71.400s nodes=11277 edges=362 truncated=0
    [bifrost-timing] END usage_graph::resolve_cpp (66828.8 ms)

After the generalized inventory and indexed C++ include resolver:

    usage_graph[0] 2.724s nodes=11277 edges=362 truncated=None
    usage_graph[1] 0.983s nodes=11277 edges=362 truncated=None
    [bifrost-timing] END usage_graph::resolve_cpp (819.8 ms)

## Interfaces and Dependencies

`src/analyzer/usages/common.rs` should expose a crate-private helper with a stable purpose, for example:

    pub(crate) fn analyzed_files_for_language(analyzer: &dyn IAnalyzer, language: Language) -> Vec<ProjectFile>

The helper should filter `analyzer.analyzed_files()` by `language_for_file(file) == language`, clone the files, sort them for deterministic behavior, and return the vector. Usage resolver code should call this helper instead of `analyzer.project().analyzable_files(language)`.

`src/analyzer/cpp/imports.rs` should expose `IncludeTargetIndex` and `resolve_include_targets_with_index`. `IncludeTargetIndex` is a prebuilt map from project-relative paths and file names to `ProjectFile`s. `resolve_include_targets_with_index` should resolve source-relative and project-relative includes from that index first, then use the index for the unique suffix fallback.
