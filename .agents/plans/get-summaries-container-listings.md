# Add container-aware get_summaries listings and update callers

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, a caller can use `get_summaries` as a code-aware directory listing. A filesystem directory returns its immediate files and child directories, while a semantic package or namespace returns its immediate top-level types and child packages. Existing file, glob, and symbol targets continue to return code summaries. The behavior is visible through the Rust API, MCP, the Python client, and the selected callers in the sibling BrokkBench repository.

## Progress

- [x] (2026-07-20 16:00Z) Researched the existing summary router, package index, MCP augmentation, Python model, and scoped BrokkBench callers.
- [x] (2026-07-20 16:00Z) Settled the public result contract and caller compatibility rules with the user.
- [x] (2026-07-20 18:05Z) Implemented the Bifrost container index, target routing, result types, and rendering.
- [x] (2026-07-20 18:05Z) Removed the obsolete unresolved-target/list_symbols container augmentation.
- [x] (2026-07-20 18:05Z) Updated Python models, MCP budgeting, descriptors, and documentation.
- [x] (2026-07-20 23:10Z) Added behavior-focused Rust, MCP, and Python tests, including gitignored-file exclusion and mixed container/summary requests.
- [x] (2026-07-20 23:10Z) Audited root-level, `p2t/**/*.py`, and `localizer/**/*.py` BrokkBench callers; updated the generic P2T research path and left concrete file-only callers unchanged.
- [x] (2026-07-20 23:10Z) Ran required validation and committed the main Bifrost implementation and BrokkBench caller update independently; final contract-clarity follow-up is ready to commit.

## Surprises & Discoveries

- Observation: directory and package targets currently become `not_found` in the core `SummaryResult`, then service and MCP wrappers call `list_symbols` to inject `compact_symbols`.
  Evidence: `src/get_summaries_output.rs` and `src/mcp_common.rs` both contain `maybe_add_directory_inventory`; `src/searchtools.rs::get_summaries` explicitly appends directory inputs to `not_found`.
- Observation: the sibling caller directory named by the user as `ptr` is actually the tracked `p2t` directory.
  Evidence: `/home/jonathan/Projects/brokkbench/ptr` is absent and `/home/jonathan/Projects/brokkbench/p2t` contains the P2T implementation and tests.
- Observation: virtual package language metadata must be propagated through every ancestor during index insertion.
  Evidence: an immediate child package may itself be virtual and therefore have no exact-package language entry to contribute when its parent listing is rendered.
- Observation: recursive filesystem-directory expansion is still used by file-pattern APIs outside `get_summaries`.
  Evidence: `resolve_file_patterns` calls `resolve_directory_target`; the helper remains, but its former semantic package-prefix fallback was removed because packages are now a first-class `get_summaries` result.
- Observation: the lightweight analyzer `TestProject` intentionally reports its inline file set without applying `.gitignore`, while production `FilesystemProject` supplies the git-visible file contract.
  Evidence: the ignored-file behavior test must construct `FilesystemProject`; it then excludes an ignored file while retaining tracked and unignored non-source files.
- Observation: P2T's generic research path needs all structured result sections but should not inherit future presentation defaults from `render_text()` implicitly.
  Evidence: its dedicated formatter assembles summaries, listings, compact fallback, and diagnostics explicitly, and its test rejects calls to the model's top-level default renderer.

## Decision Log

- Decision: add first-class `listings` to `SummaryResult` instead of introducing another tool.
  Rationale: `get_summaries` already accepts mixed file, symbol, directory, and package targets, so one result can preserve mixed requests without another discovery step.
  Date/Author: 2026-07-20 / user and Codex.
- Decision: listings are immediate, include child containers, and use all files visible to the project walker.
  Rationale: this matches ordinary directory navigation and includes configuration and documentation files that analyzers do not index.
  Date/Author: 2026-07-20 / user and Codex.
- Decision: package listings include all top-level type-like declarations normalized as `CodeUnitType::Class`.
  Rationale: the normalized category intentionally covers classes, interfaces, enums, records, structs, traits, objects, aliases, and language equivalents.
  Date/Author: 2026-07-20 / user and Codex.
- Decision: retain `compact_symbols` only for oversized ordinary MCP summaries.
  Rationale: it remains useful as a response-budget fallback but must no longer represent directory or package results.
  Date/Author: 2026-07-20 / user and Codex.
- Decision: audit BrokkBench root `*.py` without recursion, plus recursive `p2t/**/*.py` and `localizer/**/*.py`.
  Rationale: this is the caller scope explicitly requested by the user; generated runs and unrelated checkout trees are excluded.
  Date/Author: 2026-07-20 / user and Codex.
- Decision: describe directory entries consistently as immediate git-visible files, defined as tracked or unignored, and state that gitignored files are excluded.
  Rationale: "directory listing" alone could incorrectly imply raw filesystem contents; the API is deliberately bounded by the project walker's visibility contract.
  Date/Author: 2026-07-20 / user and Codex.
- Decision: give P2T a local structured-result formatter instead of calling `SymbolSummariesResult.render_text()` wholesale.
  Rationale: P2T needs listings and diagnostics, but choosing each section explicitly prevents unrelated default-rendering changes from silently changing research prompts.
  Date/Author: 2026-07-20 / user and Codex.

## Outcomes & Retrospective

The container-listing contract is implemented across Rust, MCP, Python, and the scoped BrokkBench callers. Directory listings contain immediate child directories and git-visible files, including non-source files but excluding gitignored files; package listings contain direct child packages and exact-package top-level types. The old container-to-`compact_symbols` augmentation is removed, while compact symbols remain an MCP budget fallback for ordinary summaries. P2T renders each structured result section explicitly. Focused tests, the Python suite, formatting, clippy, and the broad Rust suite pass; two unrelated flaky Rust cases failed only in full-suite conditions and passed independently, so the final broad run skipped those two while exercising every other test.

## Context and Orientation

`src/searchtools.rs` owns `SummariesParams`, `SummaryResult`, target routing, summary construction, and compact per-file symbol outlines. `src/analyzer/global_usage_definition_index.rs` indexes workspace declarations by package and symbol. `src/searchtools_render.rs` renders typed results. `src/searchtools_service.rs` exposes tools to native and Python callers, while `src/mcp_common.rs` applies the MCP response budget. `bifrost_searchtools/models.py` is the typed Python result layer.

The current container behavior is indirect. `route_summary_targets` groups directories and language package paths together as files. Core `get_summaries` reports their original targets as unresolved. `src/get_summaries_output.rs` and `src/mcp_common.rs` then retry those targets through `list_symbols` and attach the result as `compact_symbols`. This duplicates routing, loses the distinction between filesystem and semantic containers, and exposes different behavior through different calling surfaces.

The sibling repository `/home/jonathan/Projects/brokkbench` consumes the Python API directly and through MCP-facing agent surfaces. Only root-level Python files and recursive Python files under `p2t` and `localizer` are in scope. File-only callers should continue to read `summaries`; generic callers must accept listings as successful output and render the complete result.

## Plan of Work

Define public container result types in `src/searchtools.rs`: `ContainerKind`, `ContainerListing`, and a serde-tagged `ContainerListingEntry` with directory, file, package, and type variants. Add `listings` to `SummaryResult`. A listing records the normalized target, container kind, package languages where applicable, retained entries, total entry count, and whether entries were truncated.

Refactor summary routing so each target is classified with this precedence: literal file, filesystem directory, glob, semantic package, then symbol. Directory recognition must inspect the gitignore-aware `Project::all_files` set and compare `Path` components, not source-string prefixes. A directory listing returns only immediate files and the first path component of deeper descendants. The root target `.` is supported. Real filesystem directories win collisions with package identities.

Extend `GlobalUsageDefinitionIndex` with language-qualified exact package types and direct child package relationships. Build those relationships from analyzer-produced package identities at index insertion time through one shared language-aware package-parent helper. Do not inspect or parse source text. Package listings may resolve an exact package or a virtual parent that has child packages but no direct declarations. Type entries are top-level `CodeUnitType::Class` units whose package exactly equals the target. Preserve separate declaration locations rather than conflating same-named partial or companion declarations.

Delete the old directory fields and `summarize_targets_with_directory_inventory` path from `src/searchtools.rs`, delete package-prefix file lookup that only supported that path, and delete `src/get_summaries_output.rs`. Remove the corresponding service hook and both service/MCP `maybe_add_directory_inventory` retry implementations. Keep `list_symbols`, `SkimFilesResult`, and MCP `compact_symbols` summary degradation.

Implement deterministic rendering in `src/searchtools_render.rs`: listings follow first target occurrence; entries show child packages/directories before types/files and sort alphabetically within those groups. Extend MCP fitting so ordinary summaries may still degrade to `compact_symbols`, while any transport-level listing truncation preserves `total_entries`, sets `truncated`, and renders only retained structured entries.

Mirror the result types in `bifrost_searchtools/models.py`. `SymbolSummariesResult.render_text()` renders ordinary summaries, listings, compact budget fallback, and unresolved/ambiguous diagnostics in that order. Update the MCP descriptor and published Python documentation to explain the new behavior and remove the old direct-client limitation.

In BrokkBench, inspect every matching root, `p2t`, and `localizer` Python caller. Leave callers unchanged when their contract proves they pass existing files or symbols and intentionally consume code summaries. Update generic consumers and result-validity checks so a nonempty listing is not treated as a miss. Ensure P2T research can surface listing text returned for arbitrary planner targets. Update test doubles only when they exercise the complete result contract.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, implement and validate incrementally with:

    cargo test --all-features --test searchtools_summary_ranges
    cargo test --all-features --test searchtools_service
    cargo test --all-features --test bifrost_mcp_server
    scripts/test_python.sh
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

From `/home/jonathan/Projects/brokkbench`, run only targeted tests for changed behavior and lint only changed Python files:

    PYTHONPATH=. uv run pytest p2t/phase1/test_research.py
    PYTHONPATH=.:localizer uv run pytest <changed-localizer-test-modules>
    ruff check --config pyproject.toml <changed-python-files>

Commit Bifrost and BrokkBench separately on their current `master` branches. Stage explicit paths only and use multiline commit messages that explain why the result contract and callers changed.

## Validation and Acceptance

A Java package target such as `com.example` must return direct top-level types in that exact package plus a `com.example.internal` child package, without returning types inside the child package. A Go import package must provide equivalent behavior with slash-separated canonical identities. A virtual package parent must list its child packages even if it has no direct declarations.

A directory target such as `src` must return immediate files including non-source files and immediate child directories, without recursively flattening descendant files. Mixed targets such as a directory, package, file, and class must produce listings and summaries together; resolved containers must not appear in `not_found` or `compact_symbols`.

Python callers must deserialize and render the same structured listings. A generic P2T research request for a directory or package must retain the rendered listing in its research section. Existing BrokkBench file-summary extraction and reranking must continue to use summary blocks without accidentally treating listing entries as source summaries.

## Idempotence and Recovery

All edits are source changes and can be rerun safely. Cargo uses the repository target directory unless an isolated build is explicitly needed; no manually named temporary Cargo target is allowed. Existing unrelated dirty and untracked files in both repositories must remain untouched. If validation fails, update this plan with the failure and continue from the failing milestone rather than reverting user changes.

## Artifacts and Notes

Expected compact structured shape:

    {
      "summaries": [],
      "listings": [{
        "target": "src",
        "kind": "directory",
        "languages": [],
        "entries": [
          {"kind": "directory", "name": "analyzer", "path": "src/analyzer"},
          {"kind": "file", "name": "lib.rs", "path": "src/lib.rs"}
        ],
        "total_entries": 2,
        "truncated": false
      }],
      "not_found": [],
      "ambiguous": []
    }

## Interfaces and Dependencies

No new external dependency is required. The public Rust and serialized interfaces are:

    pub struct SummaryResult {
        pub summaries: Vec<SummaryBlock>,
        pub listings: Vec<ContainerListing>,
        pub not_found: Vec<NotFoundInput>,
        pub ambiguous: Vec<AmbiguousSymbol>,
        pub ambiguous_paths: Vec<AmbiguousPathInput>,
    }

    pub struct ContainerListing {
        pub target: String,
        pub kind: ContainerKind,
        pub languages: Vec<String>,
        pub entries: Vec<ContainerListingEntry>,
        pub total_entries: usize,
        pub truncated: bool,
    }

`ContainerListingEntry` is internally represented as a Rust enum serialized with `#[serde(tag = "kind", rename_all = "snake_case")]`. The Python model exposes equivalent immutable dataclasses and preserves the tagged JSON shape.
