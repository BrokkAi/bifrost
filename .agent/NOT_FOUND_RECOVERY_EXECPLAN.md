# Structured not_found recovery notes

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` in this repository. It is written so a reader with only this working tree can understand and complete the change.

## Purpose / Big Picture

Search tool callers currently receive `not_found` as a list of strings in several response types. That hides whether the missing input was interpreted as a symbol, a file path, or an anchored selector such as `src/a.js#Widget`. After this change, every affected `not_found` entry carries the original input and, when the cause is known, a recovery note that tells an agent what command or argument form to try next. `get_symbol_ancestors` also stops rejecting an entire batch when one resolved input is a function rather than a class, module, or type.

The behavior is visible through JSON tool responses and rendered text. For example, an unresolvable symbol should serialize as an object containing `input` and a note mentioning `search_symbols`, while an anchored selector whose name exists only in another file should mention re-calling with the bare name to list valid selectors.

## Progress

- [x] (2026-07-03T12:47Z) Read `.agent/PLANS.md` and the required commit context: `git show b6c9e02 --stat` and `git show 9305628`.
- [x] (2026-07-03T12:47Z) Grepped source and tests for `not_found`, selector resolution, rendering, and service registration.
- [x] (2026-07-03T12:47Z) Add `NotFoundInput` and convert the six requested result structs plus helper paths that compute scan usage warnings.
- [x] (2026-07-03T12:47Z) Preserve anchored-selector vs unresolved-symbol causes through `SelectableDefinitionResolution::NotFound`.
- [x] (2026-07-03T12:47Z) Make `get_symbol_ancestors` handle non-type units per input instead of returning an error for the whole batch, and switch the service registration because no `Err` path remains.
- [x] (2026-07-03T12:47Z) Update rendered text output to display each not-found input and optional note.
- [x] (2026-07-03T12:47Z) Update existing tests and add selector recovery and ancestors batch coverage.
- [x] (2026-07-03T12:47Z) Run formatting, affected tests, and `cargo clippy-no-cuda`.

## Surprises & Discoveries

- Observation: `get_symbol_ancestors` currently returns `Err` only for a resolved non-ancestor target; the missing type hierarchy provider path already returns a successful result with all requested symbols in `not_found`.
  Evidence: `src/searchtools.rs` around `get_symbol_ancestors` has a single `return Err(format!(...))` inside the resolved-code-unit loop.
- Observation: `most_relevant_files` only accepts file seed paths, so its `not_found` entries all come from `WorkspaceFileResolver::resolve_literal` and should receive the file-path recovery note.
  Evidence: `src/searchtools.rs` around `most_relevant_files.resolve_seeds` pushes `ResolvedFileInput::NotFound(item)` directly into `not_found`.
- Observation: After converting the public result types, `cargo check` found one non-test formatter in `src/bin/most_relevant_files.rs` that still joined `result.not_found` as strings.
  Evidence: `cargo check` failed with `method join exists for Vec<NotFoundInput>, but its trait bounds were not satisfied`; updating the CLI formatter made `cargo check` pass.
- Observation: `get_summaries` degraded-output helpers parse `not_found` from structured JSON and needed compatibility with object entries.
  Evidence: `src/get_summaries_output.rs` and `src/mcp_common.rs` now read either a legacy string or an object `input` field when calculating unresolved targets.

## Decision Log

- Decision: Treat unmatched file-looking summary targets, directory inventory inputs folded into summaries, and `most_relevant_files` missing seeds as file causes with the path/glob note.
  Rationale: These paths are routed through file or directory target resolution, not symbol resolution, and the requested note explicitly distinguishes no-such-file from no-such-symbol.
  Date/Author: 2026-07-03 / Codex.
- Decision: Use `NotFoundInput` for internal scan usage warning helpers as well as public result structs.
  Rationale: The summary builders accept the same `not_found` vector; keeping it typed avoids lossy formatting before serialization and rendering.
  Date/Author: 2026-07-03 / Codex.
- Decision: Leave directory-target `get_summaries` not-found entries and resolved-but-not-renderable entries with `note: None`.
  Rationale: A directory target did resolve to files, so the no-workspace-file note would be false. Empty render output after a resolved symbol/file reflects analyzer display data or source availability, not a caller recovery path.
  Date/Author: 2026-07-03 / Codex.

## Outcomes & Retrospective

Implemented structured `not_found` entries for the six requested result types, cause-specific recovery notes for unresolved symbols, anchored-selector misses, and file path misses, plus note-less entries for resolved-but-not-renderable and directory-target compatibility cases. `get_symbol_ancestors` is now infallible at the service layer and reports non-type inputs per symbol without dropping valid batch results. The requested affected test suites, `cargo fmt`, and `cargo clippy-no-cuda` passed.

Validation evidence:

    BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_definition_selectors --test searchtools_service --test searchtools_fuzzy_symbol_lookup --test get_definition_test --test most_relevant_files --test searchtools_summary_ranges --test go_canonical_fqn_test --test bifrost_tool_cli
    passed: bifrost_tool_cli 15, get_definition_test 338, go_canonical_fqn_test 9, most_relevant_files 17, searchtools_definition_selectors 8, searchtools_fuzzy_symbol_lookup 16, searchtools_service 71 passed / 1 ignored, searchtools_summary_ranges 16

    cargo fmt
    passed

    cargo clippy-no-cuda
    passed

## Context and Orientation

The relevant public result structs live in `src/searchtools.rs`: `SymbolLocationsResult`, `SymbolAncestorsResult`, `SummaryResult`, `SymbolSourcesResult`, `MostRelevantFilesResult`, and `ScanUsagesResult`. They currently expose `not_found: Vec<String>`.

Definition selectors are strings in the form `path#name`. The path is a workspace-relative file path and the name is a symbol name. `resolve_selectable_definitions` resolves the name first, then narrows the result to the selected path. It currently returns `SelectableDefinitionResolution::NotFound(String)`, which loses whether no symbol matched at all or whether the name matched but the file anchor filtered all definitions out.

Rendered text lives in `src/searchtools_render.rs`. Some tools render a single inline `Not found: ...` line, and some use a `## Not found` list. Both forms must include the input and the optional note.

The service dispatch lives in `src/searchtools_service.rs`. `decode_render_and_try_run` converts a handler `Err(String)` into an invalid-params failure for the whole call. `decode_render_and_run` is for infallible handlers.

Tests that assert `not_found` appear across `tests/searchtools_definition_selectors.rs`, `tests/searchtools_service.rs`, `tests/searchtools_fuzzy_symbol_lookup.rs`, `tests/most_relevant_files.rs`, `tests/searchtools_summary_ranges.rs`, `tests/go_canonical_fqn_test.rs`, and smaller CLI/service suites.

## Plan of Work

First, define `NotFoundInput` next to the affected result types and add small constructors for the three public recovery causes: symbol unresolved, anchored selector narrowed to no definitions, and file path/glob unmatched. Change `SelectableDefinitionResolution::NotFound` to carry `NotFoundInput` so all tools using that resolver can preserve the cause.

Second, update all push sites in `get_symbol_locations`, `get_symbol_ancestors`, `summarize_symbol_targets`, `summarize_routed_targets`, `get_symbol_sources`, `most_relevant_files`, and `scan_usages`. For resolved-but-not-renderable cases, inspect whether these can happen in normal operation. If they represent an internal inability to render a resolved unit rather than caller error, emit `NotFoundInput` with `note: None`.

Third, change `get_symbol_ancestors` so each resolved selector group filters to units accepted by `is_ancestor_target`. If no unit in a group qualifies, push a `NotFoundInput` whose note says the symbol resolves to the first rejected unit kind and that `get_symbol_ancestors` only accepts class/module/type symbols. If at least one unit qualifies, return those ancestors and ignore non-qualifying units. After removing the only `Err` path, change the function to return `SymbolAncestorsResult` directly and dispatch with `decode_render_and_run`.

Fourth, update rendering to print `NotFoundInput.input` plus `NotFoundInput.note` when present. Update tests mechanically for `{"input": ...}` objects and add behavior-focused selector and ancestors tests.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Run targeted source inspection with `rg -n "not_found|SelectableDefinitionResolution|get_symbol_ancestors" src tests`.

After editing, run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_definition_selectors --test searchtools_service --test searchtools_fuzzy_symbol_lookup --test get_definition_test --test most_relevant_files --test searchtools_summary_ranges
    cargo fmt
    cargo clippy-no-cuda

If the diff touches additional scan usage or summaries suites, include them in the test command or run them separately.

## Validation and Acceptance

Acceptance requires the following observable behaviors:

An unresolvable symbol in any affected symbol tool serializes `not_found` as an object with `input` set to the requested string and a note exactly saying `no symbol matched; try search_symbols with a substring or regex pattern`.

An anchored selector such as `src/wrong.js#Widget` where `Widget` exists elsewhere serializes a note exactly saying `` `Widget` resolved, but no definition is in `src/wrong.js`; re-call with the bare name to list valid selectors ``.

A file-looking summary target or missing `most_relevant_files` seed serializes a note exactly saying `no workspace file matched this path; check the relative path or pass a glob pattern`.

`get_symbol_ancestors` called with one valid class and one plain function returns the class ancestors and a `not_found` object for the function with a kind-mismatch note, rather than an invalid-params error for the whole call.

All requested quality gates must pass cleanly. The work must remain uncommitted in the working tree.

## Idempotence and Recovery

The edits are ordinary source and test changes and can be re-run safely. Do not create branches, switch branches, or commit. If a validation command fails, inspect the failing output, update this plan with the discovery, and fix the smallest source or test issue that explains the failure.

## Artifacts and Notes

Required context already read:

    git show b6c9e02 --stat
    git show 9305628

The current branch starts from `master` at `9305628` as requested.

## Interfaces and Dependencies

Define in `src/searchtools.rs`:

    #[derive(Debug, Clone, Serialize)]
    pub struct NotFoundInput {
        pub input: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

Update all affected result structs to use `Vec<NotFoundInput>`. Keep `AmbiguousSymbol` unchanged except for existing note behavior from `9305628`.

Revision note 2026-07-03: Initial plan created after source inspection so the cross-cutting type migration and validation remain restartable.

Revision note 2026-07-03: Updated progress and outcomes after implementation, test repair, formatting, and clippy validation.
