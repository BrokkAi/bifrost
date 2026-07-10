# Add source-window diagnostics to location APIs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

When an agent supplies a bad line or column to a Bifrost location API, the current result often repeats only that no target exists. The agent cannot tell whether it selected a function body instead of its declaration, counted lines from zero, or placed the column beside the intended token. After this change, every public line/column lookup that can read the requested file will include a bounded, numbered source window, a visible marker for the requested location, and a concrete recovery instruction. This directly resolves GitHub issue #605 and applies the same behavior to definition lookup, type lookup, and rename rather than fixing usage scanning alone.

## Progress

- [x] (2026-07-10) Audited the four public line/column surfaces and their current failure paths.
- [x] (2026-07-10) Added and unit-tested a shared bounded source-window formatter.
- [x] (2026-07-10) Attached source context and tool-specific recovery to usage, definition, type, and rename failures.
- [x] (2026-07-10) Added behavior tests for missing columns, past-end lines and columns, Unicode columns, long lines, and each public location surface.
- [x] (2026-07-10) Ran formatting, the full feature-enabled Rust suite, 38 Python tests, focused suites, and `cargo clippy-no-cuda`; committed only task-owned files on `master`.

## Surprises & Discoveries

- Observation: The split usage API fixed cross-file and body-line selection correctness for issue #607, but its body-line regression test explicitly preserved the weak `no declaration at location` message from issue #605.
  Evidence: `src/searchtools.rs` constructs that exact text and `tests/searchtools_service.rs` checks only for that phrase.

- Observation: Definition and type resolution share `reference_site.rs`, while rename has a separate cursor resolver and usage scanning has its own declaration-name selector.
  Evidence: public results converge only in `src/searchtools.rs`, making that module plus a shared text formatter the narrowest place to standardize external diagnostics without changing byte-based analyzer internals.

## Decision Log

- Decision: Render two source lines before and after a valid requested line, with a `>` prefix and a caret marker labeled with the requested one-based line and column.
  Rationale: This is enough context to recognize common off-by-one errors while keeping responses bounded.
  Date/Author: 2026-07-10 / Codex

- Decision: Treat an omitted optional column as “column not supplied” and place the visual marker at column 1; never invent a caller-supplied column.
  Rationale: Usage, definition, and type lookup allow line-only selection, so the diagnostic must remain truthful while still showing which line was selected.
  Date/Author: 2026-07-10 / Codex

- Decision: For line zero or a line past end-of-file, show the nearest file boundary and a synthetic requested-line marker outside the source window. For an invalid column, clamp only the visual caret to the nearest line boundary while retaining the exact requested column in its label.
  Rationale: Invalid coordinates have no literal source character to mark, but boundary context still makes zero/one-based and stale-line mistakes obvious.
  Date/Author: 2026-07-10 / Codex

- Decision: Cap displayed source lines and center a long target line around the requested column.
  Rationale: Diagnostics are model-facing output and must not become unbounded because a source file contains a generated or minified line.
  Date/Author: 2026-07-10 / Codex

## Outcomes & Retrospective

The implementation meets the requested behavior across all four public line/column APIs. `searchtools_service` passes 113 tests with one ignored, `get_definition_test` passes 397 tests, six `text_utils` unit tests cover formatter boundaries, the full `nlp,python` Rust suite passes when its UV cache is placed under `/tmp`, 38 Python tests pass, and `cargo clippy-no-cuda` is clean. The first full-suite attempt exposed only a read-only global UV cache; rerunning the affected sidecar test and full suite with `UV_CACHE_DIR=/tmp/bifrost-uv-cache` passed.

## Context and Orientation

The public request and result types for all four tools live in `src/searchtools.rs`. `scan_usages_by_location` resolves declaration-name locations in `resolve_scan_usages_target`. `get_definitions_by_location` and `get_type_by_location` call analyzer resolvers and then turn their outcomes into public results in `render_definition_lookup` and `render_type_lookup`. `rename_symbol` calls the internal byte-based rename engine and converts its failure into a public `RenameSymbolResult`. The source-window formatter belongs in `src/text_utils.rs`, which already owns line-start and snippet helpers.

A source-window diagnostic is a short plain-text block embedded in the existing structured message or diagnostic field. It contains the project-relative path and requested coordinates, numbered source lines, a `>` marker on the selected line, a caret beneath the requested character, and a `Recovery:` sentence. Analyzer ranges, tree-sitter nodes, and LSP requests continue to use byte offsets internally.

## Plan of Work

First, add a crate-private formatter to `src/text_utils.rs`. It will accept source text, a path, a one-based line, an optional one-based character column, a reason, and a recovery sentence. It will preserve the exact requested coordinates in text, render at most two neighboring lines on each side, handle CRLF, clamp impossible markers to the nearest boundary, and truncate long lines around the requested character. Unit tests will pin valid Unicode columns, omitted columns, out-of-range lines and columns, and bounded long-line output.

Second, update `src/searchtools.rs`. Usage-location not-found and invalid-coordinate results will use the formatter after the file is read. Definition and type rendering will retain the resolved `ProjectFile` long enough to append a `location_context` diagnostic for invalid locations and semantic no-result statuses. Rename failures with a complete line/column request will append the same source window after the internal engine reports `invalid_location` or `not_found`. Each surface will name its own tool and legal next steps in `Recovery:`.

Third, add behavior-focused tests in `tests/searchtools_service.rs` and the existing definition/type/rename test areas. Tests will verify exact coordinates, `>` and caret markers, lines before and after, truthful handling of omitted or impossible columns, and recovery instructions naming the appropriate tools. Existing success behavior and structured status values must remain unchanged.

## Concrete Steps

Work in `/home/jonathan/Projects/bifrost` on the existing `master` branch. Edit only the new ExecPlan, `src/text_utils.rs`, `src/searchtools.rs`, and relevant tests unless implementation evidence requires another task-owned file. Run:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --lib text_utils
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --test searchtools_service
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --test get_definition_test
    cargo clippy-no-cuda

Run broader tests if a shared resolver or renderer change affects additional suites. Stage explicit task-owned paths and commit directly to `master`. Do not add the pre-existing untracked `.agents/docs/` or `.brokk/` files.

## Validation and Acceptance

For a valid file and a location that does not identify a declaration or reference, the JSON result must retain its current status and include `Requested location: path:line:column`, numbered neighboring lines, a `>` selected-line marker, a caret, and a `Recovery:` instruction. Line-only calls must say the column was not supplied. A line before or after the file must display the nearest boundary plus a synthetic requested-line marker. A column past the line must display the requested column in the label while clamping the caret to the line end. Long or minified lines must not make the diagnostic unbounded.

The usage recovery must mention moving to a declaration name and may recommend `get_summaries` or `search_symbols`. Definition and type recovery must mention moving the target to the intended reference token. Rename recovery must require an identifier token. Path-not-found and ambiguous-path results remain path diagnostics because no source can be rendered.

## Idempotence and Recovery

All edits and tests are repeatable. The working tree contains unrelated untracked files, so staging must name task paths explicitly. If a focused test exposes an established message contract, update it only when the new source window is the intended public behavior; do not weaken semantic status assertions.

## Artifacts and Notes

Issue #605 reports `scan_usages` location failures such as `pkg/cmd/copilot/copilot.go:1 (no declaration at location)` and asks for a concrete next step. The desired shape is conceptually:

    no declaration at location
    Requested location: app.js:3:5
      1 | export function run() {
      2 |   const value = 1;
    > 3 |   return value;
        |     ^ requested line 3, column 5
      4 | }
    Recovery: move the target to a declaration name token and retry scan_usages_by_location; use get_summaries or search_symbols if the declaration location is unknown.

## Interfaces and Dependencies

Add a crate-private formatter in `src/text_utils.rs` with a signature equivalent to:

    pub(crate) fn render_location_diagnostic(
        source: &str,
        path: &str,
        line: usize,
        column: Option<usize>,
        reason: &str,
        recovery: &str,
    ) -> String

No new dependency is needed. The formatter works in Unicode scalar-value columns because that is the character-column convention already used by these public APIs.

Plan revision note (2026-07-10): Created the plan after auditing issue #605 against the merged split-usage implementation and generalized the requested behavior across every public line/column lookup. Updated after implementation to record the shared formatter, all four integrations, focused and full validation, the UV-cache environment discovery, and completion on `master`.
