# Emit side-specific patch symbol effects

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

`analyze_commit` currently reports changed symbols through top-level lists whose edited entries are postimage symbols. A downstream user needs a stable contract that says exactly which parent-side symbols overlapped deleted patch lines and which commit-side symbols overlapped added patch lines. After this change, callers can inspect `patch_symbols.preimage` and `patch_symbols.postimage` without converting symbols between old and new file images, and can audit each entry from explicit touched line numbers.

## Progress

- [x] (2026-07-02) Wrote this ExecPlan from the current implementation and requested contract.
- [x] (2026-07-02) Updated the Rust `analyze_commit` result model and side-specific diff line tracking.
- [x] (2026-07-02) Updated Python client models for the new result shape.
- [x] (2026-07-02) Updated tests to assert old-side and new-side touched symbol effects.
- [x] (2026-07-02) Ran focused validation and recorded outcomes.

## Surprises & Discoveries

- Observation: The existing `diff_metadata` stores old and new changed lines under a single display path selected from the new path when present. This is not precise enough for renames because parent-side line overlap must be keyed by the old path and commit-side line overlap must be keyed by the new path.
  Evidence: `src/commit_analysis.rs` currently uses `delta.new_file().path().or_else(|| delta.old_file().path())` before inserting both `line.old_lineno()` and `line.new_lineno()`.

- Observation: A postimage declaration range can overlap more than the edited expression line when a hunk also includes the declaration's closing brace.
  Evidence: `analyze_commit_reports_symbol_and_edge_effects` observes `Existing` with `touched_new_lines` `[6, 7]`, while the parent-side overlap remains `touched_old_lines` `[4]`.

## Decision Log

- Decision: Remove the old top-level `introduced_symbols`, `edited_symbols`, and `deleted_symbols` fields rather than keeping aliases.
  Rationale: Backwards compatibility is explicitly out of scope for this change, and retaining aliases would keep the ambiguous old contract alive.
  Date/Author: 2026-07-02 / Codex

- Decision: Use `CodeUnit::identifier()` for the new `name` field.
  Rationale: `identifier()` is the analyzer-owned short structural name and avoids parsing fully qualified names in `analyze_commit` or in consumers.
  Date/Author: 2026-07-02 / Codex

- Decision: Keep inferred `moved_symbols` and `signature_changes` separate from `patch_symbols`.
  Rationale: `patch_symbols` is the gold patch-overlap output. Move and signature inference remains useful, but mixing it into gold touched functions would make the result noisy.
  Date/Author: 2026-07-02 / Codex

## Outcomes & Retrospective

Completed. `analyze_commit` now returns `patch_symbols` with preimage and postimage symbol effects computed directly from the matching analyzer image and side-specific diff lines. The old top-level gold symbol lists were removed. Validation passed with:

    cargo test --test commit_analysis_test
    cargo test --test bifrost_mcp_server
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    uv run pytest python_tests/test_searchtools_client.py

## Context and Orientation

The implementation is centered in `src/commit_analysis.rs`. The public MCP tool `analyze_commit` resolves one non-merge commit, exports both parent and commit trees into temporary directories, builds analyzers for each image, indexes declarations, compares old and new symbol keys, and returns a serializable `CommitAnalysisResult`.

A preimage symbol is a declaration found by the parent analyzer. Its `path`, `start_line`, and `end_line` must describe the parent tree. A postimage symbol is a declaration found by the commit analyzer. Its location must describe the commit tree. A hunk-overlap symbol is a symbol whose declaration range intersects at least one changed patch line for the same image.

The generated-style Python client models live in `bifrost_searchtools/models.py`. Tests for this tool live in `tests/commit_analysis_test.rs`.

## Plan of Work

First, change `diff_metadata` so `ChangedLines.old` is recorded under the old file path and `ChangedLines.new` is recorded under the new file path. Preserve existing `FileChange` metadata and sorting behavior.

Next, add Rust result structs for `PatchSymbols`, `PreimagePatchSymbols`, `PostimagePatchSymbols`, and `PatchTouchedSymbol`. `PatchTouchedSymbol` will include `fqn`, `name`, `kind`, `signature`, `path`, `start_line`, `end_line`, `language`, `is_test`, `touched_old_lines`, `touched_new_lines`, and `change_reason`. The irrelevant touched line field for a side will serialize as an empty list so callers have stable fields.

Then, update `symbol_index` so each snapshot carries both the comparable key and the new `PatchTouchedSymbol` base data with `name` from `CodeUnit::identifier()`. Build four patch-overlap lists directly from the two symbol indexes: parent symbols missing from the postimage go to `preimage.deleted` when they overlap old lines; parent symbols present in both images go to `preimage.edited` when the parent range overlaps old lines; postimage symbols missing from the preimage go to `postimage.introduced` when they overlap new lines; postimage symbols present in both images go to `postimage.edited` when the commit range overlaps new lines.

Finally, remove old top-level symbol lists from the result and Python model, update changed test symbol summaries to derive from `patch_symbols`, and keep inferred analysis fields unchanged.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit `src/commit_analysis.rs`, `bifrost_searchtools/models.py`, and `tests/commit_analysis_test.rs`. Run:

    cargo test --test commit_analysis_test
    cargo test --test bifrost_mcp_server
    cargo fmt --check

Run the repository's clippy command when practical for the host:

    cargo clippy-no-cuda

If the host has CUDA and `nvcc`, use:

    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The updated `analyze_commit_reports_symbol_and_edge_effects` test should prove that an edited function appears in both `patch_symbols.preimage.edited` and `patch_symbols.postimage.edited`, with old touched lines only on the preimage entry and new touched lines only on the postimage entry. A new rename-focused test should prove that preimage path and touched lines come from the old filename while postimage path and touched lines come from the new filename.

The JSON result must no longer contain top-level `introduced_symbols`, `edited_symbols`, or `deleted_symbols`.

## Idempotence and Recovery

All edits are ordinary source changes. Test-created git repositories are temporary. If validation fails, inspect the failing assertion, adjust the side-specific overlap logic or model shape, and rerun the focused test.

## Artifacts and Notes

The most important expected result shape is:

    {
      "patch_symbols": {
        "preimage": {
          "edited": [
            {
              "fqn": "sample.Existing",
              "name": "Existing",
              "path": "old.go",
              "touched_old_lines": [4],
              "touched_new_lines": [],
              "change_reason": "old_hunk_overlap"
            }
          ],
          "deleted": []
        },
        "postimage": {
          "edited": [
            {
              "fqn": "sample.Existing",
              "name": "Existing",
              "path": "new.go",
              "touched_old_lines": [],
              "touched_new_lines": [4],
              "change_reason": "new_hunk_overlap"
            }
          ],
          "introduced": []
        }
      }
    }

## Interfaces and Dependencies

`CommitAnalysisResult` must expose `patch_symbols: PatchSymbols` in `src/commit_analysis.rs`. The Python dataclass `CommitAnalysisResult` must expose `patch_symbols: PatchSymbols` and parse it from `data["patch_symbols"]`.

No new dependencies are required.
