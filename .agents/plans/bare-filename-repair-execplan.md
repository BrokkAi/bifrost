# Bare Filename Repair Across File-Oriented Tools

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](../../.agents/PLANS.md).

## Purpose / Big Picture

After this change, model-facing tools that expect file paths can silently recover from a common mistake: passing `Foo.java` instead of the full project-relative path such as `src/app/Foo.java`. If the workspace contains exactly one `Foo.java`, tools should just use it. If the workspace contains multiple matches, tools must refuse to guess and instead return a structured ambiguity listing the candidate files. This reduces wasted probing while keeping path repair conservative.

The visible proof is straightforward: run file-oriented tools with a bare filename in a workspace that has one matching file and observe that the correct file is used; run the same tools in a workspace with duplicate basenames and observe that the tool reports ambiguity instead of silently picking one.

## Progress

- [x] (2026-06-09 19:06Z) Added a shared basename-aware literal resolver in `src/path_utils.rs` with exact-path precedence and explicit ambiguity results.
- [x] (2026-06-09 19:13Z) Threaded the resolver through `searchtools`, `file_tools`, and `structured_data`, adding additive `ambiguous_paths` result fields.
- [x] (2026-06-09 19:33Z) Finished the remaining file-path consumers in `code_quality`, `git_tools`, `searchtools_render`, and the `get_summaries` compatibility wrapper in `searchtools_service`.
- [x] (2026-06-09 19:40Z) Added focused tests for unique basename repair and duplicate-basename ambiguity in `file_tools`, `structured_data`, `searchtools`, `searchtools_render`, and `git_tools`.
- [x] (2026-06-09 19:46Z) Ran `cargo test --lib`, `cargo test --test searchtools_service python_boundary_returns_structured_json`, `cargo fmt --all`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-06-09 19:50Z) Committed the completed feature as `2ede288` with a multiline checkpoint message describing the shared-resolver rationale and validation.

## Surprises & Discoveries

- Observation: file-path behavior was already fragmented across multiple modules. `searchtools`, `file_tools`, `structured_data`, `code_quality`, and `git_tools` each had their own exact-path logic.
  Evidence: repository reads on 2026-06-09 showed separate resolution code in `src/searchtools.rs`, `src/file_tools.rs`, `src/structured_data.rs`, `src/code_quality/mod.rs`, and `src/git_tools.rs`.

- Observation: some tool families already had ambiguity channels for symbols but nothing parallel for paths.
  Evidence: `SummaryResult` and `SymbolSourcesResult` already exposed `ambiguous: Vec<AmbiguousSymbol>` before this change, making a separate `ambiguous_paths` field the least disruptive path.

- Observation: `get_summaries` has a compatibility wrapper in `src/searchtools_service.rs` that can silently drop newly added result fields unless it is updated separately from `src/searchtools.rs`.
  Evidence: the first compile pass failed because `GetSummariesCompatibilityResult` did not carry the new `ambiguous_paths` field, even though `SummaryResult` already did.

## Decision Log

- Decision: restrict silent repair to single-segment, non-glob literal inputs.
  Rationale: this catches the model error we care about (`Foo.java`) without changing the meaning of globs, directories, or explicit relative paths.
  Date/Author: 2026-06-09 / Codex

- Decision: exact project-relative paths win over basename repair.
  Rationale: callers that already provide `Foo.java` at the workspace root should keep getting that file even if another `nested/Foo.java` exists.
  Date/Author: 2026-06-09 / Codex

- Decision: keep the behavior out of MCP tool descriptions.
  Rationale: the feature is meant to be a quiet recovery path for model mistakes, not part of the formal public prompt contract.
  Date/Author: 2026-06-09 / Codex

- Decision: surface duplicate-basename cases as additive structured `ambiguous_paths` results instead of overloading symbol ambiguity.
  Rationale: path ambiguity and symbol ambiguity are different failure modes and are easier for callers to handle separately.
  Date/Author: 2026-06-09 / Codex

## Outcomes & Retrospective

The implementation now provides a uniform literal-path repair path across the file-oriented MCP surfaces that were in scope for this change. A unique bare filename such as `Foo.java` resolves silently to the full project-relative path. Duplicate basenames surface explicit `ambiguous_paths` in structured JSON, searchtool text rendering shows an “Ambiguous paths” section, and `get_git_log` returns a one-line ambiguity explanation instead of guessing.

The main lesson from the work is that this repository had multiple layers of file-path handling: per-tool handlers, shared helpers, renderers, and service compatibility wrappers. The shared resolver removed the behavior drift at the handler layer, but the service wrapper for `get_summaries` still needed explicit maintenance to preserve the new result field.

## Context and Orientation

The main shared logic for path handling lives in `src/path_utils.rs`. Before this change, that file normalized project-relative paths and rejected workspace escapes, but it did not know how to interpret a bare filename as “the only file in the workspace with this basename”.

The user-facing tool handlers are split by concern:

- `src/searchtools.rs` holds symbol-oriented tools that also accept file-like targets, including `get_summaries`, `list_symbols`, file-backed `get_symbol_sources`, and `most_relevant_files`.
- `src/file_tools.rs` holds direct file tools such as `get_file_contents`, `search_file_contents`, and `skim_files`.
- `src/structured_data.rs` holds file-backed JSON/XML tools such as `jq`, `xml_skim`, and `xml_select`.
- `src/code_quality/` contains several report-generating tools that take file path lists and return text reports.
- `src/git_tools.rs` contains `get_git_log`, which optionally filters history by a path.
- `src/searchtools_render.rs` renders searchtool JSON results to model-facing text, so any new structured ambiguity field must also be represented there.

In this repository, a “project-relative path” means a path rooted at the current workspace, such as `src/app/Foo.java`. A “bare filename” means a single path segment like `Foo.java` with no slash and no glob syntax.

## Plan of Work

First, centralize the behavior in `src/path_utils.rs`. Add a resolver that accepts a literal input string, preserves the existing workspace-escape guard, tries exact project-relative lookup first, and then performs a basename scan only when the input is a single-segment literal. The resolver must return one of three outcomes: resolved file, explicit ambiguity with all matching paths, or not found.

Next, route all eligible literal file inputs through that resolver. `src/searchtools.rs` should use it for file-pattern expansion when the item is not a glob or directory, for file-backed `get_symbol_sources`, and for `most_relevant_files.seed_file_paths`. `src/file_tools.rs` should use it for `get_file_contents`, literal `search_file_contents.file_path`, and `skim_files`. `src/structured_data.rs` should use it for literal `file_path` arguments and leave glob behavior alone.

Then finish the remaining file-path consumers. In `src/code_quality/mod.rs`, update `resolve_project_files` so the existing report tools inherit the same literal repair behavior and can collect ambiguous inputs separately from skipped inputs. In `src/code_quality/comment_density.rs`, which intentionally does not use the shared helper, add the same resolver directly so it can keep its per-input note style. In `src/git_tools.rs`, use the resolver for literal `get_git_log.file_path` filters and return a one-line ambiguity explanation instead of guessing.

After that, update text rendering. `src/searchtools_render.rs` should render a dedicated “Ambiguous paths” section for searchtool families that now expose the additive field. Code-quality tools already render plain text directly, so the per-tool report builders should append short ambiguity notes inline.

Finally, add focused tests using `tests/common/inline_project.rs` where a few inline files are enough. Cover one workspace with a unique `Foo.java` basename and one with duplicate basenames so the JSON and rendered text paths both prove the intended behavior.

## Concrete Steps

Work from the repository root:

    cd /home/jonathan/Projects/bifrost

Inspect the shared resolver and tool surfaces:

    sed -n '1,220p' src/path_utils.rs
    sed -n '560,1060p' src/searchtools.rs
    sed -n '1,220p' src/file_tools.rs
    sed -n '1,220p' src/structured_data.rs
    sed -n '1,220p' src/code_quality/mod.rs
    sed -n '180,280p' src/git_tools.rs

After the code changes, run focused tests first, then the full Rust checks:

    cargo test --test searchtools_summary_ranges --test searchtools_fuzzy_symbol_lookup --test searchtools_service
    cargo test --lib file_tools
    cargo test --lib structured_data
    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings

Expected validation shape:

    running <n> tests
    test ... ok
    ...
    test result: ok. <n> passed; 0 failed

    Finished `dev` profile ...

## Validation and Acceptance

Acceptance is behavioral:

1. A literal bare filename input such as `Foo.java` should resolve silently when exactly one file in the workspace has that basename. The tool result should contain the full project-relative path and should not emit any ambiguity note.
2. The same literal input should return structured ambiguity when the workspace contains multiple `Foo.java` files. Searchtool text rendering should list the candidate paths instead of guessing.
3. Literal glob-like inputs such as `**/*.java` must continue to behave as globs, not basename repair candidates.
4. Exact project-relative paths must keep precedence over basename repair.
5. `get_git_log` with an ambiguous bare filename should return a one-line ambiguity explanation rather than filtering history against an arbitrary file.

## Idempotence and Recovery

All edits are additive and safe to rerun. The resolver can be applied repeatedly because exact-path lookup remains the first step and basename ambiguity is read-only over the workspace file list.

If a test reveals that a tool family depends on its previous silent-skip behavior, adjust that tool’s result field to carry both `not_found` and `ambiguous_paths` rather than reverting the shared resolver. The recovery path is to keep the resolver and narrow only the affected caller’s presentation.

## Artifacts and Notes

Representative ambiguity text for searchtools should look like this:

    Ambiguous paths:
    - Foo.java -> app/Foo.java, lib/Foo.java

Representative `get_git_log` ambiguity text should look like this:

    Ambiguous path: Foo.java matches app/Foo.java, lib/Foo.java

## Interfaces and Dependencies

The shared resolver lives in `src/path_utils.rs` and should expose these internal types:

    pub struct AmbiguousPathInput {
        pub input: String,
        pub matches: Vec<String>,
    }

    pub(crate) enum ResolvedFileInput {
        File(ProjectFile),
        Ambiguous(AmbiguousPathInput),
        NotFound(String),
    }

    pub(crate) struct WorkspaceFileResolver<'a> { ... }

    impl<'a> WorkspaceFileResolver<'a> {
        pub fn new(project: &'a dyn Project) -> Self;
        pub fn resolve_literal(&self, input: &str) -> ResolvedFileInput;
    }

Result types that accept literal file inputs should gain additive `ambiguous_paths: Vec<AmbiguousPathInput>` fields with `#[serde(skip_serializing_if = "Vec::is_empty", default)]` so existing callers remain compatible.

Revision note: created during implementation after discovering that file-path handling was duplicated across multiple modules; the plan records the shared-resolver approach chosen to keep the repair behavior consistent.

Revision note: updated after implementation and validation to record the service-wrapper discovery, the completed test and validation commands, and the final behavior that shipped.
