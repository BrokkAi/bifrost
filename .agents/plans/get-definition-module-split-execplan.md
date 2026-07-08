# Split `get_definition.rs` into per-language modules

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](../../.agents/PLANS.md).

## Purpose / Big Picture

After this change, the get-definition resolver remains behaviorally identical, but its implementation is organized as a module directory with one file per language. That makes future language-specific work easier to navigate and reduces the risk of unrelated edits colliding inside one 12k-line file. The visible proof is that `src/analyzer/usages/get_definition/` contains `mod.rs` plus the requested language files, and the Rust checks still pass.

## Progress

- [x] (2026-06-20 00:27Z) Read `.agents/PLANS.md`, inspected `src/analyzer/usages/get_definition.rs`, and mapped the top-level resolver sections by language.
- [x] (2026-06-20 00:40Z) Split `src/analyzer/usages/get_definition.rs` into `src/analyzer/usages/get_definition/{mod.rs,cpp.rs,rust.rs,go.rs,js_ts.rs,scala.rs,java.rs,csharp.rs,python.rs,php.rs}` and rewired the dispatcher and parse helpers through child modules.
- [x] (2026-06-20 00:48Z) Ran `cargo fmt`, `cargo check`, and `cargo clippy --all-targets --all-features -- -D warnings` successfully after fixing shared dotted-reference helpers needed by both Rust and Go.

## Surprises & Discoveries

- Observation: `src/analyzer/usages/get_definition.rs` is currently 12,115 lines, so this is a mechanical but non-trivial refactor.
  Evidence: `wc -l src/analyzer/usages/get_definition.rs` returned `12115`.

- Observation: The Go resolver reuses the dotted-reference token helpers that originally lived inside the Rust section, so the first split failed until those helpers were promoted back to shared scope.
  Evidence: `cargo check` initially failed with `cannot find function dotted_reference_segments in this scope` from `src/analyzer/usages/get_definition/go.rs`.

## Decision Log

- Decision: Keep the dispatcher, shared request/outcome types, batch context, reference-site helpers, parse helpers, and final common outcome helpers in `mod.rs`; move each language resolver block and its private structs/enums into its matching language file.
  Rationale: That matches the user’s requested ownership model while keeping genuinely cross-language code centralized.
  Date/Author: 2026-06-20 / Codex

- Decision: Leave the large import surface in `mod.rs` and have child modules use `use super::*;` rather than re-curating every per-language import during the split.
  Rationale: This keeps the refactor mechanical, minimizes semantic churn, and still passes `clippy -D warnings`.
  Date/Author: 2026-06-20 / Codex

## Outcomes & Retrospective

The refactor completed as intended. `src/analyzer/usages/get_definition.rs` is now a directory module with one file per language plus `mod.rs` for shared API, dispatcher, and common helpers. The only notable adjustment beyond the requested layout was promoting the dotted-reference helper pair back into shared scope because Go and Rust both depend on them. Validation passed with `cargo fmt`, `cargo check`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## Context and Orientation

The file being refactored is `src/analyzer/usages/get_definition.rs`. It currently contains all get-definition logic for Rust, JavaScript/TypeScript, Go, C++, Scala, Java, PHP, C#, and Python, along with shared request types, parse helpers, and common outcome constructors. The parent module is `src/analyzer/usages/mod.rs`, which currently declares `pub(crate) mod get_definition;`. Rust module resolution allows replacing `src/analyzer/usages/get_definition.rs` with a directory `src/analyzer/usages/get_definition/` containing `mod.rs` without changing that declaration.

The existing section boundaries are already language-oriented: `resolve_rust` starts around line 522, `resolve_js_ts` around 1957, `resolve_go` around 4196, `resolve_cpp` around 5303, `resolve_scala` around 7657, `resolve_java` around 8883, `resolve_php` around 10287, `resolve_csharp` around 10369, and `resolve_python` around 10999. Common outcome helpers remain near the end.

## Plan of Work

First, create the new directory `src/analyzer/usages/get_definition/` and move the current file contents into `mod.rs` as the staging point. In `mod.rs`, add `mod rust;`, `mod js_ts;`, `mod go;`, `mod cpp;`, `mod scala;`, `mod java;`, `mod php;`, `mod csharp;`, and `mod python;`, then update the dispatcher in `resolve_one` to call `rust::resolve_rust`, `js_ts::resolve_js_ts`, and so on.

Next, carve each language block out of the old monolith into its corresponding file, keeping associated private structs and enums with that block. Add the minimal `use super::{...};` imports each child module needs for shared types and helpers from `mod.rs`, and keep crate-level imports local to the files that actually use them.

Finally, trim `mod.rs` down to the public/shared API surface and cross-language helpers, format the module tree, and run Rust validation to catch any missing imports or privacy mistakes.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`:

1. Create the ExecPlan and inspect the resolver boundaries.
2. Replace `src/analyzer/usages/get_definition.rs` with a directory module rooted at `src/analyzer/usages/get_definition/mod.rs`.
3. Move each language-specific section into its own file and wire child modules from `mod.rs`.
4. Run:

       cargo fmt
       cargo check
       cargo clippy --all-targets --all-features -- -D warnings

5. Record any deviations, especially if `clippy` is impractical due to unrelated workspace issues.

## Validation and Acceptance

Acceptance is:

1. `src/analyzer/usages/get_definition/` contains exactly the requested module files.
2. `src/analyzer/usages/mod.rs` continues to compile with `pub(crate) mod get_definition;`.
3. `cargo fmt` succeeds.
4. `cargo check` succeeds.
5. `cargo clippy --all-targets --all-features -- -D warnings` succeeds, or any pre-existing blocking issue is documented with exact command output and scope.

## Idempotence and Recovery

This refactor is safe to repeat because it is a source-layout change with no intended behavior change. If a partial split leaves imports broken, rerun `cargo fmt` and `cargo check` after each module move to localize the missing symbol. The unrelated untracked file `src/bin/semantic_index_profile.rs` must be left untouched.

## Artifacts and Notes

Important initial evidence:

    $ wc -l src/analyzer/usages/get_definition.rs
    12115 src/analyzer/usages/get_definition.rs

## Interfaces and Dependencies

At the end of the refactor:

- `src/analyzer/usages/get_definition/mod.rs` must define the shared types `DefinitionLookupRequest`, `DefinitionLookupOutcome`, `DefinitionLookupStatus`, `ResolvedReferenceSite`, and `DefinitionLookupDiagnostic`, plus `resolve_definition_batch`.
- `src/analyzer/usages/get_definition/mod.rs` must dispatch language handling to child modules named `rust`, `js_ts`, `go`, `cpp`, `scala`, `java`, `php`, `csharp`, and `python`.
- Each child module must own its language-specific resolver entry point and any helper structs/enums that only exist for that language.

Revision note: Created this ExecPlan before implementation because the requested source-layout split is a significant refactor of a 12k-line file, and the repository requires ExecPlans for work at that scale.

Revision note: Updated progress and outcomes after implementation, and recorded the shared helper discovery that surfaced during `cargo check`.
