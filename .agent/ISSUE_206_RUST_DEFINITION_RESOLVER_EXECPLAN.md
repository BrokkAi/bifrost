# Share Rust get_definition Resolver Ownership

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` in this repository. It is self-contained so a future contributor can resume from this file and the current working tree alone.

## Purpose / Big Picture

The public `get_definition_by_location` and `get_definition_by_reference` tools should resolve Rust references using Rust analyzer-owned import and export semantics, not a second definition-only parser. Before this work, Rust definition lookup consumed `RustReferenceContext` for simple bare and scoped names, then fell back to local helper code in `src/analyzer/usages/get_definition/rust.rs` that reparsed visible `use` statements and walked export indexes itself. After this change, a user can ask for definitions through named imports, grouped imports, glob imports, and glob re-exports, and the answer comes from Rust analyzer-owned resolver helpers shared with usage analysis.

## Progress

- [x] (2026-06-22T10:10Z) Created this ExecPlan from issue #206 and the accepted Rust-first implementation plan.
- [x] (2026-06-22T10:10Z) Confirmed branch `206-track-remaining-get_definition-resolver-drift-across-graph-backed-languages` is up to date with its upstream.
- [x] (2026-06-22T10:17Z) Moved Rust import/export lookup out of `get_definition/rust.rs` and into Rust analyzer-owned helpers.
- [x] (2026-06-22T10:17Z) Added Rust definition regressions for glob imports, private names hidden behind glob imports, glob re-exports, and local shadowing.
- [x] (2026-06-22T10:18Z) Ran focused Rust definition validation: `cargo test --test get_definition_test rust_` passed with 32 tests.
- [x] (2026-06-22T10:18Z) Ran Rust usage graph validation: `cargo test --test usages_rust_graph_test` passed with 61 tests.
- [x] (2026-06-22T10:20Z) Ran final formatting and lint gates: `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` passed.
- [x] (2026-06-22T10:37Z) Ran guided review over the milestone diff. Addressed correctness findings for explicit-vs-glob precedence, struct-pattern type names, function-local item shadowing, `let` initializer shadowing, closed inner-block leakage, later block-local items, and tuple-struct pattern binders.
- [x] (2026-06-22T10:37Z) Reran focused Rust definition validation after review fixes: `cargo test --test get_definition_test rust_` passed with 39 tests.
- [x] (2026-06-22T10:37Z) Reran Rust usage graph validation after review fixes: `cargo test --test usages_rust_graph_test` passed with 61 tests.

## Surprises & Discoveries

- Observation: `RustAnalyzer::import_binder_of` already consumes flattened top-level imports because Rust parsing records flattened `ImportInfo` values, but nested function-local `use` declarations are only visible from source/AST inspection.
  Evidence: `src/analyzer/rust/declarations.rs` flattens root `use_declaration` nodes before storing `parsed.imports`; the old definition fallback still traversed the source tree to find visible local `use` declarations.

- Observation: Rust top-level `use` items are order-independent for the existing definition behavior, but parent-module `use` items must not leak into inline child modules.
  Evidence: the first focused run failed `rust_later_module_use_resolves_earlier_same_module_reference` and `rust_parent_module_use_does_not_leak_into_inline_child_module` until the analyzer-owned visible-import helper preserved the old enclosing-`mod_item` check while allowing later top-level imports.

- Observation: Cursor-local shadowing needs Rust lexical scope-chain semantics, not a flat "all earlier descendants" scan.
  Evidence: guided review found uncovered failures for `let Foo = Foo {};`, `{ let Foo = (); } let _ = Foo {};`, later block-local `struct Foo;`, and tuple-struct binders. The helper now walks only the lexical scope chain containing the reference, treats block-local items as visible throughout their block, and only lets `let` patterns shadow after their declaration is complete.

## Decision Log

- Decision: Keep the first #206 implementation slice Rust-only.
  Rationale: Rust has the highest remaining drift risk and already has analyzer-owned `RustReferenceContext` and `RustUsageIndex` primitives to extend. Python, Java, Scala, C++, C#, and PHP remain follow-up slices.
  Date/Author: 2026-06-22 / Codex.

- Decision: Return analyzer-level Rust identities from new helpers, not `DefinitionLookupOutcome`.
  Rationale: The Rust analyzer should own language resolution, while `get_definition` should own converting resolved targets into public result metadata and diagnostics.
  Date/Author: 2026-06-22 / Codex.

- Decision: Allow explicit named/namespace imports to fall back to same-crate declarations when an export entry is absent, but keep glob imports export-only.
  Rationale: Existing Rust definition behavior allowed explicit same-crate imports of declarations that were not public module exports. Glob imports should expose only exported names, which is the behavior covered by the new private-name regression.
  Date/Author: 2026-06-22 / Codex.

- Decision: Split Rust lexical-source helpers into `src/analyzer/rust/lexical_scope.rs` and keep `RustAnalyzer::resolve_imported_export_from_binder` independent of source byte positions and `DefinitionLookupIndex`.
  Rationale: The analyzer-owned import/export helper remains reusable from usage and definition code, while `get_definition` owns the cursor-local adapter step that builds a visible binder and applies local shadowing for a concrete reference location.
  Date/Author: 2026-06-22 / Codex.

- Decision: Explicit named and namespace imports take precedence over glob imports even when the explicit target set is empty.
  Rationale: Rust name binding should not merge an explicit local binding with same-named glob exports. Returning an empty target set is the conservative definition outcome for an unresolved explicit binding.
  Date/Author: 2026-06-22 / Codex.

## Outcomes & Retrospective

The Rust-first #206 slice is implemented. Rust definition lookup now delegates imported/exported target interpretation to `RustAnalyzer::resolve_imported_export`, `RustAnalyzer::resolve_imported_export_from_binder`, `RustReferenceContext`, and `RustUsageIndex` instead of owning a second raw `use` parser and export walker inside `get_definition/rust.rs`. Cursor-local source handling lives in the Rust analyzer-owned `lexical_scope` helper and the definition adapter maps analyzer-level identities through `DefinitionLookupIndex`. Existing Rust definition behavior remains covered, and new regressions prove public glob imports, private names behind glob imports, glob re-exports, explicit import precedence, and local shadowing behavior across values, local items, struct patterns, tuple-struct patterns, and nested blocks.

Validation completed from `/Users/dave/.codex/worktrees/d8b1/bifrost`:

    cargo test --test get_definition_test rust_
    test result: ok. 39 passed; 0 failed

    cargo test --test usages_rust_graph_test
    test result: ok. 61 passed; 0 failed

    cargo fmt --check
    no output

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

## Context and Orientation

Rust definition lookup lives in `src/analyzer/usages/get_definition/rust.rs`. Public searchtools and MCP APIs call that resolver through `get_definition_by_location` and `get_definition_by_reference`; those public APIs are not changing in this plan.

Rust analyzer-owned import and export state lives in `src/analyzer/rust/graph_support.rs` and `src/analyzer/rust/usage_index.rs`. `RustReferenceContext` resolves simple reference text such as `Foo` or `module::helper` to Rust fully qualified names. `RustUsageIndex` follows `pub use` re-export chains and lowers glob imports into named import edges for usage analysis. A "glob import" means `use crate::service::*;`, which makes exported names from `service` visible without naming each one. A "glob re-export" means `pub use crate::service::*;`, which re-exports public names from one module through another module.

The old definition-only fallback in `get_definition/rust.rs` reparsed visible `use` statements, manually converted module paths to files, and recursively walked export indexes. That duplicate path is the drift this plan removes.

## Plan of Work

First, extend Rust analyzer-owned helpers. `RustAnalyzer::import_binder_of` should remain the source of import bindings, and any source-visible local `use` parsing needed for exact location lookup should live beside it in the Rust analyzer module. `RustUsageIndex` should expose a crate-internal way to resolve exported targets from one or more module files, following named re-exports and star re-exports. The result should be Rust identities such as `(ProjectFile, local_name)`, not public definition results.

Second, add a Rust analyzer helper for definition lookup import resolution. Given an importing file, a local reference name, and an optional byte position, it should return the imported targets that name can refer to. For explicit named or namespace imports, it may fall back to same-crate declarations when no public export entry exists. For glob imports, it must only expose names from the export index, so private declarations hidden behind `use module::*` remain unresolved.

Third, simplify `src/analyzer/usages/get_definition/rust.rs`. Replace calls to definition-local `rust_import_candidates`, `rust_import_statement_candidates`, `rust_export_candidates`, and `rust_visible_use_statements_from_source` with the Rust analyzer helper. Keep Rust member, field, macro, local type, and terminal diagnostic code in the definition module because those paths still shape public definition results.

Fourth, add focused tests in `tests/get_definition_test.rs`. Keep existing named, grouped, crate/super, macro, and field behavior passing, and add tests for public glob import success, private glob import `no_definition`, glob re-export success, and local shadowing over a glob import.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/d8b1/bifrost

Refresh the branch before implementation:

    git fetch
    git rebase

Edit only the Rust analyzer, Rust definition resolver, Rust definition tests, and this ExecPlan unless validation exposes a directly related issue. This implementation touched `src/analyzer/rust/graph_support.rs`, `src/analyzer/rust/usage_index.rs`, `src/analyzer/rust/lexical_scope.rs`, `src/analyzer/rust/mod.rs`, `src/analyzer/usages/get_definition/mod.rs`, `src/analyzer/usages/get_definition/rust.rs`, `tests/get_definition_test.rs`, and this ExecPlan.

Run focused validation after the code edits:

    cargo test --test get_definition_test rust_
    cargo test --test usages_rust_graph_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The work is accepted when the Rust definition tests show that:

- a named import such as `use crate::util::format_value; format_value()` resolves to the imported function;
- a grouped import such as `use app::{ env::{env_init} }; env_init()` resolves;
- `use crate::service::*; Foo` resolves to exported `Foo`;
- `use crate::service::*; Hidden` returns `no_definition` when `Hidden` is not exported;
- `pub use crate::service::*; use crate::index::Foo; Foo` resolves through the re-export;
- a local value named `Foo` before a `Foo` reference blocks the glob-imported definition and returns `no_definition`;
- an explicit `use crate::private_mod::Foo;` wins over a same-named glob import;
- `let Foo = Foo {};` resolves the initializer `Foo` through the import instead of treating the new binding as already visible;
- a binding inside a completed inner block does not shadow an outer later reference;
- a later block-local `struct Foo;` shadows a same-block glob import;
- a tuple-struct pattern binder named `Foo` shadows a later `Foo` reference while the tuple-struct type name itself is not treated as a binder;
- existing Rust crate/super path, macro, field, and external-boundary tests continue to pass.

The final validation commands listed in Concrete Steps must pass.

## Idempotence and Recovery

The edits are local refactors and focused tests. Re-running tests is safe. If a helper creates broader Rust usage graph behavior changes, use `cargo test --test usages_rust_graph_test` to identify the regression and keep the existing usage graph contract unless the change is required by this plan. Do not revert unrelated user changes.

## Artifacts and Notes

Initial branch evidence:

    git status --short --branch
    ## 206-track-remaining-get_definition-resolver-drift-across-graph-backed-languages...origin/206-track-remaining-get_definition-resolver-drift-across-graph-backed-languages

    git rebase
    Current branch 206-track-remaining-get_definition-resolver-drift-across-graph-backed-languages is up to date.

Final validation evidence:

    cargo test --test get_definition_test rust_
    running 39 tests
    test result: ok. 39 passed; 0 failed; 201 filtered out

    cargo test --test usages_rust_graph_test
    running 61 tests
    test result: ok. 61 passed; 0 failed

    cargo fmt --check
    no output

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

Revision note 2026-06-22 / Codex: Updated after completing the Rust-first implementation slice and post-milestone guided-review remediation so the progress, discoveries, decisions, outcomes, touched files, and validation evidence reflect the current working tree.
