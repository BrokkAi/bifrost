# Reconcile and fix usagebench issues #486-#498

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Usagebench issue reports #486 through #498 describe residual declaration-to-usage and usage-to-definition parity failures across Java, JavaScript, TypeScript, PHP, Python, C++, C#, Rust, Scala, and Go. The reports were created from Bifrost `df11434d4ed1443e5245b3b49de8e064a2563344`, while this checkout is `master` at `2111bf7a3d8407be937879be8250e4034d504014`. The first goal is therefore to reconcile the current analyzer behavior against those reports before changing code. The observable result is that current Bifrost tests prove which cases are already fixed, remaining failures get focused regression coverage and fixes, and usagebench expected-failure cleanup is either completed or explicitly blocked by the missing usagebench checkout.

## Progress

- [x] (2026-07-06T16:18Z) Created this ExecPlan and confirmed the local Bifrost worktree is clean.
- [x] (2026-07-06T16:18Z) Checked for a sibling usagebench checkout under `/home/jonathan/Projects`; none was found.
- [x] (2026-07-06T16:24Z) Ran focused existing Bifrost tests for the issue shapes that current summaries showed were already covered.
- [x] (2026-07-06T16:24Z) Determined no analyzer code fix is justified from local evidence because all targeted current-state tests passed.
- [ ] Remove usagebench expected-failure markers after a usagebench checkout is available and the matching cases pass there.

## Surprises & Discoveries

- Observation: The usagebench reports are against an older Bifrost commit.
  Evidence: GitHub issue bodies cite `df11434d4ed1443e5245b3b49de8e064a2563344`; `git rev-parse HEAD` in this checkout returned `2111bf7a3d8407be937879be8250e4034d504014`.
- Observation: The usagebench repository is not available in the expected local project roots.
  Evidence: `find /home/jonathan/Projects -maxdepth 2 -type d -name '*usagebench*' -o -name 'usagebench'` returned no paths.
- Observation: Existing Bifrost tests already name many of the issue shapes.
  Evidence: `get_summaries` showed current tests for Go promoted embedded members, PHP trait/interface relations, Rust UFCS and associated types, Scala extension methods, C# partial property access, JS/TS object/static/property lookup, and Python reexported class alias/decorator/property lookup.
- Observation: The targeted current-state reconciliation tests all passed on this checkout.
  Evidence: Focused `cargo test` commands listed in `Artifacts and Notes` passed for Go #495, PHP #489/#496, Rust #497, Scala #494/#498, C# #492, JS/TS #487/#488, Python #490, Java #486, and C++ #491 representative shapes.

## Decision Log

- Decision: Start with current-state reconciliation rather than immediately editing analyzers.
  Rationale: Many issue bodies describe failures from an older commit, and current tests already cover several supposedly open shapes. Changing code without first reproducing current failures risks churn and regressions.
  Date/Author: 2026-07-06 / Codex.
- Decision: Use existing language-focused test files as the first validation surface, then add new inline-project tests only for uncovered failures.
  Rationale: The repo instruction prefers `InlineTestProject` for small ad hoc analyzer fixtures, but existing tests are the cheapest proof when they already match the reported shape.
  Date/Author: 2026-07-06 / Codex.
- Decision: Do not add analyzer patches in this checkpoint.
  Rationale: Every focused local test corresponding to the reported shapes passed. The remaining action is usagebench expected-failure cleanup, but the usagebench checkout is not present locally.
  Date/Author: 2026-07-06 / Codex.

## Outcomes & Retrospective

Current-state reconciliation is complete for the local Bifrost checkout. No analyzer code was changed because no current local failure was reproduced. The remaining work is to run the matching usagebench cases and remove expected-failure markers in the usagebench repository; that work is blocked in this environment because no usagebench checkout was found.

## Context and Orientation

Usage lookup is implemented by per-language graph modules under `src/analyzer/usages/*_graph/`. Each language usually has an `extractor.rs` for forward declaration-to-usage scans, `resolver.rs` for target specifications and type/name resolution, `inverted.rs` for graph edge construction, and `hits.rs` for rendering `UsageHit` ranges. Usage-to-definition entrypoints live under `src/analyzer/usages/get_definition/`.

The issue range splits into two practical groups. Narrow residual reference issues are #486 through #494. Broader relation-capability issues are #495 through #498, but current code summaries show several of those broader capabilities already have in-tree tests and implementations.

Issue inventory:

- #486 Java constructor/class-construction and annotated override locations. Likely code: `src/analyzer/usages/get_definition/java.rs`, `src/analyzer/usages/java_graph/*`; likely tests: `tests/usages_java_graph_test.rs`, `tests/jdt_goto_definition.rs`, `tests/intellij_java_find_usages.rs`.
- #487 JavaScript member references. Likely code: `src/analyzer/usages/get_definition/js_ts.rs`, `src/analyzer/usages/js_ts_graph/*`; likely tests: `tests/usages_js_ts_graph_test.rs`, `tests/javascript_analyzer_test.rs`, `tests/get_definition_test.rs`.
- #488 TypeScript property/static method references. Same JS/TS code; likely tests: `tests/usages_js_ts_graph_test.rs`, `tests/typescript_analyzer_test.rs`, `tests/get_definition_test.rs`, `tests/usage_graph_ts_test.rs`.
- #489 PHP direct/static member references. Likely code: `src/analyzer/usages/get_definition/php.rs`, `src/analyzer/usages/php_graph/*`, `src/analyzer/php/aliases.rs`; likely tests: `tests/usages_php_graph_test.rs`, `tests/phpactor_goto_definition.rs`.
- #490 Python method, class alias, and property lookups. Likely code: `src/analyzer/usages/get_definition/python.rs`, `src/analyzer/usages/python_graph/*`, `src/analyzer/python/imports.rs`; likely tests: `tests/usages_python_graph_test.rs`, `tests/intellij_python_definition.rs`, `tests/python_decorators_test.rs`, `tests/get_definition_test.rs`.
- #491 C++ direct field and concrete override member references. Likely code: `src/analyzer/usages/cpp_graph/*`, `src/analyzer/usages/cpp_call_match.rs`; likely tests: `tests/usages_cpp_graph_test.rs`, `tests/clangd_find_references.rs`.
- #492 C# partial property access. Likely code: `src/analyzer/usages/get_definition/csharp.rs`, `src/analyzer/usages/csharp_graph/*`, `src/analyzer/csharp/declarations.rs`; current tests include `csharp_partial_property_receiver_usages_share_one_type_surface` and `csharp_partial_property_receiver_resolves_to_declaration`.
- #493 Rust direct method and module declaration lookup. Likely code: `src/analyzer/usages/get_definition/rust.rs`, `src/analyzer/usages/rust_graph/*`, `src/analyzer/rust/imports.rs`; current tests include direct receiver and module export coverage.
- #494 Scala direct member and renamed-import companion references. Likely code: `src/analyzer/usages/get_definition/scala.rs`, `src/analyzer/usages/scala_graph/*`, `src/analyzer/scala/imports.rs`; current tests include renamed member import and direct member coverage.
- #495 Go embedded promotion. Current summaries show promoted receiver collection in `src/analyzer/usages/go_graph/resolver.rs` and `go_graph_strategy_finds_promoted_go_embedded_member_usages`.
- #496 PHP trait/interface relation behavior. Current summaries show `PhpHierarchyIndex`, trait/interface graph tests, and PHP get-definition trait tests.
- #497 Rust UFCS trait methods and associated types. Current summaries show `resolve_trait_associated_item` and UFCS/associated-type graph tests.
- #498 Scala extension method resolution. Current summaries show `ExtensionMethod`, extension declaration extraction, visible extension methods, and extension graph/get-definition tests.

## Plan of Work

First, run focused existing tests that directly match the issue shapes. Record pass/fail evidence in this plan. If a test name already covers an issue and passes, mark that issue row as locally reconciled. If the shape lacks an exact test or the test fails, add a small `InlineTestProject` regression in the nearest existing language test file before implementing the fix.

Second, implement only current failures. For JS/TS, keep shared member resolution fixes in the shared JS/TS modules. For Java, C++, C#, PHP, Python, Rust, Scala, and Go, keep changes in structured graph/get-definition helpers and reuse existing resolver metadata. Do not add regex/text-search fallbacks or source-text mini parsers.

Third, run focused validation after each language slice. Commit checkpoints with only files changed by that slice. Since no usagebench checkout is available locally, do not attempt usagebench expected-failure marker cleanup in this repo; record it as blocked unless the checkout appears.

## Concrete Steps

Run commands from `/home/jonathan/Projects/bifrost`.

Initial focused validation commands:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_go_graph_test go_graph_strategy_finds_promoted_go_embedded_member_usages
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_finds_aliased_static_method_and_property_usages php_graph_finds_trait_method_calls_through_using_class php_graph_lsp_references_include_php_interface_method_implementations
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_rust_graph_test rust_graph_strategy_resolves_ufcs_trait_method_through_implementer rust_graph_strategy_resolves_associated_type_as_static_field
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test scala_graph_resolves_renamed_member_import_usages_without_external_import_hit scala_graph_resolves_visible_extension_method_usage
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_csharp_graph_test csharp_partial_property_receiver_usages_share_one_type_surface

Some cargo test invocations accept only one substring filter reliably; if a multi-filter command fails due to argument parsing rather than test failure, rerun the listed filters one at a time.

Focused reconciliation evidence from 2026-07-06 is recorded in `Artifacts and Notes`.

Final validation after code changes:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_js_ts_graph_test --test usages_go_graph_test --test usages_php_graph_test --test usages_python_graph_test --test usages_rust_graph_test --test usages_scala_graph_test --test usages_csharp_graph_test --test usages_cpp_graph_test --test usages_java_graph_test
    cargo fmt
    cargo clippy-no-cuda

## Validation and Acceptance

Acceptance requires every issue row to be in one of three states: locally passing with existing tests, locally passing after a new regression and fix, or explicitly blocked only because usagebench expected-failure cleanup requires a missing external checkout. Any analyzer fix must have a focused test that fails before the change and passes after it. This reconciliation checkpoint did not make analyzer changes, so formatter and clippy were not run for source-code validation.

## Idempotence and Recovery

All work is local source/test/plan editing under the repository root. Test commands are safe to rerun. If a broad language capability appears already implemented, do not rewrite it; keep the evidence and move to expected-failure cleanup when a usagebench checkout is available. If a focused fix creates false positives, prefer failing closed with no hit over broad same-name matching.

## Artifacts and Notes

`get_summaries` was used before creating this plan to inspect the relevant language graph modules and tests. The key local finding was that the current repository has substantially more coverage than the issue bodies imply.

Focused reconciliation commands passed on 2026-07-06:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_go_graph_test go_graph_strategy_finds_promoted_go_embedded_member_usages
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_finds_aliased_static_method_and_property_usages
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_finds_trait_method_calls_through_using_class
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_lsp_references_include_php_interface_method_implementations
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test php_trait_method_resolves_through_using_class
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_rust_graph_test rust_graph_strategy_resolves_ufcs_trait_method_through_implementer
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_rust_graph_test rust_graph_strategy_resolves_associated_type_as_static_field
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test scala_graph_resolves_renamed_member_import_usages_without_external_import_hit
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test scala_graph_resolves_visible_extension_method_usage
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_csharp_graph_test csharp_partial_property_receiver_usages_share_one_type_surface
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test csharp_partial_property_receiver_resolves_to_declaration
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test typescript_static_method_call_resolves_to_static_definition
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_js_ts_graph_test ts_static_member_on_class_value_resolves_member_usage
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_js_ts_graph_test js_object_literal_method_member_calls_resolve_to_plain_key
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test javascript_same_file_object_literal_property_resolves_to_definition
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test typescript_imported_object_literal_property_resolves_through_star_barrel
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_js_ts_graph_test ts_interface_property_usages_include_typed_reads_and_contextual_return_keys
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_python_graph_test reexported_class_alias_receiver_resolves_member_usages
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test python_reexported_class_alias_resolves_static_members_and_name_range
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test python_property_getter_resolves_on_module_level_receiver
    BIFROST_SEMANTIC_INDEX=off cargo test --test intellij_python_find_usages classmethod_on_class_usage
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_java_graph_test java_graph_strategy_keeps_nested_constructor_usage_narrow
    BIFROST_SEMANTIC_INDEX=off cargo test --test jdt_goto_definition jdt_def_annotated_override_method_targets_name_token
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_cpp_graph_test cpp_graph_finds_constructors_methods_and_field_accesses_for_typed_receivers
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_cpp_graph_test cpp_graph_resolves_header_declaration_to_out_of_line_definition_sites

Revision note, 2026-07-06 / Codex: Recorded local reconciliation results and the decision not to patch analyzer code without a current failing local test. Usagebench marker cleanup remains blocked by the missing usagebench checkout.
