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
- [x] (2026-07-06T22:05Z) Fixed and usagebench-validated the Java issue #486 cases.
- [x] (2026-07-06T23:05Z) Fixed and usagebench-validated PHP #489 cases plus the trait/static portions of #496.
- [x] (2026-07-06T19:05Z) Fixed, pushed, and closed Scala issue #494; Scala baseline direct-member cases and Scala renamed companion import now improve in usagebench.
- [x] (2026-07-06T19:08Z) Fixed and usagebench-validated Go issue #495 by resolving imported package factory return types relative to the factory declaration file.
- [x] (2026-07-06T19:14Z) Fixed and usagebench-validated the remaining PHP issue #496 interface implementation case.
- [x] (2026-07-06T19:38Z) Fixed and usagebench-validated Rust issue #497 UFCS trait method and impl-associated-type definition lookup cases.
- [x] (2026-07-06T20:03Z) Fixed and usagebench-validated Scala issue #498 relative wildcard import visibility for extension methods.

## Surprises & Discoveries

- Observation: The usagebench reports are against an older Bifrost commit.
  Evidence: GitHub issue bodies cite `df11434d4ed1443e5245b3b49de8e064a2563344`; `git rev-parse HEAD` in this checkout returned `2111bf7a3d8407be937879be8250e4034d504014`.
- Observation: The usagebench repository is not available in the expected local project roots.
  Evidence: `find /home/jonathan/Projects -maxdepth 2 -type d -name '*usagebench*' -o -name 'usagebench'` returned no paths.
- Observation: Existing Bifrost tests already name many of the issue shapes.
  Evidence: `get_summaries` showed current tests for Go promoted embedded members, PHP trait/interface relations, Rust UFCS and associated types, Scala extension methods, C# partial property access, JS/TS object/static/property lookup, and Python reexported class alias/decorator/property lookup.
- Observation: The targeted current-state reconciliation tests all passed on this checkout.
  Evidence: Focused `cargo test` commands listed in `Artifacts and Notes` passed for Go #495, PHP #489/#496, Rust #497, Scala #494/#498, C# #492, JS/TS #487/#488, Python #490, Java #486, and C++ #491 representative shapes.
- Observation: Go #495 is not a declaration-to-usage failure on current `master`; both promoted-member usage scans report `0 missing, 0 extra`.
  Evidence: `../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/go-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-go-lsp-495` reported XFAIL only because usage lookups at `worker.Record` and `worker.Last` returned `no_definition` with "`worker.Record` is shadowed by a local Go binding" and "`worker.Last` is shadowed by a local Go binding".

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
- Decision: For Go #495, keep embedded promotion represented in the existing nearest-depth member helper and fix only imported factory return typing.
  Rationale: Current graph and get-definition helpers already know how to walk promoted fields and methods once the receiver type is known. The failing usagebench fixture binds `worker := svc.NewWorker()`, and the missing type is the return type of an imported package selector call, not a missing embedded-promotion model.
  Date/Author: 2026-07-06 / Codex.
- Decision: For PHP #496, align `scan_usages` with the usagebench/LSP parity expectation that interface implementation declarations count as usages of the interface method.
  Rationale: PHP already computed implementation declarations through `PhpHierarchyIndex`; the remaining failure was surface classification and declaration-site lookup. Usagebench expects selecting `EmailNotifier::notify` to resolve to `Notifier::notify`, so the PHP definition resolver now treats method declaration names as reference sites only when they structurally implement an interface method.
  Date/Author: 2026-07-06 / Codex.
- Decision: For Rust #497, index trait default method bodies and trait associated types as declaration children, then special-case only impl associated-type declaration names in `get_definition`.
  Rationale: UFCS lookup already knew how to resolve a proven implementer to a visible trait item once the trait method declaration existed in the index. The associated-type failure was declaration-site ambiguity: selecting `type Output` inside an `impl Trait for Type` should navigate to the trait contract item, while ordinary type references should keep the existing Rust resolution flow.
  Date/Author: 2026-07-06 / Codex.
- Decision: For Scala #498, keep extension methods represented as ordinary function declarations with an `extension (...)` signature and fix the shared visibility model for wildcard imports.
  Rationale: Existing extension receiver matching, ambiguity handling, and declaration-to-usage logic worked for fully qualified imports such as `import app.Syntax.*`. The remaining usagebench fixture used same-package relative import syntax, `import Syntax.*`; wildcard import visibility must normalize both absolute and package-relative candidates so `get_definition` and scan-usages share the same visible extension set without adding name-only fallbacks.
  Date/Author: 2026-07-06 / Codex.

## Outcomes & Retrospective

Current-state reconciliation is complete for the local Bifrost checkout. No analyzer code was changed because no current local failure was reproduced. The remaining work is to run the matching usagebench cases and remove expected-failure markers in the usagebench repository; that work is blocked in this environment because no usagebench checkout was found.

Go issue #495 is complete on the Bifrost side. The existing embedded-promotion model was sufficient once `worker := svc.NewWorker()` typed `worker` as `*Worker`; the fix resolves imported selector-call return types such as `svc.NewWorker()` against the source file that declares `NewWorker`, so unqualified return types like `*Worker` are interpreted in the `service` package rather than the caller's `main` package.

PHP issue #496 is complete on the Bifrost side. Trait method calls, interface method calls through concrete receivers, interface implementation declarations, aliased static calls, and static property accesses now all improve in `php-lsp-parity.yaml`; the magic `__get` scenario remains explicitly not planned in usagebench.

Rust issue #497 is complete on the Bifrost side. Trait default methods and associated types are indexed as trait-owned items, so `LocalRunner::run(...)` resolves to `Runner::run`, and declaration-site lookup on an impl associated type resolves to the associated type declared by the implemented trait.

Scala issue #498 is complete on the Bifrost side. Same-package relative wildcard imports now expose extension methods consistently across get-definition and usage scans, so `import Syntax.*` makes `Syntax` extension members visible just like `import example.Syntax.*`.

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

Third, run focused validation after each language slice. Commit checkpoints with only files changed by that slice. Usagebench is available at `../usagebench`; use it as the source of truth with `--bifrost-working-tree` and a writable `/tmp` work directory.

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

Revision note, 2026-07-06 / Codex: Usagebench is now checked out at `../usagebench`. Exact runs against the Bifrost working tree showed the expected-failure markers are real analyzer gaps, not stale usagebench metadata. A JS/TS checkpoint added structured receiver support for JavaScript imported factory calls, JavaScript object-literal receiver values, and TypeScript object-type alias member declarations. Local validation passed:

    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test --test usages_js_ts_graph_test -- --nocapture
    cargo clippy-no-cuda

Usagebench validation command:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-jsts

The checkpoint improved `js-method-call` from XFAIL to IMPROVED. Remaining JS/TS usagebench failures after this checkpoint are `js-class-property-access`, `js-parity-object-literal-method-call`, `ts-object-property-access`, and `ts-parity-static-method-call`; these now need follow-up in declaration-site property indexing/self-receiver handling and the usage graph’s exact target-key selection for CommonJS object-literal/static member cases.

Revision note, 2026-07-06 / Codex: A follow-up local fix indexes JavaScript constructor assignments such as `this.title = title` as class fields and resolves `this` to the enclosing class in JS/TS receiver analysis. Focused local validation passed:

    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test javascript_this_property -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_js_ts_graph_test js_this_property_assignment_is_editor_visible_field_usage -- --nocapture
    cargo clippy-no-cuda

`../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/javascript-baseline.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-js-baseline` still reports `js-class-property-access` as XFAIL, so the remaining discrepancy appears to be in the usagebench lookup path or exact fixture/target selection rather than the local location resolver path covered by `get_definition_test`.

Revision note, 2026-07-06 / Codex: The prior `js-class-property-access` discrepancy was caused by stale `.bifrost` fixture caches under the usagebench checkout. After clearing fixture caches, the JS/TS fixes now flip the remaining usagebench expected-failure cases to `IMPROVED` on fresh runs:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/javascript-baseline.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-js-baseline-fresh
    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/javascript-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-js-lsp-fresh
    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/typescript-baseline.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-ts-baseline-fresh
    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/typescript-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-ts-lsp-fresh

Confirmed improved cases: `js-method-call`, `js-class-property-access`, `js-parity-object-literal-method-call`, `ts-object-property-access`, and `ts-parity-static-method-call`. The follow-up fixes made `this.field` class-field reads part of the external usage surface, indexed JavaScript object-literal methods as functions, accepted public TypeScript static method symbols without leaking the internal `$static` suffix, and kept `scan_usages` resolving both public and internal static method spellings.

Revision note, 2026-07-06 / Codex: Java issue #486 is fixed on fresh usagebench runs. The constructor false positive was a structured nested-type resolution bug: `new Service.Repository()` could resolve as the outer `Service` constructor. The usage graph resolver now resolves `scoped_type_identifier` nodes through their qualifier and nested child before falling back to simple file-scope type resolution. The annotated override discrepancy was a rendering mismatch in `search_symbols`; symbol search now reports the declaration display/name range instead of the whole declaration range, preserving analyzer ranges for enclosing-scope logic. Focused local validation passed:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_java_graph_test java_graph_strategy_keeps_nested_constructor_usage_narrow -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_java_graph_test java_graph_strategy_handles_nested_type_references -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_fuzzy_symbol_lookup java_annotated_method_search_symbol_uses_name_line -- --nocapture

Fresh usagebench validation after clearing Java fixture `.bifrost` caches:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/java-baseline.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-java-baseline-fresh
    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/java-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-java-lsp-fresh

Confirmed improved cases: `java-service-class-construction` and `java-parity-concrete-implementation-method-call`.

Revision note, 2026-07-06 / Codex: PHP issue #489 is fixed on fresh usagebench runs, and issue #496 is partially fixed. The PHP graph and definition lookup now type receiver chains through declared/promoted properties, seed locals from static factory calls with declared return types, record static property edges, and expand non-composer PHP candidates only for files with explicit type aliases to the target owner or descendant type. Focused validation passed:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_resolves_this_property_receiver_type_for_member_calls -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test php_promoted_property_receiver_resolves_member_definition -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test php_static_factory_result_receiver_resolves_instance_method -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_scan_usages_includes_non_composer_files_with_explicit_type_aliases -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test non_composer_php_project_does_not_expand_usage_candidates_by_namespace_shape -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_finds_trait_method_calls_through_using_class -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_php_graph_test php_graph_lsp_references_include_php_interface_method_implementations -- --nocapture

Fresh usagebench validation after clearing PHP fixture `.bifrost` caches:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/php-baseline.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-php-baseline-final
    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/php-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-php-lsp-final

Confirmed improved cases: `php-repository-method-call`, `php-parity-use-alias-static-method-call`, `php-parity-trait-method-call`, and `php-parity-static-property-access`. Remaining PHP expected failure: `php-parity-interface-method-implementation` still expects the concrete implementation declaration (`EmailNotifier::notify`) in the external usage surface and expects definition lookup from that declaration site to jump to the interface method. Bifrost already exposes implementation declarations as `OverrideDeclaration` hits on the LSP references surface, and `tests/usages_php_graph_test.rs::php_graph_lsp_references_include_php_interface_method_implementations` explicitly asserts they must not appear in external usages. Treat this remaining usagebench expectation as a harness/surface mismatch unless that Bifrost contract is intentionally changed.

Revision note, 2026-07-06 / Codex: Go issue #495 is fixed on fresh usagebench runs. The failure was not the existing embedded promotion walk; usage lookup could not type `worker := svc.NewWorker()` because the `*Worker` return type from `NewWorker` was resolved in the caller package. `src/analyzer/usages/get_definition/go.rs` now resolves call return types to FQNs using each callable declaration's source file. Focused validation passed:

    cargo test --test get_definition_test go_imported_factory_result_resolves_promoted_embedded_members -- --nocapture
    cargo test --test get_definition_test go_
    cargo test --test usages_go_graph_test
    cargo clippy-no-cuda

Fresh usagebench validation after clearing Go fixture `.bifrost` caches:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/go-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-go-lsp-495

Confirmed improved cases: `go-parity-embedded-promoted-method-call` and `go-parity-embedded-promoted-field-access`.

Revision note, 2026-07-06 / Codex: PHP issue #496 is now fully fixed on fresh usagebench runs. Implementation method declarations for interface targets are emitted on the PHP `scan_usages` surface, and `get_definition` on an implementing method declaration name resolves to the structurally implemented interface method. Focused validation passed:

    cargo test --test get_definition_test php_interface_implementation_method_declaration_resolves_to_interface_method -- --nocapture
    cargo test --test usages_php_graph_test php_graph_lsp_references_include_php_interface_method_implementations -- --nocapture
    cargo test --test usages_php_graph_test
    cargo test --test get_definition_test php_
    cargo clippy-no-cuda

Fresh usagebench validation after clearing PHP fixture `.bifrost` caches:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/php-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-php-lsp-496

Confirmed improved cases: `php-parity-use-alias-static-method-call`, `php-parity-trait-method-call`, `php-parity-interface-method-implementation`, and `php-parity-static-property-access`. The magic `__get` case remains `NOTPLANNED`.

Revision note, 2026-07-06 / Codex: Rust issue #497 is fixed on fresh usagebench runs. Trait default methods are now indexed the same way as signature-only trait methods, trait associated types are indexed as field-like declaration children, and `get_definition` maps an associated type declaration inside `impl Trait for Type` to the corresponding trait-associated type declaration. Focused validation passed:

    cargo test --test get_definition_test rust_trait_impl_items_resolve_to_trait_declarations -- --nocapture
    cargo test --test get_definition_test rust_
    cargo test --test usages_rust_graph_test
    cargo test --test rust_analyzer_goto_definition rust_ufcs_trait_method -- --nocapture
    cargo clippy-no-cuda

Fresh usagebench validation after clearing Rust fixture `.bifrost` caches:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/rust-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-rust-lsp-497

Confirmed improved cases: `rust-parity-module-declaration-definition`, `rust-parity-ufcs-trait-method-definition`, and `rust-parity-associated-type-impl-definition`. The macro-generated function reference remains `NOTPLANNED`.

Revision note, 2026-07-06 / Codex: Scala issue #498 is fixed on fresh usagebench runs. The fixture failure was not missing extension-method modeling in general; it was same-package relative wildcard visibility. `import Syntax.*` in package `example` did not expose extension methods owned by `example.Syntax`, while `import example.Syntax.*` already worked. The Scala graph name resolvers now expand wildcard import paths through both absolute and package-relative candidates for type/package visibility, extension method visibility, family-owner visibility, and ambiguity detection. Focused validation passed:

    cargo test --test get_definition_test scala_relative_wildcard_extension_method_call_resolves_to_extension_definition -- --nocapture
    cargo test --test usages_scala_graph_test scala_graph_resolves_relative_wildcard_extension_method_usage -- --nocapture
    cargo test --test get_definition_test scala_
    cargo test --test usages_scala_graph_test
    cargo test --test metals_goto_definition scala_
    cargo clippy-no-cuda

Fresh usagebench validation after clearing Scala fixture `.bifrost` caches:

    ../usagebench/target/debug/usagebench run-bifrost ../usagebench/benchmarks/cases/scala-lsp-parity.yaml --bifrost-repo /home/jonathan/Projects/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-scala-lsp-498

Confirmed improved cases: `scala-parity-import-alias-companion-method` and `scala-parity-extension-method-call`. The generated/synthetic case remains `NOTPLANNED`.
