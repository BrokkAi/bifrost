# Resolve Rust inverse imports that collide with local names

This ExecPlan is a living document. Maintain it under `.agents/PLANS.md` as work proceeds. It covers GitHub issue #1377 on branch `dave/1377-rust-inverse-loses-imported` at `ffd3fb71b` before implementation begins.

## Purpose / Big Picture

`scan_usages` must report a Rust call when an import binds the called name. Today it loses the call when a same-named declaration exists in the file. After this work, inverse usage queries find the imported call in two real cases: mutually exclusive cfg branches and a function-scoped `use` inside a same-named function. They must still refuse a true parameter, local binding, or function-local item shadow.

An implementer can prove the change by running the focused Rust usage test. Each imported target must contain the expected `UsageHitKind::Reference` call range. The existing negative shadow tests must still contain no hit.

## Progress

- [x] (2026-08-07 11:52Z) Read issue #1377 and its two comments. The second comment adds the nom `recognize` function-scoped import witness.
- [x] (2026-08-07 11:52Z) Inspected the inverse scan path, the shared Rust resolver, lexical scope handling, existing shadow tests, and the current remote state.
- [x] (2026-08-07 12:36Z) Added behavior tests for both issue witnesses. Corrected the cfg fixture to select the call, not the same-named fallback declaration.
- [x] (2026-08-07 12:36Z) Added position-aware import precedence and cfg-alternative candidate handling in the shared Rust resolver.
- [x] (2026-08-07 12:36Z) Updated shared-resolver callers to keep function-local item shadows while leaving module items for candidate comparison.
- [x] (2026-08-07 14:05Z) Passed both issue tests, three qualified-path guards, all 1,544 usage tests, 42 `brokk-bifrost-rust` tests, formatting, and focused Clippy. The required policy run returned `unreliable` with exit 2 because existing fixture findings and incomplete policy results remain in the workspace report.

## Surprises & Discoveries

- Observation: The scan path does not use the whole-workspace inverted graph. It calls `ScanCtx::matches_resolved_identifier` in `crates/bifrost-analysis/src/analyzer/usages/rust_graph/extractor.rs`, which calls the shared `usage_reference_at` function in `crates/bifrost-rust/src/usage_index.rs`.
  Evidence: `matches_resolved_identifier` computes `shadowed` from `RustLexicalScopeIndex` and passes it to `usage_reference_at`.

- Observation: `usage_reference_at` returns `Unresolved` before it examines imports when `root_shadowed` is true. If that guard is relaxed, it currently adds both the import route and same-file declaration to one candidate set and returns `Ambiguous`.
  Evidence: `usage_index.rs` lines 2211 and 2231-2347.

- Observation: Function-scoped imports already have exact visibility extents. `RustImportExtent::LocalOnly` records the enclosing module range and the nested scope range. The resolver does not give that route precedence over a module item.
  Evidence: `imports.rs` creates `RustImportOwner::LocalOnly`; `usage_index.rs` projects it into `RustImportExtent::LocalOnly` and filters it by `contains(byte)`.

- Observation: The existing lexical item predicate combines module items and function-local items. These require different behavior. A nested `type Error` must continue to hide an outer import. An enclosing module function must not defeat a `use` in its own body.
  Evidence: `RustLexicalScopeIndex::item_bound_at` only compares the nearest module extent. The existing regression `inverse_rust_usages_do_not_shadow_imported_type_with_impl_associated_type_name` protects the nested `type Error` case.

- Observation: A simple import-first rule is not safe. An unconditional module `use` plus a same-named module item is invalid Rust and the existing `local_definition_shadows_imported_rust_name` test intentionally reports no imported hit.
  Evidence: That test is in `tests/suite_usages/usages_rust_graph_test.rs` and currently passes by treating the name as shadowed or ambiguous.

- Observation: The direct cfg parser reads `cfg(feature = "query_apply")` and `cfg(not(feature = "query_apply"))` from tree-sitter nodes.
  Evidence: `lexical_scope::tests::cfg_condition_reads_direct_feature_and_not_feature_attributes` passes.

- Observation: Bare-name and qualified-path shadow predicates cannot share one broad item rule. Qualified roots need the existing target-aware module-item rule, while bare imported names need the new function-local item rule.
  Evidence: The full suite exposed `rust_qualified_resolution_respects_module_and_local_import_extents` and `rust_graph_scoped_member_chain_keeps_module_owner_hit`; both pass after separating the predicates.

## Decision Log

- Decision: Fix the shared target-aware resolver. Do not add a scan-only fallback.
  Rationale: `usage_reference_at` also serves `graph/resolver.rs` and `graph/inverted.rs`. A scan-only result would leave inverse and forward-related paths inconsistent.
  Date/Author: 2026-08-07 / Codex.

- Decision: Keep three distinct precedence outcomes: lexical bindings and function-local items shadow imports; visible local-only imports hide outer module items; module imports and module items remain competitors unless their cfg conditions are proven incompatible.
  Rationale: This resolves both witnesses without reviving the known `type Error` false positive or treating syntactically invalid unconditional duplicates as valid imports.
  Date/Author: 2026-08-07 / Codex.

- Decision: Use a conservative, tree-sitter-based cfg condition model. It must return "not proven exclusive" whenever it cannot prove two conditions cannot both hold.
  Rationale: A false positive inverse edge is worse than an incomplete one. The issue fixture needs `cfg(X)` versus `cfg(not(X))`; unknown cfg syntax must retain the current ambiguity behavior.
  Date/Author: 2026-08-07 / Codex.

- Decision: Support only an atomic cfg predicate and its direct `not(...)` complement. Treat compound, multiple, and malformed cfg forms as unknown.
  Rationale: The issue requires a direct complement. Unknown forms stay ambiguous and cannot create a false inverse edge.
  Date/Author: 2026-08-07 / Codex.

- Decision: Keep `RustReferenceResolution` target-aware. A target root is exact when every competing candidate either loses lexical precedence or is proven cfg-incompatible with it. Do not claim one global forward target for cfg-agnostic source.
  Rationale: A call may legitimately refer to different declarations in mutually exclusive builds. An inverse query for either target should retain the call, while overlapping candidates remain ambiguous.
  Date/Author: 2026-08-07 / Codex.

## Outcomes & Retrospective

The implementation records cfg conditions on imports and declarations. It preserves function-local item shadows, gives visible local-only imports precedence over module items, and lets a target win only when every competing candidate is cfg-incompatible. It keeps qualified-path resolution on its previous target-aware rule. The complete usage suite, crate tests, formatting, and Clippy pass. The policy tool remains an external failed gate because it returned `unreliable`; its findings do not point to these changes.

## Context and Orientation

Rust inverse usage analysis first narrows the possible files with import edges. It then scans identifiers in `crates/bifrost-analysis/src/analyzer/usages/rust_graph/extractor.rs`. `ScanCtx::matches_resolved_identifier` asks `usage_reference_at` whether an identifier resolves to the requested target root. A target root is a declaration selected by the user's usage request.

`crates/bifrost-rust/src/usage_index.rs` owns the shared import index and `usage_reference_at`. `RustOriginRoute` is a prepared path from a local import name to the declaration where the import originated. `RustImportExtent` tells whether that path is visible for a whole module or only inside a nested block. `RustReferenceResolution` currently says `Exact`, `Ambiguous`, or `Unresolved` for the target roots passed to it.

`crates/bifrost-rust/src/lexical_scope.rs` constructs `RustLexicalScopeIndex` from tree-sitter Rust nodes. A lexical binding is a parameter or local pattern name. An item is a `fn`, `type`, `struct`, `enum`, `trait`, or `mod` declaration. A module item is declared at the file or `mod` level. A function-local item is declared inside a function. These have different lookup priority relative to a nested `use`.

`crates/bifrost-rust/src/imports.rs` projects each `use` statement with its lexical owner. It is the correct place to attach structured cfg metadata to an import. Do not parse attributes with regular expressions, `split`, or manual delimiter scanning. Read tree-sitter attribute nodes and their named fields.

The behavior tests live in `tests/suite_usages/usages_rust_graph_test.rs`, included by `tests/suite_usages/main.rs`. They use `InlineTestProject`, which creates a small temporary Rust project and hides paths. The test must use this harness.

## Plan of Work

### Milestone 1: Pin the two issue witnesses and their safety boundaries

Add behavior tests to `tests/suite_usages/usages_rust_graph_test.rs`. Use separate tests so each failure names one rule.

The first test must create `apply.rs` with `pub fn apply_from_stdin`, then import it in `ncl.rs` under `#[cfg(feature = "query_apply")]`. The file must also contain `#[cfg(not(feature = "query_apply"))] fn apply_from_stdin`. Query the imported definition with `UsageFinder::find_usages_default`. Assert a `Reference` hit at the bare call, not only an import hit. Query the fallback definition too, and assert the same call is available to that cfg alternative. This proves target-aware cfg resolution rather than arbitrary import preference.

The second test must create `combinator.rs` with `pub fn recognize` and a consumer test function also named `recognize`. The function body must contain `use crate::combinator::recognize;` and a nested function that calls `recognize()`. Query `combinator.recognize` and require the call reference. Query the enclosing test declaration and require that it does not receive the nested call.

Keep and run the existing negative tests. Add a focused near-miss only if existing coverage is not exact enough: a function-local `type Error` inside a function with an outer imported `Error` must not produce a reference to the import. The existing test named `inverse_rust_usages_do_not_shadow_imported_type_with_impl_associated_type_name` is the expected primary guard. The unconditional module duplicate test `local_definition_shadows_imported_rust_name` must remain unchanged and passing.

Run the two new tests before the resolver changes. Each must fail because the expected call is absent. Record the short failure output in `Surprises & Discoveries`.

### Milestone 2: Represent lexical precedence and conservative cfg alternatives

In `crates/bifrost-rust/src/lexical_scope.rs`, add a public query that distinguishes a function-local item from a module item at a byte position. Preserve `item_bound_at` for callers that need the old broad predicate. Store enough owner information on `ItemVisibility` to answer this without reparsing or source-text searching.

In the same module, add a small structured cfg-condition reader. It must walk the `attribute_item` and nested meta-item tree-sitter nodes attached to a `use` declaration or named declaration. Represent an unconditional item explicitly. Support an atomic predicate and its direct `not(...)` complement. Give the model one operation: `proven_mutually_exclusive(left, right)`. It must return true only when the parsed forms prove that no build can enable both candidates. At minimum it must prove `cfg(X)` and `cfg(not(X))` exclusive, including the feature predicate used by issue #1377. Treat compound, multiple, unsupported, and malformed forms as unknown and therefore competing candidates. Do not use feature flags from the host build; this analysis stays cfg-agnostic.

In `crates/bifrost-rust/src/imports.rs`, extend `RustProjectedImport` or its owner metadata so each projected `use` retains its cfg condition. In `crates/bifrost-rust/src/usage_index.rs`, preserve this condition in `RustImportEdge` and `RustOriginRoute`. Build a parallel declaration-condition lookup keyed by the exact declaration identity. If an identity can represent more than one syntactic declaration, retain all conditions and treat them as competing unless their conditions prove exclusivity.

Keep this metadata internal to `brokk-bifrost-rust`. Do not add a public MCP, LSP, or JSON field.

### Milestone 3: Select candidates with the right precedence

Refactor the one-segment, non-macro branch of `usage_reference_at` in `crates/bifrost-rust/src/usage_index.rs`. Keep the current route, namespace, module, domain, and absolute-path checks. Collect visible origin-route candidates and same-module declaration candidates with their cfg conditions before reducing them to `RustReferenceResolution`.

Apply precedence in this order:

1. Keep the early `root_shadowed` return for lexical bindings and function-local items. They have higher priority than imports.
2. When a visible `RustImportExtent::LocalOnly` route binds the exact first segment, remove outer module-item candidates for that reference byte. The nested import wins in its lexical scope.
3. For module imports, retain same-module declaration candidates. A candidate competes with a requested root only if its cfg condition can overlap the root candidate's cfg condition.
4. Return `Exact` when exactly one requested root candidate remains after precedence and compatibility filtering. Return `Ambiguous` when more than one overlapping candidate remains. Return `Unresolved` when none remain.

Do not change multi-segment, macro, module-prefix, or fallback behavior unless a test proves they share the same candidate representation. Their current rules protect import routing and macro visibility.

### Milestone 4: Make every caller use the same shadow rule

Replace duplicated broad item-shadow expressions with the shared lexical-precedence helper. Update these known call sites after searching for all `usage_reference_at(` calls:

- `crates/bifrost-analysis/src/analyzer/usages/rust_graph/extractor.rs`, especially `ScanCtx::matches_resolved_identifier` and `item_shadows_target`.
- `crates/bifrost-rust/src/graph/inverted.rs`, in bare callee and exact AST owner resolution.
- `crates/bifrost-rust/src/graph/resolver.rs`, in trait visibility checks.

The helper must keep parameter and local-pattern shadows intact. It must report a function-local item as a shadow. It must leave a module item for `usage_reference_at` to compare against visible imports and cfg conditions. Do not add a language-specific name allowlist.

### Milestone 5: Validate the behavior and guard against regressions

Run the focused tests first. Then run the whole `suite_usages` test binary because the change affects shared resolution. Run the `brokk-bifrost-rust` crate tests to cover lexical scope and import-index unit tests. Format before all test runs.

Review the final diff for these conditions: no source-text cfg parser, no regular-expression fallback, no ignored tests, no broad change to macro or multi-segment routing, and no unrequested public API.

Run Bifrost policy validation once after code changes. Select `bifrost.code-smells`, use the current UTC date, and include each executable repository policy root identified by repository instructions. Treat `finding` as work to review and `unreliable` as a failed gate. If the call takes over five seconds, search the open issues for the documented latency path and record material new timing evidence.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/af03/bifrost`.

1. Confirm the tests fail before implementation:

       cargo test --test suite_usages -- usages_rust_graph_test::issue_1377_cfg_alternatives_keep_both_inverse_targets --exact --nocapture
       cargo test --test suite_usages -- usages_rust_graph_test::issue_1377_function_scoped_import_beats_enclosing_function_name --exact --nocapture

   Expect each command to fail with an assertion that the expected reference range is missing.

2. Make the Milestone 2 through 4 edits. After each coherent milestone, run:

       cargo fmt --check
       cargo test --test suite_usages -- usages_rust_graph_test::issue_1377_ --nocapture

   Expect both tests to pass after Milestone 4.

3. Run the relevant regression family:

       cargo test --test suite_usages -- usages_rust_graph_test::inverse_rust_usages_do_not_shadow_imported_type_with_impl_associated_type_name --exact
       cargo test --test suite_usages -- usages_rust_graph_test::local_definition_shadows_imported_rust_name --exact
       cargo test --test suite_usages -- usages_rust_graph_test::rust_graph_same_crate_imported_bare_function_call_stays_exact_after_persisted_reopen --exact

4. Run broader featureless validation:

       cargo test --test suite_usages
       cargo test -p brokk-bifrost-rust
       cargo clippy -p brokk-bifrost-rust -p brokk-bifrost-analysis --all-targets -- -D warnings

5. Discover and run the required policy selection after the code is complete. Use the live MCP request form:

       {"policy_packs":["bifrost.code-smells"],"evaluation_date":"YYYY-MM-DD","fail_on":"warning"}

   Add explicit `policy_files` only after confirming an executable repository policy root. Expect `status: "clean"` and `exit_status: 0`. A result with `status: "unreliable"` is not a passing policy result.

## Validation and Acceptance

Acceptance is behavioral. In the cfg fixture, a usage query for either `apply_from_stdin` definition reports the call in `ncl.rs` as a reference. In the function-scoped fixture, a usage query for `combinator.recognize` reports the nested call, while a query for the enclosing test `recognize` does not report it.

The existing true-shadow tests pass. In particular, a function-local `type Error` does not create an imported `Error` hit, and an unconditional module duplicate does not create an imported hit. The focused and full `suite_usages` commands pass, as do the featureless Rust crate tests and the two-crate Clippy command. The final policy result is clean and reliable.

## Idempotence and Recovery

The inline test fixtures are temporary directories managed by `InlineTestProject`. They do not alter the checkout. `cargo fmt`, the test commands, and Clippy are safe to rerun.

If a focused test fails after the resolver refactor, first inspect whether the candidate was excluded by lexical precedence or cfg compatibility. Do not weaken the result to a name match. If the condition reader cannot prove the two attributes exclusive, keep the candidates ambiguous and extend the tree-sitter condition reader with a focused unit test. Do not add raw-text special cases for `feature`.

If a shared resolver caller behaves differently, add a regression through its public behavior before changing another caller. Update the helper instead of copying another shadow expression.

## Artifacts and Notes

The two issue witnesses are:

    #[cfg(feature = "query_apply")]
    use crate::apply::apply_from_stdin;
    fn run() { apply_from_stdin(); }
    #[cfg(not(feature = "query_apply"))]
    fn apply_from_stdin() {}

and:

    fn recognize() {
        use crate::combinator::recognize;
        fn nested() { recognize(); }
    }

The first source has two mutually exclusive candidate declarations. The second has one inner import with higher lexical priority than the outer module function. Both calls must survive inverse scanning without loosening genuine local shadows.

## Interfaces and Dependencies

In `crates/bifrost-rust/src/lexical_scope.rs`, add a public query with this behavior, using a final name that fits the local module:

    pub fn local_item_bound_at(&self, name: &str, byte: usize) -> bool

It returns true only for an item whose enclosing function or closure contains `byte`. It must not return true for a module-level item.

In `crates/bifrost-rust/src/usage_index.rs`, keep `usage_reference_at` as the shared target-aware interface:

    pub fn usage_reference_at(
        rust: &dyn RustUsageSource,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        root_shadowed: bool,
        leading_absolute: bool,
    ) -> RustReferenceResolution

Do not add a second public resolver. Internally, replace its untyped `HashSet<RustSymbolIdentity>` accumulator with a candidate form that retains identity, import extent or declaration origin, and cfg condition until precedence and overlap checks finish. Preserve the existing final enum and all callers' meaning of `is_exact()`.

Revision note (2026-08-07): Created the plan after source-level root-cause investigation. The plan adds a cfg-compatibility stage because a function-scoped-import-only fix cannot solve the mutually exclusive cfg witness safely.
