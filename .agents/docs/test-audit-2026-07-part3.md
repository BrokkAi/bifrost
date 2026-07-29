# Test audit — part 3 (tests/ r–z)

Slice: the 97 integration-test files from `tests/ruby_lsp_goto_definition.rs` through
`tests/workspace_analyzer_test.rs`. **154,286 lines, 2,404 `#[test]` functions.**

Verdict up front: **this slice is in very good shape.** 13 tests (0.54%) are recommended for
removal, plus 3 individual assertions inside otherwise-valuable tests. There are **zero**
implementation-mirror tests and **zero** snapshot-of-today tests in the entire slice — the
registry/name-list anti-pattern CLAUDE.md warns about simply does not occur here. Almost every
file pairs positives against explicit negative controls, asserts exact byte offsets rather than
"some hit exists", and carries issue-numbered regression pins.

Method: 76 files read directly; 21 giants (>2,000 lines) read in full by parallel auditors whose
every flag was then re-verified by hand against the source before being admitted below.

---

## Recommended for removal

### 1. `tests/semantic_ir_contract.rs`

**`typescript_and_java_share_the_same_neutral_effects`** (L290) — **Tautology**

```rust
assert_eq!(neutral_effects(typescript_procedure), neutral_effects(java_procedure));
```

Both artifacts are built by the *same* test-local helper, `assignment_artifact()` (L189), which
emits a fixed list of `SemanticEffect` / `ControlEdge` / `SemanticValue` literals. Language is
threaded only into the `SemanticLocator`, which none of the three extractor closures
(`neutral_effects`, `neutral_edges`, `neutral_values`) reads. The equality is guaranteed by
construction — no analyzer, no adapter, no lowering runs. The named claim (cross-language neutral
IR) is genuinely covered by `tests/semantic_language_conformance.rs` (133 tests) and
`tests/semantic_value_language_contract.rs`, which materialize through the real adapters. The only
non-vacuous residue here is that `try_new` accepts the shape — asserted by every other test in the
file via the same `build_artifact` helper.

### 2. `tests/searchtools_summary_ranges.rs`

**`summary_renderer_uses_ranges_for_multiline_elements`** (L768) — **Cannot-fail**

```rust
assert_eq!("12..14: class Foo(\n  x: int,\n  y: int", rendered);
```

`render_summary_element` is defined at L41 **of this test file** and exists nowhere in `src/`
(verified). The test constructs a `SummaryElement` literal, passes it to the test's own formatting
helper, and asserts the helper's output. No product code is exercised. The real `SummaryElement`
range contract is asserted against production output by `file_summaries_preserve_fixture_line_numbers`
(L60) and `go_file_summaries_use_full_declaration_ranges` (L545), which feed the same helper with
analyzer-produced elements.

### 3. `tests/searchtools_fuzzy_symbol_lookup.rs`

**`javascript_double_sigil_names_are_searchable`** (L214) — **Subsumed** (copy-paste defect)

`diff <(sed -n '175,211p') <(sed -n '215,251p')` reports **no differences**: the body is byte-for-byte
identical to `scala_case_class_and_companion_in_object_index_under_the_object` (L174), down to the
copied `// http4s Message.EntityStreamException shape…` comment. It builds a `Language::Scala`
project from `src/Message.scala`; it touches no JavaScript path whatsoever and can only fail when
L174 also fails.

Caveat worth surfacing to the owner: the *name* is a coverage lie. Nothing in the file covers JS
double-sigil identifiers (`javascript_sigil_prefixed_field_is_searchable_by_literal_pattern` at L289
covers single `$`). If that is a real contract, rewrite against a JS fixture rather than delete
silently.

### 4. `tests/rust_alias_test.rs` (entire file — 1 test)

**`test_is_type_alias`** (L15) — **Subsumed**

Third of three copies of the same assertion triple. `rust_analyzer_parity.rs::rust_type_aliases_are_marked`
(L168) uses a character-identical fixture (`type MyResult<T>` / `struct MyStruct` / `fn my_func`),
makes the same three `is_type_alias` assertions, **and** additionally checks the
`type_alias_provider()` delegation. Strictly stronger; keep that one.

### 5. `tests/rust_import_test.rs`

**`test_type_alias_detection_via_import_suite`** (L157) — **Subsumed**

The weakest of the three alias copies: positive case + provider delegation only, no negative
controls. Fully contained in `rust_analyzer_parity.rs::rust_type_aliases_are_marked`, which adds the
struct and fn negatives. It is also topically misplaced — an alias test in an import suite.

### 6. `tests/rust_analyzer_parity.rs`

**`rust_discovers_modules_impl_targets_and_members`** (L19) — **Subsumed**

Every assertion is covered by the union of two tests in `rust_analyzer_test.rs`:
`test_module_class_and_function_code_units` (L55) asserts the same seven definitions, and
`test_field_skeletons` (L475) asserts the `Point` field skeleton and
`Point.ID` → `"pub const ID: i32 = 1;"` (and would panic in its own `definition()` helper if
`Point.ID` were missing). Nothing here is reachable only through this test.

**`rust_extracts_impl_target_names_for_wrapped_types`** (L89) — **Subsumed**

Asserts `T.act` and `Vec.act` are non-empty. `rust_analyzer_test.rs::test_impl_target_extraction_variants`
(L102) asserts exactly those two *plus* the matching negatives (`T` and `Vec` themselves must **not**
be indexed as types), plus `ast.StringLike`, `T.deref`, `T.len`. Strict superset.

> Caveat for both: `*_parity.rs` files are ports of the predecessor Java test-suite. They carry no
> header comment or doc declaring them a maintained conformance matrix, and the per-language parity
> files have entirely disjoint test names — so this is genuine redundancy, not matrix membership.
> If the owner wants the port kept verbatim for provenance, the counterpart tests in
> `rust_analyzer_test.rs` are the ones to drop instead. Pick one side; today both are paid for.

### 7. `tests/rust_analyzer_update_test.rs`

**`explicit_update`** (L6) — **Subsumed**

Identical three steps (write `foo`; assert `foo` present / `bar` absent; rewrite with `bar`;
`update(&{file})`; assert `bar` present) as the first half of
`rust_analyzer_parity.rs::rust_updates_add_and_remove_definitions` (L205), which then also covers
deletion via `update_all`.

Keep `auto_detect` (L23) — it is the only test of `update_all()` **detecting an addition**, which the
parity test does not cover.

### 8. `tests/structural_search_cross_language.rs`

**`remaining_languages_search_without_unsupported_adapter_diagnostics_during_issue_527_rollout`**
(L107) — **Subsumed**

```rust
assert_eq!(rows, vec![("cpp", "cpp/app.cpp", "audit()"), /* …7 rows… */]);
```

`shared_call_query_matches_every_analyzable_language_without_adapter_diagnostics` (L189) runs the
byte-identical query over byte-identical sources at byte-identical paths for all seven of these
languages plus five more, and asserts the same `(language, path, text)` rows (as a `BTreeSet`), the
diagnostic language set against `STRUCTURAL_ADAPTER_PENDING`, and `case_languages == Language::ANALYZABLE`.
Verified line by line. That gate is strictly stronger *and* self-maintaining: adding an analyzable
language fails it until listed. The #527 rollout it names is finished — every language in its corpus
now has an adapter.

Caveat: L189 does not check cross-language row *ordering* (BTreeSet vs Vec). Ordering is independently
pinned as an ordered `Vec` by `same_eval_call_query_matches_python_java_javascript_and_typescript`
(L2826), `decorator_query_matches_python_decorators_java_annotations_and_js_ts_decorators` (L2911),
and `member_call_callee_is_terminal_name_and_receiver_carries_object` (L3202). For zero loss, fold an
ordered-`Vec` row check into L189 rather than keeping L107.

### 9. `tests/usages_csharp_graph_test.rs`

**`csharp_graph_finds_static_and_instance_member_references`** (L6016) — **Subsumed**

```rust
assert!(!hits.is_empty(), "{} should have graph-backed member hits", target.fq_name());
```

That is the test's only assertion, applied in a loop over six targets. 160 lines later,
`csharp_graph_counts_field_and_property_references_precisely` (L6177) uses the *same* consumer
statements for `Count`/`Name`/`Value`/`Size` and asserts exact counts (2/1/2/2) — strictly stronger,
since it also catches over-counting. The two remaining targets are covered with exact counts
elsewhere in the file: the `using`-imported static call form by
`csharp_graph_resolves_static_calls_when_namespace_and_class_share_name` (L6129,
`assert_eq!(1, …)`), and the declared-type local receiver call by
`csharp_graph_receiver_method_calls_skip_precise_nonmatching_owners` (L4532). Verified all three by
hand.

Caveat: subsumption is across three sibling tests, not one. If the removal bar is single-test
subsumption, leave it — but note that `!is_empty()` over six targets is the weakest assertion form
in an 8,000-line file that otherwise asserts exact ranges everywhere.

### 10. `tests/usages_php_graph_test.rs`

**`php_graph_resolves_interface_typed_receiver_to_interface_method`** (L1621) — **Subsumed**

Fixture and both assertions are identical to
`php_graph_resolves_attributed_interface_typed_receiver_to_interface_method` (L1653), whose interface
merely carries an extra `#[SomeAttribute]`. The attributed version catches every bug the plain one
can, plus attribute-induced parse regressions. The plain interface-receiver hit is *also* asserted by
`php_graph_counts_inherited_and_concrete_interface_receivers` (L1344).

Counter-argument, for the record: as a pair they give differential diagnosis (if only the attributed
one fails, the attribute is the cause). That is diagnostic value, not bug-catching value — no bug
reaches the plain test that does not reach the attributed one.

**`php_graph_scopes_receiver_facts_to_enclosing_functions`** (L1723) — **Subsumed**

```rust
assert!(graph_hits(&analyzer, "App.Target.run").is_empty());
```

Its entire fixture — `first(Target $target){}` plus `second($target){ $target->run(); }` — is present
verbatim as the `sibling` / `otherSibling` pair inside
`php_graph_blocks_shadowed_reassigned_unknown_and_sibling_receivers` (L1686), which makes the identical
empty-result assertion over a strictly larger fixture (also covering shadow-reassignment and unknown
receivers). Verified side by side.

### 11. `tests/usages_java_graph_test.rs`

**`java_graph_strategy_handles_nested_type_references`** (L436) — **Subsumed**

```rust
assert!(!hits.is_empty());
```

`Outer.Inner` appears twice (return type + `new Outer.Inner()`); "at least one hit" lets half the
references silently vanish. `java_graph_strategy_keeps_nested_constructor_usage_narrow` (L3301)
covers cross-file `Service.Repository` in both declaration and `new` position with exact counts and
exact token ranges, and `java_graph_strategy_resolves_each_scoped_type_segment_by_identity` (L3430)
pins nested-segment resolution across field, qualified and generic positions.

Residual sliver: neither subsuming test uses a nested type in a *method return type* cross-file
(L3781 does so same-file). In tree-sitter that is the same `scoped_type_identifier` node shape as the
already-covered field declaration.

---

## Assertion-level deletions (keep the test, drop the line)

These are inside tests worth keeping; the lines themselves cannot fail.

1. **`tests/typescript_analyzer_test.rs:818-822`**, in `test_file_filtering_and_top_level_behavior`:
   ```rust
   assert!(declarations.iter().all(|code_unit| declarations.contains(code_unit)));
   ```
   `X ⊆ X`. Cannot fail for any value of `declarations`. The adjacent
   `assert!(declarations.len() > top_level.len())` is the real assertion.

   Same test, L807-810: `assert_eq!(Language::TypeScript, Language::from_extension("ts"))` ×4 is an
   extension→language table restated inside a file-filtering test. Harmless but misplaced; belongs in
   a `Language` unit test if anywhere.

2. **`tests/semantic_language_conformance.rs:2950`** (`cpp_nested_lambda_is_a_separate_immediate_procedure`)
   and **`:3755`** (`c_vla_bound_calls_are_retained_in_declaration_flow`):
   ```rust
   assert_eq!(call_site_source(lambda, source, exact_call_site(lambda, source, "cpp_leaf(1)")), "cpp_leaf(1)");
   ```
   `exact_call_site` locates the call site *by matching that same source text* and `expect`s on
   failure; the assertion then re-derives the text and compares it to the search key. Reduces to
   `assert_eq!(x, x)` after the real work is done. Both surrounding tests are valuable — replace with
   the bare `exact_call_site(...)` existence call, matching the `let _ = exact_call_site(...)` idiom
   already used elsewhere in the same file.

---

## Borderline — considered and kept

**`usage_finder_routes_*_through_graph_strategy` (10 tests across 9 files).** One auditor flagged four
of these (java L145, python L1673, js/ts L115, php L72) as thin single-assertion duplicates. I
overrode that. `rg 'fn usage_finder_routes_'` shows a consistently-named family spanning java, python,
js/ts, php, go, csharp, rust (×3), scala and cpp — a deliberate per-language `UsageFinder` dispatch
matrix, where membership *is* the contract per the audit brief. Deleting four rows breaks the matrix
and makes "did we forget a language?" unanswerable. **Strengthen instead**: several already assert
`query.graph_failure.is_none()` (e.g. python L2614); the rest should, since that is the routing claim
their names make. Note also that `usage_finder_routes_go_targets_through_graph_strategy` is the only
one driving a *cross-package* target and is independently load-bearing.

**`tests/scala_descendant_index_bench.rs` (2 tests).** Both `#[ignore]`d with **zero assertions** —
formally category 4. Kept: the header documents it as a `#908` measurement harness with an explicit
run command, it never executes in CI, and it is the only scaling instrument for the descendant-index
path. Deleting it destroys a tool, not a test.

**`tests/rust_dead_code_smells.rs::rust_dead_code_smell_honors_threshold` (L414).** Asserts the full
report header verbatim, including every default cap (`Input files analyzed cap: 25`, `Candidate symbol
cap: 200`, …). Changing any default breaks it as a pure text update — the shape of a snapshot pin. Kept
because the *behavior* (min_score 100 suppresses the finding that `rust_dead_code_smell_reports_one_call_wrapper`
produces at default) is real and covered nowhere else. Recommend narrowing the assertion to the
"No dead code … met minScore 100." tail.

**`tests/workspace_analyzer_test.rs` — the four `inline_project_*` tests.** These test the
`InlineTestProject` harness (language inference, single/multi dispatch, unsupported-file rejection)
rather than product code. Kept: the harness backs several hundred tests across the suite, so a silent
inference regression would mis-target them all.

**`tests/usages_python_test.rs::usage_finder_default_strategy_returns_results` (L24)** and
**`empty_overloads_yields_empty_success` (L77).** `!hits.is_empty()` and empty-in/empty-out
respectively. Weak, but the first covers default-strategy selection (not the explicit-strategy path of
its neighbour) and the second is a genuine degenerate-input contract (`Success`, not `Failure`).

**`tests/usages_python_graph_test.rs::inherited_base_member_counts_for_subclass_receiver` (L2265).**
Single-level MRO walk; arguably subsumed by the grandchild variant at L2346 since a depth-1 failure
implies a depth-2 failure. Kept: it is a one-line entry in a dense matrix of distinct receiver forms,
and removing base cases from an inheritance-depth matrix costs more in clarity than it saves.

**`tests/usages_csharp_graph_test.rs::cpp_graph_v3_preserves_declaration_filtering_and_fallback_boundaries`**
(cpp file, L6287) runs the identical restricted `find_usages` query twice (L6321-6341 and L6345-6349)
with the same `len() == 1` assertion. Dead block inside a valuable test — tidy-up, not removal.

**Unused negative controls in `tests/usages_scala_graph_test.rs`** (L1478, L1514, L1545): three tests
build a decoy into the fixture (`negative-other-overload`, `secondary-explicit-overload`,
`negative-other-explicit-apply`) and never assert against it. These need one `assert_no_hit_contains`
line each to make the "…exactly" claim in their names load-bearing — strengthen, do not delete.

---

## Files with zero findings (notable)

`semantic_language_conformance.rs` (133 tests), `semantic_oracle_contract.rs` (41),
`semantic_cfg_contract.rs` (38), `semantic_value_language_contract.rs` (14),
`usages_cpp_graph_test.rs` (164), `usages_scala_graph_test.rs` (155), `usages_rust_graph_test.rs` (211),
`searchtools_service.rs` (187), `searchtools_definition_selectors.rs` (69), `usages_go_graph_test.rs` (51),
`usages_ruby_test.rs` (42), `typestate_client.rs` (44), `taint_client.rs` (23),
`scala_definition_precedence_test.rs` (52), and every `usage_graph_*_test.rs`,
`*_type_hierarchy_test.rs`, `*_dead_code_smells.rs` and `*_semantic_diagnostics.rs` file in the slice.

Two caveats on the giants: `usages_scala_graph_test.rs` and `usages_rust_graph_test.rs` were being
edited during the audit (144→155 and 198→211 tests respectively). Re-run against a quiesced tree
before acting on anything in those two files.
