# Test audit — part 2 (tests/ j–r, 97 integration files)

Slice: the 97 files listed in `audit-p2.txt` (`tests/java_field_parity.rs` … `tests/ruby_lsp_find_references.rs`),
~40.5k lines. Every file was read; suspicious tests were read in full and cross-checked against the
implementation (`src/analyzer/multi_analyzer.rs`, `src/benchmark/artifact_lifecycle.rs`,
`src/mcp_property_fuzzer/service_probes.rs`) before being listed.

**Headline:** this slice is in good shape. The recommendations concentrate in four files
(`multi_analyzer_test.rs`, `multi_analyzer_capability_test.rs`, `multi_analyzer_import_test.rs`,
`measure_dataflow_lifecycle.rs`), plus four isolated tests elsewhere. **No implementation-mirror
findings at all** — the hardcoded name lists in this slice (`java_fixture_parity`,
`php_analyzer_test`, `python_module_analyzer_test`, `policy_source`) are all declaration-extraction
contracts where membership *is* the user-visible surface.

---

## tests/multi_analyzer_test.rs

The weakest file in the slice: 5 of its 13 tests carry no signal.

### `test_is_test_file_falls_back_to_heuristics_when_delegate_lacks_capability` — **Tautology**
The assertion is `assert!(fallback_test_file_heuristic(&python_test_file, &multi))`, and
`fallback_test_file_heuristic` is defined *in this test file* (line 28) as
`analyzer.contains_tests(file) || <filename starts with "test" / contains "_test" / …>`. The file is
named `test_script.py`, so the second disjunct is `true` unconditionally — the `MultiAnalyzer` is
never consulted in a way that can change the outcome. The test asserts its own helper.
*Covered instead by:* nothing needs to be — the real capability-fallback behaviour is covered by
`multi_analyzer_routing::multi_analyzer_handles_unknown_extensions_conservatively`.

### `test_unknown_extension_no_exception` — **Cannot-fail**
Zero assertions. Seven `let _ = multi.…(&unknown_class)` calls and nothing else. Every one of those
methods returns `Option`/`Vec` on the no-delegate path; there is no panic to guard against.
*Covered instead by:* `multi_analyzer_routing::multi_analyzer_handles_unknown_extensions_conservatively`
(same surfaces, with actual `is_empty()`/`!contains_tests` assertions).

### `test_unknown_extension_returns_empty_get_source` — **Subsumed**
One assertion (`get_source(...).is_none()`) on a hand-fabricated `CodeUnit` over a `.xyz` path,
identical setup to `test_unknown_extension_returns_empty_get_sources` two tests above.
*Covered instead by:* `test_unknown_extension_returns_empty_get_sources` (same dispatch path — the
`.xyz` extension maps to no delegate before any per-method logic runs).

### `test_unknown_extension_returns_empty_get_skeleton` — **Subsumed**
Same as above, third copy of the same one-line dispatch check.

### `test_get_top_level_declarations_unsupported_language_returns_empty` — **Subsumed**
*Covered instead by:* `multi_analyzer_routing::multi_analyzer_handles_unknown_extensions_conservatively`,
which asserts `top_level_declarations`, `import_statements`, `contains_tests` and
`is_access_expression` on an unrouted file in one test.

---

## tests/multi_analyzer_capability_test.rs

`MultiAnalyzer::{type_alias,type_hierarchy,import_analysis}_provider` is implemented as
`self.delegates.values().any(|d| d.<x>_provider().is_some()).then_some(self)`
(`src/analyzer/multi_analyzer.rs:1140-1152`). With a single delegate whose own provider is
unconditionally `Some`, the outer `is_some()` is a static fact of the delegate's trait impl.

### `type_alias_provider_is_present_when_delegate_supports_it` — **Cannot-fail**
Builds a Rust project containing `type Alias = i32;` — the file contents are never used — and asserts
only `provider.is_some()`. `RustAnalyzer::type_alias_provider` returns `Some(self)` unconditionally,
so this cannot fail without a compile error.
*Covered instead by:* nothing exercises `TypeAliasProvider` behaviour here; if that is the intent the
test should call a provider method, not test enum plumbing.

### `type_hierarchy_provider_is_present_when_delegate_supports_it` — **Cannot-fail**
Same shape: builds `base.py`/`derived.py`, never queries the hierarchy, asserts `is_some()`.
*Covered instead by:* `multi_analyzer_routing::multi_analyzer_routes_java_queries_and_capabilities`
asserts `type_hierarchy_provider().is_some()` *and* uses the returned providers; `php_type_hierarchy_test`
and `python_type_hierarchy_test` cover the actual hierarchy behaviour.

### `import_analysis_provider_is_empty_when_no_delegate_supports_capability` — **Tautology**
Constructs `MultiAnalyzer::new(BTreeMap::new())` and asserts the provider is `None`. This asserts
`[].any(..) == false`. The test's name claims a delegate-lacks-capability case, but no delegate exists.

Note: `import_analysis_provider_is_present_when_delegate_supports_it` in the same file **should stay** —
it asserts `provider.unwrap().import_info_of(&file).len() == 1`, i.e. real routed behaviour.

---

## tests/multi_analyzer_import_test.rs

### `test_delegation_to_java_analyzer` — **Subsumed**
*Covered instead by:* `test_delegation_routes_to_correct_language` in the same file, which contains
the identical three assertions (`java_imports.len() == 1`, `identifier == "List"`,
`relevant_imports_for` contains `java.util.List`) verbatim, plus the Python half, plus an update pass.
`test_three_way_routing_java_python_go` covers it a third time.

### `test_delegation_to_python_analyzer` — **Subsumed / partly Cannot-fail**
Same subsumption as above, and its final statement is
`let _ = provider.relevant_imports_for(&python_unit);` — a discarded call with no assertion at all.
*Covered instead by:* `test_delegation_routes_to_correct_language` and `test_three_way_routing_java_python_go`.

---

## tests/java_update_regressions.rs

### `incremental_class_replacement_keeps_new_children` — **Subsumed**
This test is a **verbatim duplicate** of the first half of
`java_update_parity::multi_step_update_reproduction_cases_match_remaining_java_update_tests`
(same fixture `pkg/Target.java`, same `class Target; class Target { void method() {} }` rewrite, same
`update(&BTreeSet::from([target]))`, same three assertions on `direct_children` / skeleton contains
`method` / skeleton lacks `baseline`). The parity test additionally covers the `update_all()` variant.

---

## tests/java_fixture_provenance.rs

### `class_manifest_reports_missing_added_and_modified_paths` — **Tautology**
`verify_class_manifest`, `read_manifest`, and `read_class_digests` are all defined *in this test file*
(lines 51-139). The test writes a manifest, writes class bytes, and asserts the test file's own diff
formatter produced `"<name>: expected X, actual Y"` strings. No `brokk_bifrost` symbol is imported by
this file at all — it cannot catch a product bug of any kind.
*Keep:* `checked_in_java_class_fixtures_match_manifest` in the same file — that one is the real
supply-chain pin on `tests/fixtures/testcode-java/bin`.

---

## tests/measure_dataflow_lifecycle.rs

### `median_helpers_select_the_middle_retained_sample` — **Tautology**
`assert_eq!(median_f64(vec![7.0, 1.0, 5.0, 3.0, 9.0]), 5.0)`. `median_f64`/`median_u64` are declared
at lines 1272/1278 **of this same test file** (`src/benchmark/query_code.rs` has its own private copy
that this cannot reach). It tests three lines of sort-and-index written directly above it.

### `generated_sources_expose_unique_roots` — **Tautology**
Calls the test file's own `generated_branch_source(8)` / `generated_call_source(8)` string builders
(lines 976/988) and asserts the emitted text contains `"export function branchRoot"` once and
`"if (input ==="` eight times — i.e. that a `for _ in 0..branches` loop ran `branches` times. The
expectation restates the generator's loop bound.
*Covered instead by:* `benchmark_clients_are_deterministic_and_bounded_on_a_real_icfg` in the same
file, which runs the generated fixture through a real ICFG and pins checksums and fact counts.

---

## tests/measure_summary_lifecycle.rs

### `summary_lifecycle_contract_blocks_non_equivalent_hydration` — **Tautology**
`assert!(!black_box(EXACT_EQUIVALENCE))` where line 83 is `const EXACT_EQUIVALENCE: bool = false;`
in the same file — `black_box` only suppresses the const-propagation lint, it does not make the
assertion capable of failing. The second assertion,
`assert_eq!(promotion_decision(EXACT_EQUIVALENCE, evaluation.passed()), "insufficient_evidence")`,
calls `promotion_decision` — also test-local (line 1480) — on a hardcoded `false`. Only the middle
`evaluate_artifact_promotion(...)` call touches product code
(`src/benchmark/artifact_lifecycle.rs:147`), and its inputs are hand-picked to pass by a 10× margin
(hydrate 20 ms vs rebuild 200 ms).
*Covered instead by:* the promotion gate itself is exercised with real measurements inside the
`#[ignore]`d `summary_lifecycle_measurement` (line 1415).

---

## tests/measure_analyzer_persisted_memory.rs (partial — assertions, not the whole test)

### `analyzer_persisted_memory_does_not_scale_with_total_source_size` — **Tautology (10 assertions)**
Keep the test; delete lines 258-270. Every one of those assertions round-trips a value the parent
process itself put into the child's environment:

```rust
assert_eq!(small_cold.modules, SMALL_MODULES);   // modules came from CHILD_ENV=SMALL_MODULES
assert_eq!(large_warm.modules / small_warm.modules, 10);  // 2000/200, both constants
assert_eq!(small_cold.mode, "cold");             // mode came from CHILD_MODE_ENV="cold"
```

The `parses == 0` / `fresh_parse_error_files == 0` pair and the `large_warm.delta <= allowed` bound
are the real content and must stay.

---

## tests/php_analyzer_test.rs

### `test_php_initialization` — **Cannot-fail / Subsumed**
`assert!(!analyzer.is_empty())` on the shared PHP fixture project. Every other test in the file
(`test_php_determine_package_name`, `test_php_get_declarations_in_file_foo`, all six skeleton tests…)
resolves specific `fq_name`s out of that same fixture and would fail loudly if the analyzer were
empty. The only failure mode unique to this test is "the fixture directory vanished", which the
other tests report better.

---

## tests/model_handle_semantics.rs (partial — assertions, not the whole test)

### `code_unit_equality_ordering_and_hash_are_semantic` — **Snapshot-of-today (2 assertions)**
Keep the test; drop these two lines:

```rust
assert_eq!(set.len(), 2);                                   // restates the assert_eq!/assert_ne! above
assert_eq!(left.cmp(&different_signature), Ordering::Greater);
```

The `BTreeSet` insert of `{left, same, different_signature}` having length 2 follows mechanically
from `left == same` and `left != different_signature`, both asserted three lines earlier. The
`Ordering::Greater` pins that `Some("void method()")` sorts after `Some("int method()")` — an
incidental lexicographic consequence of deriving `Ord` on the signature string. Nothing depends on
signature sort direction; a legitimate change to `CodeUnit`'s field order breaks it and the fix is
always "flip the expectation".
The equality/hash/inequality assertions above them are the real contract and must stay.

---

# BORDERLINE — considered, kept

**`multi_analyzer_get_test_modules_test::test_get_test_modules_delegation`** — computes `expected` by
calling each delegate's `get_test_modules` then `extend/sort/dedup`, which is exactly what
`MultiAnalyzer::get_test_modules` does, so the `assert_eq!` is close to an implementation mirror.
Kept because it is the only multi-language routing check for that method (a `MultiAnalyzer` that
queried only the first delegate would produce a non-empty `expected` and an empty `got`), and the
`expected.contains("Billing")` guard stops it degrading to `empty == empty`.

**`multi_analyzer_routing::language_from_extension_matches_supported_values`** — a five-entry
extension→`Language` table, the classic implementation-mirror shape. Kept: extension routing *is* the
user-visible contract (`.jsx` → JavaScript, `.hpp` → Cpp), it carries a negative control
(`"unknown"` → `Language::None`), and a wrong entry silently disables a whole analyzer.

**`multi_analyzer_test::test_get_top_level_declarations_non_existent_file`** — nearly the same as the
unknown-extension test, but `NonExistent.java` *does* route to the Java delegate, so it exercises a
different path (missing file, not missing delegate). One assertion, but a real one.

**`no_stringly_name_parsing::shape_c_unit_tests` (6 tests)** — these test the gate file's own
`find_shape_c_violations`/`is_exempted` scanners, i.e. test-local code. Kept: the module header
documents them as the recorded mutation check for a build-blocking lint, and a silently-drifted
matcher is exactly the failure mode a lint gate cannot detect about itself (the `exempted > 0` drift
guard in the main test is necessary but not sufficient).

**`measure_semantic_cfg::representation_models_preserve_procedure_and_rich_edge_contracts`** — asserts
over `freeze_dataset`/`mix`/`retained_memory`, all defined in the test file. Kept: this is a
decision-grade benchmark, and the assertions (three layouts agree on forward/reverse traversal;
`mix` distinguishes `source_mapping` from `evidence`) are what makes the published numbers mean
anything. Flagging for the record, not for removal.

**`javascript_analyzer_test::test_javascript_top_level_variables_and_usage_page_imports`** —
`assert_eq!(44, import_lines)` is a magic-number snapshot of a fixture's rendered module skeleton.
Kept: it is the only assertion that the module skeleton renders *every* import rather than a
truncated prefix, and the fixture is checked in so the number only moves deliberately.

**`ruby_analyzer_test::{empty_file_yields_no_declarations, deeply_nested_input_does_not_overflow_the_stack}`** —
the first is a one-assertion negative control (cheap, keep per the presumed-KEEP rule); the second has
literally zero assertions, but stack overflow **aborts the process**, so "completes" is a genuine
observable and the 5000-deep fixture is a real regression pin for the iterative-traversal rule in
CLAUDE.md.

**`java_lambda_parity::normalize_full_name_matches_java_helper_surface` /
`java_signature_normalization::normalize_full_name_handles_non_ascii_before_anonymous_marker`** — both
open with an identity assertion (`normalize("a.b.c") == "a.b.c"`). Kept: those are negative controls
against over-normalization sitting next to the real `$1`/generics/`Κ`-stripping cases.

**`policy_source::shipped_examples_cover_every_document_and_analysis_variant`** — iterates hardcoded
`POLICY_FIXTURES`/`ENDPOINT_FIXTURES` lists. Kept: this is a coverage guard asserting each shipped
`.rqlp` decodes to its intended analysis variant, not a name-list mirror.

**All `measure_*` peak-RSS harnesses (`go/jsts/python_usage_graph_memory`,
`jsts_scan_usages_baseline`, `structural_facts_memory`, `file_dependency_graph`,
`hierarchy_relations`, `usage_relevance_graph`)** — these show `0 asserts` or `1 assert` on a grep,
which reads as cannot-fail. All are `#[ignore]`d benchmarks that delegate their assertions to
`tests/common/memory_benchmark.rs`, and they carry real expectation structs
(`GeneratedFixtureExpectations { minimum_nodes, minimum_edges, expected_edge_suffixes }`). No action.

**LSP parity suites (`jdt/metals/roslyn/phpactor/ruby_lsp` × goto-definition/find-references),
`reference_differential*`, `mcp_property_fuzzer*`, `receiver_language_*`, all `policy_*`,
`lsp_click_around_regression`, `lsp_parameter_definition`, all `*_dead_code_smells`,
`*_structural_clone_smells`, `*_test_assertion_smells`, `*_test_detection_test`,
`*_type_hierarchy_test`** — reviewed, nothing recommended. These are the presumed-KEEP categories and
they hold up: every one drives real analyzer/LSP/policy machinery and asserts a discriminating
outcome. `mcp_property_fuzzer_service::minimize_batch_*` was checked specifically —
`minimize_batch` is product code (`src/mcp_property_fuzzer/service_probes.rs:497`), so those three
delta-debugging tests are legitimate.
