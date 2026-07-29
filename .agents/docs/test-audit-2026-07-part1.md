# Test audit — part 1 (tests/ a–j, 97 integration files)

Scope: the 97 integration-test files in `tests/` from `analyzer_capability_parity.rs` through
`java_declarations_parity.rs` (alphabetical) — 90,845 lines, **1,880 `#[test]` functions**.

Bar applied (CLAUDE.md "Analyzer Test Guidance" + owner brief): remove tests that mirror
implementation-shaped lists where membership is not the user-visible contract, and tests that assert
tautologies. Presumed keep: `issue_*` regression pins, complexity/counter pins, negative controls,
cross-language conformance matrices, advertised MCP/LSP surface lists, property-fuzzer invariants,
and the real-LSP parity suites (`clangd_*`, `gopls_*`, `basedpyright_*`, `intellij_*`).

**Result: 22 tests recommended for removal (1.2% of the slice), plus 2 line-level blocks inside
tests that should otherwise stay.** Every claim below was verified against the working tree by
reading or diffing the cited bodies. HEAD moved from `25978616` to `d1b07897` during the audit;
findings reflect the current tree, and test names (not line numbers) are the stable identifiers.

Category totals: Tautology 4 · Implementation mirror 5 · Subsumed 12 · Cannot-fail 1 ·
Snapshot-of-today 0.

---

## Tautologies

### tests/analyzer_query_parity.rs — `java_primitive_queries_match_forwarding_aliases`, `python_primitive_queries_match_forwarding_aliases`

Both tests are built from two helpers that assert `f(x) == g(x)` where `g` is a defaulted trait
method whose entire body is `self.f(x)`:

```rust
assert_eq!(analyzer.top_level_declarations(file), analyzer.get_top_level_declarations(file));
assert_eq!(analyzer.ranges(unit), analyzer.ranges_of(unit));
assert_eq!(analyzer.signatures(unit), analyzer.signatures_of(unit));
```

`src/analyzer/i_analyzer.rs:545-583` defines every one of these aliases as a literal forwarder
(`fn ranges_of(&self, code_unit) -> Vec<Range> { self.ranges(code_unit) }`, and so on). I grepped
every `impl IAnalyzer for` block in `src/`: only scala, rust, typescript, php, go, kotlin, javascript,
csharp and the workspace wrapper override any alias, and only `get_analyzed_files` /
`get_all_declarations` / `get_definitions` — none of which these two tests could distinguish, because
neither `JavaAnalyzer` nor `PythonAnalyzer` (nor `MultiAnalyzer`) overrides anything. The assertions
cannot fail while the crate compiles.

The file's `assert_primary_range` helper additionally computes its expectation by re-running the
implementation:

```rust
let expected_range = analyzer.ranges(expected).into_iter()
    .min_by_key(|range| (range.start_line, range.start_byte));
assert_eq!(primary_range, expected_range);
```

which is character-for-character the body of `IAnalyzer::all_declarations_with_primary_ranges`
(`src/analyzer/i_analyzer.rs:314-324`).

Covered instead: the residual real assertions (`direct_children` contains the method, imports
non-empty) are covered for Java by `java_declarations_parity.rs`
(`packaged_file_declarations_include_module_and_members`,
`nested_class_identifiers_match_java_expectations`) and for Python by the cross-language declaration
suites. Keep `ordinary_analyzer_build_does_not_activate_unified_cache_backend` in this file — it is a
real negative control on cache-DB creation.

### tests/benchmark_workflow_policy.rs — `workflow_contract_normalizes_windows_line_endings`

Tests nothing but the test file's own three-line helper, which is one call to `str::replace`:

```rust
assert_eq!(normalize_newlines("on:\r\n  schedule:\r\n"), "on:\n  schedule:\n");
```

`normalize_newlines` is defined ten lines above as `contents.replace("\r\n", "\n")`. No product code
sits between the input and the assertion. The CRLF handling it nominally covers is exercised
implicitly by `benchmark_workflow_enforces_actionable_regressions_by_default`, which calls the same
helper on the real workflow file.

### tests/code_query_public_api.rs — `public_semantic_result_contracts_are_constructible_without_dense_ids`

Constructs `CodeQueryProcedure` / `CodeQueryProgramPoint` / `CodeQueryControlEdge` by struct literal,
serializes them, and reads back the literals it just wrote:

```rust
assert_eq!(value["path"], "src/app.ts");
assert_eq!(value["language"], "typescript");
assert!(value["id"].as_str().is_some_and(|id| id.len() == 64));
```

`path` and `language` were assigned a few lines earlier; `id` is `"11".repeat(32)`, so the length
check restates the test's own input. The one non-trivial-looking assertion
(`!value.to_string().contains("artifact_key")`) also cannot fail: the struct literals are exhaustive,
so adding an `artifact_key` field breaks compilation first. The genuine content of the test — that
these types are publicly constructible — is a compile-time property that the `use` and the struct
literals already provide without any assertion.

Keep `public_cancellable_profile_returns_cancellation_observations` in this file (drives a real
cancelled profile execution).

---

## Implementation mirrors — the `--help` genus

Five tests across four CLI files assert that a `--help` banner contains flag names. In every case the
banner is either a static `r#"…"#` literal in the binary (`print_general_help`,
`src/bin/bifrost.rs:931`; the policy banner at `:971`; `print_help` in
`src/bin/bifrost_reference_differential.rs:1171`) or clap-generated text derived from the very option
struct being asserted. Nothing computes between the declaration and the assertion, so the only way
to fail is to deliberately rename or delete a documented flag — and the tests pass for every real bug
in what those flags do. They also cannot catch the failure that would matter (a *new* flag going
undocumented), because they only check flags already listed.

### tests/bifrost_tool_cli.rs — `help_mentions_tool_mode`

```rust
assert!(stdout.contains("--tool NAME"), "{stdout}");
assert!(stdout.contains("--query-file PATH"), "{stdout}");
assert!(stdout.contains("--args"), "{stdout}");
assert!(stdout.contains("--sources PATH"), "{stdout}");
assert!(!stdout.contains("search_ast"), "{stdout}");
```

Covered instead, in the same file: `--tool` (13 tests), `--query-file`
(`query_file_runs_rql_from_the_current_workspace`), `--sources` (`tool_sources_*`, 5 tests), `--args`
(`tool_get_summaries_prints_structured_json_without_content`). Caveat worth honoring: the final
`!contains("search_ast")` line is the one assertion that touches generated output (the toolset→tool
listing *is* registry-generated), so if the reviewer wants belt-and-braces, fold that single line into
`removed_search_ast_tool_name_is_reported_as_unknown` rather than dropping it.

### tests/bifrost_policy_cli.rs — `policy_help_names_suppression_controls`

```rust
assert!(help.contains("--suppressions-file PATH"));
assert!(help.contains("--evaluation-date YYYY-MM-DD"));
assert!(help.contains("default: .bifrost/suppressions.json"));
```

Covered instead by `policy_suppressions_are_deterministic_auditable_and_threshold_aware_across_formats`,
which writes `.bifrost/suppressions.json`, proves it is loaded by default, then exercises
`--suppressions-file` and `--evaluation-date` across human/JSON/SARIF output plus expiry.

### tests/bifrost_reference_differential_cli.rs — `help_describes_repo_and_corpus_modes`

Spawns the binary three times to assert hand-written `println!` lines mention two subcommand names,
two flag names, and one prose fragment.

```rust
assert!(stdout.contains("run-repo"), "{stdout}");
assert!(stdout.contains("run-corpus"), "{stdout}");
assert!(repo_stdout.contains("--cache-mode"), "{repo_stdout}");
assert!(corpus_stdout.contains("workers per repository"), "{corpus_stdout}");
```

Covered instead: `corpus_dry_run_selects_largest_valid_clone_by_recorded_loc` and
`run_repo_writes_completed_jsonl_report_for_tiny_project` (subcommands),
`run_repo_ephemeral_cache_does_not_create_persisted_database` + `invalid_cache_mode_is_rejected`
(`--cache-mode`/`ephemeral`), `corpus_runs_distinct_repositories_concurrently_and_resumes_safely`
(`--repo-jobs`, asserting actual concurrency).

### tests/bifrost_benchmark_cli.rs — `compare_help_mentions_baseline_candidate_and_strict`, `run_help_mentions_max_files_subset_option`

```rust
assert!(stdout.contains("--baseline"), "{stdout}");
assert!(stdout.contains("--candidate"), "{stdout}");
assert!(stdout.contains("--strict"), "{stdout}");
```

Covered instead: `benchmark_compare.rs` exercises `--baseline`/`--candidate`/`--strict` semantics
(strict mode failing on regression); `bifrost_benchmark_run.rs` exercises `--max-files`. A second
auditor argued for keeping `run_help_mentions_max_files_subset_option` because it is the only pin
that the `BIFROST_BENCHMARK_QUERY_CODE_ACCESS` escape hatch stays documented; that string is also a
literal in the same clap attribute, so I still recommend removal, but this is the weakest of the five.
Keep `validate_subcommand_reports_checked_in_manifest_coverage` — it runs a real subcommand against
the checked-in manifest (though its `"validated 10 repos"` count is a snapshot pin worth loosening).

---

## Subsumed

### tests/get_definition_test.rs (675 tests) — `scala_object_apply_call_resolves_from_constructor_like_reference`

**Byte-for-byte identical** to `scala_object_apply_call_resolves_to_definition` in the same file —
verified by extracting both bodies and diffing (no output). Same two fixture files, same source
strings, same `column_of(line, "Factory")`, same assertions. The name promises a "constructor-like
reference" variant that the body never constructs.

```rust
assert_eq!(result["status"], "resolved", "{value}");
assert_eq!(result["definitions"][0]["fqn"], "app.Factory$.apply", "{value}");
```

The constructor-vs-apply distinction it claims is actually covered by
`scala_bare_calls_do_not_confuse_universal_construction_with_instance_apply_or_object` and
`scala_unqualified_member_call_beats_same_named_object_apply`.

### tests/get_definition_test.rs — `scala_service_execute_receiver_resolves_to_definition`

Differs from `scala_typed_receiver_method_resolves_to_definition` by exactly one consistent rename,
`run` → `execute` (verified by diff: six changed lines, all the same identifier). Same package, same
`class Service` / `class Controller { def handle(service: Service) … }` shape, same typed-receiver
path. Neither identifier is special to Scala or to the resolver.

```diff
- "package app\nclass Service { def run(): Int = 1 }\n",
+ "package app\nclass Service { def execute(): Int = 1 }\n",
- result["definitions"][0]["fqn"], "app.Service.run",
+ result["definitions"][0]["fqn"], "app.Service.execute",
```

Genuinely different receiver shapes are covered by
`scala_factory_returned_receiver_method_resolves_to_definition` and
`scala_companion_method_call_resolves_from_type_receiver`.

### tests/bifrost_lsp_server.rs (194 tests) — `bifrost_lsp_server_advertises_completion_when_client_supports_completion_items`

The whole test is: spawn, initialize with `completion_initialize_params`, assert
`completionProvider` is an object, shut down.

```rust
assert!(
    initialize["result"]["capabilities"]["completionProvider"].is_object(),
    "completionProvider should be advertised when the client exposes completion sub-capabilities: {initialize}"
);
```

`bifrost_lsp_server_completion_finds_symbol_by_prefix` initializes with the same helper, makes the
same assertion, and then drives a real completion request and checks the returned item label/kind
(both bodies read on disk). The complementary half of the contract — provider omitted when the client
advertises no completion sub-capabilities — lives in `bifrost_lsp_server_handles_initialize_and_shutdown`
and is unaffected. Removing this also deletes a full server-process spawn from the suite.

### tests/bifrost_lsp_server.rs — `bifrost_lsp_server_did_save_suppresses_python_semantic_diagnostics`

```rust
assert!(items.is_empty(), "expected no semantic lints: {publish}");
```

`bifrost_lsp_server_unrecognized_symbol_diagnostics_are_runtime_opt_in` uses the identical fixture
(`"def run():\n    missing_value\n"`), sends the identical `didSave`, asserts the same empty publish,
and then proves the enable/disable/re-enable transitions and the pull path — verified on disk. Save
handling itself is covered by `bifrost_lsp_server_did_save_triggers_reindex` and
`bifrost_lsp_server_did_save_publishes_diagnostics`.

Explicitly **not** candidates: the sibling `did_save_suppresses_{go,php,rust,js_ts}` tests. Those
languages have only pull-path coverage elsewhere, so their push assertions are unique.

### tests/cpp_analyzer_test.rs (39 tests) — `is_empty_test`

```rust
fn is_empty_test() {
    let analyzer = fixture_analyzer();
    assert!(!analyzer.is_empty());
}
```

`IAnalyzer::is_empty()` is `self.all_declarations().next().is_none()`, so this asserts only that the
shared C++ fixture corpus parsed at least one thing — the precondition every other test in the file
already depends on. `test_comprehensive_counts_specific_file_and_advanced_skeletons` and
`test_namespace_class_struct_and_global_analysis` name specific classes, functions and fields in the
same corpus.

### tests/cpp_analyzer_test.rs — `test_cpp_type_alias_and_stable_definition_ordering`

The "stable definition ordering" the name promises is never asserted, and both halves exist elsewhere.
The definitions half is a verbatim copy of the corresponding block in
`test_definition_vs_declaration_detection_and_stable_definitions`:

```rust
let defs = analyzer.get_definitions("overloadedFunction");
assert!(defs.len() >= 3);
let unique_signatures: BTreeSet<_> = defs.iter().filter_map(|cu| cu.signature()).collect();
assert!(!unique_signatures.is_empty());
assert!(unique_signatures.len() >= 2);
```

The alias half only checks that two `using X = Y;` aliases land in the `is_class()` set;
`cpp_template_alias_is_indexed_once_with_lexical_namespace_identity` proves far more about the same
construct (exactly-once indexing, `CodeUnitType::Class`, `package_name`, `is_type_alias`,
`!is_synthetic`, `fq_name`, `get_source`, `signature`).

### tests/bifrost_mcp_server.rs (26 tests) — `bifrost_core_server_can_hide_line_numbers_in_text_preview`

A line-for-line copy of `bifrost_searchtools_server_can_hide_line_numbers_in_text_preview` with
`"searchtools"` swapped for `"core"` — same fixture, same seven tool-name assertions, same
`Unknown tool` call, same five preview assertions — minus two schema assertions the searchtools
version additionally makes.

```rust
let mut child = spawn_server(&fixture_root, "core", &["--no-line-numbers"]);
...
assert!(names.contains(&"get_definitions_by_reference"), "{names:?}");
assert!(!names.contains(&"get_definitions_by_location"), "{names:?}");
```

The `--no-line-numbers` tool swap lives entirely in
`crate::mcp_core::symbol_tool_descriptors(render_options.render_line_numbers)`
(`src/mcp_registry.rs:180`), which both server modes reach through the same `symbol` toolset, so the
mode swap cannot change the outcome. Per-mode registry membership stays pinned by
`bifrost_split_servers_publish_expected_tool_sets` (advertised MCP surface — presumed keep).

### tests/cpp_type_hierarchy_test.rs (12 tests) — `cpp_type_hierarchy_resolves_single_inheritance`

One base class, one assertion on `get_direct_ancestors`. `base_class_clause` has N children, so any
breakage of the single-base walk necessarily breaks the two-base walk.

```rust
let child = definition(&analyzer, "Child");
assert_eq!(fq_names(analyzer.get_direct_ancestors(&child)), BTreeSet::from(["Base".to_string()]));
```

Covered by `cpp_type_hierarchy_resolves_multiple_inheritance` (same API, superset fixture) plus
`cpp_type_hierarchy_direct_descendants_are_not_transitive` for the reverse edge.

### tests/cpp_type_hierarchy_test.rs — `cpp_type_hierarchy_resolves_namespace_qualified_base`

Single-file `struct Child : api::Base`.
`cpp_type_hierarchy_resolves_relative_qualified_sibling_bases_and_aliases` is also single-file and
resolves relative-qualified, global-qualified (`::rc522::Base`) and aliased bases against *shadowing*
same-named namespaces — a strictly harder version of the same resolution.
`cpp_type_hierarchy_resolves_base_from_included_header` is this exact fixture split across an
`#include`, with the identical assertion.

```rust
assert_eq!(fq_names(analyzer.get_direct_ancestors(&child)), BTreeSet::from(["api.Base".to_string()]));
```

### tests/go_analyzer_test.rs (17 tests) — `test_determine_package_name_from_fixtures`

Calls the same pure `determine_package_name(&str)` on the same four input classes as
`test_determine_package_name_cases` (`package main` / named package / no package decl / empty), only
sourcing the strings from fixture files instead of literals. `read_to_string` adds no machinery to the
function under test, and the literal-input version covers strictly more (the comment-wrapped
`// comment\npackage main /* another comment */` case).

```rust
assert_eq!("main", analyzer.determine_package_name(
    &ProjectFile::new(root.clone(), "packages.go").read_to_string().unwrap()));
```

### tests/go_analyzer_update_test.rs — `explicit_update`

`go_analyzer_parity.rs::go_module_helpers_and_updates_match_expected_behavior` contains this test
verbatim as its second half (same `a.go` fixture, same `main.Foo`/`main.Bar`, same
`analyzer.update(&BTreeSet::from([file.clone()]))`) and then continues with the delete + `update_all`
leg. Diffed line by line against the current tree.

```rust
assert!(!analyzer.get_definitions("main.Foo").is_empty());
assert!(analyzer.get_definitions("main.Bar").is_empty());
let updated = analyzer.update(&BTreeSet::from([file.clone()]));
assert!(!updated.get_definitions("main.Bar").is_empty());
```

Keep `auto_detect`: the parity twin only calls `update_all` after a deletion, so "`update_all` picks
up a modified file's new declaration" is unique there.

### tests/java_analyzer_smoke.rs — `parses_fixture_declarations`

Three `is_empty()` smoke assertions over `tests/fixtures/testcode-java`:

```rust
assert!(!analyzer.get_definitions("A").is_empty());
assert!(!analyzer.get_definitions("A.method1").is_empty());
```

`java_declarations_parity.rs::lists_all_fixture_classes` builds the same analyzer over the same
fixture and asserts the exact set of 35 class FQNs (including `A`);
`nested_class_identifiers_match_java_expectations` pins dotted member FQNs; and
`packaged_file_declarations_include_module_and_members` pins the exact ordered declaration list for a
fixture file. Any failure here fails those first, with better messages.

Keep `updates_changed_file_snapshot` — the only test asserting the pre-update analyzer stays
unchanged.

---

## Cannot-fail

### tests/issue_693_profile.rs — `profile_lgtm_large_rust_definition_and_hover`

Zero assertions in the entire body: it spawns a server, issues four LSP requests, and `eprintln!`s
timings. It is `#[ignore]`d behind `BIFROST_ISSUE_693_ROOT`, which must point at an external PR
checkout, so it never runs — and could not fail if it did.

```rust
eprintln!(
    "issue693 method={method} line={line} character={character} elapsed_ms={:.1} result={}",
    started.elapsed().as_secs_f64() * 1000.0,
    response["result"]
);
```

The #693 regression is pinned by `large_rust_file_definition_and_hover_stay_interactive` in the same
file, which builds a 600-method fixture and asserts both the resolved definition location and a
5-second latency bound. This is the only `issue_*` test recommended for removal, and only because it
is a manual profiling harness rather than a regression pin.

---

## Line-level cuts (keep the test, delete the block)

### tests/code_query_tutorials.rs — two lines inside `tutorials_cover_all_public_kinds_roles_and_pages`

```rust
assert!(seen_pages.insert(*page), "duplicate tutorial page {page}");
...
assert_eq!(seen_pages, PAGES.iter().copied().collect());
```

`seen_pages` is populated by inserting every element of the `const PAGES` literal in the loop directly
above. `PAGES` is a list of distinct string literals, so `insert` always returns `true` and the final
set equals `PAGES` by construction. Neither line can fail while the file compiles. The rest of the
test (kind/role coverage against `ALL_KINDS`, `semantic_steps` completeness, date validation) is
load-bearing and must stay — as must the whole executable-tutorial mechanism, which really does run
every documented query and diff it against the documented output.

### tests/bifrost_benchmark_run.rs — 13 lines inside `run_subcommand_executes_all_configured_scenarios_on_local_repo`

Thirteen `assert!(names.contains(&"…"))` lines mirroring the `scenarios = [...]` list the same test
just wrote into its own manifest. Delete the block, not the test: the 17-scenario count, the
per-scenario success assertions, and the query_code cold/warm cache assertions are all strong.

---

## Borderline — considered, kept

- `tests/issue_1121_cpp_nested_class_out_of_line.rs::namespace_block_nested_member_unifies_declaration_and_definition` — an exact subset of the first loop iteration of `every_display_spelling_of_the_nested_member_resolves_to_the_same_pair` two functions below (same fixture, same `"log4cxx.Outer$Inner.method"`, same four assertions). Genuinely subsumed, but it is a regression pin inside an `issue_*` file and subsumption is not tautology, so it stays under the presumed-keep rule. Flagged for the owner's call.
- `tests/issue_1093_cpp_using_namespace_owner.rs::nested_class_two_segment_owner_unifies_in_namespace_block` — duplicates both of issue_1121's tests with identical assertions on renamed fixtures; kept for the same reason.
- `tests/benchmark_workflow_policy.rs::benchmark_workflow_enforces_actionable_regressions_by_default` and `issue_1228_workflow_enforces_release_interactive_latency_with_profiles` — grep-the-checked-in-YAML snapshots, brittle by construction, but they pin a real supply-chain policy (webhook secret must never enter the job env; `workflow_dispatch` inputs must be shell-quoted through env vars rather than interpolated) that nothing else reads. Worth narrowing to the injection/secret assertions rather than deleting.
- `tests/java_declarations_parity.rs::lists_all_fixture_classes` — a hardcoded 35-name list that any fixture edit breaks, but exhaustive membership *is* the over/under-declaration contract for the Java extractor.
- `tests/analyzer_capability_parity.rs::multi_analyzer_matches_brokk_capability_matrix` — ~45 lines of delegate construction for two `is_some()` calls, but it is the only check that `MultiAnalyzer` aggregates capabilities rather than returning `None`. Its sibling `direct_analyzers_match_brokk_capability_matrix` is a real matrix with a negative control (`php.import_analysis_provider().is_none()`).
- `tests/bifrost_tool_cli.rs::query_code_help_includes_boundary_example_and_guide` — looks like the `--help` genus, but `bifrost --help query_code` renders the MCP tool description from `src/mcp_extended.rs`; the only test proving help wires through to the registry.
- `tests/bifrost_policy_cli.rs::built_in_pack_and_category_selectors_run_valid_batches` — the hardcoded 12-id ordered list is an implementation mirror duplicated by `tests/builtin_policy_pack.rs`, but the test uniquely covers `--policy-pack`/`--policy-category` CLI wiring. Better fixed by deriving the list from the manifest than by deleting.
- `tests/bifrost_policy_cli.rs::production_summary_repeated_policy_measurement` — `#[ignore]`d and its assertions are a subset of `repeated_typestate_policies_share_production_summaries_with_explicit_counters`; kept because it is an intentional timing-evidence emitter with a documented ignore reason, unlike the assertion-free #693 profiler.
- `tests/benchmark_manifest.rs` `warmup_iterations == 2` / `measured_iterations == 10` / `repos.len() == 10` — pure snapshot pins on tunables, but the surrounding language/scenario/workload coverage assertions in the same tests are real.
- `tests/code_query_docs.rs::current_public_query_surfaces_use_the_new_name` and `query_documentation_tracks_public_contracts` — stale-name lint over a hardcoded path list, and doc-prose pinning (`"twelve possible classes"`); drift is "fixed" by editing the doc, which is the intended forcing function for schema-version sync.
- `tests/cpp_test_assertion_smells.rs` Catch2 `TEST_CASE` / Catch2 `SCENARIO` / Boost / MSTest quartet, and `tests/cpp_dead_code_smells.rs` "stays_on_precise_path" quartet — near-identical bodies, but each pins a distinct entry in the framework-marker table or a distinct `TargetKind` match arm.
- `tests/cpp_structural_clone_smells.rs` / `tests/csharp_structural_clone_smells.rs`, and the `*_dead_code_smells.rs` family — I specifically hunted for one shared detector re-tested per language; they route through genuinely different analyzers and match arms, with real negative controls (threshold suppression, AST refinement).
- `tests/bifrost_lsp_server.rs` `semantic_tokens_advertises_stable_full_legend` (the legend *is* the wire contract clients decode token indices against), the eight `type_definition_returns_null_for_*` per-language negative controls, the nine `type_hierarchy_*_uses_same_handler` conformance rows, `lsp_server_drop_reaps_child_process` (a real zombie-leak detector via `waitpid`→`ECHILD`).
- `tests/get_definition_test.rs` near-duplicate pairs surfaced by a bijective-rename detector: `type_lookup_rejects_oversized_batches`/`definition_lookup_rejects_oversized_batches` (different endpoints, each with its own batch limit), `ruby_..._bare_method_call`/`..._send_without_symbol_dispatch` (`send` is the dynamic-dispatch keyword), the three `cpp_macro_decorated_multi_declarator_*` tests (`first, second` vs `*first, second` vs `first, *second`), `python_staticmethod_*`/`python_classmethod_*` (different first-parameter semantics).
- `tests/analyzer_persistence.rs` (52), `tests/dataflow_summaries.rs` (28), `tests/dataflow_ide.rs` (20), `tests/icfg_contract.rs` (21), `tests/code_query_pipelines.rs` (115) — swept in full, **zero** candidates. The dataflow/ICFG files are reference-oracle suites comparing against `reference_ide_projection`/`reference_summary_projection`; `analyzer_persistence.rs` is entirely counter pins, issue-numbered regressions and negative controls.
- `tests/binary_file_handling.rs` — only two assertions and one is about its own fixture, but nothing else proves a binary file with a supported extension is skipped.
- `tests/filesystem_project_gitignore.rs::filesystem_project_works_outside_git_repo` — an assertion subset of the first test, kept because "no `.git` directory" is a distinct discovery path.

## Confidence notes

- Every recommendation was verified in the current tree: the two `get_definition_test.rs` duplicates by extracting and `diff`ing the bodies; the alias tautologies by grepping all `impl IAnalyzer` blocks for overrides; the `--help` genus by reading `print_general_help`/`print_help` in `src/bin/`; the Go and LSP subsumptions by reading both bodies side by side.
- The tree moved under the audit (`25978616` → `d1b07897`; `get_definition_test.rs` grew by ~1,200 lines, `bifrost_policy_cli.rs` by ~550, `code_query_typestate.rs` by ~140). Re-verify by test name, not line number.
- Weakest recommendation: `run_help_mentions_max_files_subset_option` (a second auditor would keep it for the `BIFROST_BENCHMARK_QUERY_CODE_ACCESS` mention).
- Strongest by a distance: the byte-identical Scala pair in `get_definition_test.rs`.
- The dominant finding of this slice is how little there is to cut — 1.2%. The suite is overwhelmingly behavior-focused: no `is_ok()`-only bodies anywhere in 97 files, no `format!("{:?}")` snapshot assertions, and the registry-name lists that do exist sit on the advertised MCP/LSP surface, where membership is the contract.
