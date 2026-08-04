# Integration-test harness consolidation (2026-07)

Each `tests/*.rs` file used to be its own test binary, statically linking the whole
library. At ~290 files and ~300-430 MB per binary that is ~85 GB of link output and
~290 full LLD links per test run. The files below were grouped into a small number of
`tests/<suite>/main.rs` harnesses; each harness links the library **once** and declares
the former files as modules, so every test keeps its name under a module prefix.

## Running tests after the change

```
cargo test --test <suite>                        # whole harness
cargo test --test <suite> -- <module>::          # one former file
cargo test --test <suite> -- <module>::<test>    # one test
cargo test --test <suite> -- <mod_a>:: <mod_b>:: # several (libtest ORs filters)
```

## Test-count accounting

`tests/common/lsp_click.rs` contains 4 `#[test]` functions. Because 211 of the old
binaries each did `mod common;`, those 4 tests were compiled and executed **once per
binary**. A harness includes `common` once, so each harness runs them once. The
expected count change for a group is therefore exactly:

    after = before - 4 * (files_in_group_that_include_common - 1)

No test is lost; the delta is redundant re-execution of the same 4 helper tests.

## Groups

### `suite_analyzers` (82 modules)

- `cpp_analyzer_test`
- `cpp_macro_call_arity`
- `cpp_macro_sentinel_recovery_test`
- `cpp_type_hierarchy_test`
- `csharp_analyzer_test`
- `csharp_analyzer_update_test`
- `csharp_test_detection_test`
- `go_analyzer_parity`
- `go_analyzer_test`
- `go_analyzer_update_test`
- `go_canonical_fqn_test`
- `go_import_test`
- `go_test_detection_test`
- `go_type_hierarchy_test`
- `java_analyzer_smoke`
- `java_comment_source`
- `java_declarations_parity`
- `java_field_parity`
- `java_fixture_parity`
- `java_fixture_provenance`
- `java_import_detail_parity`
- `java_imports_and_hierarchy`
- `java_lambda_parity`
- `java_modules_and_constructors`
- `java_parallel_and_cache`
- `java_parity_edges`
- `java_scope_analysis`
- `java_search_parity`
- `java_signature_normalization`
- `java_source_and_skeleton`
- `java_test_detection_test`
- `java_update_parity`
- `java_update_regressions`
- `javascript_analyzer_test`
- `javascript_arrow_function_test`
- `javascript_import_test`
- `jvm_shared_realm`
- `kotlin_analyzer_test`
- `kotlin_imports_and_hierarchy`
- `nlp_voyage_parity`
- `php_analyzer_test`
- `php_analyzer_update_test`
- `php_test_detection_test`
- `php_type_hierarchy_test`
- `project_change_watcher_test`
- `python_analyzer_test`
- `python_analyzer_update_test`
- `python_could_import_test`
- `python_decorators_test`
- `python_module_analyzer_test`
- `python_test_detection_test`
- `python_type_hierarchy_test`
- `ruby_analyzer_test`
- `ruby_import_test`
- `ruby_test_detection_test`
- `ruby_type_hierarchy_test`
- `rust_analyzer_parity`
- `rust_analyzer_test`
- `rust_analyzer_update_test`
- `rust_associated_type_usage_test`
- `rust_final_residual_regression_test`
- `rust_import_test`
- `rust_macro_item_indexing_test`
- `rust_macro_path_usage_test`
- `rust_reexport_regression_test`
- `rust_test_detection_test`
- `rust_type_hierarchy_test`
- `scala_analyzer_test`
- `scala_definition_precedence_test`
- `scala_definition_scope_residual_test`
- `scala_extension_soft_keyword_test`
- `scala_import_test`
- `scala_ordered_wildcard_imports_test`
- `scala_parameterized_enum_case_test`
- `scala_skeleton_test`
- `scala_source_code_test`
- `scala_test_detection_test`
- `scala_type_hierarchy_test`
- `typescript_alias_test`
- `typescript_analyzer_test`
- `typescript_analyzer_update_test`
- `typescript_import_test`

### `suite_bench_policy` (27 modules)

- `benchmark_compare`
- `benchmark_manifest`
- `benchmark_repo_cache`
- `benchmark_workflow_policy`
- `bifrost_policy_cli`
- `builtin_policy_pack`
- `cvss_classification`
- `measure_semantic_summary_taint_lifecycle`
- `no_stringly_name_parsing`
- `policy_assertion_conformance`
- `policy_assertion_evaluation`
- `policy_docs`
- `policy_loading`
- `policy_loading_workspace`
- `policy_loop_invariance_prototype`
- `policy_match_evaluation`
- `policy_rendering`
- `policy_resolution_assertions`
- `policy_resolution_conformance`
- `policy_sarif_rendering`
- `policy_scope_evaluation`
- `policy_source`
- `policy_suppression_evaluation`
- `policy_suppression_loading`
- `scan_usages_same_owner_policy`
- `taint_policy_adapter`
- `temp_storage_scripts`

### `suite_cross_language` (19 modules)

- `code_query_cpp_receiver`
- `code_query_docs`
- `code_query_lexical_environment`
- `code_query_occurrences`
- `code_query_pipelines`
- `code_query_public_api`
- `code_query_resolution_conformance`
- `code_query_tutorials`
- `code_query_typestate`
- `code_query_typestate_context`
- `code_query_value_flow`
- `cross_language_attribute_target_declarations`
- `cross_language_import_hits`
- `cross_language_receiver_definition`
- `cross_language_return_type_definition`
- `cross_language_self_usages`
- `structural_search_cross_language`
- `structural_search_planner`
- `structural_search_python`

### `suite_issues` (19 modules)

- `issue_1089_crate_name_directory_mapping`
- `issue_1092_cpp_header_source_identity`
- `issue_1093_cpp_using_namespace_owner`
- `issue_1120_cpp_bare_call_lexical_scope`
- `issue_1121_cpp_nested_class_out_of_line`
- `issue_1126_import_boundary_claims`
- `issue_1128_rust_raw_identifiers`
- `issue_1142_rust_inline_mod_items`
- `issue_1158_boundary_claim_gate`
- `issue_1162_separator_aware_enclosing_scope`
- `issue_1174_python_cross_language_claims`
- `issue_1184_cpp_file_local_globals`
- `issue_1185_cpp_member_calls`
- `issue_1198_hash_anchor_selectors`
- `issue_1218_boundary_candidate_honesty`
- `issue_1225_python_annotation_inverse`
- `issue_1325_csharp_census_complexity, issue_1332_search_notes_honesty`
- `issue_693_profile`
- `issue_csharp_verbatim_identifiers`

### `suite_lsp_parity` (21 modules)

- `basedpyright_goto_definition`
- `clangd_find_references`
- `clangd_goto_definition`
- `gopls_find_references`
- `gopls_goto_definition`
- `intellij_java_definition`
- `intellij_java_find_usages`
- `intellij_python_definition`
- `intellij_python_find_usages`
- `intellij_scala_goto_definition`
- `jdt_goto_definition`
- `metals_find_references`
- `metals_goto_definition`
- `phpactor_find_references`
- `phpactor_goto_definition`
- `roslyn_find_references`
- `roslyn_goto_definition`
- `ruby_lsp_find_references`
- `ruby_lsp_goto_definition`
- `rust_analyzer_find_references`
- `rust_analyzer_goto_definition`

### `suite_mcp_cli` (13 modules)

- `bifrost_benchmark_cli`
- `bifrost_benchmark_run`
- `bifrost_lsp_server`
- `bifrost_mcp_property_fuzzer_cli`
- `bifrost_mcp_server`
- `bifrost_reference_differential_cli`
- `bifrost_skill_install_cli`
- `bifrost_tool_cli`
- `binary_file_handling`
- `code_intelligence_runtime`
- `filesystem_project_gitignore`
- `lsp_click_around_regression`
- `lsp_parameter_definition`

### `suite_persistence` (15 modules)

- `analyzer_capability_parity`
- `analyzer_query_parity`
- `analyzer_sql_query_parity`
- `analyzer_store_reconcile`
- `model_handle_semantics`
- `multi_analyzer_capability_test`
- `multi_analyzer_get_test_modules_test`
- `multi_analyzer_import_test`
- `multi_analyzer_routing`
- `multi_analyzer_test`
- `parse_errors_cache`
- `semantic_pack_catalog`
- `structural_facts_persistence`
- `unified_cache`
- `workspace_analyzer_test`

### `suite_semantic` (45 modules)

- `dataflow_clients`
- `dataflow_ide`
- `dataflow_summaries`
- `dataflow_tabulation`
- `icfg_contract`
- `measure_analyzer_persisted_memory`
- `measure_dataflow_lifecycle`
- `measure_file_dependency_graph`
- `measure_go_usage_graph_memory`
- `measure_hierarchy_relations`
- `measure_jsts_scan_usages_baseline`
- `measure_jsts_usage_graph_memory`
- `measure_python_usage_graph_memory`
- `measure_semantic_cfg`
- `measure_semantic_cfg_persistence`
- `measure_semantic_pack_catalog`
- `measure_semantic_oracles`
- `measure_structural_facts_memory`
- `measure_structural_facts_persistence`
- `measure_summary_lifecycle`
- `measure_usage_relevance_graph`
- `reference_differential`
- `reference_differential_backlog_test`
- `ruby_semantic_diagnostics`
- `scala_semantic_diagnostics`
- `semantic_cfg_contract`
- `semantic_ir_contract`
- `semantic_language_conformance`
- `semantic_model_docs`
- `semantic_model_pack`
- `semantic_oracle_contract`
- `semantic_provider_contract`
- `semantic_search`
- `semantic_value_cpp_contract`
- `semantic_value_language_contract`
- `semantic_value_php_contract`
- `semantic_value_python_contract`
- `semantic_value_ruby_contract`
- `semantic_value_scala_contract`
- `taint_client`
- `typestate_binding`
- `typestate_client`
- `typestate_production_summary`
- `typestate_protocol`
- `value_flow_client`
- `value_flow_language_conformance`

### `suite_smells` (23 modules)

- `cpp_dead_code_smells`
- `cpp_structural_clone_smells`
- `cpp_test_assertion_smells`
- `csharp_dead_code_smells`
- `csharp_go_rust_test_assertion_smells`
- `csharp_structural_clone_smells`
- `go_dead_code_smells`
- `java_comment_density`
- `java_dead_code_smells`
- `java_structural_clone_smells`
- `java_test_assertion_smells`
- `js_ts_structural_clone_smells`
- `js_ts_test_assertion_smells`
- `php_dead_code_smells`
- `php_structural_clone_smells`
- `python_js_ts_dead_code_smells`
- `python_structural_clone_smells`
- `python_test_assertion_smells`
- `ruby_dead_code_smells`
- `rust_dead_code_smells`
- `scala_dead_code_smells`
- `scala_php_test_assertion_smells`
- `scala_structural_clone_smells`

### `suite_symbols` (10 modules)

- `classify_test_files_test`
- `diff_analysis_test`
- `get_definition_test`
- `most_relevant_files`
- `reusable_summaries`
- `searchtools_definition_selectors`
- `searchtools_fuzzy_symbol_lookup`
- `searchtools_list_symbols`
- `searchtools_service`
- `searchtools_summary_ranges`

### `suite_usages` (32 modules)

- `csharp_bounded_receiver_hardening`
- `go_rust_bounded_receiver_acceptance`
- `receiver_language_acceptance_matrix`
- `receiver_language_scope`
- `receiver_language_uncertainty`
- `scala_bounded_receiver_hardening`
- `usage_graph_cpp_test`
- `usage_graph_csharp_test`
- `usage_graph_go_test`
- `usage_graph_identity_test`
- `usage_graph_java_test`
- `usage_graph_php_test`
- `usage_graph_python_test`
- `usage_graph_ruby_test`
- `usage_graph_rust_test`
- `usage_graph_scala_test`
- `usage_graph_test`
- `usage_graph_ts_test`
- `usages_cpp_graph_test`
- `usages_csharp_graph_test`
- `usages_finder_fallback_test`
- `usages_go_graph_test`
- `usages_java_graph_test`
- `usages_js_ts_graph_test`
- `usages_js_ts_path_alias_test`
- `usages_local_inference_test`
- `usages_php_graph_test`
- `usages_python_graph_test`
- `usages_python_test`
- `usages_ruby_test`
- `usages_rust_graph_test`
- `usages_scala_graph_test`

## Kept as standalone binaries

Process isolation is load-bearing for these; they were deliberately not merged.

- **`analyzer_persistence`** - **found by audit, not on the original list**: `disable_opportunistic_gc_for_test` calls `set_min_interval_secs_for_test(i64::MAX)` and `std::mem::forget`s the returned guard, holding the process-global GC tuning mutex for the life of the process. Its own header comment states the safety argument as "nothing else *in this binary* calls `set_tuning_for_test`". `analyzer_store_reconcile` and `unified_cache` both call it, so grouping them (as the original design proposed) would have deadlocked.
- **`issue_1175_scan_usages_reparse`** - asserts on process-global scan counters via `reset_*_for_test` hooks; merging exposes the counters to other modules' analyzer work.
- **`issue_1194_csharp_scan_complexity`** - same process-global scan-counter pattern.
- **`issue_1219_location_scan_target`** - asserts the process-global Rust tree-parse counters (`RUST_TREE_PARSES`/`RUST_TREE_PARSE_REQUESTS`/`RUST_TREE_PARSED_BYTES` statics in `src/analyzer/rust/lexical_scope.rs`), which any other Rust-parsing module in the same binary would perturb.
- `issue_1325_csharp_census_complexity` was briefly kept standalone here for its process-global walk counter; the counter was then converted to a per-project-instance field (`Project::workspace_file_listing_count`, the #1099 per-instance-counter lesson), which removed the interference class entirely, and the module now lives in `suite_issues`.
- **`jsts_usage_graph_deadlock`** - **found by merging, not by inspection**: passes standalone (12.3s) but FAILS inside `suite_usages` alongside the other 1,321 tests. It is the regression pin for the JS/TS OnceLock+rayon pool deadlock (`.agents/plans/jsts-usage-graph-oncelock-rayon-deadlock.md`) and depends on a pristine global rayon pool, so concurrent analyzer work in the same process perturbs it. Pulled back out and left standalone rather than debugged, per the migration brief.
- **`mcp_property_fuzzer`** - fuzzer harness driven specially by its own runner.
- **`mcp_property_fuzzer_service`** - fuzzer harness driven specially by its own runner.
- **`nlp_semantic_search_models`** - **found by audit**: opt-in real-model suite. CLAUDE.md/AGENTS.md document `BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored`; keeping it standalone preserves that documented invocation and keeps model-downloading code out of a shared harness.
- **`scala_descendant_index_bench`** - `#[ignore]`d #908 measurement harness with process-global descendant-index counters; it is an instrument, not a regression pin.
