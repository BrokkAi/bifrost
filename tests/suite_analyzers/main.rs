//! Consolidated `suite_analyzers` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_analyzers -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod cpp_analyzer_test;
mod cpp_callable_activation_visibility;
mod cpp_macro_call_arity;
mod cpp_macro_sentinel_recovery_test;
mod cpp_type_hierarchy_test;
mod csharp_analyzer_test;
mod csharp_analyzer_update_test;
mod csharp_constructor_name_invariant;
mod csharp_import_reachability;
mod csharp_namespace_of_file;
mod csharp_test_detection_test;
mod go_analyzer_parity;
mod go_analyzer_test;
mod go_analyzer_update_test;
mod go_canonical_fqn_test;
mod go_import_test;
mod go_test_detection_test;
mod go_type_hierarchy_test;
mod java_analyzer_smoke;
mod java_comment_source;
mod java_declarations_parity;
mod java_field_parity;
mod java_fixture_parity;
mod java_fixture_provenance;
mod java_import_detail_parity;
mod java_imports_and_hierarchy;
mod java_lambda_parity;
mod java_modules_and_constructors;
mod java_parallel_and_cache;
mod java_parity_edges;
mod java_scope_analysis;
mod java_search_parity;
mod java_signature_normalization;
mod java_source_and_skeleton;
mod java_test_detection_test;
mod java_update_parity;
mod java_update_regressions;
mod javascript_analyzer_test;
mod javascript_arrow_function_test;
mod javascript_import_test;
mod jvm_shared_realm;
mod kotlin_analyzer_test;
mod kotlin_imports_and_hierarchy;
mod kotlin_test_detection_test;
#[cfg(feature = "nlp")]
mod nlp_voyage_parity;
mod php_analyzer_test;
mod php_analyzer_update_test;
mod php_test_detection_test;
mod php_type_hierarchy_test;
mod project_change_watcher_test;
mod python_analyzer_test;
mod python_analyzer_update_test;
mod python_could_import_test;
mod python_decorators_test;
mod python_module_analyzer_test;
mod python_test_detection_test;
mod python_type_hierarchy_test;
mod ruby_analyzer_test;
mod ruby_import_test;
mod ruby_test_detection_test;
mod ruby_type_hierarchy_test;
mod rust_analyzer_parity;
mod rust_analyzer_test;
mod rust_analyzer_update_test;
mod rust_associated_type_usage_test;
mod rust_final_residual_regression_test;
mod rust_import_test;
mod rust_macro_item_indexing_test;
mod rust_macro_path_usage_test;
mod rust_reexport_regression_test;
mod rust_test_detection_test;
mod rust_type_hierarchy_test;
mod scala_analyzer_test;
mod scala_definition_precedence_test;
mod scala_definition_scope_residual_test;
mod scala_extension_soft_keyword_test;
mod scala_import_test;
mod scala_ordered_wildcard_imports_test;
mod scala_parameterized_enum_case_test;
mod scala_skeleton_test;
mod scala_source_code_test;
mod scala_test_detection_test;
mod scala_type_hierarchy_test;
mod typescript_alias_test;
mod typescript_analyzer_test;
mod typescript_analyzer_update_test;
mod typescript_import_test;
