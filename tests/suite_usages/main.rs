//! Consolidated `suite_usages` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_usages -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod csharp_bounded_receiver_hardening;
mod go_rust_bounded_receiver_acceptance;
mod issue_1416_scan_name_gate;
mod issue_1450_cross_request_prepared_syntax;
mod issue_1451_cross_request_import_infos;
mod issue_1748_candidate_discovery_batching;
mod random_alias_recovery_test;
mod receiver_language_acceptance_matrix;
mod receiver_language_scope;
mod receiver_language_uncertainty;
mod scala_bounded_receiver_hardening;
mod usage_graph_cpp_test;
mod usage_graph_csharp_test;
mod usage_graph_go_test;
mod usage_graph_identity_test;
mod usage_graph_java_test;
mod usage_graph_kotlin_test;
mod usage_graph_php_test;
mod usage_graph_python_test;
mod usage_graph_ruby_test;
mod usage_graph_rust_test;
mod usage_graph_scala_test;
mod usage_graph_test;
mod usage_graph_ts_test;
mod usages_cpp_graph_test;
mod usages_cpp_macro_return_test;
mod usages_cpp_macro_sentinel_owner_test;
mod usages_cpp_macro_sentinel_receiver_test;
mod usages_cpp_macro_sibling_class_test;
mod usages_cpp_recursive_free_function_test;
mod usages_cpp_sentinel_visibility_test;
mod usages_csharp_graph_test;
mod usages_finder_fallback_test;
mod usages_go_graph_test;
mod usages_java_graph_test;
mod usages_js_ts_graph_test;
mod usages_js_ts_path_alias_test;
mod usages_kotlin_graph_test;
mod usages_local_inference_test;
mod usages_php_graph_test;
mod usages_python_graph_test;
mod usages_python_test;
mod usages_ruby_test;
mod usages_rust_graph_test;
mod usages_scala_graph_test;
