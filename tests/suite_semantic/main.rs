//! Consolidated `suite_semantic` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_semantic -- <module>::

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/value_flow_conformance.rs"]
pub mod value_flow_conformance;
#[path = "../common/value_flow_scenarios.rs"]
pub mod value_flow_scenarios;

// Shared support modules, loaded once for the whole harness: several member
// modules used to `#[path]`-include these privately, which loads the same file
// multiple times in one crate (clippy::duplicate_mod).
#[path = "../common/dataflow_fixtures.rs"]
mod dataflow_fixtures;
#[path = "../common/memory_benchmark.rs"]
mod memory_benchmark;

mod dataflow_clients;
mod dataflow_ide;
mod dataflow_summaries;
mod dataflow_tabulation;
mod dependency_pack_lifecycle;
mod dependency_semantic_pack;
mod external_artifact_pack;
mod generated_behavior_models;
mod go_semantic_diagnostics;
mod icfg_contract;
mod java_semantic_diagnostics;
mod js_ts_dependency_semantic_pack;
mod jvm_diagnostic_proof;
mod jvm_standard_library_pack;
mod kotlin_dependency_semantic_pack;
mod kotlin_semantic_diagnostics;
mod measure_analyzer_persisted_memory;
mod measure_dataflow_lifecycle;
mod measure_file_dependency_graph;
mod measure_go_usage_graph_memory;
mod measure_hierarchy_relations;
mod measure_jsts_scan_usages_baseline;
mod measure_jsts_usage_graph_memory;
mod measure_python_usage_graph_memory;
mod measure_semantic_cfg;
mod measure_semantic_cfg_persistence;
mod measure_semantic_oracles;
mod measure_semantic_pack_catalog;
mod measure_structural_facts_memory;
mod measure_structural_facts_persistence;
mod measure_summary_lifecycle;
mod measure_usage_relevance_graph;
mod php_composer_dependency_pack;
mod php_semantic_diagnostics;
mod python_dependency_pack;
mod python_semantic_diagnostics;
mod reference_differential;
mod reference_differential_backlog_test;
mod ruby_dependency_semantic_pack;
mod ruby_semantic_diagnostics;
mod rust_dependency_semantic_pack;
mod rust_semantic_diagnostics;
mod scala_semantic_diagnostics;
mod semantic_cfg_contract;
mod semantic_diagnostic_proof_conformance;
mod semantic_ir_contract;
mod semantic_language_conformance;
mod semantic_model_authoring;
mod semantic_model_conformance;
mod semantic_model_docs;
mod semantic_model_overlay;
mod semantic_model_pack;
mod semantic_model_runtime;
mod semantic_model_summary_binding;
mod semantic_oracle_contract;
mod semantic_provider_contract;
#[cfg(feature = "nlp")]
mod semantic_search;
mod semantic_value_cpp_contract;
mod semantic_value_kotlin_contract;
mod semantic_value_language_contract;
mod semantic_value_php_contract;
mod semantic_value_python_contract;
mod semantic_value_ruby_contract;
mod semantic_value_scala_contract;
mod taint_client;
mod typestate_binding;
mod typestate_client;
mod typestate_production_summary;
mod typestate_protocol;
mod value_flow_client;
mod value_flow_language_conformance;
