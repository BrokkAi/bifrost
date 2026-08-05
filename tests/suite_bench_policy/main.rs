//! Consolidated `suite_bench_policy` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_bench_policy -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod benchmark_compare;
mod benchmark_manifest;
mod benchmark_repo_cache;
mod benchmark_workflow_policy;
mod bifrost_policy_cli;
mod builtin_policy_pack;
mod cvss_classification;
mod measure_semantic_summary_taint_lifecycle;
mod no_stringly_name_parsing;
mod policy_assertion_conformance;
mod policy_assertion_evaluation;
mod policy_docs;
mod policy_edge_parity_assertions;
mod policy_loading;
mod policy_loading_workspace;
mod policy_loop_invariance_prototype;
mod policy_match_evaluation;
mod policy_rendering;
mod policy_resolution_assertions;
mod policy_resolution_conformance;
mod policy_sarif_rendering;
mod policy_scope_evaluation;
mod policy_source;
mod policy_suppression_evaluation;
mod policy_suppression_loading;
mod scan_usages_same_owner_policy;
mod taint_policy_adapter;
#[cfg(unix)]
mod temp_storage_scripts;
