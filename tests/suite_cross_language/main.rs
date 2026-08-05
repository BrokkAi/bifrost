//! Consolidated `suite_cross_language` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_cross_language -- <module>::

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/value_flow_conformance.rs"]
pub mod value_flow_conformance;
#[path = "../common/value_flow_scenarios.rs"]
pub mod value_flow_scenarios;

mod code_query_cpp_receiver;
mod code_query_docs;
mod code_query_edge_conformance;
mod code_query_lexical_environment;
mod code_query_occurrences;
mod code_query_pipelines;
mod code_query_public_api;
mod code_query_reference_edges;
mod code_query_resolution_conformance;
mod code_query_tutorials;
mod code_query_typestate;
mod code_query_typestate_context;
mod code_query_value_flow;
mod cross_language_attribute_target_declarations;
mod cross_language_import_hits;
mod cross_language_receiver_definition;
mod cross_language_return_type_definition;
mod cross_language_self_usages;
mod structural_search_cross_language;
mod structural_search_planner;
mod structural_search_python;
