//! Consolidated `suite_issues` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_issues -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod issue_1089_crate_name_directory_mapping;
mod issue_1092_cpp_header_source_identity;
mod issue_1093_cpp_using_namespace_owner;
mod issue_1120_cpp_bare_call_lexical_scope;
mod issue_1121_cpp_nested_class_out_of_line;
mod issue_1126_import_boundary_claims;
mod issue_1128_rust_raw_identifiers;
mod issue_1142_rust_inline_mod_items;
mod issue_1158_boundary_claim_gate;
mod issue_1162_separator_aware_enclosing_scope;
mod issue_1174_python_cross_language_claims;
mod issue_1184_cpp_file_local_globals;
mod issue_1185_cpp_member_calls;
mod issue_1198_hash_anchor_selectors;
mod issue_1218_boundary_candidate_honesty;
mod issue_1225_python_annotation_inverse;
mod issue_1230_rust_scan_complexity;
mod issue_1231_bare_identifier_scan_targets;
mod issue_1325_csharp_census_complexity;
mod issue_1332_search_notes_honesty;
mod issue_1333_small_repo_cache_warmth;
mod issue_1334_resolver_walk_memo;
mod issue_1341_rust_submodule_fn_exports;
mod issue_1342_rust_module_declaration_files;
mod issue_1347_rust_alias_cycle;
mod issue_1546_rust_cfg_test_module_files;
mod issue_1786_flow_dialect_degradation;
mod issue_1811_c_single_candidate_unproven_arity;
mod issue_1812_c_no_candidate_macro_fallback;
mod issue_1824_cpp_complete_guard_family_callable;
mod issue_1825_cpp_macro_namespace_callable;
mod issue_1826_cpp_member_unproven_arity;
mod issue_1827_cpp_signature_identity;
mod issue_1828_cpp_unresolvable_alias_target;
mod issue_1832_cpp_out_of_line_owner_binding;
mod issue_1833_cpp_template_derived_bases;
mod issue_1835_cpp_using_declaration_overloads;
mod issue_1836_cpp_resolution_determinism;
mod issue_1843_cpp_using_declaration_hiding;
mod issue_1844_cpp_include_closure_definition;
mod issue_693_profile;
mod issue_csharp_verbatim_identifiers;
