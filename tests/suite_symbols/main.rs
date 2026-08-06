//! Consolidated `suite_symbols` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_symbols -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod bifrostignore;
mod classify_test_files_test;
mod diff_analysis_test;
mod get_definition_test;
mod most_relevant_files;
mod reusable_summaries;
mod searchtools_definition_selectors;
mod searchtools_fuzzy_symbol_lookup;
mod searchtools_list_symbols;
mod searchtools_service;
mod searchtools_summary_ranges;
mod searchtools_too_broad_scope;
