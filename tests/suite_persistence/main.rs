//! Consolidated `suite_persistence` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_persistence -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod analyzer_capability_parity;
mod analyzer_query_parity;
mod analyzer_sql_query_parity;
mod analyzer_store_reconcile;
mod model_handle_semantics;
mod multi_analyzer_capability_test;
mod multi_analyzer_get_test_modules_test;
mod multi_analyzer_import_test;
mod multi_analyzer_routing;
mod multi_analyzer_test;
mod parse_errors_cache;
mod scratch_cache_isolation;
mod semantic_pack_catalog;
mod structural_facts_persistence;
#[cfg(feature = "nlp")]
mod unified_cache;
mod versioned_cache_store;
mod workspace_analyzer_test;
