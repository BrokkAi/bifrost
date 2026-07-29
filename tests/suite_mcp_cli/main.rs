//! Consolidated `suite_mcp_cli` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_mcp_cli -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod bifrost_benchmark_cli;
mod bifrost_benchmark_run;
mod bifrost_lsp_server;
mod bifrost_mcp_property_fuzzer_cli;
mod bifrost_mcp_server;
mod bifrost_reference_differential_cli;
mod bifrost_skill_install_cli;
mod bifrost_tool_cli;
mod binary_file_handling;
mod code_intelligence_runtime;
mod filesystem_project_gitignore;
mod lsp_click_around_regression;
mod lsp_parameter_definition;
