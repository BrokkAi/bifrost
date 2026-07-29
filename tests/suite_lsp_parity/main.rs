//! Consolidated `suite_lsp_parity` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_lsp_parity -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod basedpyright_goto_definition;
mod clangd_find_references;
mod clangd_goto_definition;
mod gopls_find_references;
mod gopls_goto_definition;
mod intellij_java_definition;
mod intellij_java_find_usages;
mod intellij_python_definition;
mod intellij_python_find_usages;
mod intellij_scala_goto_definition;
mod jdt_goto_definition;
mod metals_find_references;
mod metals_goto_definition;
mod phpactor_find_references;
mod phpactor_goto_definition;
mod roslyn_find_references;
mod roslyn_goto_definition;
mod ruby_lsp_find_references;
mod ruby_lsp_goto_definition;
mod rust_analyzer_find_references;
mod rust_analyzer_goto_definition;
