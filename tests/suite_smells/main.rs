//! Consolidated `suite_smells` test harness.
//!
//! Each module below was previously its own `tests/*.rs` integration binary.
//! They were merged so the suite links the library once instead of once per
//! file; module scoping keeps every test path and helper name isolated.
//! Run a single former file with:
//!     cargo test --test suite_smells -- <module>::

#[path = "../common/mod.rs"]
mod common;

mod cpp_dead_code_smells;
mod cpp_structural_clone_smells;
mod cpp_test_assertion_smells;
mod csharp_dead_code_smells;
mod csharp_go_rust_test_assertion_smells;
mod csharp_structural_clone_smells;
mod exception_handling_smells;
mod go_dead_code_smells;
mod go_rust_ruby_structural_clone_smells;
mod go_structural_clone_smells;
mod java_dead_code_smells;
mod java_structural_clone_smells;
mod java_test_assertion_smells;
mod js_ts_structural_clone_smells;
mod js_ts_test_assertion_smells;
mod kotlin_dead_code_smells;
mod kotlin_test_assertion_smells;
mod php_dead_code_smells;
mod php_structural_clone_smells;
mod python_js_ts_dead_code_smells;
mod python_structural_clone_smells;
mod python_test_assertion_smells;
mod ruby_dead_code_smells;
mod ruby_structural_clone_smells;
mod ruby_test_assertion_smells;
mod rust_dead_code_smells;
mod rust_structural_clone_smells;
mod scala_dead_code_smells;
mod scala_php_test_assertion_smells;
mod scala_structural_clone_smells;
