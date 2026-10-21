use crate::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::{Language, TestProject};
use std::path::Path;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_analyzer(root: &Path) -> RustAnalyzer {
    RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
}
