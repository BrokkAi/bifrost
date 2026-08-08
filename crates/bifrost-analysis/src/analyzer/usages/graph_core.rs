//! Shared import-edge types for the per-language usage indices.
//!
//! Each language builds these edges from its own module resolution, so
//! `scan_usages` and `usage_graph` resolve references through one per-language
//! source: an index for Python (`PythonUsageIndex`), Go (`GoProjectGraph`) and
//! JS/TS (`JsTsUsageIndex`), and store-backed walks for Rust
//! (`rust::usage_walks`).

use crate::analyzer::ProjectFile;

/// A resolved import binding: `importer` binds `local_name` to a symbol exported
/// by `target_file`, in the manner given by `kind`.
#[derive(Debug, Clone)]
pub struct ImportEdge {
    pub importer: ProjectFile,
    pub local_name: String,
    pub target_file: ProjectFile,
    pub kind: ImportEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportEdgeKind {
    Named(String),
    Default,
    Namespace,
    CommonJsRequire(String),
}
