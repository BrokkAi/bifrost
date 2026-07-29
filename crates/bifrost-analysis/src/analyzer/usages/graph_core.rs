//! Shared import-edge types for the per-language usage indices.
//!
//! Each language's usage index (`RustUsageIndex`, `PythonUsageIndex`,
//! `GoProjectGraph`, `JsTsUsageIndex`) builds these edges from its own module
//! resolution, so `scan_usages` and `usage_graph` resolve references through one
//! index per language.

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
