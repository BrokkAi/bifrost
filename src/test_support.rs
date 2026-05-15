//! Shared test fixtures used across MCP-tool unit tests. Each fixture
//! materializes a `TempDir` workspace, builds a `WorkspaceAnalyzer` over
//! it, and exposes both for assertions. Test-only.

#![cfg(test)]

use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

/// Owns a `TempDir` workspace and the analyzer built over it.
pub(crate) struct AnalyzerFixture {
    _temp: TempDir,
    pub(crate) analyzer: WorkspaceAnalyzer,
}

impl AnalyzerFixture {
    /// Build a fixture from `(relative_path, file_contents)` pairs.
    pub(crate) fn new(files: &[(&str, &str)]) -> Self {
        let temp = TempDir::new().expect("tempdir");
        for (rel, content) in files {
            let abs = temp.path().join(rel);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(&abs, content).expect("write");
        }
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(temp.path().to_path_buf()).expect("project"));
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        Self {
            _temp: temp,
            analyzer,
        }
    }

    pub(crate) fn project_root(&self) -> PathBuf {
        self.analyzer.analyzer().project().root().to_path_buf()
    }
}
