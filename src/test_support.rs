//! Shared test fixtures used across MCP-tool unit tests. Each fixture
//! materializes a `TempDir` workspace, builds a `WorkspaceAnalyzer` over
//! it, and exposes both for assertions. Test-only.

use crate::analyzer::{
    AnalyzerConfig, FilesystemProject, Language, Project, ProjectFile, TestProject,
    WorkspaceAnalyzer,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

/// Owns a `TempDir` workspace and the analyzer built over it.
pub(crate) struct AnalyzerFixture {
    _temp: TempDir,
    pub(crate) analyzer: WorkspaceAnalyzer,
    test_project: Option<TestProject>,
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
            test_project: None,
        }
    }

    pub(crate) fn new_for_language(language: Language, files: &[(&str, &str)]) -> Self {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (rel, content) in files {
            ProjectFile::new(root.clone(), rel)
                .write(content)
                .unwrap_or_else(|err| panic!("failed to write {rel}: {err}"));
        }
        let project = TestProject::new(root, language);
        let analyzer =
            WorkspaceAnalyzer::build(Arc::new(project.clone()), AnalyzerConfig::default());
        Self {
            _temp: temp,
            analyzer,
            test_project: Some(project),
        }
    }

    pub(crate) fn test_project(&self) -> &TestProject {
        self.test_project
            .as_ref()
            .expect("fixture was not built with TestProject")
    }

    pub(crate) fn project_root(&self) -> PathBuf {
        self.analyzer.analyzer().project().root().to_path_buf()
    }
}
