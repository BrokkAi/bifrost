use crate::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

pub(crate) struct AnalyzerFixture {
    _temp: TempDir,
    pub(crate) analyzer: WorkspaceAnalyzer,
}

impl AnalyzerFixture {
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
}
