use brokk_analyzer::{
    AnalyzerConfig, Language, Project, ProjectFile, TestProject, WorkspaceAnalyzer,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
pub struct InlineTestProject {
    language: Option<Language>,
    files: Vec<(PathBuf, String)>,
}

impl InlineTestProject {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn with_language(language: Language) -> Self {
        Self::new().language(language)
    }

    pub fn language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }

    pub fn file(mut self, rel_path: impl Into<PathBuf>, contents: impl Into<String>) -> Self {
        self.files.push((rel_path.into(), contents.into()));
        self
    }

    pub fn build(self) -> BuiltInlineTestProject {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp
            .path()
            .canonicalize()
            .expect("failed to canonicalize temp dir");

        for (path, contents) in &self.files {
            ProjectFile::new(root.clone(), path.clone())
                .write(contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
        }

        let project = match self.language {
            Some(language) => TestProject::new(root.clone(), language),
            None => {
                TestProject::from_root_with_inferred_languages(root.clone()).unwrap_or_else(|err| {
                    panic!("inline test project must include at least one supported file: {err}")
                })
            }
        };

        BuiltInlineTestProject { temp, project }
    }
}

#[allow(dead_code)]
pub struct BuiltInlineTestProject {
    temp: tempfile::TempDir,
    project: TestProject,
}

#[allow(dead_code)]
impl BuiltInlineTestProject {
    pub fn project(&self) -> &TestProject {
        &self.project
    }

    pub fn project_arc(&self) -> Arc<TestProject> {
        Arc::new(self.project.clone())
    }

    pub fn project_dyn(&self) -> Arc<dyn Project> {
        self.project_arc()
    }

    pub fn root(&self) -> &Path {
        self.project.root()
    }

    pub fn file(&self, rel_path: impl AsRef<Path>) -> ProjectFile {
        ProjectFile::new(
            self.project.root().to_path_buf(),
            rel_path.as_ref().to_path_buf(),
        )
    }

    pub fn languages(&self) -> BTreeSet<Language> {
        self.project.analyzer_languages()
    }

    pub fn workspace_analyzer(&self, config: AnalyzerConfig) -> WorkspaceAnalyzer {
        WorkspaceAnalyzer::build(self.project_dyn(), config)
    }
}
