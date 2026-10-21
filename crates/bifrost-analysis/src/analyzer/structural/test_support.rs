use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, IAnalyzer, Language, Project, ProjectFile, TestProject,
    WorkspaceAnalyzer,
};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

#[doc(hidden)]
pub fn content_identity(seed: u64) -> WorkspaceContentIdentity {
    WorkspaceContentIdentity::for_test(seed)
}

pub(crate) fn declarations_ending_with<'a>(
    analyzer: &'a dyn IAnalyzer,
    suffix: &'a str,
) -> impl Iterator<Item = CodeUnit> + 'a {
    analyzer
        .all_declarations()
        .filter(move |unit| unit.fq_name().ends_with(suffix))
}

pub(crate) fn workspace_fixture(
    language: Language,
    sources: &[(&str, &str)],
) -> (TempDir, WorkspaceAnalyzer, Vec<ProjectFile>, Vec<String>) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root: PathBuf = temp.path().canonicalize().expect("canonical root");
    let mut files = Vec::with_capacity(sources.len());
    let mut source_texts = Vec::with_capacity(sources.len());
    for (relative_path, source) in sources {
        let file = ProjectFile::new(root.clone(), *relative_path);
        file.write(source).expect("write fixture source");
        files.push(file);
        source_texts.push((*source).to_owned());
    }
    let project = TestProject::new(root, language);
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(project) as Arc<dyn Project>,
        AnalyzerConfig::default(),
    )
    .expect("ephemeral workspace should build");
    (temp, workspace, files, source_texts)
}
