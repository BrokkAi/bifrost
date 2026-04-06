use brokk_analyzer::{AnalyzerConfig, FilesystemProject, Language, WorkspaceAnalyzer};
use std::collections::BTreeSet;
use std::sync::Arc;

#[test]
fn workspace_build_for_languages_limits_analyzer_set() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("a.py"), "VALUE = 1\n").unwrap();
    std::fs::write(temp.path().join("b.js"), "export const value = 1;\n").unwrap();

    let project = Arc::new(FilesystemProject::new(temp.path()).unwrap());
    let workspace = WorkspaceAnalyzer::build_for_languages(
        project,
        AnalyzerConfig::default(),
        &BTreeSet::from([Language::Python]),
    );

    assert_eq!(
        BTreeSet::from([Language::Python]),
        workspace.analyzer().languages()
    );
}
