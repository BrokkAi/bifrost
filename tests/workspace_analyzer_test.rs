mod common;

use brokk_analyzer::{AnalyzerConfig, FilesystemProject, Language, Project, WorkspaceAnalyzer};
use common::InlineTestProject;
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

#[test]
fn inline_project_infers_single_language_workspace() {
    let project = InlineTestProject::new()
        .file("pkg/mod.py", "VALUE = 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    assert!(matches!(workspace, WorkspaceAnalyzer::Single(_)));
    assert_eq!(BTreeSet::from([Language::Python]), project.languages());
    assert_eq!(
        BTreeSet::from([Language::Python]),
        workspace.analyzer().languages()
    );
    assert_eq!(
        Some(project.file("pkg/mod.py")),
        project
            .project()
            .file_by_rel_path(std::path::Path::new("pkg/mod.py"))
    );
}

#[test]
fn inline_project_infers_multi_language_workspace() {
    let project = InlineTestProject::new()
        .file("pkg/mod.py", "VALUE = 1\n")
        .file("web/app.js", "export const value = 1;\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    assert!(matches!(workspace, WorkspaceAnalyzer::Multi(_)));
    assert_eq!(
        BTreeSet::from([Language::JavaScript, Language::Python]),
        project.languages()
    );
    assert_eq!(
        BTreeSet::from([Language::JavaScript, Language::Python]),
        workspace.analyzer().languages()
    );
}

#[test]
fn inline_project_explicit_language_overrides_inference() {
    let project = InlineTestProject::new()
        .language(Language::Python)
        .file("pkg/mod.py", "VALUE = 1\n")
        .file("web/app.js", "export const value = 1;\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    assert!(matches!(workspace, WorkspaceAnalyzer::Single(_)));
    assert_eq!(BTreeSet::from([Language::Python]), project.languages());
    assert_eq!(
        BTreeSet::from([Language::Python]),
        workspace.analyzer().languages()
    );
}

#[test]
#[should_panic(expected = "inline test project must include at least one supported file")]
fn inline_project_rejects_unsupported_only_files() {
    let _ = InlineTestProject::new()
        .file("README.md", "# unsupported\n")
        .build();
}
