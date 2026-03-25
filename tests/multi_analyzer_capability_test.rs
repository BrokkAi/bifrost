use brokk_analyzer::{
    AnalyzerDelegate, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
    RustAnalyzer, TestProject,
};
use std::collections::BTreeMap;
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    let root = temp.keep();
    for (path, contents) in files {
        ProjectFile::new(root.clone(), path).write(*contents).unwrap();
    }
    TestProject::new(root, Language::Java)
}

#[test]
fn import_analysis_provider_is_present_when_delegate_supports_it() {
    let project = inline_project(&[("A.java", "import java.util.List; class A { List<String> x; }")]);
    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
    )]));

    let provider = multi.import_analysis_provider();
    assert!(provider.is_some());

    let file = ProjectFile::new(project.root_path().to_path_buf(), "A.java");
    assert_eq!(1, provider.unwrap().import_info_of(&file).len());
}

#[test]
fn import_analysis_provider_is_empty_when_no_delegate_supports_capability() {
    let multi = MultiAnalyzer::new(BTreeMap::new());
    assert!(multi.import_analysis_provider().is_none());
}

#[test]
fn type_hierarchy_provider_is_present_when_delegate_supports_it() {
    let project = inline_project(&[
        ("base.py", "class Base: pass\n"),
        ("derived.py", "from base import Base\nclass Derived(Base): pass\n"),
    ]);
    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Python,
        AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.clone())),
    )]));

    let provider = multi.type_hierarchy_provider();
    assert!(provider.is_some());
}

#[test]
fn type_alias_provider_is_present_when_delegate_supports_it() {
    let project = inline_project(&[("lib.rs", "type Alias = i32;\nstruct Thing;\n")]);
    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Rust,
        AnalyzerDelegate::Rust(RustAnalyzer::from_project(project.clone())),
    )]));

    let provider = multi.type_alias_provider();
    assert!(provider.is_some());
}
