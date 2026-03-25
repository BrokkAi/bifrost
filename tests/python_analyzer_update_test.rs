use brokk_analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, TestProject};
use std::collections::BTreeSet;

#[test]
fn explicit_update() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "mod.py");
    file.write(
        r#"
        def foo():
            return 1
        "#,
    )
    .unwrap();
    let analyzer =
        PythonAnalyzer::from_project(TestProject::new(root, brokk_analyzer::Language::Python));

    assert!(!analyzer.get_definitions("mod.foo").is_empty());
    assert!(analyzer.get_definitions("mod.bar").is_empty());

    file.write(
        r#"
        def foo():
            return 1

        def bar():
            return 2
        "#,
    )
    .unwrap();
    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("mod.bar").is_empty());
}

#[test]
fn auto_detect_changes_and_deletes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "mod.py");
    file.write(
        r#"
        def foo():
            return 1
        "#,
    )
    .unwrap();
    let analyzer =
        PythonAnalyzer::from_project(TestProject::new(root, brokk_analyzer::Language::Python));

    file.write(
        r#"
        def foo():
            return 42
        "#,
    )
    .unwrap();
    let updated = analyzer.update_all();
    assert!(!updated.get_definitions("mod.foo").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("mod.foo").is_empty());
}
