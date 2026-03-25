use brokk_analyzer::{GoAnalyzer, IAnalyzer, Language, ProjectFile, TestProject};
use std::collections::BTreeSet;
use tempfile::tempdir;

#[test]
fn explicit_update() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "a.go");
    file.write(
        r#"
        package main
        func Foo() int { return 1 }
        "#,
    )
    .unwrap();
    let analyzer = GoAnalyzer::from_project(TestProject::new(root, Language::Go));
    assert!(!analyzer.get_definitions("main.Foo").is_empty());
    assert!(analyzer.get_definitions("main.Bar").is_empty());

    file.write(
        r#"
        package main
        func Foo() int { return 1 }
        func Bar() int { return 2 }
        "#,
    )
    .unwrap();
    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("main.Bar").is_empty());
}

#[test]
fn auto_detect() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "a.go");
    file.write(
        r#"
        package main
        func Foo() int { return 1 }
        "#,
    )
    .unwrap();
    let analyzer = GoAnalyzer::from_project(TestProject::new(root, Language::Go));

    file.write(
        r#"
        package main
        func Foo() int { return 1 }
        func Baz() int { return 3 }
        "#,
    )
    .unwrap();
    let updated = analyzer.update_all();
    assert!(!updated.get_definitions("main.Baz").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("main.Foo").is_empty());
}
