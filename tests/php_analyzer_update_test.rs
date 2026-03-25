use brokk_analyzer::{IAnalyzer, Language, PhpAnalyzer, ProjectFile, TestProject};
use std::collections::BTreeSet;
use tempfile::tempdir;

#[test]
fn explicit_update() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "foo.php");
    file.write(
        r#"
        <?php
        function foo(): int { return 1; }
        "#,
    )
    .unwrap();

    let analyzer = PhpAnalyzer::from_project(TestProject::new(root, Language::Php));
    assert!(!analyzer.get_definitions("foo").is_empty());
    assert!(analyzer.get_definitions("bar").is_empty());

    file.write(
        r#"
        <?php
        function foo(): int { return 1; }
        function bar(): int { return 2; }
        "#,
    )
    .unwrap();

    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("bar").is_empty());
}

#[test]
fn auto_detect() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "foo.php");
    file.write(
        r#"
        <?php
        function foo(): int { return 1; }
        "#,
    )
    .unwrap();

    let analyzer = PhpAnalyzer::from_project(TestProject::new(root, Language::Php));
    file.write(
        r#"
        <?php
        function foo(): int { return 1; }
        function baz(): int { return 3; }
        "#,
    )
    .unwrap();

    let updated = analyzer.update_all();
    assert!(!updated.get_definitions("baz").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("foo").is_empty());
}
