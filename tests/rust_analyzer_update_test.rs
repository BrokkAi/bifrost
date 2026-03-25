use brokk_analyzer::{IAnalyzer, Language, ProjectFile, RustAnalyzer, TestProject};
use std::collections::BTreeSet;
use tempfile::tempdir;

#[test]
fn explicit_update() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    assert!(!analyzer.get_definitions("foo").is_empty());
    assert!(analyzer.get_definitions("bar").is_empty());

    file.write("pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n")
        .unwrap();
    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("bar").is_empty());
}

#[test]
fn auto_detect() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    file.write("pub fn foo() -> i32 { 1 }\npub fn baz() -> i32 { 3 }\n")
        .unwrap();
    let updated = analyzer.update_all();
    assert!(!updated.get_definitions("baz").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("foo").is_empty());
}
