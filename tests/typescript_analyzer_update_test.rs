mod common;

use brokk_analyzer::{IAnalyzer, Language, TestProject, TypescriptAnalyzer};
use std::collections::BTreeSet;
use tempfile::tempdir;

use common::write_file;

#[test]
fn explicit_update() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "hello.ts",
        "export function foo(): number { return 1; }\n",
    );
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    assert!(!analyzer.get_definitions("foo").is_empty());
    assert!(analyzer.get_definitions("bar").is_empty());

    file.write(
        r#"
            export function foo(): number { return 1; }
            export function bar(): number { return 2; }
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
    let file = write_file(
        root,
        "hello.ts",
        "export function foo(): number { return 1; }\n",
    );
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    file.write(
        r#"
            export function foo(): number { return 1; }
            export function baz(): number { return 3; }
        "#,
    )
    .unwrap();

    let updated = analyzer.update_all();
    assert!(!updated.get_definitions("baz").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let removed = updated.update_all();
    assert!(removed.get_definitions("foo").is_empty());
}
