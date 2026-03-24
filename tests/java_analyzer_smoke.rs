use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject};
use std::collections::BTreeSet;

#[test]
fn parses_fixture_declarations() {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);

    assert!(!analyzer.get_definitions("A").is_empty());
    assert!(!analyzer.get_definitions("A.method1").is_empty());
    assert!(!analyzer.get_top_level_declarations(&ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "A.java"
    ))
    .is_empty());
}

#[test]
fn updates_changed_file_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), "A.java");
    file.write(
        r#"
public class A {
  public int method1() { return 1; }
}
"#,
    )
    .unwrap();

    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    assert!(!analyzer.get_definitions("A.method1").is_empty());
    assert!(analyzer.get_definitions("A.method2").is_empty());

    file.write(
        r#"
public class A {
  public int method1() { return 1; }
  public int method2() { return 2; }
}
"#,
    )
    .unwrap();

    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("A.method2").is_empty());
    assert!(analyzer.get_definitions("A.method2").is_empty());
}
