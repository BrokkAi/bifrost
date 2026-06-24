use brokk_bifrost::{CSharpAnalyzer, IAnalyzer, Language, ProjectFile, TestProject};
use std::collections::BTreeSet;
use tempfile::tempdir;

#[test]
fn explicit_update() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "A.cs");
    file.write(
        r#"
        namespace TestNs {
          public class A {
            public int Method1() { return 1; }
          }
        }
        "#,
    )
    .unwrap();

    let analyzer = CSharpAnalyzer::from_project(TestProject::new(root, Language::CSharp));
    assert!(!analyzer.get_definitions("TestNs.A.Method1").is_empty());
    assert!(analyzer.get_definitions("TestNs.A.Method2").is_empty());

    file.write(
        r#"
        namespace TestNs {
          public class A {
            public int Method1() { return 1; }
            public int Method2() { return 2; }
          }
        }
        "#,
    )
    .unwrap();

    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("TestNs.A.Method2").is_empty());
}

#[test]
fn auto_detect() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "A.cs");
    file.write(
        r#"
        namespace TestNs {
          public class A {
            public int Method1() { return 1; }
          }
        }
        "#,
    )
    .unwrap();

    let analyzer = CSharpAnalyzer::from_project(TestProject::new(root, Language::CSharp));
    file.write(
        r#"
        namespace TestNs {
          public class A {
            public int Method1() { return 1; }
            public int Method3() { return 3; }
          }
        }
        "#,
    )
    .unwrap();
    let updated = analyzer.update_all();
    assert!(!updated.get_definitions("TestNs.A.Method3").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("TestNs.A").is_empty());
}

#[test]
fn file_scoped_namespace_qualifies_members() {
    // Regression: a file-scoped namespace (`namespace X;`, C# 10+) has no body, so its
    // type declarations are following siblings. Their package_name must still be the
    // namespace, exactly as for a block namespace -- otherwise fq_name drops it.
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "A.cs");
    file.write(
        "namespace TestNs.Sub;\n\npublic class A {\n  public int Method1() { return 1; }\n}\n",
    )
    .unwrap();

    let analyzer = CSharpAnalyzer::from_project(TestProject::new(root, Language::CSharp));
    assert!(
        !analyzer.get_definitions("TestNs.Sub.A.Method1").is_empty(),
        "file-scoped namespace member should be fully qualified",
    );
    assert!(
        analyzer.get_definitions("A.Method1").is_empty(),
        "file-scoped namespace member must not be left unqualified",
    );
}
