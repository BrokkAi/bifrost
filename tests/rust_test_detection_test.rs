use brokk_analyzer::{IAnalyzer, Language, Project, ProjectFile, RustAnalyzer, TestProject};
use tempfile::tempdir;

fn rust_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Rust)
}

#[test]
fn test_contains_tests_detection() {
    let project = rust_project(&[
        (
            "logic.rs",
            r#"
            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    assert_eq!(2 + 2, 4);
                }
            }
            "#,
        ),
        (
            "lib.rs",
            r#"
            pub fn add(a: i32, b: i32) -> i32 {
                a + b
            }
            "#,
        ),
    ]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    assert!(analyzer.contains_tests(&ProjectFile::new(project.root().to_path_buf(), "logic.rs")));
    assert!(!analyzer.contains_tests(&ProjectFile::new(project.root().to_path_buf(), "lib.rs")));
}

#[test]
fn test_non_test_attributes_do_not_trigger_detection() {
    let project = rust_project(&[(
        "not_a_test.rs",
        r#"
        #[foo]
        fn bar() {}

        #[derive(Debug)]
        struct Baz;
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "not_a_test.rs",
    )));
}

#[test]
fn test_cfg_test_detection() {
    let project = rust_project(&[(
        "test_mod.rs",
        r#"
        #[cfg(test)]
        mod tests {
        }
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "test_mod.rs",
    )));
}

#[test]
fn test_false_positive_function_name() {
    let project = rust_project(&[(
        "false_positive.rs",
        r#"
        fn test_function_name() {
        }
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "false_positive.rs",
    )));
}
