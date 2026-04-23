use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, Project, ProjectFile, TestProject};
use tempfile::tempdir;

fn java_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Java)
}

#[test]
fn detects_junit_annotations() {
    let project = java_project(&[(
        "AnnotatedTest.java",
        r#"
        import org.junit.Test;

        public class AnnotatedTest {
            @Test
            public void runs() {}
        }
        "#,
    )]);
    let analyzer = JavaAnalyzer::from_project(project.clone());

    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "AnnotatedTest.java",
    )));
}

#[test]
fn detects_testcase_extends_with_whitespace() {
    let project = java_project(&[
        (
            "LegacyTest.java",
            r#"
            public class LegacyTest extends
                TestCase {
            }
            "#,
        ),
        (
            "QualifiedLegacyTest.java",
            r#"
            public class QualifiedLegacyTest extends
                junit.framework.TestCase {
            }
            "#,
        ),
    ]);
    let analyzer = JavaAnalyzer::from_project(project.clone());

    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "LegacyTest.java",
    )));
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "QualifiedLegacyTest.java",
    )));
}

#[test]
fn ignores_non_test_file() {
    let project = java_project(&[(
        "Application.java",
        r#"
        public class Application {
            public void run() {}
        }
        "#,
    )]);
    let analyzer = JavaAnalyzer::from_project(project.clone());

    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Application.java",
    )));
}
