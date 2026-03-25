use brokk_analyzer::{IAnalyzer, Language, Project, ProjectFile, ScalaAnalyzer, TestProject};
use tempfile::tempdir;

fn inline_scala_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Scala)
}

#[test]
fn detects_junit_test_annotation() {
    let project = inline_scala_project(&[(
        "Example.scala",
        r#"
        import org.junit.Test

        class Example {
          @Test
          def itWorks(): Unit = {
            ()
          }
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Example.scala");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn detects_funsuite_structure_without_imports() {
    let project = inline_scala_project(&[(
        "Example.scala",
        r#"
        class ExampleSuite {
          test("it works") {
            assert(1 + 1 == 2)
          }
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Example.scala");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn detects_flatspec_structure_without_imports() {
    let project = inline_scala_project(&[(
        "Example.scala",
        r#"
        class ExampleSpec {
          "A Calculator" should "add two numbers" in {
            assert(1 + 1 == 2)
          }
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Example.scala");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn negative_case_with_scalatest_import_only() {
    let project = inline_scala_project(&[(
        "Example.scala",
        r#"
        import org.scalatest.funsuite.AnyFunSuite

        class Example {
          def add(a: Int, b: Int): Int = a + b
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Example.scala");
    assert!(!analyzer.contains_tests(&file));
}

#[test]
fn negative_case_no_markers_no_scalatest_imports() {
    let project = inline_scala_project(&[(
        "Example.scala",
        r#"
        class Example {
          def add(a: Int, b: Int): Int = a + b
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Example.scala");
    assert!(!analyzer.contains_tests(&file));
}
