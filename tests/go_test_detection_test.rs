use brokk_analyzer::{GoAnalyzer, IAnalyzer, Language, Project, ProjectFile, TestProject};
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Go)
}

#[test]
fn test_contains_tests_detection() {
    let project = inline_project(&[
        (
            "pkg/ptr.go",
            r#"
            package foo
            import "testing"
            func TestPointer(t *testing.T) {}
            "#,
        ),
        (
            "pkg/val.go",
            r#"
            package foo
            import "testing"
            func TestValue(t testing.T) {}
            "#,
        ),
        (
            "pkg/bench.go",
            r#"
            package foo
            import "testing"
            func BenchmarkOnly(b *testing.B) {}
            "#,
        ),
        (
            "pkg/lib.go",
            r#"
            package foo
            import "testing"
            func BenchmarkStuff(b *testing.B) {}
            type S struct {}
            func (s *S) TestMethod(t *testing.T) {}
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/ptr.go"
    )));
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/val.go"
    )));
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/bench.go"
    )));
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/lib.go"
    )));
}

#[test]
fn test_go_test_detection_negative_shapes() {
    let project = inline_project(&[
        (
            "pkg/wrong_param.go",
            r#"
            package foo
            import "testing"
            func TestNotReally(t *testing.B) {}
            "#,
        ),
        (
            "pkg/multi_param.go",
            r#"
            package foo
            import "testing"
            func TestMulti(a, b *testing.T) {}
            "#,
        ),
        (
            "pkg/extra_param.go",
            r#"
            package foo
            import "testing"
            func TestExtra(t *testing.T, x int) {}
            "#,
        ),
        (
            "pkg/generic_test.go",
            r#"
            package foo
            import "testing"
            func TestGeneric[T any](t *testing.T) {}
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone()).update_all();
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/wrong_param.go"
    )));
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/multi_param.go"
    )));
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/extra_param.go"
    )));
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "pkg/generic_test.go"
    )));
}
