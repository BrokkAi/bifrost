use brokk_analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, TestProject};

fn single_file_project(path: &str, contents: &str) -> (TestProject, ProjectFile) {
    let temp = tempfile::tempdir().unwrap();
    let file = ProjectFile::new(temp.path().to_path_buf(), path);
    file.write(contents).unwrap();
    (
        TestProject::new(temp.keep(), brokk_analyzer::Language::Python),
        file,
    )
}

#[test]
fn test_test_prefixed_function_detection() {
    let (project, file) = single_file_project(
        "Example.py",
        r#"
        def test_addition():
            assert 1 + 1 == 2
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn test_test_prefixed_method_detection() {
    let (project, file) = single_file_project(
        "Example.py",
        r#"
        class TestMath:
            def test_addition(self):
                assert 1 + 1 == 2
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn test_pytest_mark_detection() {
    let (project, file) = single_file_project(
        "Example.py",
        r#"
        import pytest

        @pytest.mark.slow
        def some_helper():
            return 123
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn test_negative_detection() {
    let (project, file) = single_file_project(
        "Example.py",
        r#"
        def add(a, b):
            return a + b

        class Math:
            def add(self, a, b):
                return a + b
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    assert!(!analyzer.contains_tests(&file));
}

#[test]
fn test_pytest_fixture_detection() {
    let (project, file) = single_file_project(
        "Example.py",
        r#"
        import pytest

        @pytest.fixture
        def some_data():
            return 42
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    assert!(!analyzer.contains_tests(&file));
}

#[test]
fn test_test_name_without_underscore() {
    let (project, file) = single_file_project(
        "Example.py",
        r#"
        def test():
            pass
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    assert!(!analyzer.contains_tests(&file));
}
