use brokk_analyzer::{
    AnalyzerDelegate, GoAnalyzer, IAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
    TestProject,
};
use std::collections::BTreeMap;
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    let root = temp.keep();
    for (path, contents) in files {
        ProjectFile::new(root.clone(), path).write(*contents).unwrap();
    }
    TestProject::new(root, Language::Go)
}

#[test]
fn test_get_test_modules_delegation() {
    let project = inline_project(&[
        ("callbacks/x_test.go", "package callbacks\nfunc TestThing(t *testing.T) {}\n"),
        ("pkg/test_x.py", "def test_ok():\n    assert True\n"),
    ]);

    let go = GoAnalyzer::from_project(project.clone());
    let py = PythonAnalyzer::from_project(project.clone());
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (Language::Go, AnalyzerDelegate::Go(go.clone())),
        (Language::Python, AnalyzerDelegate::Python(py.clone())),
    ]));

    let go_file = ProjectFile::new(project.root_path().to_path_buf(), "callbacks/x_test.go");
    let py_file = ProjectFile::new(project.root_path().to_path_buf(), "pkg/test_x.py");

    let mut expected = go.get_test_modules(std::slice::from_ref(&go_file));
    expected.extend(py.get_test_modules(std::slice::from_ref(&py_file)));
    expected.sort();
    expected.dedup();

    assert_eq!(expected, multi.get_test_modules(&[go_file, py_file]));
}
