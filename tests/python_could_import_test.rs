use brokk_analyzer::{
    ImportAnalysisProvider, ImportInfo, ProjectFile, PythonAnalyzer, TestProject,
};

fn analyzer_for_temp_root(root: &std::path::Path) -> PythonAnalyzer {
    PythonAnalyzer::from_project(TestProject::new(root, brokk_analyzer::Language::Python))
}

#[test]
fn test_could_import_file_relative_parent_import() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = ProjectFile::new(root.to_path_buf(), "pkg/sub/module.py");
    source.write("from .. import utils").unwrap();
    let target = ProjectFile::new(root.to_path_buf(), "pkg/utils.py");
    target.write("def some_fn(): pass").unwrap();

    let analyzer = analyzer_for_temp_root(root);
    let import = ImportInfo {
        raw_snippet: "from .. import utils".to_string(),
        is_wildcard: false,
        identifier: Some("utils".to_string()),
        alias: None,
    };
    assert!(analyzer.could_import_file(&source, &[import], &target));
}

#[test]
fn test_could_import_file_relative_parent_module_import() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = ProjectFile::new(root.to_path_buf(), "pkg/sub/module.py");
    source.write("from ..other import something").unwrap();
    let target = ProjectFile::new(root.to_path_buf(), "pkg/other.py");
    target.write("something = 1").unwrap();

    let analyzer = analyzer_for_temp_root(root);
    let import = ImportInfo {
        raw_snippet: "from ..other import something".to_string(),
        is_wildcard: false,
        identifier: Some("something".to_string()),
        alias: None,
    };
    assert!(analyzer.could_import_file(&source, &[import], &target));
}

#[test]
fn test_could_import_file_invalid_relative_import_conservative_return() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = ProjectFile::new(root.to_path_buf(), "pkg/module.py");
    source.write("from ... import utils").unwrap();
    let target = ProjectFile::new(root.to_path_buf(), "some_other.py");
    target.write("").unwrap();

    let analyzer = analyzer_for_temp_root(root);
    let import = ImportInfo {
        raw_snippet: "from ... import utils".to_string(),
        is_wildcard: false,
        identifier: Some("utils".to_string()),
        alias: None,
    };
    assert!(analyzer.could_import_file(&source, &[import], &target));
}

#[test]
fn test_could_import_file_negative_match() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = ProjectFile::new(root.to_path_buf(), "pkg/module.py");
    source.write("import unrelated").unwrap();
    let target = ProjectFile::new(root.to_path_buf(), "pkg/target.py");
    target.write("").unwrap();

    let analyzer = analyzer_for_temp_root(root);
    let import = ImportInfo {
        raw_snippet: "import unrelated".to_string(),
        is_wildcard: false,
        identifier: Some("unrelated".to_string()),
        alias: None,
    };
    assert!(!analyzer.could_import_file(&source, &[import], &target));
}
