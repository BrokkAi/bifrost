use brokk_analyzer::{IAnalyzer, JavascriptAnalyzer, Language, ProjectFile, TestProject};

#[test]
fn analyzer_skips_binary_file_with_supported_extension() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let binary = ProjectFile::new(root.to_path_buf(), "binary.js");
    std::fs::write(binary.abs_path(), b"const x = 1;\0binary").unwrap();

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    assert!(binary.is_binary().unwrap());
    assert!(analyzer.get_analyzed_files().is_empty());
}
