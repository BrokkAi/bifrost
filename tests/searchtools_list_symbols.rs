use brokk_analyzer::{
    JavaAnalyzer, Language, TestProject,
    searchtools::{FilePatternsParams, list_symbols},
};

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

#[test]
fn list_symbols_preserves_package_headers() {
    let analyzer = fixture_analyzer();
    let params = FilePatternsParams {
        file_patterns: vec!["Packaged.java".to_string()],
    };

    let result = list_symbols(&analyzer, params);

    assert_eq!(1, result.files.len());
    assert_eq!("Packaged.java", result.files[0].path);
    assert_eq!(
        Some(&"# io.github.jbellis.brokk".to_string()),
        result.files[0].lines.first()
    );
    assert!(result.files[0].lines.contains(&"- Foo".to_string()));
    assert!(result.files[0].lines.contains(&"  - bar".to_string()));
}
