use brokk_analyzer::{
    JavaAnalyzer, Language, TestProject,
    searchtools::{FilePatternsParams, skim_files, summarize_symbols},
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
fn summarize_symbols_matches_skim_files_and_preserves_package_headers() {
    let analyzer = fixture_analyzer();
    let params = FilePatternsParams {
        file_patterns: vec!["Packaged.java".to_string()],
    };

    let summarize_result = summarize_symbols(&analyzer, params.clone());
    let skim_result = skim_files(&analyzer, params);

    assert_eq!(1, summarize_result.files.len());
    assert_eq!("Packaged.java", summarize_result.files[0].path);
    assert_eq!(
        Some(&"# io.github.jbellis.brokk".to_string()),
        summarize_result.files[0].lines.first()
    );
    assert!(
        summarize_result.files[0]
            .lines
            .contains(&"- Foo".to_string())
    );
    assert!(
        summarize_result.files[0]
            .lines
            .contains(&"  - bar".to_string())
    );

    assert_eq!(skim_result.files.len(), summarize_result.files.len());
    assert_eq!(skim_result.files[0].path, summarize_result.files[0].path);
    assert_eq!(skim_result.files[0].loc, summarize_result.files[0].loc);
    assert_eq!(skim_result.files[0].lines, summarize_result.files[0].lines);
    assert_eq!(skim_result.truncated, summarize_result.truncated);
}
