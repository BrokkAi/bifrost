use brokk_analyzer::{IAnalyzer, Language, ProjectFile, RustAnalyzer, TestProject};
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
fn test_is_type_alias() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        r#"
        type MyResult<T> = Result<T, Error>;
        struct MyStruct;
        fn my_func() {}
        "#,
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs");
    let declarations = analyzer.get_declarations(&file);

    let alias = declarations
        .iter()
        .find(|cu| cu.identifier() == "MyResult")
        .unwrap();
    let structure = declarations
        .iter()
        .find(|cu| cu.identifier() == "MyStruct")
        .unwrap();
    let function = declarations
        .iter()
        .find(|cu| cu.identifier() == "my_func")
        .unwrap();

    assert!(analyzer.is_type_alias(alias));
    assert!(!analyzer.is_type_alias(structure));
    assert!(!analyzer.is_type_alias(function));
}
