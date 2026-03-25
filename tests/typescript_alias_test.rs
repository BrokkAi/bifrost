mod common;

use brokk_analyzer::{IAnalyzer, Language, TestProject, TypescriptAnalyzer};
use tempfile::tempdir;

use common::write_file;

#[test]
fn test_is_type_alias() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "src/main.ts",
        r#"
            export type MyResult<T> = Result<T, Error>;
            class MyStruct {}
            function my_func() {}
        "#,
    );

    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let declarations = analyzer.get_declarations(&file);
    let alias = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "MyResult")
        .unwrap();
    let class = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "MyStruct")
        .unwrap();
    let function = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "my_func")
        .unwrap();

    assert!(analyzer.is_type_alias(alias));
    assert!(!analyzer.is_type_alias(class));
    assert!(!analyzer.is_type_alias(function));
}
