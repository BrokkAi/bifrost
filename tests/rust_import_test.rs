use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, Language, ProjectFile, RustAnalyzer, TestProject,
};
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
fn test_import_statement_shapes() {
    let basic = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::collections::HashMap;",
    )]));
    let basic_file = ProjectFile::new(basic.project().root().to_path_buf(), "src/main.rs");
    assert_eq!(
        vec!["use std::collections::HashMap;".to_string()],
        basic.import_statements_of(&basic_file)
    );

    let nested = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::collections::{HashMap, HashSet};",
    )]));
    let nested_file = ProjectFile::new(nested.project().root().to_path_buf(), "src/main.rs");
    let imports = nested.import_statements_of(&nested_file);
    assert!(imports.contains(&"use std::collections::HashMap;".to_string()));
    assert!(imports.contains(&"use std::collections::HashSet;".to_string()));

    let alias = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::collections::HashMap as MyMap;",
    )]));
    let alias_file = ProjectFile::new(alias.project().root().to_path_buf(), "src/main.rs");
    assert_eq!(
        vec!["use std::collections::HashMap as MyMap;".to_string()],
        alias.import_statements_of(&alias_file)
    );

    let wildcard =
        RustAnalyzer::from_project(rust_project(&[("src/main.rs", "use std::collections::*;")]));
    let wildcard_file = ProjectFile::new(wildcard.project().root().to_path_buf(), "src/main.rs");
    assert_eq!(
        vec!["use std::collections::*;".to_string()],
        wildcard.import_statements_of(&wildcard_file)
    );

    let self_import = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::io::{self, Read, Write};",
    )]));
    let self_file = ProjectFile::new(self_import.project().root().to_path_buf(), "src/main.rs");
    let imports = self_import.import_statements_of(&self_file);
    assert!(imports.contains(&"use std::io;".to_string()));
    assert!(imports.contains(&"use std::io::Read;".to_string()));
    assert!(imports.contains(&"use std::io::Write;".to_string()));
}

#[test]
fn test_type_alias_detection_via_import_suite() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "type MyResult<T> = Result<T, Error>;",
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs");
    let alias = analyzer
        .get_declarations(&file)
        .into_iter()
        .find(|cu| cu.identifier() == "MyResult")
        .unwrap();
    assert!(analyzer.is_type_alias(&alias));
    assert!(
        analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(&alias))
    );
}

#[test]
fn test_resolve_imports_semantic_cases() {
    let semantic = RustAnalyzer::from_project(rust_project(&[
        ("src/my_module.rs", "pub struct MyStruct;"),
        (
            "src/main.rs",
            r#"
            use crate::my_module::MyStruct;
            fn main() { let _s = MyStruct; }
            "#,
        ),
    ]));
    let main_file = ProjectFile::new(semantic.project().root().to_path_buf(), "src/main.rs");
    let imported = semantic.imported_code_units_of(&main_file);
    assert!(imported.iter().any(|cu| cu.identifier() == "MyStruct"));

    let aliased = RustAnalyzer::from_project(rust_project(&[
        ("src/lib.rs", "pub struct TargetStruct;"),
        (
            "src/main.rs",
            r#"
            use crate::TargetStruct as AliasStruct;
            fn main() { let _s = AliasStruct; }
            "#,
        ),
    ]));
    let main_file = ProjectFile::new(aliased.project().root().to_path_buf(), "src/main.rs");
    let imported = aliased.imported_code_units_of(&main_file);
    assert!(imported.iter().any(|cu| cu.identifier() == "TargetStruct"));

    let nested = RustAnalyzer::from_project(rust_project(&[
        ("src/shared/models.rs", "pub struct TargetStruct;"),
        (
            "src/nested/app/user.rs",
            r#"
            use crate::shared::models::TargetStruct;
            fn use_type() { let _t = TargetStruct; }
            "#,
        ),
    ]));
    let user_file = ProjectFile::new(
        nested.project().root().to_path_buf(),
        "src/nested/app/user.rs",
    );
    let imported = nested.imported_code_units_of(&user_file);
    assert!(imported.iter().any(|cu| cu.identifier() == "TargetStruct"));

    let super_root = RustAnalyzer::from_project(rust_project(&[
        ("src/lib.rs", "pub struct ExternalStruct;"),
        (
            "src/main.rs",
            r#"
            use super::ExternalStruct;
            fn main() {}
            "#,
        ),
    ]));
    let main_file = ProjectFile::new(super_root.project().root().to_path_buf(), "src/main.rs");
    let imported = super_root.imported_code_units_of(&main_file);
    assert!(
        imported
            .iter()
            .any(|cu| cu.identifier() == "ExternalStruct")
    );
}
