use brokk_bifrost::{
    AnalyzerDelegate, IAnalyzer, ImportAnalysisProvider, Language, MultiAnalyzer, Project,
    ProjectFile, RustAnalyzer, TestProject,
};
use std::collections::BTreeMap;
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
fn rust_imports_aliases_and_test_detection_match_expected_behaviors() {
    let project = rust_project(&[
        ("src/my_module.rs", "pub struct MyStruct;\n"),
        (
            "src/main.rs",
            r#"
            use crate::my_module::MyStruct;
            use crate::my_module::MyStruct as AliasStruct;
            use std::io::{self, Read, Write};

            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    let _s = AliasStruct;
                    let _ = MyStruct;
                }
            }
            "#,
        ),
    ]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    let main_file = ProjectFile::new(project.root().to_path_buf(), "src/main.rs");

    let imports = analyzer.import_statements(&main_file);
    assert!(imports.contains(&"use crate::my_module::MyStruct;".to_string()));
    assert!(imports.contains(&"use crate::my_module::MyStruct as AliasStruct;".to_string()));
    assert!(imports.contains(&"use std::io;".to_string()));
    assert!(imports.contains(&"use std::io::Read;".to_string()));
    assert!(imports.contains(&"use std::io::Write;".to_string()));

    let imported = analyzer.imported_code_units_of(&main_file);
    assert!(
        imported
            .iter()
            .any(|code_unit| code_unit.identifier() == "MyStruct")
    );
    assert!(analyzer.contains_tests(&main_file));

    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Rust,
        AnalyzerDelegate::Rust(analyzer.clone()),
    )]));
    assert!(multi.contains_tests(&main_file));
}
