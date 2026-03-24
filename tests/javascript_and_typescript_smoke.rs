use brokk_analyzer::{
    AnalyzerDelegate, IAnalyzer, ImportAnalysisProvider, JavascriptAnalyzer, Language,
    MultiAnalyzer, ProjectFile, TestProject, TypescriptAnalyzer,
};
use std::collections::{BTreeMap, BTreeSet};
use tempfile::tempdir;

#[test]
fn javascript_arrow_functions_are_discovered() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    ProjectFile::new(root.to_path_buf(), "arrows.js")
        .write(
            r#"
        const myFunc = (x) => x * 2;
        const asyncFunc = async () => { return 42; };
        let anotherFunc = (a, b) => a + b;
        "#,
        )
        .unwrap();

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let file = ProjectFile::new(root.to_path_buf(), "arrows.js");
    let declarations = analyzer.get_declarations(&file);

    let functions: BTreeSet<_> = declarations
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .collect();
    assert_eq!(3, functions.len());
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name() == "myFunc")
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name() == "asyncFunc")
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name() == "anotherFunc")
    );
}

#[test]
fn javascript_import_resolution_finds_relative_helper() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    ProjectFile::new(root.to_path_buf(), "utils/helper.js")
        .write("export function helper() { return 42; }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "main.js")
        .write("import { helper } from './utils/helper';\nfunction main() { return helper(); }\n")
        .unwrap();

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let main_file = ProjectFile::new(root.to_path_buf(), "main.js");
    let imported = analyzer.imported_code_units_of(&main_file);

    assert!(imported.iter().any(|code_unit| {
        code_unit.is_function()
            && code_unit.identifier() == "helper"
            && code_unit
                .source()
                .rel_path()
                .to_string_lossy()
                .ends_with("utils/helper.js")
    }));
}

#[test]
fn typescript_aliases_are_tagged() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    ProjectFile::new(root.to_path_buf(), "src/main.ts")
        .write(
            r#"
            export type MyResult<T> = Result<T, Error>;
            class MyStruct {}
            function my_func() {}
            "#,
        )
        .unwrap();

    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let file = ProjectFile::new(root.to_path_buf(), "src/main.ts");
    let declarations = analyzer.get_declarations(&file);

    let alias = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "MyResult")
        .unwrap();
    let class = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "MyStruct")
        .unwrap();

    assert!(analyzer.is_type_alias(alias));
    assert!(!analyzer.is_type_alias(class));
}

#[test]
fn typescript_update_adds_new_definition() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "hello.ts");
    file.write("export function foo(): number { return 1; }\n")
        .unwrap();

    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    assert!(!analyzer.get_definitions("foo").is_empty());
    assert!(analyzer.get_definitions("bar").is_empty());

    file.write(
        r#"
        export function foo(): number { return 1; }
        export function bar(): number { return 2; }
        "#,
    )
    .unwrap();

    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("bar").is_empty());
}

#[test]
fn multi_analyzer_routes_javascript_and_typescript() {
    let js_temp = tempdir().unwrap();
    let ts_temp = tempdir().unwrap();
    let js_root = js_temp.path();
    let ts_root = ts_temp.path();

    let js_file = ProjectFile::new(js_root.to_path_buf(), "hello.js");
    js_file
        .write("export function helper() { return 1; }\n")
        .unwrap();
    let ts_file = ProjectFile::new(ts_root.to_path_buf(), "hello.ts");
    ts_file
        .write("export type Thing = string;\nexport function helper(): number { return 1; }\n")
        .unwrap();

    let js = JavascriptAnalyzer::from_project(TestProject::new(js_root, Language::JavaScript));
    let ts = TypescriptAnalyzer::from_project(TestProject::new(ts_root, Language::TypeScript));
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (Language::JavaScript, AnalyzerDelegate::JavaScript(js)),
        (Language::TypeScript, AnalyzerDelegate::TypeScript(ts)),
    ]));

    assert_eq!(2, multi.get_definitions("helper").len());
    assert!(
        multi
            .get_declarations(&ts_file)
            .iter()
            .any(|code_unit| code_unit.identifier() == "Thing")
    );
}
