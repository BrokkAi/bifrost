use brokk_analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, JavascriptAnalyzer, Language, ProjectFile,
    TestProject, TypescriptAnalyzer,
};
use pretty_assertions::assert_eq;
use std::collections::BTreeSet;
use tempfile::tempdir;

fn js_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-js").unwrap(),
        Language::JavaScript,
    )
}

fn ts_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ts").unwrap(),
        Language::TypeScript,
    )
}

#[test]
fn javascript_fixture_skeletons_match_basic_brokk_shapes() {
    let analyzer = JavascriptAnalyzer::from_project(js_fixture_project());
    let root = analyzer.project().root().to_path_buf();

    let hello_jsx = ProjectFile::new(root.clone(), "Hello.jsx");
    let jsx_class = CodeUnit::new(
        hello_jsx.clone(),
        brokk_analyzer::CodeUnitType::Class,
        "",
        "JsxClass",
    );
    let jsx_arrow = CodeUnit::new(
        hello_jsx.clone(),
        brokk_analyzer::CodeUnitType::Function,
        "",
        "JsxArrowFnComponent",
    );
    let local_arrow = CodeUnit::new(
        hello_jsx.clone(),
        brokk_analyzer::CodeUnitType::Function,
        "",
        "LocalJsxArrowFn",
    );
    let plain_jsx = CodeUnit::new(
        hello_jsx.clone(),
        brokk_analyzer::CodeUnitType::Function,
        "",
        "PlainJsxFunc",
    );

    assert_eq!(
        "export class JsxClass {\n  function render(): JSX.Element ...\n}",
        analyzer.get_skeleton(&jsx_class).unwrap()
    );
    assert_eq!(
        "export JsxArrowFnComponent({ name }): JSX.Element => ...",
        analyzer.get_skeleton(&jsx_arrow).unwrap()
    );
    assert_eq!(
        "LocalJsxArrowFn() => ...",
        analyzer.get_skeleton(&local_arrow).unwrap()
    );
    assert_eq!(
        "function PlainJsxFunc() ...",
        analyzer.get_skeleton(&plain_jsx).unwrap()
    );

    let hello_js = ProjectFile::new(root, "Hello.js");
    let hello_class = CodeUnit::new(
        hello_js.clone(),
        brokk_analyzer::CodeUnitType::Class,
        "",
        "Hello",
    );
    let util_fn = CodeUnit::new(hello_js, brokk_analyzer::CodeUnitType::Function, "", "util");
    assert_eq!(
        "export class Hello {\n  function greet() ...\n}",
        analyzer.get_skeleton(&hello_class).unwrap()
    );
    assert_eq!(
        "export function util() ...",
        analyzer.get_skeleton(&util_fn).unwrap()
    );
}

#[test]
fn javascript_symbols_and_import_edges_match_current_brokk_behaviors() {
    let analyzer = JavascriptAnalyzer::from_project(js_fixture_project());
    let root = analyzer.project().root().to_path_buf();

    let hello_js = ProjectFile::new(root.clone(), "Hello.js");
    let hello_jsx = ProjectFile::new(root.clone(), "Hello.jsx");
    let vars_js = ProjectFile::new(root, "Vars.js");

    let hello_class = CodeUnit::new(hello_js, brokk_analyzer::CodeUnitType::Class, "", "Hello");
    let jsx_arrow = CodeUnit::new(
        hello_jsx.clone(),
        brokk_analyzer::CodeUnitType::Function,
        "",
        "JsxArrowFnComponent",
    );
    let top_const = CodeUnit::new(
        vars_js.clone(),
        brokk_analyzer::CodeUnitType::Field,
        "",
        "Vars.js.TOP_CONST_JS",
    );

    let symbols =
        analyzer.get_symbols(&BTreeSet::from([hello_class.clone(), jsx_arrow, top_const]));
    assert_eq!(
        BTreeSet::from([
            "Hello".to_string(),
            "greet".to_string(),
            "JsxArrowFnComponent".to_string(),
            "TOP_CONST_JS".to_string(),
        ]),
        symbols
    );

    let temp = tempdir().unwrap();
    let root = temp.path();
    ProjectFile::new(root.to_path_buf(), "polyfill.js")
        .write("export const POLYFILL_VERSION = '1.0';\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "app.js")
        .write("import './polyfill';\nfunction main() {}\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "lib/index.js")
        .write("export function libFunc() { return 'lib'; }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "main.js")
        .write("import { libFunc } from './lib';\nlibFunc();\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "util-dir.js")
        .write("export function fromFile() { return 1; }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "util-dir/index.js")
        .write("export function fromIndex() { return 2; }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "explicit.js")
        .write("import { fromFile } from './util-dir.js';\nfromFile();\n")
        .unwrap();

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let app_file = ProjectFile::new(root.to_path_buf(), "app.js");
    let main_file = ProjectFile::new(root.to_path_buf(), "main.js");
    let explicit_file = ProjectFile::new(root.to_path_buf(), "explicit.js");

    let side_effect_imports = analyzer.imported_code_units_of(&app_file);
    assert!(side_effect_imports.iter().any(|code_unit| {
        code_unit.identifier() == "POLYFILL_VERSION"
            && code_unit
                .source()
                .rel_path()
                .to_string_lossy()
                .ends_with("polyfill.js")
    }));

    let index_imports = analyzer.imported_code_units_of(&main_file);
    assert!(index_imports.iter().any(|code_unit| {
        code_unit.identifier() == "libFunc"
            && code_unit
                .source()
                .rel_path()
                .to_string_lossy()
                .ends_with("lib/index.js")
    }));

    let explicit_imports = analyzer.imported_code_units_of(&explicit_file);
    assert!(explicit_imports.iter().any(|code_unit| {
        code_unit.identifier() == "fromFile"
            && code_unit.source().rel_path().to_string_lossy() == "util-dir.js"
    }));
    assert!(!explicit_imports.iter().any(|code_unit| {
        code_unit
            .source()
            .rel_path()
            .to_string_lossy()
            .ends_with("util-dir/index.js")
    }));
}

#[test]
fn javascript_extract_type_identifiers_and_relevant_imports_work() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let work = ProjectFile::new(root.to_path_buf(), "work.js");
    work.write(
        r#"
        import { Used } from './used';
        import { Unused } from './unused';
        export function doWork() {
            Used.process();
        }
        "#,
    )
    .unwrap();
    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let do_work = analyzer
        .get_definitions("doWork")
        .into_iter()
        .next()
        .unwrap();
    let relevant = analyzer.relevant_imports_for(&do_work);
    assert_eq!(
        BTreeSet::from(["import { Used } from './used';".to_string()]),
        relevant
    );

    let identifiers = analyzer.extract_type_identifiers(
        r#"
        function useFoo() {
            const x = new Foo();
            return <Bar prop={x} />;
        }
        "#,
    );
    assert!(identifiers.contains("Foo"));
    assert!(identifiers.contains("Bar"));
    assert!(identifiers.contains("x"));
}

#[test]
fn typescript_fixture_skeletons_cover_basic_hello_and_vars_cases() {
    let analyzer = TypescriptAnalyzer::from_project(ts_fixture_project());
    let root = analyzer.project().root().to_path_buf();
    let hello = ProjectFile::new(root.clone(), "Hello.ts");
    let vars = ProjectFile::new(root, "Vars.ts");

    let greeter = CodeUnit::new(
        hello.clone(),
        brokk_analyzer::CodeUnitType::Class,
        "",
        "Greeter",
    );
    let pi = CodeUnit::new(
        hello.clone(),
        brokk_analyzer::CodeUnitType::Field,
        "",
        "Hello.ts.PI",
    );
    let string_or_number = CodeUnit::new(
        hello,
        brokk_analyzer::CodeUnitType::Field,
        "",
        "Hello.ts.StringOrNumber",
    );
    let max_users = CodeUnit::new(
        vars.clone(),
        brokk_analyzer::CodeUnitType::Field,
        "",
        "Vars.ts.MAX_USERS",
    );
    let config = CodeUnit::new(
        vars.clone(),
        brokk_analyzer::CodeUnitType::Field,
        "",
        "Vars.ts.config",
    );
    let global_func = analyzer
        .get_definitions("globalFunc")
        .into_iter()
        .next()
        .unwrap();
    let arrow = analyzer
        .get_definitions("anArrowFunc")
        .into_iter()
        .next()
        .unwrap();

    assert!(
        analyzer
            .get_skeleton(&greeter)
            .unwrap()
            .contains("export class Greeter")
    );
    assert!(
        analyzer
            .get_skeleton(&greeter)
            .unwrap()
            .contains("constructor(message: string) { ... }")
    );
    assert_eq!(
        "export function globalFunc(num: number): number { ... }",
        analyzer.get_skeleton(&global_func).unwrap()
    );
    assert_eq!(
        "export const PI: number = 3.14159",
        analyzer.get_skeleton(&pi).unwrap()
    );
    assert_eq!(
        "export type StringOrNumber = string | number",
        analyzer.get_skeleton(&string_or_number).unwrap()
    );
    assert_eq!(
        "export const MAX_USERS = 100",
        analyzer.get_skeleton(&max_users).unwrap()
    );
    assert_eq!("const config", analyzer.get_skeleton(&config).unwrap());
    assert_eq!(
        "const anArrowFunc = (msg: string): void => { ... }",
        analyzer.get_skeleton(&arrow).unwrap()
    );
}

#[test]
fn typescript_import_edges_and_type_identifiers_match_brokk_cases() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    ProjectFile::new(root.to_path_buf(), "utils/greet.ts")
        .write("export function greet(): string { return 'hello'; }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "main.ts")
        .write("import { greet } from './utils/greet.ts';\nfunction main(): string { return greet(); }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "lib/index.ts")
        .write("export function libFunc(): string { return 'lib'; }\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "dir.ts")
        .write("import { libFunc } from './lib';\nlibFunc();\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "external.ts")
        .write("import _ from 'lodash';\nfunction foo(): void {}\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    let main_file = ProjectFile::new(root.to_path_buf(), "main.ts");
    let dir_file = ProjectFile::new(root.to_path_buf(), "dir.ts");
    let external_file = ProjectFile::new(root.to_path_buf(), "external.ts");
    let greet_file = ProjectFile::new(root.to_path_buf(), "utils/greet.ts");
    let index_file = ProjectFile::new(root.to_path_buf(), "lib/index.ts");

    let imports = analyzer.imported_code_units_of(&main_file);
    assert!(
        imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "greet")
    );

    let dir_imports = analyzer.imported_code_units_of(&dir_file);
    assert!(dir_imports.iter().any(|code_unit| {
        code_unit.identifier() == "libFunc"
            && code_unit
                .source()
                .rel_path()
                .to_string_lossy()
                .ends_with("lib/index.ts")
    }));

    let main_import_info = analyzer.import_info_of(&main_file);
    assert!(analyzer.could_import_file(&main_file, &main_import_info, &greet_file));
    let dir_import_info = analyzer.import_info_of(&dir_file);
    assert!(analyzer.could_import_file(&dir_file, &dir_import_info, &index_file));
    let external_import_info = analyzer.import_info_of(&external_file);
    assert!(!analyzer.could_import_file(&external_file, &external_import_info, &greet_file));

    let identifiers = analyzer.extract_type_identifiers(
        r#"
        function process(input: Foo): void {
            console.log(input);
        }
        "#,
    );
    assert!(identifiers.contains("Foo"));
    assert!(identifiers.contains("input"));
    assert!(identifiers.contains("process"));
}
