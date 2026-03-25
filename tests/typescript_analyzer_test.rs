mod common;

use brokk_analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, TestProject, TypescriptAnalyzer,
};
use pretty_assertions::assert_eq;
use std::collections::BTreeSet;
use tempfile::tempdir;

use common::{assert_code_eq, assert_linewise_eq, definition, ts_fixture_project, write_file};

fn fixture_analyzer() -> TypescriptAnalyzer {
    TypescriptAnalyzer::from_project(ts_fixture_project())
}

#[test]
fn test_hello_ts_skeletons() {
    let analyzer = fixture_analyzer();
    let hello = ProjectFile::new(analyzer.project().root().to_path_buf(), "Hello.ts");
    let skeletons = analyzer.get_skeletons(&hello);

    let greeter = CodeUnit::new(hello.clone(), CodeUnitType::Class, "", "Greeter");
    let _global_func = CodeUnit::new(hello.clone(), CodeUnitType::Function, "", "globalFunc");
    let pi = CodeUnit::new(hello.clone(), CodeUnitType::Field, "", "Hello.ts.PI");
    let point = CodeUnit::new(hello.clone(), CodeUnitType::Class, "", "Point");
    let color = CodeUnit::new(hello.clone(), CodeUnitType::Class, "", "Color");
    let string_or_number =
        CodeUnit::new(hello.clone(), CodeUnitType::Field, "", "Hello.ts.StringOrNumber");
    let local_details = CodeUnit::new(hello.clone(), CodeUnitType::Field, "", "Hello.ts.LocalDetails");

    assert_code_eq(
        r#"
        export class Greeter {
          greeting: string
          constructor(message: string) { ... }
          greet(): string { ... }
        }
        "#,
        skeletons.get(&greeter).unwrap(),
    );
    assert_eq!(
        "export function globalFunc(num: number): number { ... }",
        analyzer.get_skeleton(&definition(&analyzer, "globalFunc")).unwrap()
    );
    assert_eq!("export const PI: number = 3.14159", skeletons.get(&pi).unwrap());
    assert_code_eq(
        r#"
        export interface Point {
          x: number
          y: number
          label?: string
          readonly originDistance?: number
          move(dx: number, dy: number): void
        }
        "#,
        skeletons.get(&point).unwrap(),
    );
    assert_code_eq(
        r#"
        export enum Color {
          Red,
          Green = 3,
          Blue
        }
        "#,
        skeletons.get(&color).unwrap(),
    );
    assert_eq!(
        "export type StringOrNumber = string | number",
        skeletons.get(&string_or_number).unwrap()
    );
    assert_eq!(
        "type LocalDetails = { id: number, name: string }",
        skeletons.get(&local_details).unwrap()
    );

    let declarations = analyzer.get_declarations(&hello);
    assert!(declarations.contains(&greeter));
    assert!(declarations
        .iter()
        .any(|code_unit| code_unit.fq_name() == "globalFunc"));
    assert!(declarations.contains(&pi));
    assert!(declarations.contains(&point));
    assert!(declarations.contains(&color));
    assert!(declarations.contains(&string_or_number));
    assert!(declarations.contains(&local_details));
    assert!(declarations.contains(&CodeUnit::new(
        hello.clone(),
        CodeUnitType::Field,
        "",
        "Greeter.greeting",
    )));
    assert!(declarations
        .iter()
        .any(|code_unit| code_unit.fq_name() == "Greeter.constructor"));
    assert!(declarations
        .iter()
        .any(|code_unit| code_unit.fq_name() == "Greeter.greet"));
    assert!(declarations.contains(&CodeUnit::new(
        hello.clone(),
        CodeUnitType::Field,
        "",
        "Point.x",
    )));
    assert!(declarations
        .iter()
        .any(|code_unit| code_unit.fq_name() == "Point.move"));
    assert!(declarations.contains(&CodeUnit::new(
        hello,
        CodeUnitType::Field,
        "",
        "Color.Red",
    )));
}

#[test]
fn test_vars_ts_skeletons_and_arrow_function_classification() {
    let analyzer = fixture_analyzer();
    let vars = ProjectFile::new(analyzer.project().root().to_path_buf(), "Vars.ts");
    let skeletons = analyzer.get_skeletons(&vars);

    let max_users = CodeUnit::new(vars.clone(), CodeUnitType::Field, "", "Vars.ts.MAX_USERS");
    let current_user = CodeUnit::new(vars.clone(), CodeUnitType::Field, "", "Vars.ts.currentUser");
    let config = CodeUnit::new(vars.clone(), CodeUnitType::Field, "", "Vars.ts.config");
    let arrow = CodeUnit::new(vars.clone(), CodeUnitType::Function, "", "anArrowFunc");
    let legacy = CodeUnit::new(vars.clone(), CodeUnitType::Field, "", "Vars.ts.legacyVar");
    let _local_helper = CodeUnit::new(vars, CodeUnitType::Function, "", "localHelper");

    assert_eq!("export const MAX_USERS = 100", skeletons.get(&max_users).unwrap());
    assert_eq!(
        "let currentUser: string = \"Alice\"",
        skeletons.get(&current_user).unwrap()
    );
    assert_eq!("const config", skeletons.get(&config).unwrap());
    assert_eq!(
        "const anArrowFunc = (msg: string): void => { ... }",
        skeletons.get(&arrow).unwrap()
    );
    assert_eq!("export var legacyVar = \"legacy\"", skeletons.get(&legacy).unwrap());
    assert_eq!(
        "function localHelper(): string { ... }",
        analyzer.get_skeleton(&definition(&analyzer, "localHelper")).unwrap()
    );
}

#[test]
fn test_default_export_skeletons() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "DefaultExport.ts");
    let skeletons = analyzer.get_skeletons(&file);

    assert_code_eq(
        r#"
        export default class MyDefaultClass {
          constructor() { ... }
          doSomething(): void { ... }
          get value(): string { ... }
        }
        "#,
        skeletons
            .get(&CodeUnit::new(
                file.clone(),
                CodeUnitType::Class,
                "",
                "MyDefaultClass",
            ))
            .unwrap(),
    );
    assert_eq!(
        "export default function myDefaultFunction(param: string): string { ... }",
        analyzer
            .get_skeleton(&definition(&analyzer, "myDefaultFunction"))
            .unwrap()
    );
    assert_code_eq(
        r#"
        export class AnotherNamedClass {
          name: string = "Named"
        }
        "#,
        skeletons
            .get(&CodeUnit::new(
                file.clone(),
                CodeUnitType::Class,
                "",
                "AnotherNamedClass",
            ))
            .unwrap(),
    );
    assert_eq!(
        "export const utilityRate: number = 0.15",
        skeletons
            .get(&CodeUnit::new(
                file.clone(),
                CodeUnitType::Field,
                "",
                "DefaultExport.ts.utilityRate",
            ))
            .unwrap()
    );
    assert_eq!(
        "export default type DefaultAlias = boolean",
        skeletons
            .get(&CodeUnit::new(
                file,
                CodeUnitType::Field,
                "",
                "DefaultExport.ts.DefaultAlias",
            ))
            .unwrap()
    );
}

#[test]
fn test_get_method_source_get_symbols_and_get_class_source() {
    let analyzer = fixture_analyzer();

    assert_linewise_eq(
        r#"
        greet(): string {
            return "Hello, " + this.greeting;
        }
        "#,
        &analyzer
            .get_source(&definition(&analyzer, "Greeter.greet"), true)
            .unwrap(),
    );
    assert_linewise_eq(
        r#"
        constructor(message: string) {
            this.greeting = message;
        }
        "#,
        &analyzer
            .get_source(&definition(&analyzer, "Greeter.constructor"), true)
            .unwrap(),
    );
    assert_linewise_eq(
        r#"
        const anArrowFunc = (msg: string): void => {
            console.log(msg);
        };
        "#,
        &analyzer
            .get_source(&definition(&analyzer, "anArrowFunc"), true)
            .unwrap(),
    );
    assert!(
        analyzer
            .get_source(&definition(&analyzer, "asyncNamedFunc"), true)
            .unwrap()
            .contains("export async function asyncNamedFunc")
    );

    let hello = ProjectFile::new(analyzer.project().root().to_path_buf(), "Hello.ts");
    let vars = ProjectFile::new(analyzer.project().root().to_path_buf(), "Vars.ts");
    let symbols = analyzer.get_symbols(&BTreeSet::from([
        CodeUnit::new(hello.clone(), CodeUnitType::Class, "", "Greeter"),
        CodeUnit::new(hello.clone(), CodeUnitType::Field, "", "Hello.ts.PI"),
        CodeUnit::new(vars, CodeUnitType::Field, "", "Vars.ts.anArrowFunc"),
        CodeUnit::new(hello, CodeUnitType::Field, "", "Hello.ts.StringOrNumber"),
    ]));
    assert_eq!(
        BTreeSet::from([
            "Greeter".to_string(),
            "greeting".to_string(),
            "constructor".to_string(),
            "greet".to_string(),
            "PI".to_string(),
            "anArrowFunc".to_string(),
            "StringOrNumber".to_string(),
        ]),
        symbols
    );

    let greeter_source = analyzer.get_source(&definition(&analyzer, "Greeter"), true).unwrap();
    assert!(greeter_source.starts_with("export class Greeter"));
    assert!(greeter_source.contains("greeting: string;"));
    assert!(greeter_source.contains("greet(): string {"));
}

#[test]
fn test_search_definitions_case_sensitive_and_regex() {
    let analyzer = fixture_analyzer();
    let lower: BTreeSet<_> = analyzer
        .search_definitions("greeter", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    let upper: BTreeSet<_> = analyzer
        .search_definitions("GREETER", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(lower, upper);

    let greeter_regex: BTreeSet<_> = analyzer
        .search_definitions(".*Greeter.*", false)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(greeter_regex.iter().any(|name| name.contains("Greeter")));

    let color: BTreeSet<_> = analyzer
        .search_definitions("Color", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(color.iter().any(|name| name.contains("Color")));

    let method_regex: BTreeSet<_> = analyzer
        .search_definitions(".*\\.greet", false)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(method_regex.iter().any(|name| name.contains("Greeter.greet")));
}

#[test]
fn test_file_filtering_and_top_level_behavior() {
    let analyzer = fixture_analyzer();
    let java_file = ProjectFile::new(analyzer.project().root().to_path_buf(), "test/A.java");
    assert!(analyzer.get_skeletons(&java_file).is_empty());
    assert!(analyzer.get_declarations(&java_file).is_empty());

    let temp = tempdir().unwrap();
    let root = temp.path();
    write_file(root, "valid.ts", "export const ok = 1;\n");
    write_file(root, "valid.js", "export const jsValue = 1;\n");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    assert!(!analyzer.get_definitions("valid.ts.ok").is_empty());
    let updated = analyzer.update(&BTreeSet::from([
        ProjectFile::new(root.to_path_buf(), "valid.ts"),
        ProjectFile::new(root.to_path_buf(), "valid.js"),
        ProjectFile::new(root.to_path_buf(), "invalid.java"),
        ProjectFile::new(root.to_path_buf(), "invalid.py"),
    ]));
    assert!(!updated.get_definitions("valid.ts.ok").is_empty());

    let no_relevant = updated.update(&BTreeSet::from([
        ProjectFile::new(root.to_path_buf(), "test.java"),
        ProjectFile::new(root.to_path_buf(), "test.py"),
        ProjectFile::new(root.to_path_buf(), "test.rs"),
    ]));
    assert!(!no_relevant.get_definitions("valid.ts.ok").is_empty());

    assert_eq!(Language::TypeScript, Language::from_extension("ts"));
    assert_eq!(Language::TypeScript, Language::from_extension("tsx"));
    assert_eq!(Language::JavaScript, Language::from_extension("js"));
    assert_eq!(Language::JavaScript, Language::from_extension("jsx"));

    let hello = ProjectFile::new(
        fixture_analyzer().project().root().to_path_buf(),
        "Hello.ts",
    );
    let top_level = fixture_analyzer().get_top_level_declarations(&hello);
    let declarations = fixture_analyzer().get_declarations(&hello);
    assert!(declarations.iter().all(|code_unit| declarations.contains(code_unit)));
    assert!(declarations.len() > top_level.len());
    assert!(top_level.iter().any(|code_unit| code_unit.fq_name() == "Greeter"));
    assert!(!top_level
        .iter()
        .any(|code_unit| code_unit.fq_name() == "Greeter.greet"));
    assert!(fixture_analyzer()
        .get_top_level_declarations(&ProjectFile::new(
            fixture_analyzer().project().root().to_path_buf(),
            "NonExistent.ts",
        ))
        .is_empty());
}

#[test]
fn test_complex_field_initializer_and_multi_assignment_signatures() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let fields = write_file(
        root,
        "fields.ts",
        r#"
            export const simpleInt: number = 42;
            let simpleString: string = "hello";
            var complexObj: ComplexType = new ComplexObject("args");
            const inlineObj = { a: 1, b: 2 };
        "#,
    );
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let skeletons = analyzer.get_skeletons(&fields);
    assert_eq!(
        "export const simpleInt: number = 42",
        skeletons
            .get(&definition(&analyzer, "fields.ts.simpleInt"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "let simpleString: string = \"hello\"",
        skeletons
            .get(&definition(&analyzer, "fields.ts.simpleString"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "var complexObj: ComplexType",
        skeletons
            .get(&definition(&analyzer, "fields.ts.complexObj"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "const inlineObj",
        skeletons
            .get(&definition(&analyzer, "fields.ts.inlineObj"))
            .unwrap()
            .trim()
    );

    let multi = write_file(
        root,
        "multi.ts",
        "export const a: number = 1, b: number = 2;\nlet x = 'one', y = 'two';",
    );
    let updated = analyzer.update_all();
    let multi_skeletons = updated.get_skeletons(&multi);
    assert_eq!(
        "export const a: number = 1",
        multi_skeletons
            .get(&CodeUnit::new(
                multi.clone(),
                CodeUnitType::Field,
                "",
                "multi.ts.a",
            ))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "export const b: number = 2",
        multi_skeletons
            .get(&CodeUnit::new(
                multi.clone(),
                CodeUnitType::Field,
                "",
                "multi.ts.b",
            ))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "let x = 'one'",
        multi_skeletons
            .get(&CodeUnit::new(
                multi.clone(),
                CodeUnitType::Field,
                "",
                "multi.ts.x",
            ))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "let y = 'two'",
        multi_skeletons
            .get(&CodeUnit::new(multi, CodeUnitType::Field, "", "multi.ts.y"))
            .unwrap()
            .trim()
    );
}
