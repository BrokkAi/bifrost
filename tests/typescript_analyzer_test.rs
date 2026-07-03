mod common;

use brokk_bifrost::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, TestProject, TypeHierarchyProvider,
    TypescriptAnalyzer,
};
use pretty_assertions::assert_eq;
use std::collections::BTreeSet;
use tempfile::tempdir;

use common::{
    InlineTestProject, assert_code_eq, assert_linewise_eq, definition, ts_fixture_project,
    write_file,
};

fn fixture_analyzer() -> TypescriptAnalyzer {
    TypescriptAnalyzer::from_project(ts_fixture_project())
}

fn ts_inline_analyzer(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::TypeScript);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn fq_names(units: impl IntoIterator<Item = CodeUnit>) -> Vec<String> {
    let mut names: Vec<_> = units.into_iter().map(|unit| unit.fq_name()).collect();
    names.sort();
    names
}

fn definition_in_file(
    analyzer: &TypescriptAnalyzer,
    file: &ProjectFile,
    fq_name: &str,
) -> CodeUnit {
    analyzer
        .get_declarations(file)
        .into_iter()
        .find(|unit| unit.fq_name() == fq_name)
        .unwrap_or_else(|| {
            panic!(
                "missing definition for {fq_name} in {}",
                file.rel_path().display()
            )
        })
}

#[test]
fn typescript_type_hierarchy_resolves_same_file_class_extends() {
    let (_project, analyzer) =
        ts_inline_analyzer(&[("models.ts", "class Base {}\nclass Child extends Base {}\n")]);

    let base = definition(&analyzer, "Base");
    let child = definition(&analyzer, "Child");

    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        vec!["Base"]
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        vec!["Child"]
    );
}

#[test]
fn typescript_type_hierarchy_resolves_imported_class_implements_interface() {
    let (_project, analyzer) = ts_inline_analyzer(&[
        ("contract.ts", "export interface Runnable {}\n"),
        (
            "worker.ts",
            "import { Runnable } from './contract';\nexport class Worker implements Runnable {}\n",
        ),
    ]);

    let runnable = definition(&analyzer, "Runnable");
    let worker = definition(&analyzer, "Worker");

    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        vec!["Runnable"]
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&runnable)),
        vec!["Worker"]
    );
}

#[test]
fn typescript_type_hierarchy_resolves_imported_interface_extends() {
    let (_project, analyzer) = ts_inline_analyzer(&[
        ("base.ts", "export interface BaseContract {}\n"),
        (
            "child.ts",
            "import { BaseContract } from './base';\nexport interface ChildContract extends BaseContract {}\n",
        ),
    ]);

    let base = definition(&analyzer, "BaseContract");
    let child = definition(&analyzer, "ChildContract");

    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        vec!["BaseContract"]
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        vec!["ChildContract"]
    );
}

#[test]
fn typescript_type_hierarchy_keeps_ambiguous_barrel_import_conservative() {
    let (_project, analyzer) = ts_inline_analyzer(&[
        ("one.ts", "export interface Contract {}\n"),
        ("two.ts", "export interface Contract {}\n"),
        (
            "barrel.ts",
            "export * from './one';\nexport * from './two';\n",
        ),
        (
            "worker.ts",
            "import { Contract } from './barrel';\nexport class Worker implements Contract {}\n",
        ),
    ]);

    let worker = definition(&analyzer, "Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
}

#[test]
fn typescript_type_hierarchy_keeps_same_named_interfaces_distinct() {
    let (project, analyzer) = ts_inline_analyzer(&[
        ("one.ts", "export interface Contract {}\n"),
        ("two.ts", "export interface Contract {}\n"),
        (
            "worker.ts",
            "import { Contract as One } from './one';\nimport { Contract as Two } from './two';\nexport class Worker implements One, Two {}\n",
        ),
    ]);

    let one_contract = definition_in_file(&analyzer, &project.file("one.ts"), "Contract");
    let two_contract = definition_in_file(&analyzer, &project.file("two.ts"), "Contract");
    let worker = definition(&analyzer, "Worker");

    let mut ancestors = analyzer.get_direct_ancestors(&worker);
    ancestors.sort();
    let mut expected = vec![one_contract.clone(), two_contract.clone()];
    expected.sort();
    assert_eq!(ancestors, expected);
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&one_contract)),
        vec!["Worker"]
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&two_contract)),
        vec!["Worker"]
    );
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
    let string_or_number = CodeUnit::new(
        hello.clone(),
        CodeUnitType::Field,
        "",
        "Hello.ts.StringOrNumber",
    );
    let local_details = CodeUnit::new(
        hello.clone(),
        CodeUnitType::Field,
        "",
        "Hello.ts.LocalDetails",
    );

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
        analyzer
            .get_skeleton(&definition(&analyzer, "globalFunc"))
            .unwrap()
    );
    assert_eq!(
        "export const PI: number = 3.14159",
        skeletons.get(&pi).unwrap()
    );
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
    assert!(
        declarations
            .iter()
            .any(|code_unit| code_unit.fq_name() == "globalFunc")
    );
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
    assert!(
        declarations
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Greeter.constructor")
    );
    assert!(
        declarations
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Greeter.greet")
    );
    assert!(declarations.contains(&CodeUnit::new(
        hello.clone(),
        CodeUnitType::Field,
        "",
        "Point.x",
    )));
    assert!(
        declarations
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Point.move")
    );
    assert!(declarations.contains(&CodeUnit::new(hello, CodeUnitType::Field, "", "Color.Red",)));
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

    assert_eq!(
        "export const MAX_USERS = 100",
        skeletons.get(&max_users).unwrap()
    );
    assert_eq!(
        "let currentUser: string = \"Alice\"",
        skeletons.get(&current_user).unwrap()
    );
    assert_eq!(
        "const config\n  host: \"localhost\"\n  port: 8080",
        skeletons.get(&config).unwrap()
    );
    assert_eq!(
        "const anArrowFunc = (msg: string): void => { ... }",
        skeletons.get(&arrow).unwrap()
    );
    assert_eq!(
        "export var legacyVar = \"legacy\"",
        skeletons.get(&legacy).unwrap()
    );
    assert_eq!(
        "function localHelper(): string { ... }",
        analyzer
            .get_skeleton(&definition(&analyzer, "localHelper"))
            .unwrap()
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
fn typescript_anonymous_arrow_default_export_indexes_default_function() {
    let (project, analyzer) = ts_inline_analyzer(&[(
        "module.ts",
        r#"
            export default (o: Options, c: Constructor, d: Dayjs) => {
                return d.extend(o, c);
            };
        "#,
    )]);
    let file = project.file("module.ts");
    let declarations = analyzer.get_declarations(&file);
    let default = declarations
        .iter()
        .find(|unit| unit.short_name() == "default")
        .expect("default export declaration");

    assert_eq!(CodeUnitType::Function, default.kind());
    assert_eq!(
        "export default (o: Options, c: Constructor, d: Dayjs) => { ... }",
        analyzer.get_skeleton(default).unwrap()
    );
    assert_eq!(
        "export default (o: Options, c: Constructor, d: Dayjs) => {\n                return d.extend(o, c);\n            };",
        analyzer.get_source(default, true).unwrap().trim()
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

    let greeter_source = analyzer
        .get_source(&definition(&analyzer, "Greeter"), true)
        .unwrap();
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
    assert!(
        method_regex
            .iter()
            .any(|name| name.contains("Greeter.greet"))
    );
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
    assert!(
        declarations
            .iter()
            .all(|code_unit| declarations.contains(code_unit))
    );
    assert!(declarations.len() > top_level.len());
    assert!(
        top_level
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Greeter")
    );
    assert!(
        !top_level
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Greeter.greet")
    );
    assert!(
        fixture_analyzer()
            .get_top_level_declarations(&ProjectFile::new(
                fixture_analyzer().project().root().to_path_buf(),
                "NonExistent.ts",
            ))
            .is_empty()
    );
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
        "const inlineObj\n  a: 1\n  b: 2",
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

#[test]
fn test_static_instance_member_overlap() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "StaticInstanceOverlap.ts",
    );
    let declarations = analyzer.get_declarations(&file);
    assert!(!declarations.is_empty());

    let color_units: Vec<_> = declarations
        .iter()
        .filter(|code_unit| code_unit.fq_name().starts_with("Color."))
        .cloned()
        .collect();

    let instance_transparent = color_units
        .iter()
        .find(|code_unit| code_unit.fq_name() == "Color.transparent")
        .unwrap();
    let static_transparent = color_units
        .iter()
        .find(|code_unit| code_unit.fq_name() == "Color.transparent$static")
        .unwrap();
    assert!(instance_transparent.is_function());
    assert!(static_transparent.is_field());

    assert!(
        color_units
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Color.normalize")
    );
    assert!(
        color_units
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Color.normalize$static")
    );
    assert!(
        color_units
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Color.count")
    );
    assert!(
        color_units
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Color.count$static")
    );
}

#[test]
fn test_call_argument_object_literal_does_not_index_variable_member_definitions() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "tool.ts",
        r#"
            export function log(definition: { handler(): void }): void {}

            export const listTools = log({
              handler(): void {},
            });
        "#,
    );
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "tool.ts.listTools.handler")
    );
    assert!(
        !analyzer
            .get_skeleton(&definition(&analyzer, "tool.ts.listTools"))
            .unwrap()
            .contains("handler")
    );
}

#[test]
fn test_function_overload_signatures() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "Overloads.ts");
    let skeletons = analyzer.get_skeletons(&file);
    assert!(!skeletons.is_empty());

    let add = skeletons
        .keys()
        .find(|code_unit| code_unit.short_name() == "add" && code_unit.is_function())
        .unwrap();
    let add_signatures = analyzer.signatures_of(add);
    assert_eq!(3, add_signatures.len());
    assert!(add_signatures.iter().any(|signature| {
        signature.contains("number") && signature.contains("(a: number, b: number)")
    }));
    assert!(add_signatures.iter().any(|signature| {
        signature.contains("string") && signature.contains("(a: string, b: string)")
    }));
    assert!(
        add_signatures
            .iter()
            .any(|signature| signature.contains("any"))
    );

    let query = skeletons
        .keys()
        .find(|code_unit| code_unit.short_name() == "query" && code_unit.is_function())
        .unwrap();
    let query_signatures = analyzer.signatures_of(query);
    assert_eq!(3, query_signatures.len());
    assert!(
        query_signatures
            .iter()
            .any(|signature| signature.contains('?'))
    );

    let combine = skeletons
        .keys()
        .find(|code_unit| code_unit.short_name() == "combine" && code_unit.is_function())
        .unwrap();
    let combine_signatures = analyzer.signatures_of(combine);
    assert_eq!(3, combine_signatures.len());
    assert!(
        combine_signatures
            .iter()
            .any(|signature| signature.contains("..."))
    );

    let map = skeletons
        .keys()
        .find(|code_unit| code_unit.short_name() == "map" && code_unit.is_function())
        .unwrap();
    let map_signatures = analyzer.signatures_of(map);
    assert_eq!(3, map_signatures.len());
    assert!(
        map_signatures
            .iter()
            .any(|signature| signature.contains("[]") && signature.contains("=>"))
    );

    let multiply = analyzer
        .get_declarations(&file)
        .into_iter()
        .find(|code_unit| code_unit.fq_name().contains("multiply"))
        .unwrap();
    let multiply_signatures = analyzer.signatures_of(&multiply);
    assert_eq!(3, multiply_signatures.len());
    assert!(
        multiply_signatures
            .iter()
            .any(|signature| signature.contains("(a: number, b: number)"))
    );
    assert!(
        multiply_signatures
            .iter()
            .any(|signature| signature.contains("(a: string, b: number)"))
    );
}

#[test]
fn test_interface_overload_signatures_preserve_source_order() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "InterfaceOverloads.ts",
        r#"
            interface Parser {
                parse(value: string): string;
                parse(value: number): number;
                parse(value: unknown): unknown;
            }
        "#,
    );
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let parse = analyzer
        .get_declarations(&file)
        .into_iter()
        .find(|code_unit| code_unit.short_name() == "Parser.parse" && code_unit.is_function())
        .unwrap();

    let signatures = analyzer.signatures_of(&parse);
    assert_eq!(
        vec![
            "parse(value: string): string",
            "parse(value: number): number",
            "parse(value: unknown): unknown",
        ],
        signatures
    );
}

#[test]
fn test_identical_overloads_merged_by_lookup_key() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "IdenticalOverloads.ts",
        r#"
            interface Logger {
                log(message: string): void;
                log(message: string): void;
            }
        "#,
    );
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let declarations = analyzer.get_declarations(&file);
    let log_methods: Vec<_> = declarations
        .iter()
        .filter(|code_unit| code_unit.short_name() == "Logger.log" && code_unit.is_function())
        .cloned()
        .collect();
    assert_eq!(1, log_methods.len());
    let signatures = analyzer.signatures_of(&log_methods[0]);
    assert_eq!(1, signatures.len());
    assert!(signatures[0].contains("log(message: string): void"));
}

#[test]
fn test_alias_signature_formatting() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(root, "AliasTest.ts", "export type Foo = string | number;");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let alias = analyzer
        .get_declarations(&file)
        .into_iter()
        .find(|code_unit| code_unit.short_name().contains("Foo"))
        .unwrap();
    let signatures = analyzer.signatures_of(&alias);
    assert!(!signatures.is_empty());
    assert_eq!("export type Foo = string | number;", signatures[0]);
}
