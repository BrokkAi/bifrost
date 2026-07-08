mod common;

use brokk_bifrost::{
    CodeUnit, CodeUnitType, IAnalyzer, JavascriptAnalyzer, Language, ProjectFile, TestProject,
    TypeHierarchyProvider,
};
use pretty_assertions::assert_eq;
use std::collections::BTreeSet;
use tempfile::tempdir;

use common::{InlineTestProject, assert_code_eq, definition, js_fixture_project, write_file};

fn fixture_analyzer() -> JavascriptAnalyzer {
    JavascriptAnalyzer::from_project(js_fixture_project())
}

fn js_inline_analyzer(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, JavascriptAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::JavaScript);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn fq_names(units: impl IntoIterator<Item = CodeUnit>) -> Vec<String> {
    let mut names: Vec<_> = units.into_iter().map(|unit| unit.fq_name()).collect();
    names.sort();
    names
}

fn definition_in_file(
    analyzer: &JavascriptAnalyzer,
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
fn javascript_materializes_exported_factory_object_surface() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "tool.js",
        r#"
            export const ReadTool = Tool.define({
                execute() {
                    return true;
                },
                metadata: { name: 'read' },
                [dynamicKey]() {}
            });
        "#,
    )]);
    let file = project.file("tool.js");
    let declarations = analyzer.get_declarations(&file);

    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "",
        "ReadTool",
    )));
    assert!(
        declarations
            .iter()
            .all(|unit| unit.short_name() != "ReadTool.dynamicKey")
    );
    assert!(
        !analyzer
            .get_skeleton(&definition_in_file(&analyzer, &file, "ReadTool"))
            .unwrap()
            .contains("execute")
    );
}

#[test]
fn javascript_materializes_commonjs_exported_object_root() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "context.js",
        r#"
            const proto = {
                inspect() {
                    return this;
                },
                status: 200
            };
            module.exports = proto;
        "#,
    )]);
    let file = project.file("context.js");
    let declarations = analyzer.get_declarations(&file);

    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "",
        "proto",
    )));
}

#[test]
fn javascript_does_not_promote_commonjs_member_reexport_root() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "context.js",
        r#"
            const internals = {
                public() {},
                secret() {}
            };
            exports.public = internals.public;
        "#,
    )]);
    let file = project.file("context.js");
    let declarations = analyzer.get_declarations(&file);

    assert!(declarations.iter().all(|unit| {
        unit.short_name() != "internals"
            && unit.short_name() != "internals.public"
            && unit.short_name() != "internals.secret"
    }));
}

#[test]
fn javascript_materializes_returned_object_members_under_enclosing_factory() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "directive.js",
        r#"
            function selectDirective() {
                return {
                    compile() {},
                    controller: function() {}
                };
            }

            const factory = () => ({
                run() {},
                label: 'x'
            });
            export { factory };
        "#,
    )]);
    let file = project.file("directive.js");
    let declarations = analyzer.get_declarations(&file);

    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Function,
        "",
        "selectDirective.compile",
    )));
    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Function,
        "",
        "selectDirective.controller",
    )));
    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Function,
        "",
        "factory.run",
    )));
    assert!(declarations.contains(&CodeUnit::new(
        file,
        CodeUnitType::Field,
        "",
        "factory.label",
    )));
}

#[test]
fn javascript_does_not_materialize_unexported_call_or_scalar_surfaces() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "module.js",
        r#"
            const local = makeThing({ run() {} });
            export const PI = 3.14;
        "#,
    )]);
    let file = project.file("module.js");
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .all(|unit| unit.short_name() != "local" && unit.short_name() != "local.run")
    );
    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "",
        "module.js.local",
    )));
    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "",
        "module.js.PI",
    )));
    assert!(
        declarations
            .iter()
            .all(|unit| !(unit.short_name() == "PI" && unit.source() == &file))
    );
}

#[test]
fn javascript_local_non_shape_preserving_define_function_blocks_surface_members() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "tool.js",
        r#"
            function defineThing(definition) {
                return { wrapped: definition };
            }
            export const Tool = defineThing({ run() {} });
        "#,
    )]);
    let file = project.file("tool.js");
    let declarations = analyzer.get_declarations(&file);

    assert!(declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "",
        "tool.js.Tool",
    )));
    assert!(
        declarations
            .iter()
            .all(|unit| unit.short_name() != "Tool.run")
    );
}

#[test]
fn javascript_type_hierarchy_resolves_same_file_extends() {
    let (_project, analyzer) =
        js_inline_analyzer(&[("models.js", "class Base {}\nclass Child extends Base {}\n")]);

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
fn javascript_type_hierarchy_resolves_imported_extends() {
    let (_project, analyzer) = js_inline_analyzer(&[
        ("base.js", "export class Base {}\n"),
        (
            "child.js",
            "import { Base } from './base';\nexport class Child extends Base {}\n",
        ),
    ]);

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
fn javascript_type_hierarchy_keeps_ambiguous_barrel_import_conservative() {
    let (_project, analyzer) = js_inline_analyzer(&[
        ("one.js", "export class Base {}\n"),
        ("two.js", "export class Base {}\n"),
        (
            "barrel.js",
            "export * from './one';\nexport * from './two';\n",
        ),
        (
            "child.js",
            "import { Base } from './barrel';\nexport class Child extends Base {}\n",
        ),
    ]);

    let child = definition(&analyzer, "Child");

    assert!(analyzer.get_direct_ancestors(&child).is_empty());
}

#[test]
fn javascript_type_hierarchy_direct_descendants_are_not_transitive() {
    let (_project, analyzer) = js_inline_analyzer(&[(
        "models.js",
        "class Base {}\nclass Mid extends Base {}\nclass Child extends Mid {}\n",
    )]);

    let base = definition(&analyzer, "Base");
    let mid = definition(&analyzer, "Mid");

    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        vec!["Mid"]
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&mid)),
        vec!["Child"]
    );
}

#[test]
fn javascript_type_hierarchy_keeps_same_named_modules_distinct() {
    let (project, analyzer) = js_inline_analyzer(&[
        ("one.js", "export class Base {}\n"),
        ("two.js", "export class Base {}\n"),
        (
            "child.js",
            "import { Base } from './one';\nexport class Child extends Base {}\n",
        ),
    ]);

    let one_base = definition_in_file(&analyzer, &project.file("one.js"), "Base");
    let two_base = definition_in_file(&analyzer, &project.file("two.js"), "Base");
    let child = definition(&analyzer, "Child");

    assert_eq!(
        analyzer.get_direct_ancestors(&child),
        vec![one_base.clone()]
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&one_base)),
        vec!["Child"]
    );
    assert!(analyzer.get_direct_descendants(&two_base).is_empty());
}

#[test]
fn javascript_type_hierarchy_resolves_commonjs_default_parent() {
    let (_project, analyzer) = js_inline_analyzer(&[
        ("base.js", "class Base {}\nmodule.exports = Base;\n"),
        (
            "child.js",
            "const Base = require('./base');\nclass Child extends Base {}\n",
        ),
    ]);

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
fn test_javascript_jsx_skeletons() {
    let analyzer = fixture_analyzer();
    let root = analyzer.project().root().to_path_buf();
    let hello_jsx = ProjectFile::new(root.clone(), "Hello.jsx");
    let hello_js = ProjectFile::new(root, "Hello.js");

    let skel_jsx = analyzer.get_skeletons(&hello_jsx);
    let jsx_class = CodeUnit::new(hello_jsx.clone(), CodeUnitType::Class, "", "JsxClass");
    let jsx_arrow = CodeUnit::new(
        hello_jsx.clone(),
        CodeUnitType::Function,
        "",
        "JsxArrowFnComponent",
    );
    let local_arrow = CodeUnit::new(
        hello_jsx.clone(),
        CodeUnitType::Function,
        "",
        "LocalJsxArrowFn",
    );
    let plain_jsx = CodeUnit::new(
        hello_jsx.clone(),
        CodeUnitType::Function,
        "",
        "PlainJsxFunc",
    );

    assert!(skel_jsx.contains_key(&jsx_class));
    assert!(skel_jsx.contains_key(&jsx_arrow));
    assert!(skel_jsx.contains_key(&local_arrow));
    assert!(skel_jsx.contains_key(&plain_jsx));
    assert_code_eq(
        r#"
        export class JsxClass {
          function render(): JSX.Element ...
        }
        "#,
        skel_jsx.get(&jsx_class).unwrap(),
    );
    assert_code_eq(
        "export JsxArrowFnComponent({ name }): JSX.Element => ...",
        skel_jsx.get(&jsx_arrow).unwrap(),
    );
    assert_code_eq(
        "LocalJsxArrowFn() => ...",
        skel_jsx.get(&local_arrow).unwrap(),
    );
    assert_code_eq(
        "function PlainJsxFunc() ...",
        skel_jsx.get(&plain_jsx).unwrap(),
    );

    let declarations = analyzer.get_declarations(&hello_jsx);
    assert!(declarations.contains(&jsx_class));
    assert!(declarations.contains(&jsx_arrow));
    assert!(declarations.contains(&local_arrow));
    assert!(declarations.contains(&plain_jsx));
    assert!(declarations.contains(&CodeUnit::new(
        hello_jsx.clone(),
        CodeUnitType::Function,
        "",
        "JsxClass.render",
    )));

    let skel_js = analyzer.get_skeletons(&hello_js);
    let hello_class = CodeUnit::new(hello_js.clone(), CodeUnitType::Class, "", "Hello");
    let util = CodeUnit::new(hello_js, CodeUnitType::Function, "", "util");
    assert_code_eq(
        r#"
        export class Hello {
          function greet() ...
        }
        "#,
        skel_js.get(&hello_class).unwrap(),
    );
    assert_code_eq("export function util() ...", skel_js.get(&util).unwrap());
}

#[test]
fn test_javascript_get_symbols() {
    let analyzer = fixture_analyzer();
    let root = analyzer.project().root().to_path_buf();
    let hello_js = ProjectFile::new(root.clone(), "Hello.js");
    let hello_jsx = ProjectFile::new(root.clone(), "Hello.jsx");
    let vars_js = ProjectFile::new(root, "Vars.js");

    let symbols = analyzer.get_symbols(&BTreeSet::from([
        CodeUnit::new(hello_js.clone(), CodeUnitType::Class, "", "Hello"),
        CodeUnit::new(
            hello_jsx.clone(),
            CodeUnitType::Function,
            "",
            "JsxArrowFnComponent",
        ),
        CodeUnit::new(
            vars_js.clone(),
            CodeUnitType::Field,
            "",
            "Vars.js.TOP_CONST_JS",
        ),
    ]));
    assert_eq!(
        BTreeSet::from([
            "Hello".to_string(),
            "greet".to_string(),
            "JsxArrowFnComponent".to_string(),
            "TOP_CONST_JS".to_string(),
        ]),
        symbols
    );

    assert!(analyzer.get_symbols(&BTreeSet::new()).is_empty());
    assert_eq!(
        BTreeSet::from(["util".to_string()]),
        analyzer.get_symbols(&BTreeSet::from([CodeUnit::new(
            hello_js,
            CodeUnitType::Function,
            "",
            "util",
        )]))
    );
    assert_eq!(
        BTreeSet::from(["JsxClass".to_string(), "render".to_string()]),
        analyzer.get_symbols(&BTreeSet::from([CodeUnit::new(
            hello_jsx.clone(),
            CodeUnitType::Class,
            "",
            "JsxClass",
        )]))
    );
    assert_eq!(
        BTreeSet::from(["localVarJs".to_string()]),
        analyzer.get_symbols(&BTreeSet::from([CodeUnit::new(
            vars_js,
            CodeUnitType::Field,
            "",
            "Vars.js.localVarJs",
        )]))
    );
}

#[test]
fn test_jsx_features_skeletons() {
    let analyzer = fixture_analyzer();
    let features_file =
        ProjectFile::new(analyzer.project().root().to_path_buf(), "FeaturesTest.jsx");
    let skeletons = analyzer.get_skeletons(&features_file);

    let module = CodeUnit::new(
        features_file.clone(),
        CodeUnitType::Module,
        "",
        "FeaturesTest.jsx",
    );
    assert!(skeletons.contains_key(&module));
    assert_code_eq(
        r#"
        import React, { useState } from 'react';
        import { Something, AnotherThing as AT } from './another-module';
        import * as AllThings from './all-the-things';
        import DefaultThing from './default-thing';
        "#,
        skeletons.get(&module).unwrap(),
    );

    assert_code_eq(
        r#"
        // mutates: counter, wasUpdated
        export function MyExportedComponent(props): JSX.Element ...
        "#,
        skeletons
            .get(&CodeUnit::new(
                features_file.clone(),
                CodeUnitType::Function,
                "",
                "MyExportedComponent",
            ))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        // mutates: localStatus
        export MyExportedArrowComponent({ id }): JSX.Element => ...
        "#,
        skeletons
            .get(&CodeUnit::new(
                features_file.clone(),
                CodeUnitType::Function,
                "",
                "MyExportedArrowComponent",
            ))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        // mutates: isValid
        function internalProcessingUtil(dataObject) ...
        "#,
        skeletons
            .get(&CodeUnit::new(
                features_file.clone(),
                CodeUnitType::Function,
                "",
                "internalProcessingUtil",
            ))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        // mutates: global_config_val
        export function updateGlobalConfig(newVal) ...
        "#,
        skeletons
            .get(&CodeUnit::new(
                features_file.clone(),
                CodeUnitType::Function,
                "",
                "updateGlobalConfig",
            ))
            .unwrap(),
    );
    assert_code_eq(
        "export function ComponentWithComment(user /*: UserType */): JSX.Element ...",
        skeletons
            .get(&CodeUnit::new(
                features_file.clone(),
                CodeUnitType::Function,
                "",
                "ComponentWithComment",
            ))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        // mutates: age, name
        export function modifyUser(user) ...
        "#,
        skeletons
            .get(&CodeUnit::new(
                features_file.clone(),
                CodeUnitType::Function,
                "",
                "modifyUser",
            ))
            .unwrap(),
    );
}

#[test]
fn test_javascript_top_level_variables_and_usage_page_imports() {
    let analyzer = fixture_analyzer();
    let root = analyzer.project().root().to_path_buf();
    let vars_file = ProjectFile::new(root.clone(), "Vars.js");
    let skeletons = analyzer.get_skeletons(&vars_file);
    let top_const = CodeUnit::new(
        vars_file.clone(),
        CodeUnitType::Field,
        "",
        "Vars.js.TOP_CONST_JS",
    );
    let local_var = CodeUnit::new(
        vars_file.clone(),
        CodeUnitType::Field,
        "",
        "Vars.js.localVarJs",
    );

    assert_eq!(
        "export const TOP_CONST_JS = 123",
        skeletons.get(&top_const).unwrap().trim()
    );
    assert_eq!(
        "let localVarJs = \"abc\"",
        skeletons.get(&local_var).unwrap().trim()
    );
    assert!(analyzer.get_declarations(&vars_file).contains(&top_const));
    assert!(analyzer.get_declarations(&vars_file).contains(&local_var));

    let usage_page = ProjectFile::new(root, "UsagePage.jsx");
    let usage_skeletons = analyzer.get_skeletons(&usage_page);
    let module = CodeUnit::new(usage_page, CodeUnitType::Module, "", "UsagePage.jsx");
    let import_lines = usage_skeletons
        .get(&module)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    assert_eq!(44, import_lines);
}

#[test]
fn test_get_skeleton_header_members_definitions_and_search() {
    let analyzer = fixture_analyzer();

    assert_code_eq(
        r#"
        export class JsxClass {
          [...]
        }
        "#,
        &analyzer
            .get_skeleton_header(&definition(&analyzer, "JsxClass"))
            .unwrap(),
    );
    assert_eq!(
        "export JsxArrowFnComponent({ name }): JSX.Element => ...",
        analyzer
            .get_skeleton_header(&definition(&analyzer, "JsxArrowFnComponent"))
            .unwrap()
    );
    assert_eq!(
        "export function util() ...",
        analyzer
            .get_skeleton_header(&definition(&analyzer, "util"))
            .unwrap()
    );
    assert!(analyzer.get_definitions("NonExistentSymbol").is_empty());

    let jsx_members = analyzer.get_members_in_class(&definition(&analyzer, "JsxClass"));
    assert_eq!(1, jsx_members.len());
    assert!(
        jsx_members
            .iter()
            .any(|code_unit| code_unit.fq_name() == "JsxClass.render")
    );
    let hello_members = analyzer.get_members_in_class(&definition(&analyzer, "Hello"));
    assert_eq!(1, hello_members.len());
    assert!(
        hello_members
            .iter()
            .any(|code_unit| code_unit.fq_name() == "Hello.greet")
    );
    assert!(
        analyzer
            .get_members_in_class(&definition(&analyzer, "util"))
            .is_empty()
    );

    assert_eq!(
        "Hello.jsx",
        definition(&analyzer, "JsxClass")
            .source()
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    );
    assert_eq!(
        "Hello.jsx",
        definition(&analyzer, "JsxClass.render")
            .source()
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    );
    assert_eq!(
        "Vars.js",
        definition(&analyzer, "Vars.js.TOP_CONST_JS")
            .source()
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    );

    let jsx_results: BTreeSet<_> = analyzer
        .search_definitions("Jsx", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(jsx_results.contains("JsxClass"));
    assert!(jsx_results.contains("JsxClass.render"));
    assert!(jsx_results.contains("JsxArrowFnComponent"));
    assert!(jsx_results.contains("LocalJsxArrowFn"));
    assert!(jsx_results.contains("PlainJsxFunc"));

    let render_results: BTreeSet<_> = analyzer
        .search_definitions(".render", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(
        BTreeSet::from(["JsxClass.render".to_string()]),
        render_results
    );

    let lower: BTreeSet<_> = analyzer
        .search_definitions("hello", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    let upper: BTreeSet<_> = analyzer
        .search_definitions("HELLO", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(lower, upper);

    let regex: BTreeSet<_> = analyzer
        .search_definitions(".*\\..*", false)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(regex.contains("Hello.greet"));
    assert!(regex.contains("JsxClass.render"));
}

#[test]
fn test_get_class_and_method_sources_js() {
    let analyzer = fixture_analyzer();

    assert_code_eq(
        r#"
        export class Hello {
            greet() { console.log("hi"); }
        }
        "#,
        &analyzer
            .get_source(&definition(&analyzer, "Hello"), true)
            .unwrap(),
    );
    assert_code_eq(
        r#"
        export class JsxClass {
            render() {
                return <div className="class-jsx">Hello from JSX Class</div>;
            }
        }
        "#,
        &analyzer
            .get_source(&definition(&analyzer, "JsxClass"), true)
            .unwrap(),
    );
    assert_code_eq(
        r#"greet() { console.log("hi"); }"#,
        &analyzer
            .get_source(&definition(&analyzer, "Hello.greet"), true)
            .unwrap(),
    );
    assert_code_eq(
        r#"
        render() {
                return <div className="class-jsx">Hello from JSX Class</div>;
            }
        "#,
        &analyzer
            .get_source(&definition(&analyzer, "JsxClass.render"), true)
            .unwrap(),
    );
    assert_code_eq(
        r#"export function util() { return 42; }"#,
        &analyzer
            .get_source(&definition(&analyzer, "util"), true)
            .unwrap(),
    );
}

#[test]
fn test_build_related_identifiers_module_cu_and_field_signatures() {
    let analyzer = fixture_analyzer();
    let hello_file = ProjectFile::new(analyzer.project().root().to_path_buf(), "Hello.js");
    assert_code_eq(
        r#"
        - Hello
          - greet
        - util
        "#,
        &analyzer.list_symbols(&hello_file),
    );

    let temp = tempdir().unwrap();
    let root = temp.path();
    let main = write_file(
        root,
        "main.js",
        "import { foo } from './lib.js';\nexport const bar = 1;",
    );
    write_file(root, "lib.js", "export const foo = 42;");
    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let module = analyzer
        .get_declarations(&main)
        .into_iter()
        .find(|code_unit| code_unit.kind() == CodeUnitType::Module)
        .unwrap();
    assert!(
        analyzer
            .get_definitions(module.short_name())
            .contains(&module)
    );

    let temp = tempdir().unwrap();
    let root = temp.path();
    let multi = write_file(
        root,
        "multi.js",
        "export const a = 1, b = 2;\nlet x = 'one', y = 'two';",
    );
    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let skeletons = analyzer.get_skeletons(&multi);
    assert_eq!(
        "export const a = 1",
        skeletons
            .get(&CodeUnit::new(
                multi.clone(),
                CodeUnitType::Field,
                "",
                "multi.js.a",
            ))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "export const b = 2",
        skeletons
            .get(&CodeUnit::new(
                multi.clone(),
                CodeUnitType::Field,
                "",
                "multi.js.b",
            ))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "let x = 'one'",
        skeletons
            .get(&CodeUnit::new(
                multi.clone(),
                CodeUnitType::Field,
                "",
                "multi.js.x",
            ))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "let y = 'two'",
        skeletons
            .get(&CodeUnit::new(multi, CodeUnitType::Field, "", "multi.js.y"))
            .unwrap()
            .trim()
    );

    let temp = tempdir().unwrap();
    let root = temp.path();
    let fields = write_file(
        root,
        "fields.js",
        r#"
            export const simpleInt = 42;
            let simpleString = "hello";
            var complexObj = new ComplexObject("args");
            const inlineObj = { a: 1, b: 2 };
        "#,
    );
    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let skeletons = analyzer.get_skeletons(&fields);
    assert_eq!(
        "export const simpleInt = 42",
        skeletons
            .get(&definition(&analyzer, "fields.js.simpleInt"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "let simpleString = \"hello\"",
        skeletons
            .get(&definition(&analyzer, "fields.js.simpleString"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "var complexObj",
        skeletons
            .get(&definition(&analyzer, "fields.js.complexObj"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "const inlineObj\n  a: 1\n  b: 2",
        skeletons
            .get(&definition(&analyzer, "fields.js.inlineObj"))
            .unwrap()
            .trim()
    );
}

#[test]
fn test_commonjs_module_exports_assignment_is_not_indexed_as_member_definition() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "common.js",
        r#"
            module.exports = {
              run() {}
            };
        "#,
    );
    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "common.js.module.exports")
    );
    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "common.js.module.exports.run")
    );
}

#[test]
fn test_member_assignment_declarations_filter_plain_locals_only() {
    let (project, analyzer) = js_inline_analyzer(&[(
        "assignments.js",
        r#"
class Foo {}
Foo.make = function make() {};
function Bar() {}
Bar.prototype.run = function run() {};
const request = {};
request.accepts = function accepts(type) { return type; };
exports.accepts = request.accepts;
var req = exports = module.exports = {};
req.route = function route(type) { return type; };
const obj = {};
obj.spuriousmember = 1;
obj.helper = function helper() {};
"#,
    )]);
    let file = project.file("assignments.js");
    let declarations = analyzer.get_declarations(&file);
    let names = fq_names(declarations.iter().cloned());

    assert!(
        names.contains(&"Foo.make".to_string()),
        "class static assignment should remain declared: {names:?}"
    );
    assert!(
        declarations
            .iter()
            .any(|unit| unit.fq_name() == "Foo.make" && unit.kind() == CodeUnitType::Function),
        "Foo.make should be a function declaration: {declarations:?}"
    );
    assert!(
        names.contains(&"Bar.prototype.run".to_string()),
        "prototype assignment should remain declared: {names:?}"
    );
    assert!(
        names.contains(&"request.accepts".to_string()),
        "CommonJS member re-export should preserve the targeted member declaration: {names:?}"
    );
    assert!(
        names.contains(&"req.route".to_string()),
        "CommonJS export assignment-chain local object member should remain declared: {names:?}"
    );
    assert!(
        !names.iter().any(|name| name.contains("spuriousmember")),
        "plain-local member assignment must not be declared: {names:?}"
    );
    assert!(
        !names.contains(&"obj.helper".to_string()),
        "function-valued plain-local member assignment must not be declared: {names:?}"
    );
}
