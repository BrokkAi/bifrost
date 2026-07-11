mod common;

use brokk_bifrost::{CodeUnitType, IAnalyzer, JavascriptAnalyzer, Language, TestProject};
use tempfile::tempdir;

use common::{InlineTestProject, write_file};

fn inline_js_analyzer(source: &str) -> (common::BuiltInlineTestProject, JavascriptAnalyzer) {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("module.js", source)
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn test_top_level_arrow_functions() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let test_file = write_file(
        root,
        "arrows.js",
        r#"
            const myFunc = (x) => x * 2;
            const asyncFunc = async () => { return 42; };
            let anotherFunc = (a, b) => a + b;
        "#,
    );

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let declarations = analyzer.declarations(&test_file);
    let functions: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .collect();

    assert_eq!(3, functions.len());
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("myFunc"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("asyncFunc"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("anotherFunc"))
    );
}

#[test]
fn anonymous_arrow_default_export_indexes_default_function_with_full_range() {
    let (project, analyzer) = inline_js_analyzer(
        r#"
            import * as C from './constant';
            export default (o, c, d) => {
                return d.extend(o, c, C);
            };
        "#,
    );
    let file = project.file("module.js");
    let declarations = analyzer.declarations(&file);
    let default = declarations
        .iter()
        .find(|unit| unit.short_name() == "default")
        .expect("default export declaration");

    assert_eq!(CodeUnitType::Function, default.kind());
    assert_eq!(
        "export default (o, c, d) => {\n                return d.extend(o, c, C);\n            };",
        analyzer.get_source(default, true).unwrap().trim()
    );
    assert_eq!(
        "export default (o, c, d) => ...",
        analyzer.get_skeleton(default).unwrap()
    );
}

#[test]
fn anonymous_function_default_export_indexes_default_function() {
    let (project, analyzer) = inline_js_analyzer(
        r#"
            export default function () {
                return 42;
            }
        "#,
    );
    let file = project.file("module.js");
    let default = analyzer
        .declarations(&file)
        .into_iter()
        .find(|unit| unit.short_name() == "default")
        .expect("default export declaration");

    assert_eq!(CodeUnitType::Function, default.kind());
    assert_eq!(
        "export default function() ...",
        analyzer.get_skeleton(&default).unwrap()
    );
}

#[test]
fn anonymous_object_default_export_indexes_default_field_with_properties() {
    let (project, analyzer) = inline_js_analyzer(
        r#"
            export default {
                a: 1,
                b() {
                    return 2;
                }
            };
        "#,
    );
    let file = project.file("module.js");
    let declarations = analyzer.declarations(&file);

    assert!(
        declarations
            .iter()
            .any(|unit| { unit.short_name() == "default" && unit.kind() == CodeUnitType::Field })
    );
    assert!(
        declarations
            .iter()
            .any(|unit| unit.short_name() == "default.a")
    );
    assert!(
        declarations
            .iter()
            .any(|unit| unit.short_name() == "default.b")
    );
}

#[test]
fn named_identifier_default_export_does_not_synthesize_default_unit() {
    let (project, analyzer) = inline_js_analyzer(
        r#"
            const someIdentifier = (value) => value;
            export default someIdentifier;
        "#,
    );
    let file = project.file("module.js");
    let declarations = analyzer.declarations(&file);

    assert!(
        declarations
            .iter()
            .all(|unit| unit.short_name() != "default")
    );
    assert!(
        declarations
            .iter()
            .any(|unit| unit.short_name() == "someIdentifier")
    );
}

#[test]
fn test_exported_arrow_functions() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let test_file = write_file(
        root,
        "exported.js",
        r#"
            export const handler = (req, res) => {
                res.send('hello');
            };

            export const middleware = async (req, res, next) => {
                next();
            };
        "#,
    );

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let declarations = analyzer.declarations(&test_file);
    let functions: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .collect();

    assert_eq!(2, functions.len());
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("handler"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("middleware"))
    );
}

#[test]
fn test_mixed_function_types() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let test_file = write_file(
        root,
        "mixed.js",
        r#"
            function regularFunc() { }
            const arrowFunc = () => { };
            class MyClass {
                methodFunc() { }
            }
        "#,
    );

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let declarations = analyzer.declarations(&test_file);
    let functions: Vec<_> = declarations
        .iter()
        .filter(|code_unit| code_unit.is_function())
        .cloned()
        .collect();
    let classes: Vec<_> = declarations
        .iter()
        .filter(|code_unit| code_unit.is_class())
        .cloned()
        .collect();

    assert_eq!(3, functions.len());
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("regularFunc"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("arrowFunc"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("methodFunc"))
    );
    assert_eq!(1, classes.len());
}

#[test]
fn test_react_patterns() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let test_file = write_file(
        root,
        "component.js",
        r#"
            const MyComponent = () => {
                return <div>Hello</div>;
            };

            const useCustomHook = () => {
                const [state, setState] = useState(0);
                return [state, setState];
            };

            export const ComponentWithProps = ({ name, age }) => {
                return <div>{name} is {age}</div>;
            };
        "#,
    );

    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript));
    let declarations = analyzer.declarations(&test_file);
    let functions: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .collect();

    assert_eq!(3, functions.len());
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("MyComponent"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("useCustomHook"))
    );
    assert!(
        functions
            .iter()
            .any(|code_unit| code_unit.fq_name().contains("ComponentWithProps"))
    );
}
