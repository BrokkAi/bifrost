mod common;

use brokk_analyzer::{IAnalyzer, JavascriptAnalyzer, Language, TestProject};
use tempfile::tempdir;

use common::write_file;

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
    let declarations = analyzer.get_declarations(&test_file);
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
    let declarations = analyzer.get_declarations(&test_file);
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
    let declarations = analyzer.get_declarations(&test_file);
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
    let declarations = analyzer.get_declarations(&test_file);
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
