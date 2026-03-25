use brokk_analyzer::{IAnalyzer, Language, ProjectFile, ScalaAnalyzer, TestProject};
use tempfile::tempdir;

fn inline_scala_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Scala)
}

#[test]
fn test_qualified_class_and_method_source() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        package ai.brokk;

        class Foo() {

            val field1: String = "Test"
            val multiLineField: String = "
              das
              "

            def foo1(): Int = {
                return 1 + 2;
            }
        }

        def foo2(): String = {
           return "Hello, world!";
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let foo = analyzer.get_definitions("ai.brokk.Foo").into_iter().next().unwrap();
    assert_eq!(
        r#"class Foo() {

            val field1: String = "Test"
            val multiLineField: String = "
              das
              "

            def foo1(): Int = {
                return 1 + 2;
            }
        }"#,
        &analyzer.get_source(&foo, false).unwrap(),
    );

    let foo1 = analyzer
        .get_definitions("ai.brokk.Foo.foo1")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        r#"def foo1(): Int = {
                return 1 + 2;
            }"#,
        &analyzer.get_source(&foo1, false).unwrap(),
    );

    let foo2 = analyzer
        .get_definitions("ai.brokk.foo2")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        "def foo2(): String = {\n           return \"Hello, world!\";\n        }",
        &analyzer.get_source(&foo2, false).unwrap(),
    );
}
