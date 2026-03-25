mod common;

use brokk_analyzer::{IAnalyzer, Language, ProjectFile, ScalaAnalyzer, TestProject};
use common::assert_code_eq;
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
fn test_qualified_class_and_method_skeleton() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        package ai.brokk;

        class Foo() {

            val field1: String = "Test"
            val multiLineField: String = """
              das
              """

            private def foo1(): Int = {
                return 1 + 2;
            }
        }

        def foo2(): String = {
           return "Hello, world!";
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);
    let foo = analyzer
        .get_definitions("ai.brokk.Foo")
        .into_iter()
        .next()
        .unwrap();

    assert_code_eq(
        "class Foo() {\n  val field1: String = \"Test\"\n  val multiLineField: String = \"\"\"\n      das\n      \"\"\"\n  private def foo1(): Int = {...}\n}",
        &analyzer.get_skeleton(&foo).unwrap(),
    );
}

#[test]
fn test_generic_method_skeleton() {
    let project = inline_scala_project(&[(
        "GenericFoo.scala",
        r#"
        package ai.brokk;

        class GenericFoo[R]() {
            def genericMethod[T](arg: T): T = {
                return arg;
            }
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);
    let foo = analyzer
        .get_definitions("ai.brokk.GenericFoo")
        .into_iter()
        .next()
        .unwrap();

    assert_code_eq(
        r#"
        class GenericFoo[R]() {
          def genericMethod[T](arg: T): T = {...}
        }
        "#,
        &analyzer.get_skeleton(&foo).unwrap(),
    );
}

#[test]
fn test_implicit_parameter_method_skeleton() {
    let project = inline_scala_project(&[(
        "ImplicitFoo.scala",
        r#"
        package ai.brokk;

        import scala.concurrent.ExecutionContext;

        class ImplicitFoo() {
            def implicitMethod(arg: Int)(implicit ec: ExecutionContext): String = {
                return "done";
            }
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);
    let foo = analyzer
        .get_definitions("ai.brokk.ImplicitFoo")
        .into_iter()
        .next()
        .unwrap();

    assert_code_eq(
        r#"
        class ImplicitFoo() {
          def implicitMethod(arg: Int)(implicit ec: ExecutionContext): String = {...}
        }
        "#,
        &analyzer.get_skeleton(&foo).unwrap(),
    );
}

#[test]
fn test_scala3_significant_whitespace_skeleton() {
    let project = inline_scala_project(&[(
        "WhitespaceClass.scala",
        r#"
        package ai.brokk;

        class WhitespaceClass:
          val s = """
            line 1
              line 2
          """

          val i = 2
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);
    let class_unit = analyzer
        .get_definitions("ai.brokk.WhitespaceClass")
        .into_iter()
        .next()
        .unwrap();

    assert_code_eq(
        "class WhitespaceClass {\n  val s = \"\"\"\n      line 1\n        line 2\n    \"\"\"\n  val i = 2\n}",
        &analyzer.get_skeleton(&class_unit).unwrap(),
    );
}
