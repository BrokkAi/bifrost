mod common;

use brokk_analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, ProjectFile, ScalaAnalyzer, TestProject,
};
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

fn definition(analyzer: &ScalaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

#[test]
fn test_simple_unqualified_classes() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        class Foo() {}
        case class Bar()
        object Baz {}
        enum Color:
          case Red, Green, Blue
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let foo = definition(&analyzer, "Foo");
    assert!(foo.is_class());
    assert_eq!("Foo", foo.fq_name());
    assert_eq!("", foo.package_name());
    assert_eq!("Foo", foo.short_name());

    let bar = definition(&analyzer, "Bar");
    assert!(bar.is_class());
    assert_eq!("Bar", bar.fq_name());

    let baz = definition(&analyzer, "Baz$");
    assert!(baz.is_class());
    assert_eq!("Baz$", baz.fq_name());
    assert_eq!("Baz$", baz.short_name());

    let color = definition(&analyzer, "Color");
    assert!(color.is_class());
    assert_eq!("Color", color.fq_name());
}

#[test]
fn test_simple_unqualified_trait() {
    let project = inline_scala_project(&[("Foo.scala", "trait Foo {}\n")]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let foo = definition(&analyzer, "Foo");
    assert!(foo.is_class());
    assert_eq!("Foo", foo.fq_name());
}

#[test]
fn test_simple_qualified_classes() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        class Foo()
        trait Bar
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let foo = definition(&analyzer, "ai.brokk.Foo");
    assert!(foo.is_class());
    assert_eq!("ai.brokk", foo.package_name());
    assert_eq!("Foo", foo.short_name());

    let bar = definition(&analyzer, "ai.brokk.Bar");
    assert!(bar.is_class());
    assert_eq!("ai.brokk", bar.package_name());
    assert_eq!("Bar", bar.short_name());
}

#[test]
fn test_simple_methods_within_classes() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        class Foo {
          def test1(): Unit = {}
        }
        trait Bar {
          def test2: Unit = {}
        }
        object Baz {
          def test3: Unit = {}
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let test1 = definition(&analyzer, "ai.brokk.Foo.test1");
    assert!(test1.is_function());
    assert_eq!("Foo.test1", test1.short_name());

    let test2 = definition(&analyzer, "ai.brokk.Bar.test2");
    assert!(test2.is_function());
    assert_eq!("Bar.test2", test2.short_name());

    let test3 = definition(&analyzer, "ai.brokk.Baz$.test3");
    assert!(test3.is_function());
    assert_eq!("Baz$.test3", test3.short_name());
}

#[test]
fn test_simple_constructor_in_class_definition() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        class Foo(a: Int, b: String)
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let ctor = definition(&analyzer, "ai.brokk.Foo.Foo");
    assert!(ctor.is_function());
    assert_eq!("ai.brokk", ctor.package_name());
    assert_eq!("Foo.Foo", ctor.short_name());
}

#[test]
fn test_secondary_constructors_in_class_definition() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        class Foo {
          def this(a: Int, b: String) = this(a)
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let ctor = definition(&analyzer, "ai.brokk.Foo.Foo");
    assert!(ctor.is_function());
    assert_eq!("Foo.Foo", ctor.short_name());
}

#[test]
fn test_fields_within_classes_and_compilation_unit() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        var GLOBAL_VAR = "foo"
        val GLOBAL_VAL = "bar"

        class Foo:
          val Field1 = "123"
          var Field2 = 456
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    for fq_name in [
        "ai.brokk.GLOBAL_VAR",
        "ai.brokk.GLOBAL_VAL",
        "ai.brokk.Foo.Field1",
        "ai.brokk.Foo.Field2",
    ] {
        assert!(definition(&analyzer, fq_name).is_field(), "{fq_name}");
    }
}

#[test]
fn test_file_summary_no_semicolons_after_imports() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        import foo.bar

        class Foo()
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "ai/brokk/Foo.scala");

    let imports = analyzer.import_statements_of(&file);
    assert!(!imports.is_empty());
    assert!(
        imports
            .iter()
            .all(|import| !import.trim_end().ends_with(';'))
    );

    let class_unit = definition(&analyzer, "ai.brokk.Foo");
    let skeleton = analyzer
        .get_skeletons(&file)
        .get(&class_unit)
        .cloned()
        .unwrap();
    let first_line = skeleton.lines().next().unwrap_or("");
    assert!(!first_line.ends_with(';'));
}

#[test]
fn test_fields_within_enums() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        enum Colors {
          case BLUE, GREEN
        }

        enum Sports {
          case SOCCER
          case RUGBY
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    for fq_name in [
        "ai.brokk.Colors.BLUE",
        "ai.brokk.Colors.GREEN",
        "ai.brokk.Sports.SOCCER",
        "ai.brokk.Sports.RUGBY",
    ] {
        assert!(definition(&analyzer, fq_name).is_field(), "{fq_name}");
    }
}

#[test]
fn test_method_name_can_collide_with_constructor_name() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        class Foo {
          def Foo(): Int = 1
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let classes = analyzer.get_definitions("ai.brokk.Foo");
    assert_eq!(1, classes.len());
    assert!(classes[0].is_class());

    let methods = analyzer.get_definitions("ai.brokk.Foo.Foo");
    assert_eq!(1, methods.len());
    assert!(methods[0].is_function());
}

#[test]
fn test_multi_assignment_field_signatures() {
    let project = inline_scala_project(&[(
        "ai/brokk/Foo.scala",
        r#"
        package ai.brokk

        class Foo {
          var x, y: Int = 1
          val a, b = "test"
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "ai/brokk/Foo.scala");

    let x_unit = CodeUnit::new(file.clone(), CodeUnitType::Field, "ai.brokk", "Foo.x");
    let y_unit = CodeUnit::new(file.clone(), CodeUnitType::Field, "ai.brokk", "Foo.y");
    let a_unit = CodeUnit::new(file.clone(), CodeUnitType::Field, "ai.brokk", "Foo.a");
    let b_unit = CodeUnit::new(file, CodeUnitType::Field, "ai.brokk", "Foo.b");

    assert_code_eq("var x: Int = 1", &analyzer.get_skeleton(&x_unit).unwrap());
    assert_code_eq("var y: Int = 1", &analyzer.get_skeleton(&y_unit).unwrap());
    assert_code_eq("val a = \"test\"", &analyzer.get_skeleton(&a_unit).unwrap());
    assert_code_eq("val b = \"test\"", &analyzer.get_skeleton(&b_unit).unwrap());
}

#[test]
fn test_complex_field_initializer_is_omitted() {
    let project = inline_scala_project(&[(
        "ai/brokk/ComplexField.scala",
        r#"
        package ai.brokk

        class ComplexField {
          val obj = new Object()
          var x: Int = 1
          val a = "test"
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "ai/brokk/ComplexField.scala");
    let obj = CodeUnit::new(file, CodeUnitType::Field, "ai.brokk", "ComplexField.obj");
    assert_code_eq("val obj", &analyzer.get_skeleton(&obj).unwrap());
}

#[test]
fn test_private_field_context_is_preserved() {
    let project = inline_scala_project(&[(
        "ai/brokk/PrivateField.scala",
        r#"
        package ai.brokk

        class PrivateField {
          private val secret = "password"
          protected var count: Int = 0
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "ai/brokk/PrivateField.scala");

    let secret = CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "ai.brokk",
        "PrivateField.secret",
    );
    assert_code_eq(
        "private val secret = \"password\"",
        &analyzer.get_skeleton(&secret).unwrap(),
    );

    let count = CodeUnit::new(file, CodeUnitType::Field, "ai.brokk", "PrivateField.count");
    assert_code_eq(
        "protected var count: Int = 0",
        &analyzer.get_skeleton(&count).unwrap(),
    );
}
