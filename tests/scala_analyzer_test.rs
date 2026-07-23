mod common;

use brokk_bifrost::{
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
fn scala_indexes_source_backed_type_aliases_with_distinct_namespace_identity() {
    let source = r#"package aliases

type Ordinary = String
opaque type Selector = String

object Fiber {
  object Promise {
    opaque type Unsafe = String
    object Unsafe
  }
}
"#;
    let project = inline_scala_project(&[("aliases/Aliases.scala", source)]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let ordinary = definition(&analyzer, "aliases.Ordinary");
    let selector = definition(&analyzer, "aliases.Selector");
    let unsafe_alias = definition(&analyzer, "aliases.Fiber$.Promise$.Unsafe");
    let unsafe_companion = definition(&analyzer, "aliases.Fiber$.Promise$.Unsafe$");

    for alias in [&ordinary, &selector, &unsafe_alias] {
        assert_eq!(alias.kind(), CodeUnitType::Field);
        assert!(analyzer.is_type_alias(alias), "{}", alias.fq_name());
        assert!(
            analyzer
                .type_alias_provider()
                .is_some_and(|provider| provider.is_type_alias(alias)),
            "{}",
            alias.fq_name()
        );
        assert_eq!(
            analyzer.get_source(alias, false).as_deref(),
            analyzer.signatures(alias).first().map(String::as_str)
        );
    }
    assert_eq!(ordinary.short_name(), "Ordinary");
    assert_eq!(selector.short_name(), "Selector");
    assert_eq!(unsafe_alias.short_name(), "Fiber$.Promise$.Unsafe");
    assert_eq!(
        analyzer
            .parent_of(&unsafe_alias)
            .map(|parent| parent.fq_name()),
        Some("aliases.Fiber$.Promise$".to_string())
    );
    assert!(unsafe_companion.is_class());
    assert!(!analyzer.is_type_alias(&unsafe_companion));
    assert_ne!(unsafe_alias, unsafe_companion);

    let expected = "opaque type Unsafe = String";
    let expected_start = source.find(expected).expect("nested alias source");
    let range = analyzer
        .ranges(&unsafe_alias)
        .into_iter()
        .next()
        .expect("alias range");
    assert_eq!(range.start_byte, expected_start);
    assert_eq!(range.end_byte, expected_start + expected.len());
    assert_eq!(
        analyzer.get_source(&unsafe_alias, false).as_deref(),
        Some(expected)
    );
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
fn scala_indented_root_type_without_unmatched_end_marker_remains_top_level() {
    let project = inline_scala_project(&[("RootTypes.scala", "package p\nclass A\n  class B\n")]);
    let analyzer = ScalaAnalyzer::from_project(project);
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "RootTypes.scala");

    let top_level = analyzer.top_level_declarations(&file);
    assert!(top_level.iter().any(|unit| unit.fq_name() == "p.A"));
    assert!(top_level.iter().any(|unit| unit.fq_name() == "p.B"));
    assert!(analyzer.get_definitions("p.A.B").is_empty());
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
fn scala_indexes_operator_method_name() {
    let project = inline_scala_project(&[(
        "app/Box.scala",
        r#"
        package app

        class Box {
          def ! : Boolean = true
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let bang = definition(&analyzer, "app.Box.!");
    assert!(bang.is_function());
    assert_eq!("!", bang.identifier());
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
fn test_braced_package_bodies_preserve_top_level_source_order() {
    let project = inline_scala_project(&[(
        "Packages.scala",
        r#"
        package alpha { class A }
        class C
        package beta { class B }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "Packages.scala");

    let top_level: Vec<_> = analyzer
        .top_level_declarations(&file)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();

    assert_eq!(vec!["alpha.A", "alpha.C", "alpha.beta.B"], top_level);
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
fn scala_indexes_methods_inside_recovered_annotated_class_body_under_owner() {
    let project = inline_scala_project(&[(
        "ai/brokk/JobSrv.scala",
        r#"
        package ai.brokk

        @Singleton
        class JobSrv @Inject() (
          implicit val db: Database
        ) extends VertexSrv[Job] {
          def submit(id: String): Unit = {}
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let submit = definition(&analyzer, "ai.brokk.JobSrv.submit");
    assert!(submit.is_function());
    assert_eq!("JobSrv.submit", submit.short_name());
    assert!(
        analyzer.get_definitions("ai.brokk.submit").is_empty(),
        "method should not be flattened to package scope"
    );
}

#[test]
fn scala_class_name_ignores_annotation_and_extends_nodes() {
    let project = inline_scala_project(&[(
        "ai/brokk/Properties.scala",
        r#"
        package ai.brokk

        class Database
        @Singleton
        class Properties @Inject() (
          @Named("with-thehive-schema") db: Database
        ) {
          lazy val metaProperties: PublicProperties = PublicPropertyListBuilder.build
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let properties = definition(&analyzer, "ai.brokk.Properties");
    assert!(properties.is_class());
    assert_eq!("Properties", properties.short_name());
}

#[test]
fn issue_1016_scala_annotated_constructor_whitespace_forms_keep_parameters_and_bodies() {
    let project = inline_scala_project(&[(
        "ai/brokk/Annotated.scala",
        r#"
        package ai.brokk

        class A @Inject()(x: Int) {
          def first: Int = x
        }

        class B @ann() (x: Int) {
          def second: Int = x
        }

        class C @ann ()(x: Int) {
          def third: Int = x
        }
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project);

    for (class_name, method_name) in [("A", "first"), ("B", "second"), ("C", "third")] {
        let class = definition(&analyzer, &format!("ai.brokk.{class_name}"));
        let method = definition(&analyzer, &format!("ai.brokk.{class_name}.{method_name}"));
        let source = analyzer
            .get_source(&class, false)
            .unwrap_or_else(|| panic!("missing source for {class_name}"));

        assert!(source.contains("x: Int"), "{class_name}: {source}");
        assert!(
            source.contains(&format!("def {method_name}")),
            "{class_name}: {source}"
        );
        assert_eq!(
            analyzer.parent_of(&method).as_ref().map(CodeUnit::fq_name),
            Some(format!("ai.brokk.{class_name}"))
        );
    }
}

#[test]
fn issue_1068_empty_lambda_keeps_following_class_members() {
    let source = include_str!("fixtures/scala-issue-1068/VCSSpec.scala");
    let project = inline_scala_project(&[("svsimTests/VCSSpec.scala", source)]);
    let analyzer = ScalaAnalyzer::from_project(project);

    let class = definition(&analyzer, "svsimTests.VCSSpec");
    let after = definition(&analyzer, "svsimTests.VCSSpec.after");
    let following = definition(&analyzer, "svsimTests.FollowingSpec");
    let class_source = analyzer.get_source(&class, false).expect("VCSSpec source");

    assert!(class_source.contains("simulation.run("));
    assert!(class_source.contains("def after(): Int"));
    assert_eq!(
        analyzer.parent_of(&after).as_ref().map(CodeUnit::fq_name),
        Some("svsimTests.VCSSpec".to_string())
    );
    assert!(
        analyzer.parent_of(&following).is_none(),
        "following declaration must remain top-level"
    );
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

    let imports = analyzer.import_statements(&file);
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
