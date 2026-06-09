use brokk_bifrost::{
    JavaAnalyzer, Language, ScalaAnalyzer, TestProject,
    searchtools::{FilePatternsParams, list_symbols},
};

mod common;
use common::InlineTestProject;

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

#[test]
fn list_symbols_preserves_package_headers() {
    let analyzer = fixture_analyzer();
    let params = FilePatternsParams {
        file_patterns: vec!["Packaged.java".to_string()],
    };

    let result = list_symbols(&analyzer, params);

    assert_eq!(1, result.files.len());
    assert_eq!("Packaged.java", result.files[0].path);
    assert_eq!(
        Some(&"# io.github.jbellis.brokk".to_string()),
        result.files[0].lines.first()
    );
    assert!(result.files[0].lines.contains(&"- Foo".to_string()));
    assert!(result.files[0].lines.contains(&"  - bar".to_string()));
}

#[test]
fn list_symbols_renders_scala_objects_idiomatically() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/ai/brokk/ScalaObjects.scala",
            r#"package ai.brokk

object ir {
  object PrimOp {
    case object AsClockOp
  }
}

object InstanceChoiceControl {
  def select: Unit = {}
}
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let result = list_symbols(
        &analyzer,
        FilePatternsParams {
            file_patterns: vec!["src/ai/brokk/ScalaObjects.scala".to_string()],
        },
    );

    assert_eq!(1, result.files.len());
    assert_eq!("src/ai/brokk/ScalaObjects.scala", result.files[0].path);
    assert!(
        result.files[0].lines.contains(&"- ir".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0].lines.contains(&"  - PrimOp".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0]
            .lines
            .contains(&"    - AsClockOp".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0]
            .lines
            .contains(&"- InstanceChoiceControl".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0].lines.contains(&"  - select".to_string()),
        "{:#?}",
        result.files[0].lines
    );
}
