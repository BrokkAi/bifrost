mod common;

use brokk_bifrost::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, ScalaAnalyzer,
    TypeHierarchyProvider, WorkspaceAnalyzer,
};
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const ENUM_SOURCE: &str = r#"package model

trait Tagged

object Outer:
  enum Event:
    case Idle extends Tagged
    case Data(id: Int, label: String = "default") extends Tagged
"#;

fn enum_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Scala)
        .file("model/Event.scala", ENUM_SOURCE)
        .build()
}

fn only_definition(analyzer: &dyn IAnalyzer, fqn: &str) -> CodeUnit {
    let definitions = analyzer.get_definitions(fqn);
    assert_eq!(definitions.len(), 1, "expected one definition for {fqn}");
    definitions.into_iter().next().expect("one definition")
}

fn location_in(path: &str, source: &str, start: usize) -> Value {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    json!({"path": path, "line": line, "column": column})
}

#[test]
fn scala_indexes_parameterized_enum_case_as_source_backed_class_family() {
    let project = enum_project();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let file = project.file("model/Event.scala");

    let event = only_definition(&analyzer, "model.Outer$.Event");
    let idle = only_definition(&analyzer, "model.Outer$.Event.Idle");
    let data = only_definition(&analyzer, "model.Outer$.Event.Data");
    let constructor = only_definition(&analyzer, "model.Outer$.Event.Data.Data");
    let id = only_definition(&analyzer, "model.Outer$.Event.Data.id");
    let label = only_definition(&analyzer, "model.Outer$.Event.Data.label");

    assert_eq!(idle.kind(), CodeUnitType::Field);
    assert_eq!(analyzer.signatures(&idle), ["case Idle"]);
    assert_eq!(data.kind(), CodeUnitType::Class);
    assert_eq!(data.source(), &file);
    assert_eq!(constructor.kind(), CodeUnitType::Function);
    assert!(constructor.is_synthetic());
    assert_eq!(constructor.source(), &file);
    assert_eq!(id.kind(), CodeUnitType::Field);
    assert_eq!(label.kind(), CodeUnitType::Field);
    assert_eq!(analyzer.signatures(&id), ["val id: Int"]);
    assert_eq!(
        analyzer.signatures(&label),
        ["val label: String = \"default\""]
    );

    assert_eq!(analyzer.parent_of(&data), Some(event.clone()));
    assert_eq!(analyzer.parent_of(&constructor), Some(data.clone()));
    assert_eq!(analyzer.parent_of(&id), Some(data.clone()));
    assert_eq!(analyzer.parent_of(&label), Some(data.clone()));

    let ancestors = analyzer
        .get_direct_ancestors(&data)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ancestors,
        BTreeSet::from(["model.Outer$.Event".to_string(), "model.Tagged".to_string(),])
    );

    let metadata = analyzer.signature_metadata(&constructor);
    assert_eq!(metadata.len(), 1);
    let arity = metadata[0].callable_arity().expect("constructor arity");
    assert!(arity.accepts(1));
    assert!(arity.accepts(2));
    assert!(!arity.accepts(0));

    let data_range = analyzer
        .ranges(&data)
        .into_iter()
        .next()
        .expect("case range");
    assert_eq!(analyzer.ranges(&constructor), [data_range]);
    assert_eq!(
        &ENUM_SOURCE[data_range.start_byte..data_range.end_byte],
        "Data(id: Int, label: String = \"default\") extends Tagged"
    );

    assert_eq!(analyzer.get_definitions("model.Outer$.Event.Idle").len(), 1);
    assert!(
        analyzer
            .get_definitions("model.Outer$.Event.Idle.Idle")
            .is_empty(),
        "a parameterless simple_enum_case must not gain a constructor duplicate"
    );
    assert_eq!(analyzer.get_definitions("model.Outer$.Event.Data").len(), 1);
    assert!(
        analyzer
            .get_definitions("model.Outer$.Event.Data")
            .iter()
            .all(CodeUnit::is_class)
    );
}

#[test]
fn parameterized_enum_case_identity_survives_persisted_reload() {
    let project = enum_project();
    let project_arc = project.project_dyn();

    let cold = WorkspaceAnalyzer::build_persisted(project_arc.clone(), AnalyzerConfig::default())
        .expect("cold persisted Scala analyzer");
    let cold_data = only_definition(cold.analyzer(), "model.Outer$.Event.Data");
    let cold_constructor = only_definition(cold.analyzer(), "model.Outer$.Event.Data.Data");
    let cold_label = only_definition(cold.analyzer(), "model.Outer$.Event.Data.label");
    assert!(cold_data.is_class());
    assert!(cold_constructor.is_synthetic());
    assert_eq!(cold_constructor.source(), cold_data.source());
    assert_eq!(cold_label.source(), cold_data.source());
    drop(cold);

    let warm = WorkspaceAnalyzer::build_persisted(project_arc, AnalyzerConfig::default())
        .expect("warm persisted Scala analyzer");
    let warm_data = only_definition(warm.analyzer(), "model.Outer$.Event.Data");
    let warm_constructor = only_definition(warm.analyzer(), "model.Outer$.Event.Data.Data");
    let warm_label = only_definition(warm.analyzer(), "model.Outer$.Event.Data.label");
    assert_eq!(warm_data, cold_data);
    assert_eq!(warm_constructor, cold_constructor);
    assert_eq!(warm_label, cold_label);
    assert_eq!(
        warm.analyzer()
            .type_hierarchy_provider()
            .expect("Scala hierarchy provider")
            .get_direct_ancestors(&warm_data)
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["model.Outer$.Event".to_string(), "model.Tagged".to_string()])
    );
    assert_eq!(
        warm.analyzer().parent_of(&warm_constructor),
        Some(warm_data.clone())
    );
    assert_eq!(warm.analyzer().parent_of(&warm_label), Some(warm_data));
}

#[test]
fn scala_definition_api_preserves_parameterized_enum_case_source_identity() {
    let source = r#"package model

enum Token:
  case Plain
  case Number(value: Int)

object Use:
  val made = Token.Number(1)
  def read(token: Token): Int = token match
    case Token.Number(value) => value
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/Token.scala", source)
        .build();
    let pattern = source.rfind("Number(value)").expect("pattern reference");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [location_in("model/Token.scala", source, pattern)]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results.len(), 1, "{value}");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "model.Token.Number",
        "{value}"
    );
    assert_eq!(
        results[0]["definitions"][0]["path"], "model/Token.scala",
        "{value}"
    );

    let sources = call_search_tool_json(
        project.root(),
        "get_symbol_sources",
        &json!({"symbols": ["model.Token.Number.Number"]}).to_string(),
    );
    let source_results = sources["sources"].as_array().expect("source results");
    assert_eq!(source_results.len(), 1, "{sources}");
    assert!(
        sources["not_found"].as_array().unwrap().is_empty(),
        "{sources}"
    );
    assert!(
        sources["ambiguous"].as_array().unwrap().is_empty(),
        "{sources}"
    );
    assert_eq!(source_results[0]["path"], "model/Token.scala", "{sources}");
    assert_eq!(
        source_results[0]["label"], "model.Token.Number.Number",
        "{sources}"
    );
    assert_eq!(source_results[0]["text"], "Number(value: Int)", "{sources}");
}
