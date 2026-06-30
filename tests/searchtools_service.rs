use brokk_bifrost::{
    AnalyzerConfig, FilesystemProject, Language, Project, SearchToolsService,
    SearchToolsServiceErrorCode, WorkspaceAnalyzer, searchtools::SCAN_USAGES_RESPONSE_BUDGET_BYTES,
    searchtools_render::RenderOptions,
};
mod common;
use common::InlineTestProject;
use git2::{Repository, Signature};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{MAIN_SEPARATOR, PathBuf};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0)
}

fn assert_scan_usages_failure(value: &Value, symbol: &str, strategy: &str, reason_kind: &str) {
    assert_eq!(0, array_len(value, "usages"), "payload: {value}");
    assert_eq!(0, array_len(value, "ambiguous"), "payload: {value}");
    let failures = value["failures"].as_array().unwrap();
    assert_eq!(1, failures.len(), "payload: {value}");
    assert_eq!(symbol, failures[0]["symbol"], "payload: {value}");
    assert_eq!(strategy, failures[0]["strategy"], "payload: {value}");
    assert_eq!(reason_kind, failures[0]["reason_kind"], "payload: {value}");
}

#[test]
fn service_allows_concurrent_read_only_calls() {
    let service = Arc::new(SearchToolsService::new_without_semantic_index(fixture_root()).unwrap());
    let calls = [
        (
            "search_symbols",
            r#"{"patterns":["A"],"include_tests":true,"limit":5}"#,
        ),
        ("get_symbol_sources", r#"{"symbols":["A.method2"]}"#),
        ("get_summaries", r#"{"targets":["A.java"]}"#),
        (
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"limit":5}"#,
        ),
    ];

    let handles: Vec<_> = (0..16)
        .map(|index| {
            let service = Arc::clone(&service);
            let (tool, args) = calls[index % calls.len()];
            thread::spawn(move || {
                let payload = service.call_tool_json(tool, args).unwrap();
                serde_json::from_str::<Value>(&payload).unwrap()
            })
        })
        .collect();

    for handle in handles {
        let value = handle.join().unwrap();
        assert!(value.is_object(), "payload: {value}");
    }
}

#[test]
fn workspace_update_publishes_new_snapshot_without_mutating_old_snapshot() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("Thing.java");
    fs::write(&file_path, "public class First {}\n").unwrap();

    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(temp.path()).unwrap());
    let old_snapshot = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("First", true)
            .iter()
            .any(|unit| unit.fq_name() == "First")
    );

    fs::write(&file_path, "public class Second {}\n").unwrap();
    let changed_file = project
        .file_by_rel_path(std::path::Path::new("Thing.java"))
        .unwrap();
    let new_snapshot = old_snapshot.update(&BTreeSet::from([changed_file]));

    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("First", true)
            .iter()
            .any(|unit| unit.fq_name() == "First"),
        "old snapshot should retain First"
    );
    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("Second", true)
            .is_empty(),
        "old snapshot should not see Second"
    );
    assert!(
        new_snapshot
            .analyzer()
            .search_definitions("Second", true)
            .iter()
            .any(|unit| unit.fq_name() == "Second"),
        "new snapshot should see Second"
    );
}

#[test]
fn python_boundary_returns_structured_json() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["summaries"][0]["path"], "A.java");
    assert_eq!(value["summaries"][0]["elements"][0]["start_line"], 3);
}

#[test]
fn rename_symbol_returns_non_mutating_edit_set() {
    let root = fixture_root();
    let before_a = fs::read_to_string(root.join("A.java")).unwrap();
    let service = SearchToolsService::new_without_semantic_index(root.clone()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"column":19,"new_name":"renamedMethod2"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("ok", value["status"], "payload: {value}");
    assert_eq!("A.method2", value["target"]["symbol"], "payload: {value}");
    assert_eq!("method2", value["old_name"], "payload: {value}");
    assert!(
        value["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "A.java"
                && file["edits"].as_array().unwrap().iter().any(|edit| {
                    edit["new_text"] == "renamedMethod2"
                        && edit["old_text"] == "method2"
                        && edit["start_line"] == 8
                        && edit["start_column"] == 19
                })),
        "payload: {value}"
    );
    assert!(
        value["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "B.java"
                && file["edits"].as_array().unwrap().iter().any(|edit| {
                    edit["new_text"] == "renamedMethod2"
                        && edit["start_line"] == 9
                        && edit["start_column"] == 27
                })),
        "payload: {value}"
    );
    assert_eq!(
        before_a,
        fs::read_to_string(root.join("A.java")).unwrap(),
        "rename_symbol must return edits without mutating files"
    );
}

#[test]
fn rename_symbol_rejects_oversized_identifier() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = serde_json::json!({
        "path": "A.java",
        "line": 8,
        "column": 19,
        "new_name": "a".repeat(257)
    });
    let payload = service
        .call_tool_json("rename_symbol", &arguments.to_string())
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("invalid_name", value["status"], "payload: {value}");
    assert!(
        !value["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains(&"a".repeat(257)),
        "payload: {value}"
    );
}

#[test]
fn rename_symbol_rejects_mixed_or_incomplete_locations() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let mixed_payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"column":19,"start_byte":120,"new_name":"renamedMethod2"}"#,
        )
        .unwrap();
    let mixed: Value = serde_json::from_str(&mixed_payload).unwrap();
    assert_eq!("invalid_location", mixed["status"], "payload: {mixed}");

    let incomplete_payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"column":19,"end_byte":125,"new_name":"renamedMethod2"}"#,
        )
        .unwrap();
    let incomplete: Value = serde_json::from_str(&incomplete_payload).unwrap();
    assert_eq!(
        "invalid_location", incomplete["status"],
        "payload: {incomplete}"
    );
}

#[test]
fn rename_symbol_rejects_file_coupled_java_class() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":3,"column":14,"new_name":"RenamedA"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("unsupported", value["status"], "payload: {value}");
    assert!(
        value["edits"].as_array().unwrap().is_empty(),
        "payload: {value}"
    );
    assert_eq!(
        "unsupported", value["diagnostics"][0]["kind"],
        "payload: {value}"
    );
}

#[test]
fn rename_symbol_rejects_invalid_identifier() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"column":19,"new_name":"not-valid"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("invalid_name", value["status"], "payload: {value}");
    assert!(
        value["edits"].as_array().unwrap().is_empty(),
        "payload: {value}"
    );
}

#[test]
fn get_summaries_directory_target_stays_narrow_on_service_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["."]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["structured"].get("compact_symbols").is_some(),
        "{value}"
    );
    assert_eq!(false, value["structured"]["degraded"], "{value}");
    assert!(value["structured"]["degradation"].is_null(), "{value}");
    assert!(
        value["structured"]["not_found"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "."),
        "{value}"
    );
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("Not found: ."), "{rendered}");
    assert!(rendered.contains("A.java"), "{rendered}");
}

#[test]
fn get_summaries_mixed_targets_stay_narrow_on_service_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["A.java","."]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["structured"]["summaries"][0]["path"], "A.java");
    assert!(
        value["structured"]["not_found"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "."),
        "{value}"
    );
    assert!(
        value["structured"].get("compact_symbols").is_some(),
        "{value}"
    );
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("A.java"), "{rendered}");
    assert!(rendered.contains("Not found: ."), "{rendered}");
}

#[test]
fn get_summaries_large_file_glob_stays_full_fidelity_on_service_path() {
    let temp = TempDir::new().unwrap();
    for class_idx in 0..18 {
        let mut source = format!("public class Caller{class_idx} {{\n");
        for method_idx in 0..12 {
            source.push_str(&format!(
                "    public int method{method_idx}(int input) {{ return input + {class_idx} + {method_idx}; }}\n"
            ));
        }
        source.push_str("}\n");
        fs::write(temp.path().join(format!("Caller{class_idx}.java")), source).unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["*.java"]}"#)
        .unwrap();

    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value.get("degraded").is_none() || value["degraded"].is_null(),
        "{value}"
    );
    assert!(
        value.get("degradation").is_none() || value["degradation"].is_null(),
        "{value}"
    );
    assert_eq!(18, value["summaries"].as_array().unwrap().len(), "{value}");
    assert!(
        value["compact_symbols"].is_null(),
        "service path should not degrade to compact_symbols: {value}"
    );
}

#[test]
fn get_definition_by_reference_resolves_rust_crate_scoped_item() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.rs"),
        r#"pub fn helper() {}

pub fn caller() {
    crate::helper();
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definition_by_reference",
            r#"{"references":[{"symbol":"caller","context":"    crate::helper();","target":"helper"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!("helper", result["definitions"][0]["fqn"], "{value}");
}

#[test]
fn get_definition_by_reference_resolves_go_method_receiver_field_chain() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("main.go"),
        r#"package app

type Helper struct{}

func (h Helper) UpdatePackageMetadata() error { return nil }

type Client struct { npmMetadataHelper Helper }

func (c *Client) Build() error {
    return c.npmMetadataHelper.UpdatePackageMetadata()
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definition_by_reference",
            r#"{"references":[{"symbol":"example.com/app.Client.Build","context":"    return c.npmMetadataHelper.UpdatePackageMetadata()","target":"UpdatePackageMetadata"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "example.com/app.Helper.UpdatePackageMetadata", result["definitions"][0]["fqn"],
        "{value}"
    );
}

#[test]
fn get_definition_by_reference_resolves_cpp_overload_by_argument_type() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("target.h"),
        r#"namespace ncnn {
class DataReader {};
class DataReaderFromMemory : public DataReader {};
class Net {
public:
    int load_model(const char* path);
    int load_model(const DataReader& dr);
};
}
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("app.cpp"),
        r#"#include "target.h"
using namespace ncnn;

class DataReaderFromMemoryCopy : public DataReaderFromMemory {};

void PYBIND11_MODULE(Net& net, DataReaderFromMemoryCopy& dr) {
    net.load_model(dr);
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definition_by_reference",
            r#"{"references":[{"symbol":"PYBIND11_MODULE","context":"    net.load_model(dr);","target":"load_model"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "ncnn.Net.load_model", result["definitions"][0]["fqn"],
        "{value}"
    );
    assert_eq!(
        "(DataReader &)", result["definitions"][0]["signature"],
        "{value}"
    );
}

#[test]
fn get_definition_by_reference_resolves_cpp_constructor_style_local_argument() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("target.h"),
        r#"namespace ncnn {
class DataReader {};
class DataReaderFromMemory : public DataReader {};
class Net {
public:
    int load_model(const char* path);
    int load_model(const DataReader& dr);
};
}
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("app.cpp"),
        r#"#include "target.h"
using namespace ncnn;

class DataReaderFromMemoryCopy : public DataReaderFromMemory {
public:
    explicit DataReaderFromMemoryCopy(const unsigned char*& mem);
};

void PYBIND11_MODULE(Net& net, const char* mem) {
    const unsigned char* _mem = (const unsigned char*)mem;
    DataReaderFromMemoryCopy dr(_mem);
    net.load_model(dr);
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definition_by_reference",
            r#"{"references":[{"symbol":"PYBIND11_MODULE","context":"    net.load_model(dr);","target":"load_model"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "ncnn.Net.load_model", result["definitions"][0]["fqn"],
        "{value}"
    );
    assert_eq!(
        "(DataReader &)", result["definitions"][0]["signature"],
        "{value}"
    );
}

#[test]
fn get_definition_by_reference_resolves_scala_constructor_field_from_symbol_context() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("app")).unwrap();
    fs::write(
        temp.path().join("app").join("StreamContext.scala"),
        r#"package com.netflix.atlas.eval.stream
class Registry
class FlowShape
class GraphStage[T]

private[stream] class StreamContext(
  rootConfig: String,
  val registry: Registry
)
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("app").join("TimeGrouped.scala"),
        r#"package com.netflix.atlas.eval.stream

object AggrDatapoint {
  def AggregatorSettings(input: Int, intermediate: Int, registry: Registry, host: String): Int = 0
}

private[stream] class TimeGrouped(
  context: StreamContext,
  host: String
) extends GraphStage[FlowShape] {
  private val maxInputDatapointsPerExpression = 1
  private val maxIntermediateDatapointsPerExpression = 2
  private val aggrSettings = AggrDatapoint.AggregatorSettings(
    maxInputDatapointsPerExpression,
    maxIntermediateDatapointsPerExpression,
    context.registry,
    host
  )
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definition_by_reference",
            r#"{"references":[{"symbol":"com.netflix.atlas.eval.stream.TimeGrouped","context":"    context.registry,","target":"registry"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "com.netflix.atlas.eval.stream.StreamContext.registry", result["definitions"][0]["fqn"],
        "{value}"
    );
}

#[test]
fn python_boundary_returns_canonical_rendered_text_payload() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["A.method2"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["structured"]["sources"][0]["start_line"], 8);
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("## A.method2"), "{rendered}");
    assert!(rendered.contains("- Location: A.java:8..10"), "{rendered}");
    assert!(
        rendered.contains("8: public String method2(String input)"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_file_input_returns_top_level_outline_payload() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src").join("pkg")).unwrap();
    fs::write(
        temp.path().join("src").join("pkg").join("Thing.java"),
        r#"package pkg;
class Thing {
    void method() {}
    static class Inner {}
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/pkg/Thing.java"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let source = &value["structured"]["sources"][0];
    assert_eq!("src/pkg/Thing.java", source["label"]);
    assert_eq!("src/pkg/Thing.java", source["path"]);
    assert_eq!(1, source["start_line"]);
    assert_eq!(2, source["end_line"]);
    let source_text = source["text"].as_str().expect("source text");
    assert!(source_text.contains("# pkg"), "{source_text}");
    assert!(source_text.contains("- Thing"), "{source_text}");
    assert!(!source_text.contains("method"), "{source_text}");
    assert!(!source_text.contains("Inner"), "{source_text}");

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("## src/pkg/Thing.java"), "{rendered}");
    assert!(
        rendered.contains("- Location: src/pkg/Thing.java:1..2"),
        "{rendered}"
    );
    assert!(
        rendered.contains("```text\n1: # pkg\n2: - Thing\n```"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_file_input_uses_include_and_sample_fallbacks() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("only_includes.h"),
        "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("emptyish_large.h"),
        (1..=60)
            .map(|line| format!("// line {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/only_includes.h","src/emptyish_large.h"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let sources = value["structured"]["sources"].as_array().unwrap();
    let include_source = sources
        .iter()
        .find(|source| source["path"] == "src/only_includes.h")
        .unwrap();
    assert_eq!(2, include_source["start_line"]);
    assert_eq!(3, include_source["end_line"]);
    assert_eq!(
        "#include \"only/include.h\"\n#include <stdint.h>",
        include_source["text"]
    );

    let sampled_source = sources
        .iter()
        .find(|source| source["path"] == "src/emptyish_large.h")
        .unwrap();
    assert_eq!(1, sampled_source["start_line"]);
    assert_eq!(60, sampled_source["end_line"]);
    assert_eq!("sampled_excerpt", sampled_source["presentation"]);
    let sampled_text = sampled_source["text"].as_str().expect("sampled text");
    assert!(sampled_text.contains("// line 1"), "{sampled_text}");
    assert!(
        sampled_text.contains("----- OMITTED 10 LINES -----"),
        "{sampled_text}"
    );
    assert!(sampled_text.contains("// line 60"), "{sampled_text}");

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("- Location: src/only_includes.h:2..3"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#include \"only/include.h\""),
        "{rendered}"
    );
    assert!(
        rendered.contains("- Location: src/emptyish_large.h:1..60"),
        "{rendered}"
    );
    assert!(
        rendered.contains("----- OMITTED 10 LINES -----"),
        "{rendered}"
    );
}

#[test]
fn legacy_kind_filter_is_ignored_for_symbol_sources_and_locations() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    let source_payload = service
        .call_tool_json(
            "get_symbol_sources",
            r#"{"symbols":["A.method2"],"kind_filter":"function"}"#,
        )
        .unwrap();
    let source_value: Value = serde_json::from_str(&source_payload).unwrap();
    assert_eq!("A.method2", source_value["sources"][0]["label"]);

    let location_payload = service
        .call_tool_json(
            "get_symbol_locations",
            r#"{"symbols":["A.method2"],"kind_filter":"function"}"#,
        )
        .unwrap();
    let location_value: Value = serde_json::from_str(&location_payload).unwrap();
    assert_eq!("A.method2", location_value["locations"][0]["symbol"]);
}

#[test]
fn get_symbol_ancestors_rejects_non_type_targets() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Thing.java"),
        "class Base {}\nclass Thing extends Base { void run() {} }\n",
    )
    .unwrap();
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let err = service
        .call_tool_json("get_symbol_ancestors", r#"{"symbols":["Thing.run"]}"#)
        .unwrap_err();

    assert_eq!(SearchToolsServiceErrorCode::InvalidParams, err.code);
    assert!(
        err.message
            .contains("only accepts class/module/type symbols")
    );
}

#[test]
fn get_summaries_renders_include_and_excerpt_fallbacks() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("only_includes.h"),
        "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("emptyish.h"),
        (1..=25)
            .map(|line| format!("// line {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["src/only_includes.h","src/emptyish.h"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let summaries = value["structured"]["summaries"].as_array().unwrap();
    let include_summary = summaries
        .iter()
        .find(|summary| summary["path"] == "src/only_includes.h")
        .unwrap();
    assert_eq!(
        "no indexed declarations found; showing top-level includes",
        include_summary["fallback_reason"]
    );
    assert_eq!("include", include_summary["elements"][0]["kind"]);
    assert_eq!("only/include.h", include_summary["elements"][0]["symbol"]);

    let excerpt_summary = summaries
        .iter()
        .find(|summary| summary["path"] == "src/emptyish.h")
        .unwrap();
    assert_eq!(
        "no indexed declarations or top-level includes found; showing head/tail sample",
        excerpt_summary["fallback_reason"]
    );
    assert_eq!("excerpt", excerpt_summary["elements"][0]["kind"]);
    assert_eq!(25, excerpt_summary["elements"][0]["end_line"]);
    assert_eq!(
        "sampled_excerpt",
        excerpt_summary["elements"][0]["presentation"]
    );

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("Note: no indexed declarations found; showing top-level includes"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#include \"only/include.h\""),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "Note: no indexed declarations or top-level includes found; showing head/tail sample"
        ),
        "{rendered}"
    );
    assert!(rendered.contains("// line 1"), "{rendered}");
}

#[test]
fn python_boundary_returns_structural_clone_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Alpha.java"),
        "class Alpha { int compute(int input) { int total = input + 1; if (total > 10) { return total * 2; } return total - 3; } }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Beta.java"),
        "class Beta { int calculate(int seed) { int amount = seed + 1; if (amount > 10) { return amount * 2; } return amount - 3; } }\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_structural_clone_smells",
            r#"{"file_paths":["Alpha.java","Beta.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["report"]
            .as_str()
            .expect("report string")
            .starts_with("## Structural clone smells"),
        "payload: {value}"
    );
}

#[test]
fn python_boundary_returns_dead_code_smell_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("helpers.rs"), "fn helper() {}\n").unwrap();
    fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_dead_code_and_unused_abstraction_smells",
            r#"{"file_paths":["helpers.rs","main.rs"],"fq_names":["helpers.helper"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let report = value["report"].as_str().expect("report string");
    assert!(
        report.starts_with("## Dead code and unused abstraction smells"),
        "payload: {value}"
    );
    assert!(report.contains("helpers.helper"), "payload: {value}");
}

#[test]
fn python_boundary_returns_secret_scan_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.properties"),
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_path(std::path::Path::new("config.properties"))
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    repo.reference_symbolic(
        "refs/remotes/origin/HEAD",
        "refs/heads/master",
        true,
        "set remote default",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_secret_like_code",
            r#"{"max_findings":10,"max_commits":10}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["report"]
            .as_str()
            .expect("report string")
            .starts_with("## brokk-secret-scan"),
        "payload: {value}"
    );
    assert!(
        !value["report"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"),
        "payload: {value}"
    );
}

#[test]
fn python_boundary_returns_git_hotspot_report_json() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("ComplexService.java"),
        "public class ComplexService { void hotspot(int x) { if (x > 0) {} if (x > 1) {} if (x > 2) {} if (x > 3) {} if (x > 4) {} if (x > 5) {} if (x > 6) {} if (x > 7) {} if (x > 8) {} if (x > 9) {} if (x > 10) {} if (x > 11) {} if (x > 12) {} if (x > 13) {} if (x > 14) {} } }\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["src/ComplexService.java"], "initial");
    for i in 0..11 {
        fs::write(
            temp.path().join("src").join("ComplexService.java"),
            format!("public class ComplexService {{ void hotspot(int x) {{ int marker = {i}; if (x > 0) {{}} if (x > 1) {{}} if (x > 2) {{}} if (x > 3) {{}} if (x > 4) {{}} if (x > 5) {{}} if (x > 6) {{}} if (x > 7) {{}} if (x > 8) {{}} if (x > 9) {{}} if (x > 10) {{}} if (x > 11) {{}} if (x > 12) {{}} if (x > 13) {{}} if (x > 14) {{}} }} }}\n"),
        )
        .unwrap();
        commit_paths(&repo, &["src/ComplexService.java"], &format!("update {i}"));
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "analyze_git_hotspots",
            r#"{"since_iso":"2020-01-01T00:00:00Z","max_commits":500,"max_files":75}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let report = value["report"].as_str().expect("report string");
    assert_eq!(
        report,
        format!(
            "## Git hotspots\n\n- Repository: `{}`\n- Timeframe: since 2020-01-01T00:00:00Z\n- Analyzed commits: 12\n- Unique files (before cap): 1\n- Truncated: false\n\n| Path | Churn | Complexity | Category | Authors |\n|------|-------|------------|----------|---------|\n| `src{sep}ComplexService.java` | 12 | 16 | HOTSPOT | Test User(12) |",
            temp.path().canonicalize().unwrap().display(),
            sep = MAIN_SEPARATOR
        )
    );
}

#[test]
fn python_boundary_returns_list_symbols_json() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("list_symbols", r#"{"file_patterns":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["files"][0]["path"], "A.java");
    let lines = value["files"][0]["lines"].as_array().unwrap();
    assert!(lines.iter().any(|line| line.as_str() == Some("  - AInner")));
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("    - AInnerInner"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("      - method7"))
    );
}

#[test]
fn python_boundary_surfaces_invalid_params() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_json("search_symbols", r#"{"patterns":1}"#)
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
    assert!(err.message.contains("Invalid tool arguments"));
}

#[test]
fn python_boundary_returns_most_relevant_files_json() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("A.java"), "public class A { }\n").unwrap();
    fs::write(temp.path().join("B.java"), "public class B { }\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("A.java")).unwrap();
    index.add_path(std::path::Path::new("B.java")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["files"].as_array().unwrap();
    assert!(
        files.iter().any(|item| item == "B.java"),
        "payload: {value}"
    );
    assert_eq!(0, value["not_found"].as_array().unwrap().len());
}

#[test]
fn search_symbols_limit_selects_git_important_file_then_renders_alphabetically() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a_low.java"), "class ALow {}\n").unwrap();
    fs::write(temp.path().join("z_high.java"), "class ZHigh {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["a_low.java"], "add low");
    commit_paths(&repo, &["z_high.java"], "add high");
    fs::write(
        temp.path().join("z_high.java"),
        "class ZHigh { int value; }\n",
    )
    .unwrap();
    commit_paths(&repo, &["z_high.java"], "update high");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":[".*"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("z_high.java", files[0]["path"]);
    assert_eq!("class ZHigh", files[0]["classes"][0]["signature"]);
    assert_eq!(1, files[0]["classes"][0]["line"]);
}

#[test]
fn search_symbols_prefers_exact_match_over_hot_partial_match_file() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("BootmgrApple.java"),
        "class BootmgrApple { void ffDetectBootmgr() {} }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("BootmgrUtility.java"),
        "class BootmgrUtility {\n    void ffDetectBootmgrFallback() {}\n}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["BootmgrApple.java"], "add exact match");
    commit_paths(&repo, &["BootmgrUtility.java"], "add utility");
    fs::write(
        temp.path().join("BootmgrUtility.java"),
        "class BootmgrUtility {\n    void ffDetectBootmgrFallback() {}\n    void ffDetectBootmgrTelemetry() {}\n}\n",
    )
    .unwrap();
    commit_paths(&repo, &["BootmgrUtility.java"], "heat utility");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["ffDetectBootmgr"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("BootmgrApple.java", files[0]["path"], "payload: {value}");
    assert_eq!(
        "void ffDetectBootmgr()",
        files[0]["functions"][0]["signature"]
    );
}

#[test]
fn get_active_workspace_returns_initial_root() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let expected = fixture_root().canonicalize().unwrap();
    assert_eq!(value["workspace_path"], expected.display().to_string());
}

#[test]
fn activate_workspace_rejects_relative_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_json(
            "activate_workspace",
            r#"{"workspace_path":"relative/path"}"#,
        )
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
    assert!(
        err.message.contains("must be absolute"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn activate_workspace_rejects_nonexistent_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_json(
            "activate_workspace",
            r#"{"workspace_path":"/this/path/should/not/exist/bifrost-test"}"#,
        )
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
}

#[test]
fn activate_workspace_idempotent_for_same_root() {
    // Use a fresh git repo as a self-contained root so resolve_workspace_root
    // returns the same path that was passed in.
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Same.java"), "public class Same {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Same.java"], "initial");
    let same_root = temp.path().canonicalize().unwrap();

    let service = SearchToolsService::new_without_semantic_index(same_root.clone()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&same_root.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(value["workspace_path"], same_root.display().to_string());
}

#[test]
fn activate_workspace_switches_to_new_root() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Switched.java"),
        "public class Switched {}\n",
    )
    .unwrap();
    let new_root = temp.path().canonicalize().unwrap();

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&new_root.display().to_string()).unwrap()
    );
    let activate_payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let activate_value: Value = serde_json::from_str(&activate_payload).unwrap();
    assert_eq!(
        activate_value["workspace_path"],
        new_root.display().to_string()
    );

    let get_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let get_value: Value = serde_json::from_str(&get_payload).unwrap();
    assert_eq!(get_value["workspace_path"], new_root.display().to_string());

    // The new workspace should index files from the new root, not the old one.
    let summary_payload = service
        .call_tool_json("list_symbols", r#"{"file_patterns":["Switched.java"]}"#)
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["files"][0]["path"], "Switched.java");
}

#[test]
fn activate_workspace_failure_preserves_existing_workspace() {
    // Pointing activate at a regular file (not a directory) makes
    // FilesystemProject::new reject the path. The existing workspace must
    // still answer queries afterwards.
    let temp = TempDir::new().unwrap();
    let bad_path = temp.path().join("not_a_dir.txt");
    fs::write(&bad_path, "not a directory").unwrap();
    let bad_path = bad_path.canonicalize().unwrap();

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&bad_path.display().to_string()).unwrap()
    );
    let err = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap_err();
    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);

    // Original workspace must remain queryable.
    let active_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let active_value: Value = serde_json::from_str(&active_payload).unwrap();
    let expected = fixture_root().canonicalize().unwrap();
    assert_eq!(
        active_value["workspace_path"],
        expected.display().to_string()
    );

    let summary_payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["summaries"][0]["path"], "A.java");
}

#[test]
fn scan_usages_returns_call_sites_grouped_by_file() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["E.iMethod"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    assert_eq!("E.iMethod", usages[0]["symbol"]);
    assert!(
        usages[0]["total_hits"].as_u64().unwrap() >= 1,
        "expected >=1 hit, payload: {value}"
    );
    assert!(
        usages[0]["candidate_files_truncated"].is_null(),
        "candidate_files_truncated should be omitted when false: {value}"
    );

    let files = usages[0]["files"].as_array().unwrap();
    let use_e = files
        .iter()
        .find(|file| file["path"] == "UseE.java")
        .unwrap_or_else(|| panic!("expected UseE.java in files: {value}"));
    let hits = use_e["hits"].as_array().unwrap();
    assert!(
        hits.iter().any(|hit| hit["snippet"]
            .as_str()
            .unwrap_or_default()
            .contains("e.iMethod()")),
        "expected snippet to contain `e.iMethod()`: {value}"
    );

    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "ambiguous"));
    assert_eq!(0, array_len(&value, "failures"));
    assert_eq!(0, array_len(&value, "too_many_callsites"));
}

#[test]
fn scan_usages_mcp_call_uses_ruby_receiver_aware_resolution() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/user.rb",
            r#"
class User
  def save
  end
end

class Account
  def save
  end
end

class App
  def run
    user = User.new
    user.save

    account = Account.new
    account.save
  end
end
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["User.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "not_found"), "payload: {value}");
    assert_eq!(0, array_len(&value, "ambiguous"), "payload: {value}");
    assert_eq!(0, array_len(&value, "failures"), "payload: {value}");
    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    assert_eq!("User.save", usages[0]["symbol"], "payload: {value}");
    assert_eq!(1, usages[0]["total_hits"], "payload: {value}");
    let hits = usages[0]["files"][0]["hits"].as_array().unwrap();
    assert!(
        hits.iter().any(|hit| hit["snippet"]
            .as_str()
            .unwrap_or_default()
            .contains("user.save")),
        "expected user.save hit: {value}"
    );
    assert!(
        hits.iter().all(|hit| !hit["snippet"]
            .as_str()
            .unwrap_or_default()
            .contains("account.save")),
        "must not report Account#save as User#save usage: {value}"
    );
}

#[test]
fn scan_usages_mcp_call_resolves_ruby_public_send_symbol_dispatch() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/user.rb",
            r#"
class User
  def save
  end
end

class Account
  def save
  end
end

class App
  def run
    user = User.new
    user.public_send(:save)
    user.public_send(:missing, :save)

    account = Account.new
    account.public_send(:save)
  end
end
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["User.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "not_found"), "payload: {value}");
    assert_eq!(0, array_len(&value, "ambiguous"), "payload: {value}");
    assert_eq!(0, array_len(&value, "failures"), "payload: {value}");
    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    assert_eq!("User.save", usages[0]["symbol"], "payload: {value}");
    assert_eq!(1, usages[0]["total_hits"], "payload: {value}");
    let hits = usages[0]["files"][0]["hits"].as_array().unwrap();
    assert!(
        hits.iter().any(|hit| hit["snippet"]
            .as_str()
            .unwrap_or_default()
            .contains("user.public_send(:save)")),
        "expected user.public_send(:save) hit: {value}"
    );
}

#[test]
fn scan_usages_mcp_call_surfaces_ruby_unsafe_inference() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/user.rb",
            r#"
class User
  def save
  end
end

class App
  def run(obj)
    obj.save
    send(:save)
  end
end
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["User.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_scan_usages_failure(
        &value,
        "User.save",
        "RubyUsageGraphStrategy",
        "unsafe_inference",
    );
}

#[test]
fn scan_usages_accepts_location_target_without_symbols() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Greeter.java",
            "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
        )
        .file(
            "Caller.java",
            "public class Caller {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"targets":[{"path":"Greeter.java","line":2,"column":19}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(
        1,
        value["usages"].as_array().unwrap().len(),
        "payload: {value}"
    );
    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn scan_usages_requires_symbols_unless_targets_are_supplied() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    for args in [
        r#"{}"#,
        r#"{"symbols":[]}"#,
        r#"{"symbols":["   "],"targets":[]}"#,
    ] {
        let err = service.call_tool_json("scan_usages", args).unwrap_err();
        assert_eq!(SearchToolsServiceErrorCode::InvalidParams, err.code);
        assert!(
            err.message.contains("requires a non-empty `symbols` array"),
            "unexpected error for {args}: {}",
            err.message
        );
    }
}

#[test]
fn scan_usages_location_target_disambiguates_commonjs_declarations() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "node_modules/accepts/index.js",
            "module.exports = function accepts() {};\n",
        )
        .file(
            "lib/request.js",
            r#"
var accepts = require("accepts");

var req = exports = module.exports = {};

req.accepts = function acceptsMethod(type) {
  return accepts(this).types(type);
};
"#,
        )
        .file(
            "app.js",
            r#"
var req = require("./lib/request");

function run() {
  return req.accepts("json");
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let string_payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["accepts"],"include_tests":true}"#,
        )
        .unwrap();
    let string_value: Value = serde_json::from_str(&string_payload).unwrap();
    assert!(
        string_value["ambiguous"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "bare string selector should remain ambiguous: {string_value}"
    );

    let dependency_payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"targets":[{"path":"lib/request.js","line":2,"column":5}],"include_tests":true}"#,
        )
        .unwrap();
    let dependency: Value = serde_json::from_str(&dependency_payload).unwrap();
    assert_scan_usages_failure(
        &dependency,
        "lib/request.js#request.js.accepts",
        "JsTsExportUsageGraphStrategy",
        "no_graph_seed",
    );

    let method_payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"targets":[{"path":"lib/request.js","line":6,"column":5}],"include_tests":true}"#,
        )
        .unwrap();
    let method: Value = serde_json::from_str(&method_payload).unwrap();
    assert_scan_usages_failure(
        &method,
        "lib/request.js#req.accepts",
        "JsTsExportUsageGraphStrategy",
        "no_graph_seed",
    );
}

#[test]
fn scan_usages_location_target_uses_column_on_same_line_declarations() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            "export function first() {} export function second() {}\nfirst();\nsecond();\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"targets":[{"path":"app.js","line":1,"column":42}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "ambiguous"), "payload: {value}");
    assert_eq!("app.js#second", value["usages"][0]["symbol"], "{value}");
}

#[test]
fn scan_usages_location_target_does_not_select_nested_same_line_member() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            "export class Widget { render() {} }\nnew Widget();\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"targets":[{"path":"app.js","line":1,"column":14}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "ambiguous"), "payload: {value}");
    assert_eq!("app.js#Widget", value["usages"][0]["symbol"]);
}

#[test]
fn scan_usages_ambiguous_symbol_includes_capped_location_details() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("a.js", "export function helper() {}\n")
        .file("b.js", "export function helper() {}\n")
        .file("c.js", "export function helper() {}\n")
        .file("d.js", "export function helper() {}\n")
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["helper"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let ambiguous = &value["ambiguous"][0];

    assert_eq!(4, ambiguous["candidate_targets"].as_array().unwrap().len());
    assert_eq!(3, ambiguous["candidate_details"].as_array().unwrap().len());
    assert_eq!(4, ambiguous["candidate_details_total"].as_u64().unwrap());
    assert_eq!(true, ambiguous["candidate_details_truncated"]);
    assert!(
        ambiguous["note"]
            .as_str()
            .unwrap()
            .contains("Showing first 3 of 4 candidate locations"),
        "payload: {value}"
    );
    for detail in ambiguous["candidate_details"].as_array().unwrap() {
        assert!(detail["scan_usages_target"]["path"].as_str().is_some());
        assert_eq!(1, detail["scan_usages_target"]["line"].as_u64().unwrap());
        assert!(detail["scan_usages_target"]["column"].as_u64().is_some());
    }
}

#[test]
fn scan_usages_reports_unknown_symbol_as_not_found() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["does.not.Exist"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "usages"));
    let not_found = value["not_found"].as_array().unwrap();
    assert_eq!(1, not_found.len());
    assert_eq!("does.not.Exist", not_found[0]);
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn scan_usages_reports_graph_failure_reason_without_regex_fallback() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("Domain")).unwrap();
    fs::write(
        temp.path().join("Domain").join("Target.cs"),
        r#"
namespace Domain {
    public class Target {
        public void Run() {}
        public void Execute() {
            Run();
        }
    }
}
"#,
    )
    .unwrap();
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Domain.Target.Run"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "usages"));
    assert_eq!(0, array_len(&value, "not_found"));
    let failures = value["failures"].as_array().unwrap();
    assert_eq!(1, failures.len(), "payload: {value}");
    assert_eq!("Domain.Target.Run", failures[0]["symbol"]);
    assert_eq!("CSharpUsageGraphStrategy", failures[0]["strategy"]);
    assert_eq!("unsafe_inference", failures[0]["reason_kind"]);
    assert!(
        failures[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("CSharpUsageGraphStrategy")),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_skips_blank_symbols_when_non_empty_symbol_is_present() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["", "   ", "E.iMethod"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, array_len(&value, "usages"));
    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn scan_usages_excludes_test_files_when_include_tests_is_false() {
    // Two callers of `Greeter.hello`: one in production code, one in a JUnit test
    // file. With include_tests=false, the test caller must be filtered before the
    // regex scan so that test hits do not eat into DEFAULT_MAX_USAGES and do not
    // appear in the result. With include_tests=true, both callers must show up.
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Greeter.java"),
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("ProdCaller.java"),
        "public class ProdCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("GreeterTest.java"),
        "import org.junit.Test;\npublic class GreeterTest {\n    @Test\n    public void greets() { new Greeter().hello(); }\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let production_only = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":false}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&production_only).unwrap();
    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    let files = usages[0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"ProdCaller.java"),
        "ProdCaller.java should be in results: {value}"
    );
    assert!(
        !paths.contains(&"GreeterTest.java"),
        "GreeterTest.java must be filtered when include_tests=false: {value}"
    );

    let with_tests = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&with_tests).unwrap();
    let files = value["usages"][0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"ProdCaller.java"),
        "ProdCaller.java missing with include_tests=true: {value}"
    );
    assert!(
        paths.contains(&"GreeterTest.java"),
        "GreeterTest.java missing with include_tests=true: {value}"
    );
}

#[test]
fn scan_usages_paths_filter_limits_candidate_files() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("nested")).unwrap();
    fs::write(
        temp.path().join("Greeter.java"),
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("ProdCaller.java"),
        "public class ProdCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("nested").join("NestedCaller.java"),
        "public class NestedCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["nested/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["usages"][0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(vec!["nested/NestedCaller.java"], paths, "payload: {value}");
}

#[test]
fn scan_usages_paths_scope_is_independent_of_out_of_scope_callers() {
    // `Helper` is a high-fan-in symbol: 50+ files call it. Scoping the query to one file must
    // return only that file's call site, and the cost must not scale with how many other files
    // reference the symbol — the search is bounded by `paths`, not by the symbol's popularity.
    // This is the regression guard for the perf fix: candidates are resolved straight from
    // `paths` rather than enumerated workspace-wide and filtered after the fact.
    let mut project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "helper.go",
            "package app\n\nfunc Helper() string { return \"hi\" }\n",
        )
        .file(
            "want_caller.go",
            "package app\n\nfunc UseHere() string { return Helper() }\n",
        );
    for idx in 0..50 {
        project = project.file(
            format!("decoy{idx}.go"),
            format!("package app\n\nfunc Decoy{idx}() string {{ return Helper() }}\n"),
        );
    }
    let project = project.build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Helper"],"include_tests":true,"paths":["want_caller.go"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["usages"][0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(vec!["want_caller.go"], paths, "payload: {value}");
    assert_eq!(
        1,
        value["usages"][0]["total_hits"].as_u64().unwrap(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_paths_scope_returns_all_in_scope_callers() {
    // A glob `paths` matching several files must return every in-scope call site (not just the
    // first) while still excluding out-of-scope callers.
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Greeter.java",
            "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
        )
        .file(
            "scoped/CallerA.java",
            "public class CallerA {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .file(
            "scoped/CallerB.java",
            "public class CallerB {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .file(
            "OutOfScope.java",
            "public class OutOfScope {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["scoped/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["usages"][0]["files"].as_array().unwrap();
    let mut paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    paths.sort();
    assert_eq!(
        vec!["scoped/CallerA.java", "scoped/CallerB.java"],
        paths,
        "payload: {value}"
    );
}

#[test]
fn scan_usages_paths_scope_does_not_truncate_broad_glob_candidates_before_scanning() {
    let mut project = InlineTestProject::with_language(Language::Java).file(
        "Greeter.java",
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    );
    for idx in 0..1005 {
        let body = if idx == 1004 {
            "return new Greeter().hello();"
        } else {
            "return \"skip\";"
        };
        project = project.file(
            format!("scoped/Caller{idx:04}.java"),
            format!("public class Caller{idx:04} {{\n    public String run() {{ {body} }}\n}}\n"),
        );
    }
    let project = project.build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["scoped/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(false, value["summary"]["partial"], "payload: {value}");
    assert!(
        value["usages"][0]["candidate_files_truncated"].is_null(),
        "path-scoped scans must not apply the generic pre-scan candidate cap: {value}"
    );
    assert_eq!(
        1,
        value["usages"][0]["total_hits"].as_u64().unwrap(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_paths_scope_keeps_cross_language_scala_usages_of_java_type() {
    // A Java class can be referenced from Scala, and the Java usage strategy discovers those by
    // scanning Scala files in the candidate set. A path-scoped query that names a Scala file must
    // therefore still surface the cross-language usage — the language filter on path-scoped
    // candidates keeps Scala files for a Java-class target instead of dropping them.
    let project = InlineTestProject::new()
        .file(
            "com/example/Target.java",
            "package com.example;\n\npublic class Target {\n    public void run() {}\n}\n",
        )
        .file(
            "app/ScalaConsumer.scala",
            "package app\n\nimport com.example.Target\n\nclass ScalaConsumer {\n  val annotated: Target = new Target()\n}\n",
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["com.example.Target"],"include_tests":true,"paths":["app/ScalaConsumer.scala"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["usages"][0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        vec!["app/ScalaConsumer.scala"],
        paths,
        "cross-language Scala->Java usage must survive path scoping; payload: {value}"
    );
}

#[test]
fn scan_usages_demotes_large_result_to_summary_within_budget() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Target.java"),
        "public class Target {\n    public void hit() {}\n}\n",
    )
    .unwrap();
    for idx in 0..350 {
        fs::write(
            temp.path().join(format!("Caller{idx}.java")),
            format!(
                "public class Caller{idx} {{\n    public void run() {{ new Target().hit(); }}\n}}\n"
            ),
        )
        .unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Target.hit"],"include_tests":true}"#,
        )
        .unwrap();
    assert!(
        payload.len() <= SCAN_USAGES_RESPONSE_BUDGET_BYTES,
        "payload should stay within scan_usages budget, got {} bytes",
        payload.len()
    );

    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(1, value["summary"]["requested_symbols"].as_u64().unwrap());
    assert_eq!(1, value["summary"]["resolved_symbols"].as_u64().unwrap());
    assert_eq!(350, value["summary"]["total_hits"].as_u64().unwrap());
    assert_eq!(
        "scan_usages",
        value["summary"]["recommended_next_call"]["tool"]
            .as_str()
            .unwrap()
    );
    assert_eq!(0, array_len(&value, "too_many_callsites"));
    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    let usage = &value["usages"][0];
    assert_eq!("summary", usage["rendering"]);
    assert_eq!(350, usage["total_hits"].as_u64().unwrap());
    assert_eq!(
        20,
        usage["files"].as_array().unwrap().len(),
        "payload: {value}"
    );
    assert_eq!(330, usage["files_truncated"].as_u64().unwrap());
    assert!(
        usage["top_enclosing"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_resolved_symbol_with_no_hits_is_emitted_with_zero_total() {
    // method7 lives on A.AInner.AInnerInner and has no callers in the fixture.
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["A.AInner.AInnerInner.method7"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    assert_eq!("A.AInner.AInnerInner.method7", usages[0]["symbol"]);
    assert_eq!(0, usages[0]["total_hits"].as_u64().unwrap());
    assert_eq!(0, array_len(&usages[0], "files"));
    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn activate_workspace_normalizes_to_git_root() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Top.java"), "public class Top {}\n").unwrap();
    fs::create_dir_all(temp.path().join("nested")).unwrap();
    fs::write(
        temp.path().join("nested").join("Inner.java"),
        "public class Inner {}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Top.java", "nested/Inner.java"], "initial");

    let repo_root = temp.path().canonicalize().unwrap();
    let nested = repo_root.join("nested");

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&nested.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["workspace_path"], repo_root.display().to_string());
}

#[test]
fn service_initializes_generated_large_workspace_with_deep_java_shape() {
    let temp = generated_java_workspace(1_000, 256, false);
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["DeepRoot"],"include_tests":true,"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "DeepRoot.java"),
        "payload: {value}"
    );
}

#[test]
#[ignore = "expensive 10k-file smoke test for issue #175"]
fn service_initializes_ten_thousand_tracked_java_files_without_stack_overflow() {
    let temp = generated_java_workspace(10_000, 512, true);
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["Generated9999"],"include_tests":true,"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "Generated9999.java"),
        "payload: {value}"
    );
}

fn generated_java_workspace(file_count: usize, nested_depth: usize, tracked: bool) -> TempDir {
    let temp = TempDir::new().unwrap();
    let mut paths = Vec::with_capacity(file_count + 1);

    let deep_path = temp.path().join("DeepRoot.java");
    fs::write(&deep_path, deep_java_source(nested_depth)).unwrap();
    paths.push(PathBuf::from("DeepRoot.java"));

    for index in 0..file_count {
        let rel = PathBuf::from(format!("Generated{index}.java"));
        fs::write(
            temp.path().join(&rel),
            format!("public class Generated{index} {{ int value() {{ return {index}; }} }}\n"),
        )
        .unwrap();
        paths.push(rel);
    }

    if tracked {
        let repo = Repository::init(temp.path()).unwrap();
        let mut index = repo.index().unwrap();
        for path in &paths {
            index.add_path(path).unwrap();
        }
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "generated",
            &tree,
            &[],
        )
        .unwrap();
    }

    temp
}

fn deep_java_source(depth: usize) -> String {
    let mut source = String::from("public class DeepRoot {\n");
    for index in 0..depth {
        source.push_str(&format!("static class Nested{index} {{\n"));
    }
    source.push_str("int value() { return 1; }\n");
    for _ in 0..depth {
        source.push_str("}\n");
    }
    source.push_str("}\n");
    source
}

fn commit_paths(repo: &Repository, paths: &[&str], message: &str) {
    let mut index = repo.index().unwrap();
    for path in paths {
        index.add_path(std::path::Path::new(path)).unwrap();
    }
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    let parent = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .unwrap();
}

#[test]
fn semantic_search_reports_disabled_without_indexer() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_value(
            "semantic_search",
            serde_json::json!({ "query": "anything", "k": 1 }),
        )
        .expect_err("semantic_search must fail without an indexer");
    assert!(
        err.message.contains("disabled") || err.message.contains("not available"),
        "unexpected error message: {}",
        err.message
    );
}

#[test]
fn semantic_search_status_reports_disabled_without_indexer() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_value("semantic_search_status", serde_json::json!({}))
        .expect_err("semantic_search_status must fail without an indexer");
    assert!(
        err.message.contains("disabled") || err.message.contains("not available"),
        "unexpected error message: {}",
        err.message
    );
}
