//! Fan-out guards for the glob-consuming searchtools: a target that matches
//! more files than the tool's cap is skipped and reported through `too_broad`,
//! instead of summarizing (or sourcing) most of the workspace.

use crate::common::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost::{
    SearchToolsService,
    searchtools::{GET_SUMMARIES_MAX_FILES_PER_TARGET, GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET},
    searchtools_render::RenderOptions,
};
use serde_json::Value;

const WIDE_FILES: usize = 25;
const NARROW_FILES: usize = 5;

/// `wide/` holds more files than the cap, `narrow/` holds fewer, so one fixture
/// serves both the tripped and the untripped case. Names are zero padded so the
/// sample's path order is the obvious numeric one.
fn fixture() -> BuiltInlineTestProject {
    let mut project = InlineTestProject::new();
    for index in 0..WIDE_FILES {
        project = project.file(
            format!("wide/Wide{index:02}.java"),
            format!("public class Wide{index:02} {{ public int value() {{ return {index}; }} }}\n"),
        );
    }
    for index in 0..NARROW_FILES {
        project = project.file(
            format!("narrow/Narrow{index:02}.java"),
            format!(
                "public class Narrow{index:02} {{ public int value() {{ return {index}; }} }}\n"
            ),
        );
    }
    project.build()
}

fn service(project: &BuiltInlineTestProject) -> SearchToolsService {
    SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf()).unwrap()
}

fn summaries_json(service: &SearchToolsService, targets_json: &str) -> Value {
    let payload = service
        .call_tool_json("get_summaries", targets_json)
        .unwrap();
    serde_json::from_str(&payload).unwrap()
}

fn symbol_sources_json(service: &SearchToolsService, symbols_json: &str) -> Value {
    let payload = service
        .call_tool_json("get_symbol_sources", symbols_json)
        .unwrap();
    serde_json::from_str(&payload).unwrap()
}

/// `too_broad` is `skip_serializing_if = "Vec::is_empty"`, so an absent key and
/// an empty array mean the same thing to a caller.
fn array(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[test]
fn get_summaries_glob_over_cap_reports_too_broad_and_skips_summaries() {
    let project = fixture();
    let service = service(&project);

    let value = summaries_json(&service, r#"{"targets":["wide/**"]}"#);

    let too_broad = array(&value, "too_broad");
    assert_eq!(1, too_broad.len(), "{value}");
    let scope = &too_broad[0];
    assert_eq!("wide/**", scope["target"], "{value}");
    assert_eq!(WIDE_FILES as u64, scope["matched"].as_u64().unwrap());
    assert_eq!(
        GET_SUMMARIES_MAX_FILES_PER_TARGET as u64,
        scope["cap"].as_u64().unwrap()
    );
    let sample: Vec<_> = scope["sample"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap().to_string())
        .collect();
    let expected_sample: Vec<String> = (0..10).map(|i| format!("wide/Wide{i:02}.java")).collect();
    assert_eq!(expected_sample, sample, "{value}");

    assert!(array(&value, "summaries").is_empty(), "{value}");
}

#[test]
fn get_summaries_glob_under_cap_summarizes_every_file() {
    let project = fixture();
    let service = service(&project);

    let value = summaries_json(&service, r#"{"targets":["narrow/**"]}"#);

    assert!(array(&value, "too_broad").is_empty(), "{value}");
    assert_eq!(NARROW_FILES, array(&value, "summaries").len(), "{value}");
}

#[test]
fn get_summaries_explicit_file_targets_never_trip_too_broad_guard() {
    let project = fixture();
    let service = service(&project);

    let targets: Vec<String> = (0..WIDE_FILES)
        .map(|index| format!("wide/Wide{index:02}.java"))
        .collect();
    assert!(targets.len() > GET_SUMMARIES_MAX_FILES_PER_TARGET);
    let arguments = serde_json::json!({ "targets": targets }).to_string();

    let value = summaries_json(&service, &arguments);

    assert!(array(&value, "too_broad").is_empty(), "{value}");
    assert_eq!(WIDE_FILES, array(&value, "summaries").len(), "{value}");
}

#[test]
fn get_summaries_too_broad_render_names_target_counts_and_narrowing() {
    let project = fixture();
    let service = service(&project);

    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["wide/**"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let rendered = value["rendered_text"].as_str().expect("rendered text");

    assert!(rendered.contains("wide/**"), "{rendered}");
    assert!(rendered.contains(&WIDE_FILES.to_string()), "{rendered}");
    assert!(
        rendered.contains(&GET_SUMMARIES_MAX_FILES_PER_TARGET.to_string()),
        "{rendered}"
    );
    assert!(rendered.contains("wide/Wide00.java"), "{rendered}");
    assert!(rendered.contains("list_symbols"), "{rendered}");
}

#[test]
fn get_symbol_sources_glob_over_cap_reports_too_broad_and_skips_sources() {
    let project = fixture();
    let service = service(&project);

    let value = symbol_sources_json(&service, r#"{"symbols":["wide/**"]}"#);

    let too_broad = array(&value, "too_broad");
    assert_eq!(1, too_broad.len(), "{value}");
    let scope = &too_broad[0];
    assert_eq!("wide/**", scope["target"], "{value}");
    assert_eq!(WIDE_FILES as u64, scope["matched"].as_u64().unwrap());
    assert_eq!(
        GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET as u64,
        scope["cap"].as_u64().unwrap()
    );
    let sample: Vec<_> = scope["sample"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap().to_string())
        .collect();
    let expected_sample: Vec<String> = (0..10).map(|i| format!("wide/Wide{i:02}.java")).collect();
    assert_eq!(expected_sample, sample, "{value}");

    assert!(array(&value, "sources").is_empty(), "{value}");
}

#[test]
fn get_symbol_sources_glob_under_cap_returns_every_matched_file() {
    let project = fixture();
    let service = service(&project);

    assert!(NARROW_FILES <= GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET);
    let value = symbol_sources_json(&service, r#"{"symbols":["narrow/**"]}"#);

    assert!(array(&value, "too_broad").is_empty(), "{value}");
    assert_eq!(NARROW_FILES, array(&value, "sources").len(), "{value}");
}

#[test]
fn get_symbol_sources_exact_symbol_and_single_file_path_never_trip_the_guard() {
    let project = fixture();
    let service = service(&project);

    let by_name = symbol_sources_json(&service, r#"{"symbols":["Wide00"]}"#);
    assert!(array(&by_name, "too_broad").is_empty(), "{by_name}");
    assert_eq!(1, array(&by_name, "sources").len(), "{by_name}");

    let by_path = symbol_sources_json(&service, r#"{"symbols":["wide/Wide00.java"]}"#);
    assert!(array(&by_path, "too_broad").is_empty(), "{by_path}");
    assert_eq!(1, array(&by_path, "sources").len(), "{by_path}");
}

#[test]
fn get_symbol_sources_too_broad_render_names_target_counts_and_narrowing() {
    let project = fixture();
    let service = service(&project);

    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["wide/**"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let rendered = value["rendered_text"].as_str().expect("rendered text");

    assert!(rendered.contains("wide/**"), "{rendered}");
    assert!(rendered.contains(&WIDE_FILES.to_string()), "{rendered}");
    assert!(
        rendered.contains(&GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET.to_string()),
        "{rendered}"
    );
    assert!(rendered.contains("wide/Wide00.java"), "{rendered}");
    assert!(rendered.contains("list_symbols"), "{rendered}");
}
