//! End-to-end coverage of the qualified-path typed domains (#1475, M4).
//!
//! The load-bearing tests answer the two questions the mined regressions
//! turn on: does a chain arrive as ordered, decoded segments, and is every
//! focused segment's own prefix independently resolvable — with explicit
//! incompleteness where an adapter cannot answer, never an empty complete
//! result.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryResult, SCHEMA_VERSION,
    execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

fn has_diagnostic(result: &CodeQueryResult, code: CodeQueryDiagnosticCode) -> bool {
    result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

const RUST_FIXTURE: &str = "\
pub mod util {
    pub struct Widget;
}

pub fn build() -> crate::util::Widget {
    crate::util::Widget
}
";

/// A chain arrives as ordered, decoded segment rows sharing one path anchor,
/// and with `:resolved true` each segment's own prefix resolution decides the
/// namespace the token alone could not state.
#[test]
fn segments_arrive_ordered_and_independently_resolved() {
    let result = run(
        &[("src/lib.rs", RUST_FIXTURE)],
        json!({
            "schema_version": SCHEMA_VERSION,
            "paths": {},
            "steps": [{ "op": "segments_of", "resolved": true }],
            "limit": 50
        }),
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "diagnostics: {:?}",
        result.diagnostics
    );
    let value = serialized(&result);
    let segments = rows(&value);
    // Two identical three-segment paths (return type and body expression).
    assert_eq!(segments.len(), 6, "rows: {segments:#?}");

    let path_ids: std::collections::BTreeSet<&str> = segments
        .iter()
        .map(|row| row["path_ast_id"].as_str().expect("path anchor"))
        .collect();
    assert_eq!(path_ids.len(), 2);

    let mut terminal_namespaces = std::collections::BTreeSet::new();
    for row in segments {
        match row["ordinal"].as_u64().expect("ordinal") {
            0 => {
                assert_eq!(row["text"], "crate");
                assert!(row["ast_id"].is_null(), "a path keyword is not a fact");
            }
            1 => {
                assert_eq!(row["text"], "util");
                assert_eq!(row["resolution_status"], "resolved");
                assert_eq!(row["namespace"], "module");
            }
            2 => {
                assert_eq!(row["text"], "Widget");
                assert_eq!(row["resolution_status"], "resolved");
                terminal_namespaces
                    .insert(row["namespace"].as_str().expect("namespace").to_string());
            }
            other => panic!("unexpected ordinal {other}"),
        }
    }
    // The same spelling terminates two paths in two namespaces: a type
    // operand in the return type and a value use in the body. The adapter's
    // own classification states each, and resolution never overrides it.
    assert_eq!(
        terminal_namespaces.into_iter().collect::<Vec<_>>(),
        ["type", "value"],
    );
}

/// `segment-target` projects a focused segment onto the declaration its own
/// position resolves to: the module segment reaches the module, without
/// resolving the whole path's terminal.
#[test]
fn segment_target_projects_the_focused_prefix() {
    let result = run(
        &[("src/lib.rs", RUST_FIXTURE)],
        json!({
            "schema_version": SCHEMA_VERSION,
            "paths": {},
            "steps": [
                { "op": "segments_of" },
                { "op": "segment_target" }
            ],
            "limit": 50
        }),
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "diagnostics: {:?}",
        result.diagnostics
    );
    let value = serialized(&result);
    let fq_names: std::collections::BTreeSet<String> = rows(&value)
        .iter()
        .filter_map(|row| row["fq_name"].as_str().map(str::to_string))
        .collect();
    assert!(
        fq_names.iter().any(|name| name.ends_with("util")),
        "the module segment's own resolution must arrive: {fq_names:?}"
    );
    assert!(
        fq_names.iter().any(|name| name.ends_with("Widget")),
        "the terminal segment's resolution must arrive: {fq_names:?}"
    );
}

/// An adapter without the axes reports per-axis incompleteness through the
/// capability spine, never a silently empty complete answer.
#[test]
fn unclaimed_language_reports_identity_axis_unsupported() {
    let result = run(
        &[("main.go", "package main\n\nfunc main() {}\n")],
        json!({
            "schema_version": SCHEMA_VERSION,
            "paths": {},
            "languages": ["go"],
            "limit": 10
        }),
    );
    assert!(result.results.is_empty());
    assert_ne!(result.completion(), CodeQueryCompletion::Complete);
    assert!(
        has_diagnostic(&result, CodeQueryDiagnosticCode::IdentityAxisUnsupported),
        "diagnostics: {:?}",
        result.diagnostics
    );
}

/// The RQL spelling lowers to the same canonical plan as the JSON form, so
/// the two frontends cannot drift.
#[test]
fn rql_form_lowers_to_the_json_plan() {
    let rql = CodeQuery::from_sexp("(segments-of :resolved true (paths :min-segments 3))")
        .expect("RQL should parse");
    let json_query = CodeQuery::from_json(&json!({
        "paths": { "min_segments": 3 },
        "steps": [{ "op": "segments_of", "resolved": true }]
    }))
    .expect("JSON should parse");
    assert_eq!(
        json_query.to_canonical_json(),
        rql.to_canonical_json(),
        "the two frontends must agree"
    );
}

/// A min-segments filter drops shorter chains before they enter the pipeline.
#[test]
fn min_segments_filters_short_chains() {
    let result = run(
        &[(
            "src/lib.rs",
            "pub mod util {\n    pub struct Widget;\n}\npub fn build() -> util::Widget {\n    util::Widget\n}\n",
        )],
        json!({
            "schema_version": SCHEMA_VERSION,
            "paths": { "min_segments": 3 },
            "limit": 50
        }),
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "diagnostics: {:?}",
        result.diagnostics
    );
    assert!(
        result.results.is_empty(),
        "two-segment paths must not pass a min_segments of 3"
    );
}

/// The same-terminal different-owner decoy family, on the query surface: two
/// `Map` structs under different modules produce segment rows whose owner
/// segments resolve to different modules and whose terminals project onto
/// two distinct declarations — the separation the display string could
/// never state.
#[test]
fn same_terminal_decoys_separate_through_their_segments() {
    let result = run(
        &[(
            "src/lib.rs",
            concat!(
                "pub mod a {\n    pub struct Map;\n}\n",
                "pub mod b {\n    pub struct Map;\n}\n",
                "pub fn cross(x: a::Map) -> b::Map {\n",
                "    b::Map\n",
                "}\n",
            ),
        )],
        json!({
            "schema_version": SCHEMA_VERSION,
            "paths": {},
            "steps": [
                { "op": "segments_of" },
                { "op": "segment_target" }
            ],
            "limit": 50
        }),
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "diagnostics: {:?}",
        result.diagnostics
    );
    let value = serialized(&result);
    let map_targets: std::collections::BTreeSet<String> = rows(&value)
        .iter()
        .filter_map(|row| row["fq_name"].as_str())
        .filter(|name| name.ends_with("Map"))
        .map(str::to_string)
        .collect();
    assert_eq!(
        map_targets.len(),
        2,
        "the two same-spelled terminals must project onto two declarations: {map_targets:?}"
    );
}
