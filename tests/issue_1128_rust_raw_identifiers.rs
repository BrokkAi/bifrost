//! Issue #1128: Rust raw-identifier escapes (`r#type`) make declarations
//! unresolvable. nushell's `DbColumn` struct has a field written `r#type`;
//! `get_summaries` displayed it as `...DbColumn.r#type`, but resolving that
//! exact spelling returned not_found, and the un-escaped `...DbColumn.type`
//! failed too -- the field was invisible to selectors under any spelling
//! (fuzzer I3a: a displayed spelling must round-trip).
//!
//! Fix: `r#` is raw-identifier escape syntax, not part of the identifier
//! (this is how rustc/rust-analyzer treat it), so the index stores the
//! un-escaped canonical name (`type`) for short_name/fq_name/identifier, and
//! the selector side aliases the escaped spelling (`r#type`) to the same
//! canonical segment. Display naturally follows: `get_summaries` now shows
//! the canonical `type`.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use serde_json::Value;

fn call_tool(project: &common::BuiltInlineTestProject, tool: &str, args: &str) -> Value {
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");
    let payload = service
        .call_tool_json(tool, args)
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

fn symbol_sources(project: &common::BuiltInlineTestProject, symbol: &str) -> Value {
    call_tool(
        project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": [symbol] }).to_string(),
    )
}

fn assert_resolves(project: &common::BuiltInlineTestProject, symbol: &str, expected_snippet: &str) {
    let result = symbol_sources(project, symbol);
    assert_eq!(
        0,
        result["not_found"].as_array().unwrap().len(),
        "`{symbol}` must resolve: {result}"
    );
    assert_eq!(
        0,
        result["ambiguous"].as_array().unwrap().len(),
        "`{symbol}` must resolve unambiguously: {result}"
    );
    let sources = result["sources"].as_array().unwrap();
    assert!(
        !sources.is_empty(),
        "`{symbol}` must have sources: {result}"
    );
    assert!(
        sources.iter().any(|source| source["text"]
            .as_str()
            .unwrap_or("")
            .contains(expected_snippet)),
        "`{symbol}` did not resolve to text containing `{expected_snippet}`: {result}"
    );
}

/// The exact fuzzer shape from the issue: a struct with a raw-identifier
/// field (`r#type`), a plain field (`rate`, to prove ordinary `r`-prefixed
/// names are untouched), and a method whose body both uses `self.r#type` and
/// contains the two characters `r#type` inside a string literal (which must
/// never be mistaken for an identifier).
fn db_column_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "src/db_column.rs",
            "pub struct DbColumn {\n    pub r#type: String,\n    pub rate: i32,\n}\n\nimpl DbColumn {\n    pub fn describe(&self) -> String {\n        // Not an identifier: a string literal containing the two\n        // characters `r#type` must not create a phantom declaration.\n        format!(\"r#type = {}\", self.r#type)\n    }\n}\n",
        )
        .build()
}

#[test]
fn raw_identifier_field_displays_canonical_spelling_in_summaries() {
    let project = db_column_project();

    let summary = call_tool(&project, "get_summaries", r#"{"targets":["DbColumn"]}"#);
    assert_eq!(
        0,
        summary["not_found"].as_array().unwrap().len(),
        "{summary}"
    );

    let elements = summary["summaries"][0]["elements"]
        .as_array()
        .unwrap_or_else(|| panic!("expected elements array: {summary}"));
    let field_symbols: Vec<&str> = elements
        .iter()
        .filter(|element| element["kind"] == "field")
        .map(|element| element["symbol"].as_str().expect("symbol"))
        .collect();

    assert!(
        field_symbols
            .iter()
            .any(|symbol| symbol.ends_with("DbColumn.type")),
        "canonical field symbol `DbColumn.type` missing from {field_symbols:?}: {summary}"
    );
    assert!(
        !field_symbols.iter().any(|symbol| symbol.contains("r#")),
        "no displayed field symbol may retain the `r#` escape: {field_symbols:?}: {summary}"
    );
    assert!(
        field_symbols
            .iter()
            .any(|symbol| symbol.ends_with("DbColumn.rate")),
        "ordinary field `rate` must still display normally: {field_symbols:?}: {summary}"
    );
}

/// I3a round-trip: both the new canonical spelling (`DbColumn.type`) and the
/// escaped spelling users still type or copy from old displays
/// (`DbColumn.r#type`) must resolve `get_symbol_sources`, to the same field.
#[test]
fn raw_identifier_field_resolves_under_both_spellings() {
    let project = db_column_project();

    for symbol in ["DbColumn.type", "DbColumn.r#type"] {
        assert_resolves(&project, symbol, "r#type: String");
    }

    // An ordinary identifier that merely starts with `r` is untouched by the
    // raw-identifier normalization.
    assert_resolves(&project, "DbColumn.rate", "rate: i32");
}

/// File-anchored spellings compose with #1131's path#symbol anchor split
/// (commit c1053b7f): `src/db_column.rs#type` and `src/db_column.rs#r#type`
/// (whose own `#` inside the raw-identifier escape must NOT be mistaken for
/// a second anchor point) both narrow to the same field in that file.
#[test]
fn anchored_spellings_compose_with_1131_anchor_split() {
    let project = db_column_project();

    for symbol in [
        "src/db_column.rs#type",
        "src/db_column.rs#r#type",
        "src/db_column.rs#DbColumn.type",
        "src/db_column.rs#DbColumn.r#type",
    ] {
        assert_resolves(&project, symbol, "r#type: String");
    }
}

/// Usage side: a `self.r#type` field-access reference must resolve to the
/// (now canonically-named) field declaration.
#[test]
fn usage_site_self_dot_raw_type_resolves_to_the_field() {
    let project = db_column_project();

    let result = call_tool(
        &project,
        "get_definitions_by_reference",
        r#"{"references":[{"symbol":"DbColumn.describe","context":"self.r#type","target":"r#type"}]}"#,
    );
    assert_eq!(
        "resolved", result["results"][0]["status"],
        "self.r#type usage site must resolve: {result}"
    );
    let fqn = result["results"][0]["definitions"][0]["fqn"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a definition fqn: {result}"));
    assert!(
        fqn.ends_with("DbColumn.type"),
        "usage site must link to the canonically-named field, got `{fqn}`: {result}"
    );
}

// ---------------------------------------------------------------------------
// Other declaration kinds that can carry a raw-identifier escape: functions,
// modules, enum variants, and consts. Each must resolve under its canonical
// and escaped spellings.
// ---------------------------------------------------------------------------

fn other_raw_identifier_kinds_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "src/kinds.rs",
            "pub fn r#fn() -> i32 {\n    1\n}\n\npub mod r#mod {\n    pub fn value() -> i32 {\n        2\n    }\n}\n\npub enum Op {\n    r#type,\n    Other,\n}\n\npub const r#static: i32 = 3;\n",
        )
        .build()
}

#[test]
fn raw_identifier_function_resolves_under_both_spellings() {
    let project = other_raw_identifier_kinds_project();
    for symbol in ["r#fn", "fn"] {
        // `fn` alone is a reserved word for most other purposes, but as a
        // selector segment it must still reach the declaration exactly like
        // any other bare terminal name.
        assert_resolves(&project, symbol, "pub fn r#fn() -> i32");
    }
}

#[test]
fn raw_identifier_module_resolves_under_both_spellings() {
    let project = other_raw_identifier_kinds_project();
    for symbol in ["mod.value", "r#mod.value"] {
        assert_resolves(&project, symbol, "pub fn value() -> i32");
    }
}

#[test]
fn raw_identifier_enum_variant_resolves_under_both_spellings() {
    let project = other_raw_identifier_kinds_project();
    for symbol in ["Op.type", "Op.r#type"] {
        assert_resolves(&project, symbol, "r#type");
    }
}

#[test]
fn raw_identifier_const_resolves_under_both_spellings() {
    let project = other_raw_identifier_kinds_project();
    for symbol in ["static", "r#static"] {
        assert_resolves(&project, symbol, "pub const r#static: i32 = 3");
    }
}
