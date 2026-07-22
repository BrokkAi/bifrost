//! Regression coverage for issue #941: a bare file-scope begin/end macro
//! sentinel pair (object-like macros the parser cannot see, e.g.
//! `BEGIN_NS`/`END_NS`) makes tree-sitter recover the wrapped region as one bogus
//! `function_definition`, destroying declaration ownership. Targeted inverse
//! usage then returned `verified_absent` with zero hits (a confident lie) and the
//! usage graph omitted every node sourced from the region.
//!
//! The fix (`visit_sentinel_macro_region` in `src/analyzer/cpp/declarations.rs`)
//! reparses the swallowed interior as real C++ items in a padded copy of the
//! file, so the ordinary declaration visitors index namespaces/classes/members
//! with byte/line-exact ownership. Every test here fails before that recovery:
//! the wrapped symbols were `not_found` and the method's usages `verified_absent`.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::usage_graph::{find_edge, usage_graph_at};
use common::{BuiltInlineTestProject, InlineTestProject};
use serde_json::Value;

fn service(project: &BuiltInlineTestProject) -> SearchToolsService {
    SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).expect("service")
}

fn call(project: &BuiltInlineTestProject, tool: &str, args: Value) -> Value {
    let payload = service(project)
        .call_tool_json(tool, &args.to_string())
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

fn symbol_sources(project: &BuiltInlineTestProject, symbol: &str) -> Value {
    call(
        project,
        "get_symbol_sources",
        serde_json::json!({ "symbols": [symbol] }),
    )
}

/// The single resolved source for `symbol`, asserting no not_found/ambiguous.
fn unique_source<'a>(result: &'a Value, symbol: &str) -> &'a Value {
    assert_eq!(
        0,
        result["not_found"].as_array().map_or(0, Vec::len),
        "{symbol} should not be not_found: {result}"
    );
    assert_eq!(
        0,
        result["ambiguous"].as_array().map_or(0, Vec::len),
        "{symbol} should not be ambiguous: {result}"
    );
    let sources = result["sources"].as_array().expect("sources array");
    assert_eq!(
        1,
        sources.len(),
        "{symbol} should resolve to exactly one source: {result}"
    );
    &sources[0]
}

fn source_text(result: &Value, symbol: &str) -> String {
    unique_source(result, symbol)["text"]
        .as_str()
        .expect("source text")
        .to_string()
}

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
}

fn scan_usages(project: &BuiltInlineTestProject, symbol: &str) -> Value {
    call(
        project,
        "scan_usages_by_reference",
        serde_json::json!({ "symbols": [symbol], "include_tests": true }),
    )
}

/// Every `enclosing` string across every proven hit of the first result entry.
fn proven_hit_enclosings(scan: &Value) -> Vec<String> {
    scan["results"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|entry| entry["files"].as_array().into_iter().flatten())
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .filter_map(|hit| hit["enclosing"].as_str().map(str::to_string))
        .collect()
}

const SENTINEL_WIDGET: &str = r#"BEGIN_NS
namespace demo { struct Widget { void doWork(); }; }
END_NS
void callWidget() {
    demo::Widget w;
    w.doWork();
}
"#;

/// The core shape: sentinels wrapping namespace + struct + method. The struct and
/// method must resolve with exact ranges, the method's inverse usage from a caller
/// outside the region must be FOUND (the `verified_absent` lie is dead), and the
/// summary must nest the method under its struct.
#[test]
fn sentinel_wrapped_namespace_struct_method_recovers() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("widget.cpp", SENTINEL_WIDGET)
        .build();

    // (a) The struct and method resolve to exact source ranges.
    let widget = symbol_sources(&project, "Widget");
    let widget_source = unique_source(&widget, "Widget");
    assert_eq!("widget.cpp", widget_source["path"], "{widget}");
    assert_eq!(
        line_of(SENTINEL_WIDGET, "struct Widget"),
        widget_source["start_line"].as_u64().expect("start_line") as usize,
        "Widget start line must be byte/line-exact: {widget}"
    );
    assert!(
        source_text(&widget, "Widget").contains("struct Widget"),
        "{widget}"
    );

    let method = symbol_sources(&project, "doWork");
    assert!(
        source_text(&method, "doWork").contains("doWork"),
        "doWork must resolve to its declaration: {method}"
    );

    // (b) Inverse usage of the method is FOUND with the exact call site, not the
    // pre-fix `verified_absent` lie.
    let scan = scan_usages(&project, "doWork");
    assert_eq!(
        0,
        scan["summary"]["verified_absent"].as_u64().expect("count"),
        "doWork usages must not be verified_absent: {scan}"
    );
    assert!(
        scan["summary"]["found"].as_u64().expect("count") >= 1,
        "doWork must have a found usage: {scan}"
    );
    let entry = &scan["results"][0];
    assert_eq!("found", entry["status"], "{scan}");
    assert!(
        entry["total_hits"].as_u64().expect("total_hits") >= 1,
        "expected >=1 proven hit: {scan}"
    );
    let enclosings = proven_hit_enclosings(&scan);
    assert!(
        enclosings.iter().any(|e| e.contains("callWidget")),
        "the proven call site must be enclosed by callWidget: {enclosings:?} in {scan}"
    );

    // (c) The summary nests doWork under the Widget struct with the correct owner.
    let summaries = call(
        &project,
        "get_summaries",
        serde_json::json!({ "targets": ["widget.cpp"] }),
    );
    let elements: Vec<&Value> = summaries["summaries"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|block| block["elements"].as_array().into_iter().flatten())
        .collect();
    let widget_element = elements
        .iter()
        .find(|el| el["symbol"].as_str().is_some_and(|s| s.contains("Widget")))
        .unwrap_or_else(|| panic!("Widget must appear in summaries: {summaries}"));
    assert_eq!("class", widget_element["kind"], "{summaries}");
    let method_element = elements
        .iter()
        .find(|el| {
            el["symbol"].as_str().is_some_and(|s| s.contains("doWork"))
                && el["kind"].as_str() == Some("function")
        })
        .unwrap_or_else(|| panic!("doWork must appear in summaries: {summaries}"));
    assert!(
        method_element["parent_symbol"]
            .as_str()
            .is_some_and(|parent| parent.contains("Widget")),
        "doWork must be owned by Widget: {summaries}"
    );
}

/// Two independent sentinel regions plus a sentinel nested inside a real
/// namespace must all recover, and a caller must reach every wrapped method
/// through the usage graph with the correct owner nesting (one/two/outer).
#[test]
fn multiple_and_nested_sentinel_regions_all_recover() {
    let source = r#"BEGIN_NS
namespace one { struct Alpha { void aWork(); }; }
END_NS
BEGIN_NS
namespace two { struct Beta { void bWork(); }; }
END_NS
namespace outer {
BEGIN_NS
struct Gamma { void gWork(); };
END_NS
}
void useAll() {
    one::Alpha alpha; alpha.aWork();
    two::Beta beta; beta.bWork();
    outer::Gamma gamma; gamma.gWork();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("regions.cpp", source)
        .build();

    for symbol in ["Alpha", "Beta", "Gamma", "aWork", "bWork", "gWork"] {
        let resolved = symbol_sources(&project, symbol);
        unique_source(&resolved, symbol);
    }

    // Ownership: each recovered class carries its correct namespace owner, so the
    // caller's use of each type creates a usage-graph edge under the right owner.
    // The nested `outer.Gamma` proves the sentinel-inside-namespace case, and the
    // two `BEGIN_NS`/`END_NS` pairs prove multiple independent regions recover.
    let graph = usage_graph_at(project.root(), "{}");
    for (from, to) in [
        ("useAll", "one.Alpha"),
        ("useAll", "two.Beta"),
        ("useAll", "outer.Gamma"),
    ] {
        assert!(
            find_edge(&graph, from, to).is_some(),
            "expected usage-graph edge {from} -> {to} (correct owner nesting): {}",
            graph["edges"]
        );
    }

    // A method sourced from the nested region is seen by inverse usage: the caller
    // that invokes it is FOUND, not verified_absent.
    let scan = scan_usages(&project, "gWork");
    assert_eq!(
        0,
        scan["summary"]["verified_absent"].as_u64().expect("count"),
        "nested-region gWork must not be verified_absent: {scan}"
    );
    assert!(
        proven_hit_enclosings(&scan)
            .iter()
            .any(|e| e.contains("useAll")),
        "gWork's call site must be found inside useAll: {scan}"
    );
}

/// Negative guard: a real function definition must never be reparsed as items.
/// The candidate trigger keys on a malformed (`has_error`) node whose leading
/// child is a macro-token return type; a well-formed function with an all-caps
/// return type (`HANDLE makeHandle()`) carries no error, so it must stay a
/// function with its return type intact. If it were wrongly reparsed, the leading
/// `HANDLE` would be stripped from the recovered node's range.
#[test]
fn real_all_caps_return_function_is_not_reparsed() {
    let source = r#"HANDLE makeHandle() {
    return 0;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("real.cpp", source)
        .build();

    let resolved = symbol_sources(&project, "makeHandle");
    let text = source_text(&resolved, "makeHandle");
    assert!(
        text.contains("HANDLE makeHandle"),
        "the real function must keep its HANDLE return type (not be reparsed): {resolved}"
    );

    // No spurious class/namespace/struct was fabricated from the function body.
    let fabricated = symbol_sources(&project, "makeHandle");
    assert_eq!(
        1,
        fabricated["sources"].as_array().map_or(0, Vec::len),
        "makeHandle must resolve to a single real function: {fabricated}"
    );
}

/// Negative guard: a sentinel-shaped bogus node whose interior is a statement,
/// not items, is rejected by the indexability gate so nothing is fabricated.
/// `WRAP\nfor (i = 0; i < n) { step(); }` is recovered by tree-sitter as a bogus
/// `function_definition` with a macro-token leader (so the candidate trigger
/// fires), but its interior reparses to an `ERROR`, so the gate refuses it and no
/// class/struct/namespace/function is produced from the executable soup.
#[test]
fn sentinel_prefix_over_non_item_soup_indexes_nothing() {
    let source = r#"WRAP
for (i = 0; i < n) { step(); }
END_WRAP
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("soup.cpp", source)
        .build();

    // Identifiers that appear only inside the executable soup must never be
    // fabricated into declarations by the rejected reparse.
    for phantom in ["step", "WRAP", "END_WRAP"] {
        let resolved = symbol_sources(&project, phantom);
        assert_eq!(
            0,
            resolved["sources"].as_array().map_or(0, Vec::len),
            "no declaration should be fabricated for {phantom}: {resolved}"
        );
    }

    // No type-like element (class/struct/namespace) was fabricated for the file.
    let summaries = call(
        &project,
        "get_summaries",
        serde_json::json!({ "targets": ["soup.cpp"] }),
    );
    let fabricated_types: Vec<&Value> = summaries["summaries"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|block| block["elements"].as_array().into_iter().flatten())
        .filter(|el| el["kind"].as_str() == Some("class"))
        .collect();
    assert!(
        fabricated_types.is_empty(),
        "no class/struct should be fabricated from the soup: {summaries}"
    );
}
