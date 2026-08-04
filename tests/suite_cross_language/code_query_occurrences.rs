//! End-to-end coverage of the occurrence typed domain (#1473, Milestone 3).
//!
//! The load-bearing test here is `structural_capture_ast_id_equals_the_occurrence_ast_id`:
//! the whole point of the domain is that a structural capture and an occurrence
//! at the same node agree on one opaque string, so a later assertion kind can
//! join them without ever comparing ranges or spellings.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryResult, execute_workspace,
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

fn spellings(value: &Value) -> Vec<String> {
    rows(value)
        .iter()
        .map(|row| {
            row["raw_spelling"]
                .as_str()
                .expect("every occurrence row carries its raw spelling")
                .to_string()
        })
        .collect()
}

fn has_diagnostic(result: &CodeQueryResult, code: CodeQueryDiagnosticCode) -> bool {
    result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

/// Every deep adapter answers a declaration-name query with the names it
/// declares, classified consistently across languages.
#[test]
fn declaration_name_occurrences_are_classified_in_every_deep_language() {
    let files = [
        (
            "app/Widget.java",
            "class Widget {\n    int render(String label) { return label.length(); }\n}\n",
        ),
        (
            "src/widget.rs",
            "struct Widget {\n    label: String,\n}\nfn render(label: &str) -> usize { label.len() }\n",
        ),
        (
            "src/widget.py",
            "class Widget:\n    def render(self, label):\n        return len(label)\n",
        ),
        (
            "src/widget.ts",
            "class Widget {\n    render(label: string): number { return label.length; }\n}\n",
        ),
    ];

    for (path, language) in [
        ("app/Widget.java", "java"),
        ("src/widget.rs", "rust"),
        ("src/widget.py", "python"),
        ("src/widget.ts", "typescript"),
    ] {
        let result = run(
            &files,
            json!({
                "where": [path],
                "languages": [language],
                "occurrences": { "role": ["declaration_name"] },
                "limit": 50
            }),
        );
        let value = serialized(&result);
        let names = spellings(&value);
        assert!(
            names.contains(&"Widget".to_string()) && names.contains(&"render".to_string()),
            "{language} declaration-name rows should include the type and the method: {names:?}"
        );
        for row in rows(&value) {
            assert_eq!(row["result_type"], "occurrence");
            assert_eq!(row["class"], "declaration");
            assert_eq!(row["role"], "declaration_name");
            assert!(
                row["ast_id"].as_str().is_some_and(|id| !id.is_empty()),
                "every occurrence row carries a content-scoped AST id"
            );
            assert_eq!(row["target"]["target_kind"], "none");
        }
    }
}

/// Filters compose across axes, and a class filter selects exactly the roles
/// that partition into it.
#[test]
fn class_role_and_namespace_filters_narrow_the_same_row_set() {
    let files = [(
        "src/widget.ts",
        "interface Widget { label: string }\nfunction render(widget: Widget): string {\n    return widget.label;\n}\n",
    )];

    let binders = serialized(&run(
        &files,
        json!({ "occurrences": { "class": ["binding"] }, "limit": 50 }),
    ));
    assert_eq!(
        spellings(&binders),
        vec!["widget".to_string()],
        "the only binding-class token is the parameter"
    );

    let types = serialized(&run(
        &files,
        json!({ "occurrences": { "namespace": ["type"] }, "limit": 50 }),
    ));
    assert!(
        spellings(&types).contains(&"Widget".to_string()),
        "the annotation operand resolves in the type namespace: {:?}",
        spellings(&types)
    );
    for row in rows(&types) {
        assert_eq!(row["namespace"], "type");
    }

    let empty = serialized(&run(
        &files,
        json!({
            "occurrences": { "class": ["binding"], "role": ["declaration_name"] },
            "limit": 50
        }),
    ));
    assert!(
        rows(&empty).is_empty(),
        "class and role are conjunctive, and no role is both a binder and a declaration name"
    );
}

/// `occurrences-of` answers with the declaration's own name row plus the
/// reference-class rows that resolved to it.
#[test]
fn occurrences_of_a_declaration_returns_its_name_row_and_its_references() {
    let files = [(
        "src/widget.py",
        "def render(label):\n    return len(label)\n\ndef caller():\n    return render(\"x\")\n",
    )];
    let result = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "render" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "occurrences_of" }],
            "limit": 50
        }),
    );
    let value = serialized(&result);
    let classes: Vec<&str> = rows(&value)
        .iter()
        .map(|row| row["class"].as_str().expect("class label"))
        .collect();
    assert!(
        classes.contains(&"declaration"),
        "the declaration's own name row is always included: {classes:?}"
    );
    assert!(
        classes.contains(&"reference"),
        "the call site resolves to the declaration: {classes:?}"
    );
    for row in rows(&value) {
        assert_eq!(row["raw_spelling"], "render");
    }
}

/// `occurrences-in` narrows to one structural match's byte span, and
/// `file-of` maps occurrence rows back to their files.
#[test]
fn occurrences_in_respects_containment_and_file_of_maps_back() {
    let files = [(
        "src/widget.ts",
        "function outer(alpha: string) { return alpha; }\nfunction other(beta: string) { return beta; }\n",
    )];
    let inside = serialized(&run(
        &files,
        json!({
            "match": { "kind": "function", "name": "outer" },
            "steps": [{ "op": "occurrences_in", "class": ["binding"] }],
            "limit": 50
        }),
    ));
    assert_eq!(
        spellings(&inside),
        vec!["alpha".to_string()],
        "containment excludes the sibling function's binder"
    );

    let files_of = serialized(&run(
        &files,
        json!({
            "occurrences": { "class": ["binding"] },
            "steps": [{ "op": "file_of" }],
            "limit": 50
        }),
    ));
    assert_eq!(rows(&files_of).len(), 1);
    assert_eq!(files_of["results"][0]["result_type"], "file");
    assert_eq!(files_of["results"][0]["path"], "src/widget.ts");
}

/// `occurrence-target` projects a reference-class row back to the declaration
/// the resolver bound it to.
#[test]
fn occurrence_target_projects_resolved_references_to_declarations() {
    let files = [(
        "src/widget.py",
        "def render(label):\n    return len(label)\n\ndef caller():\n    return render(\"x\")\n",
    )];
    let value = serialized(&run(
        &files,
        json!({
            "occurrences": { "role": ["value_reference"] },
            "steps": [{ "op": "occurrence_target" }],
            "limit": 50
        }),
    ));
    let names: Vec<&str> = rows(&value)
        .iter()
        .map(|row| row["fq_name"].as_str().expect("declaration fq_name"))
        .collect();
    assert!(
        names.iter().any(|name| name.contains("render")),
        "the call's callee reference resolves to the function declaration: {names:?}"
    );
    for row in rows(&value) {
        assert_eq!(row["result_type"], "declaration");
    }
}

/// THE CORRELATION CONTRACT.
///
/// A structural query that captures a node and an occurrence query over the
/// same file must agree on one opaque string. Nothing here compares ranges,
/// spellings, or paths to establish the join -- only `ast_id` equality.
#[test]
fn structural_capture_ast_id_equals_the_occurrence_ast_id_at_the_same_node() {
    let files = [(
        "src/widget.ts",
        "function render(label: string): number { return label.length; }\n",
    )];

    // The capture is on the identifier token itself, which is exactly the node
    // an occurrence row addresses; capturing the enclosing function would name
    // a different arena node and correctly fail to join.
    let captured = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "identifier",
                "text": { "regex": "^render$" },
                "capture": "target"
            },
            "result_detail": "full",
            "limit": 10
        }),
    ));
    let capture_ast_id = captured["results"][0]["captures"][0]["ast_id"]
        .as_str()
        .expect("a full-detail structural capture carries its node's AST id")
        .to_string();
    assert_eq!(
        captured["results"][0]["ast_id"].as_str(),
        Some(capture_ast_id.as_str()),
        "the root capture and the match itself name the same node"
    );

    let occurrences = serialized(&run(
        &files,
        json!({
            "occurrences": { "role": ["declaration_name"] },
            "limit": 50
        }),
    ));
    let matched: Vec<&Value> = rows(&occurrences)
        .iter()
        .filter(|row| row["ast_id"].as_str() == Some(capture_ast_id.as_str()))
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "exactly one occurrence row shares the captured node's AST id; rows: {:?}",
        rows(&occurrences)
    );
    assert_eq!(matched[0]["role"], "declaration_name");
    assert_eq!(matched[0]["raw_spelling"], "render");
    assert_ne!(
        matched[0]["id"].as_str(),
        Some(capture_ast_id.as_str()),
        "the occurrence id is role-scoped and must not collide with the node id"
    );
}

/// An adapter that declares every occurrence role unsupported must make the
/// query incomplete, never answer it with a clean empty result.
#[test]
fn an_undeep_language_reports_incomplete_rather_than_an_empty_clean_answer() {
    let files = [(
        "src/widget.scala",
        "class Widget { def render(label: String): String = label }\n",
    )];
    let result = run(
        &files,
        json!({ "occurrences": { "role": ["binder"] }, "limit": 50 }),
    );
    assert!(result.results.is_empty());
    assert!(
        has_diagnostic(&result, CodeQueryDiagnosticCode::OccurrenceRoleUnsupported),
        "an all-unsupported adapter must say so: {:?}",
        result.diagnostics
    );
    assert!(
        matches!(
            result.completion(),
            brokk_bifrost::analyzer::structural::CodeQueryCompletion::Incomplete { .. }
        ),
        "an unsupported role cannot yield an exhaustive negative: {:?}",
        result.completion()
    );
}

/// A deep language answering about a role it does support stays complete, even
/// though the same adapter is incomplete for other roles.
#[test]
fn a_supported_role_is_not_degraded_by_an_unsupported_sibling_role() {
    let files = [(
        "src/widget.rs",
        "use std::collections::HashMap;\nfn take(map: HashMap<u32, u32>) -> usize { map.len() }\n",
    )];

    let binders = run(
        &files,
        json!({ "occurrences": { "role": ["binder"] }, "limit": 50 }),
    );
    assert!(
        !has_diagnostic(&binders, CodeQueryDiagnosticCode::OccurrenceRoleUnsupported),
        "Rust classifies binders, so a binder query is not degraded: {:?}",
        binders.diagnostics
    );

    // Rust cannot tell a module path segment from a type path segment at the
    // token, so a query that names that role must be told.
    let segments = run(
        &files,
        json!({ "occurrences": { "role": ["path_segment"] }, "limit": 50 }),
    );
    assert!(
        has_diagnostic(
            &segments,
            CodeQueryDiagnosticCode::OccurrenceRoleUnsupported
        ),
        "path-segment namespaces are unknown in Rust: {:?}",
        segments.diagnostics
    );
}

/// RQL and canonical JSON are two spellings of one query.
#[test]
fn rql_and_json_occurrence_queries_round_trip_to_the_same_canonical_form() {
    let from_sexp = CodeQuery::from_sexp(
        "(limit 50 (language \"rust\" (occurrences :role [binder declaration_name] :namespace value)))",
    )
    .expect("RQL occurrence seed should parse");
    let from_json = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "occurrences": { "role": ["binder", "declaration_name"], "namespace": ["value"] },
        "limit": 50
    }))
    .expect("JSON occurrence seed should parse");
    assert_eq!(from_sexp.to_canonical_json(), from_json.to_canonical_json());

    let stepped =
        CodeQuery::from_sexp("(occurrence-target (occurrences-in :class reference (function)))")
            .expect("RQL occurrence steps should parse");
    let stepped_json = CodeQuery::from_json(&json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "occurrences_in", "class": ["reference"] },
            { "op": "occurrence_target" }
        ]
    }))
    .expect("JSON occurrence steps should parse");
    assert_eq!(
        stepped.to_canonical_json(),
        stepped_json.to_canonical_json()
    );
}

/// The schema bump is load-bearing: a document pinned to the previous head
/// must not silently gain the new forms.
#[test]
fn schema_version_seven_rejects_the_occurrence_surface_while_unpinned_resolves_to_eight() {
    let pinned_seed = CodeQuery::from_json(&json!({
        "schema_version": 7,
        "occurrences": { "role": ["binder"] }
    }));
    let error = pinned_seed.expect_err("schema 7 predates the occurrence source");
    assert!(
        error.message.contains("schema version 8"),
        "the rejection must name the version that introduced it: {error:?}"
    );

    let pinned_step = CodeQuery::from_json(&json!({
        "schema_version": 7,
        "match": { "kind": "function" },
        "steps": [{ "op": "occurrences_in" }]
    }));
    assert!(
        pinned_step.is_err(),
        "schema 7 predates occurrences_in as well"
    );

    let unpinned = CodeQuery::from_json(&json!({ "occurrences": { "role": ["binder"] } }))
        .expect("an unpinned document resolves to the compatible head");
    assert_eq!(unpinned.schema_version, 8);
}

/// Unknown constrained values are rejected at decode time with the field path,
/// so an agent can self-correct rather than receive an empty result.
#[test]
fn unknown_filter_values_and_duplicate_sources_are_rejected_with_paths() {
    let unknown_role = CodeQuery::from_json(&json!({ "occurrences": { "role": ["binderr"] } }))
        .expect_err("unknown roles must not be silently ignored");
    assert_eq!(unknown_role.path, "occurrences.role[0]");

    let unknown_field = CodeQuery::from_json(&json!({ "occurrences": { "kind": ["function"] } }))
        .expect_err("the occurrence filter has a closed field set");
    assert_eq!(unknown_field.path, "occurrences.kind");

    let both_sources = CodeQuery::from_json(&json!({
        "match": { "kind": "function" },
        "occurrences": { "role": ["binder"] }
    }))
    .expect_err("a plan has exactly one source");
    assert_eq!(both_sources.path, "occurrences");

    let containment = CodeQuery::from_json(&json!({
        "occurrences": { "role": ["binder"] },
        "inside": { "kind": "class" }
    }))
    .expect_err("occurrence containment is expressed by occurrences_in");
    assert_eq!(containment.path, "inside");
}
