//! End-to-end coverage of the occurrence typed domain (#1473, Milestone 3).
//!
//! The load-bearing test here is `structural_capture_ast_id_equals_the_occurrence_ast_id`:
//! the whole point of the domain is that a structural capture and an occurrence
//! at the same node agree on one opaque string, so a later assertion kind can
//! join them without ever comparing ranges or spellings.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryResponse, CodeQueryResult, execute_workspace,
    execute_workspace_request,
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

/// Explain mode must be able to describe an occurrence plan without executing
/// it: the logical operator is a new variant and the physical one is a new
/// scan, both of which the stable explain contract has to render.
#[test]
fn explain_mode_describes_the_occurrence_scan_without_executing_it() {
    let project = InlineTestProject::new()
        .file(
            "src/widget.rs",
            "fn render(label: &str) -> usize { label.len() }\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "occurrences": { "role": ["binder"] },
        "execution_mode": "explain",
        "limit": 10
    }))
    .expect("query should parse");
    let CodeQueryResponse::Explain(explain) = execute_workspace_request(&workspace, &query) else {
        panic!("explain mode returns an explain response");
    };
    let explain = serde_json::to_value(&explain).expect("explain report should serialize");
    let operators: Vec<&str> = explain["physical_plan"]["nodes"]
        .as_array()
        .expect("physical plan nodes")
        .iter()
        .map(|node| node["operator"].as_str().expect("operator label"))
        .collect();
    assert!(
        operators.contains(&"occurrence_scan"),
        "the occurrence source selects its own physical operator: {operators:?}"
    );
    assert_eq!(
        explain["logical_plan"]["nodes"][0]["operation"]["kind"],
        "occurrence_seed"
    );
}

// ---------------------------------------------------------------------------
// Conformance fixtures (#1473, Milestone 5)
//
// Each fixture below is minimized from one of the 46 mined regressions in the
// issue body. Every pair changes only *where* a token sits, never how it is
// spelled, so a verdict that moves is a verdict about AST role and nothing
// else. The near-miss half of each pair is the realistic shape that the
// original regression confused with the positive half: the same API names, the
// same operation, one structural context away.
// ---------------------------------------------------------------------------

/// One row per occurrence of `spelling`, in source order, as
/// `(role, namespace)`.
fn roles_of(value: &Value, spelling: &str) -> Vec<(String, String)> {
    rows(value)
        .iter()
        .filter(|row| row["raw_spelling"] == spelling)
        .map(|row| {
            (
                row["role"].as_str().expect("role label").to_string(),
                row["namespace"]
                    .as_str()
                    .expect("namespace label")
                    .to_string(),
            )
        })
        .collect()
}

/// One row per occurrence of `spelling`, in source order, as
/// `(role, namespace, target_kind)`.
fn classified(value: &Value, spelling: &str) -> Vec<(String, String, String)> {
    rows(value)
        .iter()
        .filter(|row| row["raw_spelling"] == spelling)
        .map(|row| {
            (
                row["role"].as_str().expect("role label").to_string(),
                row["namespace"]
                    .as_str()
                    .expect("namespace label")
                    .to_string(),
                row["target"]["target_kind"]
                    .as_str()
                    .expect("target kind")
                    .to_string(),
            )
        })
        .collect()
}

fn resolved_targets(value: &Value, spelling: &str) -> Vec<String> {
    rows(value)
        .iter()
        .filter(|row| row["raw_spelling"] == spelling)
        .filter_map(|row| row["target"]["units"].as_array())
        .flatten()
        .map(|unit| unit["fq_name"].as_str().expect("fq_name").to_string())
        .collect()
}

fn all_occurrences(files: &[(&str, &str)]) -> Value {
    serialized(&run(files, json!({ "occurrences": {}, "limit": 200 })))
}

/// Scenario 1: renamed and shorthand destructuring (JS/TS).
///
/// Minimized from `009e510bc` ("Fix TypeScript destructuring field usages"),
/// where a destructured field name and the binder it introduces were conflated.
/// The grammar already separates them -- `shorthand_property_identifier_pattern`
/// versus `shorthand_property_identifier` -- and the occurrence domain must
/// report that separation rather than the shared spelling.
#[test]
fn conformance_shorthand_destructuring_binds_in_a_pattern_and_reads_in_an_expression() {
    let value = all_occurrences(&[(
        "src/destructure.ts",
        concat!(
            "const source = { alpha: 1, beta: 2 };\n",
            "const { alpha, beta: renamed } = source;\n",
            "const echo = { alpha };\n",
        ),
    )]);

    // Roles only: whether the shorthand *read* resolves back to the
    // destructured binding is a definition-resolution question below this
    // plan, and it currently answers `no_definition` (recorded in the ExecPlan
    // as a follow-up). The role fidelity claim is independent of it.
    assert_eq!(
        roles_of(&value, "alpha"),
        vec![
            // The object-literal key that seeds the fixture.
            ("label_or_key".into(), "label".into()),
            // Positive: the shorthand pattern element binds.
            ("binder".into(), "value".into()),
            // Near-miss: the same spelling, one structural context away, in an
            // object *expression* -- a genuine read.
            ("value_reference".into(), "value".into()),
        ],
        "shorthand role follows the node kind, never the spelling: {:?}",
        rows(&value)
    );

    assert_eq!(
        roles_of(&value, "beta"),
        vec![
            ("label_or_key".into(), "label".into()),
            // The renamed field name stays a key; only `renamed` binds.
            ("label_or_key".into(), "label".into()),
        ],
        "a renamed destructuring field is a key, not a binder"
    );
    assert_eq!(
        roles_of(&value, "renamed"),
        vec![("binder".into(), "value".into())],
        "the local introduced by the rename is the only binder of that name"
    );
}

/// Scenario 2: type operands versus binders (Python).
///
/// Minimized from `ee82b7b0b` ("Fix Python annotation usage edges", #413) and
/// `031e3be78` ("Resolve non-class Python annotation usages"). The parameter
/// name and its annotation are siblings under one `typed_parameter`; the
/// annotation is a type operand that resolves, the parameter is a binder that
/// has nothing to resolve.
#[test]
fn conformance_python_annotations_are_type_operands_and_parameters_are_binders() {
    let value = all_occurrences(&[(
        "src/widget.py",
        concat!(
            "class Widget:\n",
            "    pass\n",
            "\n",
            "def render(widget: Widget) -> int:\n",
            "    return 1\n",
            "\n",
            "def build():\n",
            "    return Widget()\n",
        ),
    )]);

    assert_eq!(
        classified(&value, "widget"),
        vec![("binder".into(), "value".into(), "none".into())],
        "the parameter binds and resolves to nothing"
    );
    assert_eq!(
        classified(&value, "Widget"),
        vec![
            ("declaration_name".into(), "type".into(), "none".into()),
            // Positive: consumed as a type.
            ("type_operand".into(), "type".into(), "resolved".into()),
            // Near-miss: the same name, the same class, read in expression
            // position -- a value reference in the value namespace.
            ("value_reference".into(), "value".into(), "resolved".into()),
        ],
        "the annotation operand and the constructor read are different roles in different namespaces"
    );
    assert_eq!(
        resolved_targets(&value, "Widget"),
        vec![
            "src.widget.Widget".to_string(),
            "src.widget.Widget".to_string()
        ],
        "both reference rows resolve to the same declaration despite differing roles"
    );
}

/// Scenario 3: keyed fields versus map keys (TS).
///
/// Minimized from `91cddbf29` ("Resolve Go struct literal field usages"), whose
/// shape is language-independent: a static key in a record literal names a
/// field and reads nothing, while a computed key and an ordinary argument of
/// the identical spelling are genuine reads of the surrounding binding.
#[test]
fn conformance_static_record_keys_are_labels_while_computed_keys_read() {
    let value = all_occurrences(&[(
        "src/keyed.ts",
        concat!(
            "const label = 1;\n",
            "const store = new Map<number, number>();\n",
            "const record = { label: 2 };\n",
            "const computed = { [label]: 3 };\n",
            "store.set(label, 4);\n",
        ),
    )]);

    assert_eq!(
        classified(&value, "label"),
        vec![
            ("binder".into(), "value".into(), "none".into()),
            // Positive: a static key is a non-reference label.
            ("label_or_key".into(), "label".into(), "none".into()),
            // Near-miss: brackets around the very same token make it a read.
            ("value_reference".into(), "value".into(), "resolved".into()),
            // The plainly-read argument, for contrast.
            ("value_reference".into(), "value".into(), "resolved".into()),
        ],
        "a static key never resolves; a computed key and an argument both do"
    );
    assert_eq!(
        resolved_targets(&value, "label"),
        vec!["keyed.ts.label".to_string(), "keyed.ts.label".to_string()],
        "exactly the two reads resolve, and they resolve to the binding"
    );
}

/// Scenario 4: static qualifiers versus shadowing values (Java).
///
/// Minimized from `8d5df9d0e` ("count static-member-qualified type
/// references"), `642e3214d` ("Resolve Java selectors by focused AST role") and
/// `abb34275d` ("Keep Java bare bindings within active lexical scope", #978).
/// A type name used as a static qualifier and a local variable that shadows the
/// same spelling in a sibling scope must not trade classifications.
#[test]
fn conformance_java_static_qualifiers_and_shadowing_locals_keep_their_roles() {
    let value = all_occurrences(&[(
        "app/Config.java",
        concat!(
            "class Config {\n",
            "    static int LIMIT = 7;\n",
            "    int qualified() { return Config.LIMIT; }\n",
            "    int shadowed() { int Config = 1; return Config; }\n",
            "}\n",
        ),
    )]);

    assert_eq!(
        classified(&value, "Config"),
        vec![
            ("declaration_name".into(), "type".into(), "none".into()),
            // Positive: the static qualifier is a receiver that resolves to the
            // type, in a method whose sibling shadows the spelling.
            (
                "receiver_position".into(),
                "value".into(),
                "resolved".into()
            ),
            // Near-miss: an unrelated local of the same spelling, one method
            // away. It binds, then reads -- it is never a receiver.
            ("binder".into(), "value".into(), "none".into()),
            (
                "value_reference".into(),
                "value".into(),
                "unresolved".into()
            ),
        ],
        "the qualifier and the shadowing local never trade roles: {:?}",
        rows(&value)
    );
    assert_eq!(
        resolved_targets(&value, "Config"),
        vec!["Config".to_string()],
        "the only Config that resolves is the static qualifier, and it resolves to the class"
    );
}

/// Scenario 5: quoted annotations versus strings (Python), plus escaped
/// identifier spellings (Rust).
///
/// Minimized from `031e3be78` ("Resolve non-class Python annotation usages").
/// The invariant is one-directional and worth stating exactly: string content
/// never enters the occurrence domain, so neither a deferred (quoted)
/// annotation nor an ordinary string of the same content can be mistaken for a
/// type operand. Deferred annotations are consequently *not* classified today;
/// see the ExecPlan's Surprises section for the recorded follow-up.
#[test]
fn conformance_quoted_annotations_and_strings_never_become_type_operands() {
    let value = all_occurrences(&[(
        "src/deferred.py",
        concat!(
            "class Widget:\n",
            "    pass\n",
            "\n",
            "def direct(widget: Widget) -> int:\n",
            "    return 1\n",
            "\n",
            "def deferred(widget: \"Widget\") -> int:\n",
            "    return 2\n",
            "\n",
            "name = \"Widget\"\n",
        ),
    )]);

    assert_eq!(
        classified(&value, "Widget"),
        vec![
            ("declaration_name".into(), "type".into(), "none".into()),
            ("type_operand".into(), "type".into(), "resolved".into()),
        ],
        "only the unquoted annotation is an identifier occurrence: {:?}",
        rows(&value)
    );
    assert!(
        !rows(&value)
            .iter()
            .any(|row| row["raw_spelling"] == "\"Widget\""),
        "a string literal is never an occurrence, whatever it spells"
    );
}

/// Scenario 5b: an escaped identifier is one token with two spellings.
///
/// The decoded spelling is a property of the token, not a substring rescue: the
/// row carries both, so a consumer comparing names never has to strip `r#`
/// itself.
#[test]
fn conformance_rust_raw_identifiers_carry_both_spellings() {
    let value = all_occurrences(&[("src/raw.rs", "fn make(r#match: u32) -> u32 { r#match }\n")]);
    let decoded: Vec<(&str, Option<&str>, &str)> = rows(&value)
        .iter()
        .filter(|row| row["raw_spelling"] == "r#match")
        .map(|row| {
            (
                row["raw_spelling"].as_str().expect("raw spelling"),
                row["decoded_spelling"].as_str(),
                row["role"].as_str().expect("role"),
            )
        })
        .collect();
    assert_eq!(
        decoded,
        vec![
            ("r#match", Some("match"), "binder"),
            ("r#match", Some("match"), "value_reference"),
        ],
        "both the binder and the read decode, and the raw spelling survives"
    );
}

/// Scenario 6: declaration heads versus genuine reads (Rust).
///
/// Minimized from `6e0ce0284` ("reject declaration-head pseudo references") and
/// `81ff35b3b` ("Fix Rust Self type reference classification", #884). A
/// declaration head is not a reference to the thing it declares, and the only
/// row that resolves is the call site.
#[test]
fn conformance_declaration_heads_are_not_reads_of_what_they_declare() {
    let value = all_occurrences(&[(
        "src/heads.rs",
        concat!(
            "fn render() -> u32 {\n",
            "    1\n",
            "}\n",
            "\n",
            "fn caller() -> u32 {\n",
            "    render()\n",
            "}\n",
        ),
    )]);

    assert_eq!(
        classified(&value, "render"),
        vec![
            // Positive: the head declares and reads nothing.
            ("declaration_name".into(), "value".into(), "none".into()),
            // Near-miss: the same spelling in the same file, called.
            ("value_reference".into(), "value".into(), "resolved".into()),
        ],
        "a declaration head never carries a reference-class row"
    );
    assert_eq!(
        classified(&value, "caller"),
        vec![("declaration_name".into(), "value".into(), "none".into())],
        "an uncalled declaration has exactly one row, and it is its head"
    );
}
