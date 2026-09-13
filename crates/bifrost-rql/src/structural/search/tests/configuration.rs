use super::*;
use crate::structural::search::results::CodeQueryConfigurationFact;

fn configuration_result(
    workspace: &WorkspaceAnalyzer,
    keys: &[&str],
    formats: &[&str],
) -> CodeQueryResult {
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {
            "formats": formats,
            "keys": keys,
        },
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("configuration facts query");

    execute_workspace(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

fn configuration_rows(result: &CodeQueryResult) -> Vec<&CodeQueryConfigurationFact> {
    result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::ConfigurationFact { value } => value.as_ref(),
            other => panic!("expected a configuration fact, got {other:?}"),
        })
        .collect()
}

fn diagnostic_with_code(
    result: &CodeQueryResult,
    code: CodeQueryDiagnosticCode,
) -> &CodeQueryDiagnostic {
    result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == code)
        .unwrap_or_else(|| panic!("missing diagnostic {code:?}: {:?}", result.diagnostics))
}

#[test]
fn json_key_filter_returns_exact_hosts_and_excludes_near_misses() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "config.json",
            r#"{
  "server": {
    "host": "primary.example",
    "hostname": "near-miss.example",
    "port": 8080
  },
  "hosts": ["array-near-miss.example"],
  "nested": {"host": {"child": true}}
}"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["json"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 2, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .map(|row| (row.node_kind, row.key.as_deref(), row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("member", Some("host"), r#"["server","host"]"#),
            ("member", Some("host"), r#"["nested","host"]"#),
        ]
    );
    assert!(rows.iter().all(|row| row.completeness == "complete"));
    assert!(
        rows.iter()
            .all(|row| !matches!(row.key.as_deref(), Some("hostname" | "hosts")))
    );
}

#[test]
fn duplicate_json_keys_have_distinct_occurrence_and_identity() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "config.json",
            r#"{"host": "first.example", "host": "second.example"}"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["json"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 2, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .map(|row| (row.occurrence, row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![(Some(1), r#"["host"]"#), (Some(2), r#"["host#2"]"#)]
    );
    assert_eq!(rows[0].parent_id, rows[1].parent_id);
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].value_id, rows[1].value_id);
}

#[test]
fn malformed_json_preserves_recovered_rows_as_incomplete() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "config.json",
            r#"{"host": "recovered.example", "broken": }"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["json"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 1, "{}", result.render_text());
    assert_eq!(rows[0].key.as_deref(), Some("host"));
    assert_eq!(rows[0].completeness, "incomplete");
    let diagnostic =
        diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial);
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(diagnostic.message.contains("partly recovered"));
}

#[test]
fn selected_unsupported_yaml_format_reports_a_typed_gap() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file("config.yaml", "host: unsupported.example\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["yaml"]);
    let rows = configuration_rows(&result);

    assert!(rows.is_empty(), "{}", result.render_text());
    let diagnostic =
        diagnostic_with_code(&result, CodeQueryDiagnosticCode::MissingStructuralAdapter);
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(diagnostic.message.contains("yaml"));
}

#[test]
fn xml_element_keys_routes_and_occurrences_are_exact() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "config.xml",
            r#"<server mode="prod">
  <host>primary.example</host>
  <host>backup.example</host>
  <hostname>near-miss.example</hostname>
  <app:port xmlns:app="https://example.com/config">8080</app:port>
</server>"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {
            "formats": ["xml"],
            "node_kinds": ["member"],
            "roles": ["xml_element"],
            "keys": ["host"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "host"}
            ]]
        },
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("XML element query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 2, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_deref(), row.occurrence, row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("host"), Some(1), r#"["server","host"]"#),
            (Some("host"), Some(2), r#"["server","host#2"]"#),
        ]
    );
    assert!(
        rows.iter().all(|row| row.format == "xml"
            && row.node_kind == "member"
            && row.role == Some("xml-element")
            && row.scalar_kind.is_none()
            && row.completeness == "complete"
            && row.path.ends_with("config.xml")),
        "{rows:#?}"
    );
    assert_eq!(rows[0].parent_id, rows[1].parent_id);
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].value_id, rows[1].value_id);

    let attribute_query = CodeQuery::from_json(&json!({
        "configuration_facts": {
            "formats": ["xml"],
            "node_kinds": ["member"],
            "roles": ["xml_attribute"],
            "keys": ["mode"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "mode"}
            ]]
        },
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("XML attribute query");
    let attribute_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &attribute_query,
    );
    let attribute_rows = configuration_rows(&attribute_result);
    assert_eq!(
        attribute_rows.len(),
        1,
        "{}",
        attribute_result.render_text()
    );
    assert_eq!(attribute_rows[0].role, Some("xml-attribute"));
    assert_eq!(attribute_rows[0].key.as_deref(), Some("mode"));
    assert_eq!(attribute_rows[0].scalar_kind, Some("string"));
    assert_eq!(attribute_rows[0].route, r#"["server","mode"]"#);
}

#[test]
fn xml_rql_selector_matches_the_canonical_element_query() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "config.xml",
            r#"<server><host>primary.example</host></server>"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(configuration-facts
  :format xml
  :node-kind member
  :role xml_element
  :key "host"
  :route [[(key "server") (key "host")]])"#,
    )
    .expect("XML RQL query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 1, "{}", result.render_text());
    let row = rows[0];
    assert_eq!(row.format, "xml");
    assert_eq!(row.node_kind, "member");
    assert_eq!(row.role, Some("xml-element"));
    assert_eq!(row.scalar_kind, None);
    assert_eq!(row.provenance, "authored");
    assert_eq!(row.completeness, "complete");
    assert_eq!(row.key.as_deref(), Some("host"));
    assert_eq!(row.occurrence, Some(1));
    assert_eq!(row.index, None);
    assert_eq!(row.route, r#"["server","host"]"#);
}

/// A production-shaped deployment document exercising every TOML container:
/// bare top-level keys, a standard table, dotted keys, a sub-table header, an
/// array of tables, an inline table, an array, and each scalar kind.
const TOML_WITNESS: &str = r#"# Deployment settings for the example service.
title = "example service"

[server]
host = "primary.example"
hostname = "near-miss.example"
port = 8080
timeout = 1.5
tls.enabled = true
tls.ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]

[server.limits]
max_body = 1048576

[[route]]
path = "/health"
host = "health.example"

[[route]]
path = "/metrics"

[client]
endpoints = { primary = "https://one.example", backup = "https://two.example" }
rotated = 2026-09-13T00:00:00Z
"#;

/// The witness lives under a nested relative directory so the seed's path
/// handling is exercised with a real separator on every supported platform.
fn toml_witness_project(body: &str) -> InlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(PathBuf::from("deploy").join("config.toml"), body)
}

#[test]
fn toml_key_filter_returns_exact_entries_and_excludes_near_misses() {
    let project = toml_witness_project(TOML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["toml"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 2, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_deref(), row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("host"), r#"["server","host"]"#),
            (Some("host"), r#"["route",0,"host"]"#),
        ]
    );
    assert!(
        rows.iter().all(|row| row.format == "toml"
            && row.node_kind == "member"
            && row.role == Some("table-entry")
            && row.scalar_kind == Some("string")
            && row.provenance == "authored"
            && row.completeness == "complete"
            && row.path.ends_with("config.toml")),
        "{rows:#?}"
    );
    // The same document holds `hostname`, a `hosts`-shaped sibling under the
    // array of tables, and a top-level `title`; none of them is an exact key.
    assert!(
        rows.iter()
            .all(|row| !matches!(row.key.as_deref(), Some("hostname" | "title")))
    );
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].parent_id, rows[1].parent_id);
    assert_eq!(
        &TOML_WITNESS[rows[0].start_byte..rows[0].end_byte],
        "host = \"primary.example\""
    );
}

#[test]
fn toml_dotted_keys_and_arrays_of_tables_carry_ordered_route_identity() {
    let project = toml_witness_project(TOML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    // A dotted key is three ordered segments, indistinguishable in route shape
    // from the `[server.limits]` header that reaches the same depth.
    let dotted = CodeQuery::from_json(&json!({
        "configuration_facts": {
            "formats": ["toml"],
            "node_kinds": ["member"],
            "roles": ["table_entry"],
            "scalar_kinds": ["boolean"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "tls"},
                {"kind": "key", "key": "enabled"}
            ]]
        },
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("dotted key query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &dotted,
    );
    let rows = configuration_rows(&result);
    assert_eq!(rows.len(), 1, "{}", result.render_text());
    assert_eq!(rows[0].key.as_deref(), Some("enabled"));
    assert_eq!(rows[0].occurrence, Some(1));
    assert_eq!(rows[0].route, r#"["server","tls","enabled"]"#);
    // The member is anchored at its own leaf key, not at the dotted prefix
    // that only introduced the intervening table.
    assert_eq!(
        &TOML_WITNESS[rows[0].start_byte..rows[0].end_byte],
        "enabled = true"
    );

    // Repeated `[[route]]` blocks are indexed, not occurrence-suffixed, and
    // their entries keep distinct identities.
    let indexed = CodeQuery::from_json(&json!({
        "configuration_facts": {
            "formats": ["toml"],
            "node_kinds": ["member"],
            "keys": ["path"],
        },
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("array of tables query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &indexed,
    );
    let rows = configuration_rows(&result);
    assert_eq!(
        rows.iter()
            .map(|row| row.route.as_str())
            .collect::<Vec<_>>(),
        vec![r#"["route",0,"path"]"#, r#"["route",1,"path"]"#],
        "{}",
        result.render_text()
    );
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].parent_id, rows[1].parent_id);

    // An inline-table entry and a TOML date-time stay queryable by their own
    // route and scalar kind.
    let inline = CodeQuery::from_json(&json!({
        "configuration_facts": {
            "formats": ["toml"],
            "node_kinds": ["member"],
            "routes": [
                [
                    {"kind": "key", "key": "client"},
                    {"kind": "key", "key": "endpoints"},
                    {"kind": "key", "key": "backup"}
                ],
                [
                    {"kind": "key", "key": "client"},
                    {"kind": "key", "key": "rotated"}
                ]
            ]
        },
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("inline table query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &inline,
    );
    let rows = configuration_rows(&result);
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_deref(), row.scalar_kind))
            .collect::<Vec<_>>(),
        vec![
            (Some("backup"), Some("string")),
            (Some("rotated"), Some("opaque"))
        ],
        "{}",
        result.render_text()
    );
}

#[test]
fn toml_rql_selector_matches_the_canonical_entry_query() {
    let project = toml_witness_project("[server]\nhost = \"primary.example\"\n").build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(configuration-facts
  :format toml
  :node-kind member
  :role table_entry
  :scalar-kind string
  :key "host"
  :route [[(key "server") (key "host")]])"#,
    )
    .expect("TOML RQL query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 1, "{}", result.render_text());
    let row = rows[0];
    assert_eq!(row.format, "toml");
    assert_eq!(row.node_kind, "member");
    assert_eq!(row.role, Some("table-entry"));
    assert_eq!(row.scalar_kind, Some("string"));
    assert_eq!(row.provenance, "authored");
    assert_eq!(row.completeness, "complete");
    assert_eq!(row.key.as_deref(), Some("host"));
    assert_eq!(row.occurrence, Some(1));
    assert_eq!(row.index, None);
    assert_eq!(row.route, r#"["server","host"]"#);
}

#[test]
fn rejected_toml_documents_report_a_typed_gap_instead_of_a_clean_empty() {
    // TOML rejects a redefined key outright, so no authored row survives; the
    // answer must say so rather than present zero rows as the whole set.
    for body in [
        "[server]\nhost = \"one\"\nhost = \"two\"\n",
        "[server]\nhost = \"one\"\n[server]\nhost = \"two\"\n",
        "[server]\nhost =\n",
    ] {
        let project = toml_witness_project(body).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result = configuration_result(&workspace, &["host"], &["toml"]);

        assert!(
            configuration_rows(&result).is_empty(),
            "{}",
            result.render_text()
        );
        let diagnostic =
            diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial);
        assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
        assert!(
            diagnostic.message.contains("config.toml")
                && diagnostic.message.contains("malformed syntax"),
            "{diagnostic:?}"
        );
    }
}

#[test]
fn toml_seed_reports_exhausted_row_budget_and_honours_cancellation() {
    let project = toml_witness_project(TOML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {"formats": ["toml"]},
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("unfiltered TOML query");

    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 3,
        ..CodeQueryExecutionLimits::default()
    };
    let bounded = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        limits,
    );
    assert_eq!(configuration_rows(&bounded).len(), 3, "{bounded:#?}");
    let diagnostic = diagnostic_with_code(
        &bounded,
        CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted,
    );
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);

    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let cancelled = execute_with_cancellation(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    );
    assert!(
        configuration_rows(&cancelled).is_empty(),
        "{}",
        cancelled.render_text()
    );
    assert!(
        cancelled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete),
        "{:?}",
        cancelled.diagnostics
    );
}

/// A nested authored document covering every JSON scalar kind, a sequence, a
/// duplicate-shaped near miss, and a subdirectory path.
const NESTED_JSON: &str = r#"{
  "server": {
    "host": "primary.example",
    "secure": true,
    "port": 8080,
    "timeout": 2.5,
    "fallback": null,
    "aliases": ["first.example", "second.example"]
  },
  "servers": {"host": "near-miss.example"}
}"#;

fn nested_json_project() -> inline_project::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        // Built with `PathBuf` joins so the fixture spells its own separator
        // the way the host filesystem does.
        .file(
            PathBuf::from("conf").join("app").join("settings.json"),
            NESTED_JSON,
        )
        .build()
}

fn configuration_query(filter: serde_json::Value) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "configuration_facts": filter,
        "result_detail": "full",
        "limit": 200,
    }))
    .expect("configuration facts query")
}

#[test]
fn json_scalar_kinds_routes_and_exact_bytes_are_canonical() {
    let project = nested_json_project();
    let source = NESTED_JSON;
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["json"],
            "node_kinds": ["member"],
            "roles": ["object_member"],
        })),
    );
    let rows = configuration_rows(&result);

    // Every authored scalar kind reaches the canonical row, and the value kind
    // travels with the member that owns it.
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_deref(), row.scalar_kind, row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("server"), None, r#"["server"]"#),
            (Some("host"), Some("string"), r#"["server","host"]"#),
            (Some("secure"), Some("boolean"), r#"["server","secure"]"#),
            (Some("port"), Some("integer"), r#"["server","port"]"#),
            (Some("timeout"), Some("decimal"), r#"["server","timeout"]"#),
            (Some("fallback"), Some("null"), r#"["server","fallback"]"#),
            (Some("aliases"), None, r#"["server","aliases"]"#),
            (Some("servers"), None, r#"["servers"]"#),
            (Some("host"), Some("string"), r#"["servers","host"]"#),
        ],
        "{}",
        result.render_text()
    );

    // Exact byte provenance: each row's span slices the authored document.
    for row in &rows {
        let slice = &source[row.start_byte..row.end_byte];
        assert!(
            slice.starts_with(&format!("\"{}\"", row.key.as_deref().unwrap_or_default())),
            "{row:#?} sliced {slice:?}"
        );
        assert!(row.completeness == "complete" && row.provenance == "authored");
    }

    // Sequence items keep zero-based index routes, not key routes.
    let items = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["json"],
            "node_kinds": ["scalar"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "aliases"},
                {"kind": "any"}
            ]],
        })),
    );
    let item_rows = configuration_rows(&items);
    assert_eq!(
        item_rows
            .iter()
            .map(|row| (
                row.index,
                row.route.as_str(),
                &source[row.start_byte..row.end_byte]
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some(0), r#"["server","aliases",0]"#, "\"first.example\""),
            (Some(1), r#"["server","aliases",1]"#, "\"second.example\""),
        ],
        "{}",
        items.render_text()
    );

    // A realistic near miss: the sibling `servers` object is never reachable
    // through the `server` route.
    let near_miss = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["json"],
            "keys": ["host"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "host"}
            ]],
        })),
    );
    let near_miss_rows = configuration_rows(&near_miss);
    assert_eq!(near_miss_rows.len(), 1, "{}", near_miss.render_text());
    assert_eq!(
        &source[near_miss_rows[0].start_byte..near_miss_rows[0].end_byte],
        "\"host\": \"primary.example\""
    );
}

#[test]
fn json_paths_stay_workspace_relative_on_every_platform() {
    let project = nested_json_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &CodeQuery::from_json(&json!({
            "where": ["conf/**/*.json"],
            "configuration_facts": {"formats": ["json"], "keys": ["port"]},
            "result_detail": "full",
            "limit": 200,
        }))
        .expect("scoped configuration query"),
    );
    let rows = configuration_rows(&result);
    assert_eq!(rows.len(), 1, "{}", result.render_text());
    // The seed's glob scope and the emitted row both use the canonical
    // forward-slash workspace spelling, independently of the host separator.
    assert_eq!(rows[0].path, "conf/app/settings.json");

    let outside = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &CodeQuery::from_json(&json!({
            "where": ["other/**/*.json"],
            "configuration_facts": {"formats": ["json"], "keys": ["port"]},
            "result_detail": "full",
            "limit": 200,
        }))
        .expect("scoped configuration query"),
    );
    assert!(
        configuration_rows(&outside).is_empty(),
        "{}",
        outside.render_text()
    );
}

#[test]
fn json_rql_selector_matches_the_canonical_json_query() {
    let project = nested_json_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let sexp = CodeQuery::from_sexp(
        r#"(configuration-facts
  :format json
  :node-kind member
  :role object_member
  :scalar-kind integer
  :key "port"
  :route [[(key "server") (key "port")]])"#,
    )
    .expect("JSON RQL query");
    let rql_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &sexp,
    );
    let json_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["json"],
            "node_kinds": ["member"],
            "roles": ["object_member"],
            "scalar_kinds": ["integer"],
            "keys": ["port"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "port"}
            ]],
        })),
    );
    let rql_rows = configuration_rows(&rql_result);
    assert_eq!(rql_rows.len(), 1, "{}", rql_result.render_text());
    assert_eq!(rql_rows[0].key.as_deref(), Some("port"));
    assert_eq!(rql_rows[0].scalar_kind, Some("integer"));
    assert_eq!(
        rql_rows.iter().map(|row| &row.id).collect::<Vec<_>>(),
        configuration_rows(&json_result)
            .iter()
            .map(|row| &row.id)
            .collect::<Vec<_>>()
    );

    // A near miss on the scalar-kind axis alone must not match.
    let wrong_kind = CodeQuery::from_sexp(
        r#"(configuration-facts :format json :key "port" :scalar-kind decimal)"#,
    )
    .expect("near-miss RQL query");
    let wrong = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &wrong_kind,
    );
    assert!(
        configuration_rows(&wrong).is_empty(),
        "{}",
        wrong.render_text()
    );
}

#[test]
fn json_document_root_cardinality_reaches_the_query_surface() {
    // A file with no value and a file with two top-level values are both
    // authored evidence the single-root model cannot represent; neither may
    // present its surviving rows as a complete answer.
    for (name, body) in [
        ("empty.json", ""),
        ("double.json", r#"{"host":"a"}{"host":"b"}"#),
    ] {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub fn ignored() {}\n")
            .file(name, body)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result = configuration_result(&workspace, &["host"], &["json"]);
        let diagnostic =
            diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial);
        assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
        assert!(
            configuration_rows(&result)
                .iter()
                .all(|row| row.completeness == "incomplete"),
            "{name}: {}",
            result.render_text()
        );
    }
}

#[test]
fn json_empty_and_recovered_keys_stay_queryable_members() {
    // SchemaStore ships released JSON configuration with an empty object key;
    // the whole document used to disappear from the query surface.
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "config.json",
            r#"{"": "empty-key", "host": "kept.example"}"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["json"]);
    let rows = configuration_rows(&result);
    assert_eq!(rows.len(), 1, "{}", result.render_text());
    assert_eq!(rows[0].completeness, "complete");

    let empty = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({"formats": ["json"], "keys": [""]})),
    );
    let empty_rows = configuration_rows(&empty);
    assert_eq!(empty_rows.len(), 1, "{}", empty.render_text());
    assert_eq!(empty_rows[0].route, r#"[""]"#);
    assert_ne!(empty_rows[0].fact_id, rows[0].fact_id);
}

#[test]
fn configuration_seed_reports_budget_and_cancellation_rather_than_clean_rows() {
    let project = nested_json_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = configuration_query(json!({"formats": ["json"]}));

    let capped = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 2,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(capped.truncated, "{}", capped.render_text());
    assert_eq!(configuration_rows(&capped).len(), 2);
    assert_eq!(
        diagnostic_with_code(
            &capped,
            CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted
        )
        .impact,
        CodeQueryDiagnosticImpact::Incomplete
    );

    let byte_capped = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(byte_capped.truncated, "{}", byte_capped.render_text());
    assert!(configuration_rows(&byte_capped).is_empty());

    let cancellation = CancellationToken::cancel_after_checks_for_test(1);
    let cancelled = execute_workspace_request_with_cancellation(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    );
    let cancelled = cancelled.result().expect("results mode");
    assert_eq!(cancelled.completion(), CodeQueryCompletion::Cancelled);
}

#[test]
fn one_execution_ingests_each_configuration_document_once() {
    // Two seeds over the same recovered document share the per-execution
    // ingestion memo, so the typed gap is reported once rather than per seed.
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file("config.json", r#"{"host": "kept.example", "broken": }"#)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            {"configuration_facts": {"formats": ["json"], "keys": ["host"]}},
            {"configuration_facts": {"formats": ["json"], "node_kinds": ["document"]}},
        ],
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("union configuration query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        configuration_rows(&result).len(),
        2,
        "{}",
        result.render_text()
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code
                == CodeQueryDiagnosticCode::SemanticAnalysisPartial)
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}
