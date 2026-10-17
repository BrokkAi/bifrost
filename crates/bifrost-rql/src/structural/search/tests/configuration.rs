use super::*;
use crate::structural::search::results::CodeQueryConfigurationFact;
use brokk_bifrost_test_macros::hardwon;

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

fn assert_scoped_configuration_path(
    workspace: &WorkspaceAnalyzer,
    query: CodeQuery,
    expected_path: &str,
) {
    let result = execute_workspace(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = configuration_rows(&result);
    assert_eq!(rows.len(), 1, "{}", result.render_text());
    // Seed globs and result paths use canonical forward-slash spelling on all
    // supported hosts.
    assert_eq!(rows[0].path, expected_path);
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

fn assert_seed_reports_row_budget_and_cancellation(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
) {
    let bounded = execute_workspace_with_limits(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(bounded.truncated, "{}", bounded.render_text());
    assert_eq!(configuration_rows(&bounded).len(), 3, "{bounded:#?}");
    assert_eq!(
        diagnostic_with_code(
            &bounded,
            CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted
        )
        .impact,
        CodeQueryDiagnosticImpact::Incomplete
    );

    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let cancelled = execute_with_cancellation(
        workspace.analyzer(),
        query,
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
    assert_eq!(
        rows.iter()
            .map(|row| row.value.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("primary.example"), Some("backup.example")]
    );

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
    assert_eq!(attribute_rows[0].value.as_deref(), Some("prod"));
}

#[test]
#[hardwon("#4381: Web.config-style .config files were skipped by the configuration seed")]
fn xml_discovery_includes_common_dot_config_documents() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file("Web.config", "<configuration/>\n")
        .file("Web.Release.config", "<configuration/>\n")
        .file("app.config", "<configuration/>\n")
        .file("packages.config", "<packages/>\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["xml"],
            "node_kinds": ["document"]
        })),
    );
    assert_eq!(
        configuration_rows(&result)
            .iter()
            .map(|row| row.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Web.Release.config",
            "Web.config",
            "app.config",
            "packages.config"
        ],
        "{}",
        result.render_text()
    );
}

#[test]
#[hardwon("#4381: XML configuration predicates could not compare decoded scalar values")]
fn xml_scalar_value_predicates_support_exact_case_insensitive_and_numeric_matching() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn ignored() {}\n")
        .file(
            "Web.config",
            r#"<configuration><system.web><httpRuntime requestValidationMode="4.0" enabled="TRUE"/><httpRuntime requestValidationMode="4.5" enabled="false"/></system.web></configuration>"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let exact = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["xml"],
            "keys": ["enabled"],
            "values": ["TRUE"]
        })),
    );
    assert_eq!(
        configuration_rows(&exact).len(),
        1,
        "{}",
        exact.render_text()
    );
    assert_eq!(configuration_rows(&exact)[0].value.as_deref(), Some("TRUE"));

    let insensitive = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["xml"],
            "keys": ["enabled"],
            "values_ignore_case": ["true"]
        })),
    );
    assert_eq!(
        configuration_rows(&insensitive).len(),
        1,
        "{}",
        insensitive.render_text()
    );

    let numeric = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["xml"],
            "keys": ["requestValidationMode"],
            "value_lt": "4.5"
        })),
    );
    assert_eq!(
        configuration_rows(&numeric).len(),
        1,
        "{}",
        numeric.render_text()
    );
    assert_eq!(
        configuration_rows(&numeric)[0].value.as_deref(),
        Some("4.0")
    );
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

#[test]
fn toml_dotted_keys_and_arrays_of_tables_carry_ordered_route_identity() {
    let project =
        inline_project::rust_project_with_file("deploy/config.toml", TOML_WITNESS).build();
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
fn rejected_toml_documents_report_a_typed_gap_instead_of_a_clean_empty() {
    // TOML rejects a redefined key outright, so no authored row survives; the
    // answer must say so rather than present zero rows as the whole set.
    for body in [
        "[server]\nhost = \"one\"\nhost = \"two\"\n",
        "[server]\nhost = \"one\"\n[server]\nhost = \"two\"\n",
        "[server]\nhost =\n",
    ] {
        let project = inline_project::rust_project_with_file("deploy/config.toml", body).build();
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

/// A production-shaped Compose-style document exercising nested block
/// mappings, a block sequence of mappings, a flow sequence, a flow mapping, an
/// anchor with an alias and a merge key, a duplicate key, and every
/// core-schema scalar kind.
const YAML_WITNESS: &str = r#"# Deployment settings for the example service.
version: "3.9"
x-defaults: &defaults
  restart: always
services:
  web:
    <<: *defaults
    image: example/web:1.4.2
    host: primary.example
    hostname: near-miss.example
    replicas: 3
    weight: 0.75
    healthy: true
    fallback: ~
    ports: ["8080:80", 8443]
    env: {DEBUG: false, LEVEL: 0x1F}
    volumes:
      - name: data
        path: /var/data
      - name: cache
        path: /var/cache
  db:
    image: example/db
    host: replica.example
    host: duplicate.example
"#;

#[test]
fn yaml_routes_sequences_and_capability_constructs_carry_ordered_identity() {
    let project =
        inline_project::rust_project_with_file("deploy/compose.yaml", YAML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let source = YAML_WITNESS;

    // A nested block mapping is three ordered segments, and the member is
    // anchored at its own line.
    let nested = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["yaml"],
            "node_kinds": ["member"],
            "roles": ["object_member"],
            "scalar_kinds": ["boolean"],
            "routes": [[
                {"kind": "key", "key": "services"},
                {"kind": "key", "key": "web"},
                {"kind": "key", "key": "healthy"}
            ]]
        })),
    );
    let rows = configuration_rows(&nested);
    assert_eq!(rows.len(), 1, "{}", nested.render_text());
    assert_eq!(rows[0].route, r#"["services","web","healthy"]"#);
    assert_eq!(
        &source[rows[0].start_byte..rows[0].end_byte],
        "healthy: true"
    );

    // Block-sequence items are indexed and their entries are reachable only
    // through the index; the two `path` entries keep distinct identities.
    let indexed = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({"formats": ["yaml"], "keys": ["path"]})),
    );
    let rows = configuration_rows(&indexed);
    assert_eq!(
        rows.iter()
            .map(|row| (row.route.as_str(), &source[row.start_byte..row.end_byte]))
            .collect::<Vec<_>>(),
        vec![
            (
                r#"["services","web","volumes",0,"path"]"#,
                "path: /var/data"
            ),
            (
                r#"["services","web","volumes",1,"path"]"#,
                "path: /var/cache"
            ),
        ],
        "{}",
        indexed.render_text()
    );
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].parent_id, rows[1].parent_id);

    // Flow-sequence items carry zero-based index routes and their own kinds.
    let items = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["yaml"],
            "node_kinds": ["scalar"],
            "routes": [[
                {"kind": "key", "key": "services"},
                {"kind": "key", "key": "web"},
                {"kind": "key", "key": "ports"},
                {"kind": "any"}
            ]]
        })),
    );
    let rows = configuration_rows(&items);
    assert_eq!(
        rows.iter()
            .map(|row| (
                row.index,
                row.scalar_kind,
                &source[row.start_byte..row.end_byte]
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some(0), Some("string"), "\"8080:80\""),
            (Some(1), Some("integer"), "8443"),
        ],
        "{}",
        items.render_text()
    );

    // Every core-schema scalar kind, plus the flow mapping's entries, reaches
    // the canonical row with the kind the grammar resolved.
    let kinds = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["yaml"],
            "node_kinds": ["member"],
            "keys": ["version", "replicas", "weight", "fallback", "DEBUG", "LEVEL"]
        })),
    );
    assert_eq!(
        configuration_rows(&kinds)
            .iter()
            .map(|row| (row.key.as_deref(), row.scalar_kind))
            .collect::<Vec<_>>(),
        vec![
            (Some("version"), Some("string")),
            (Some("replicas"), Some("integer")),
            (Some("weight"), Some("decimal")),
            (Some("fallback"), Some("null")),
            (Some("DEBUG"), Some("boolean")),
            (Some("LEVEL"), Some("integer")),
        ],
        "{}",
        kinds.render_text()
    );

    // The merge key is an authored entry whose value is the unexpanded alias:
    // both are queryable, and the alias is an opaque authored reference.
    let merge = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({"formats": ["yaml"], "keys": ["<<"]})),
    );
    let rows = configuration_rows(&merge);
    assert_eq!(rows.len(), 1, "{}", merge.render_text());
    assert_eq!(rows[0].route, r#"["services","web","<<"]"#);
    assert_eq!(rows[0].scalar_kind, Some("opaque"));
    assert_eq!(rows[0].completeness, "complete");
    assert_eq!(
        &source[rows[0].start_byte..rows[0].end_byte],
        "<<: *defaults"
    );
    // The anchored mapping's own entries are not duplicated under `web`.
    let restart = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({"formats": ["yaml"], "keys": ["restart"]})),
    );
    assert_eq!(
        configuration_rows(&restart)
            .iter()
            .map(|row| row.route.as_str())
            .collect::<Vec<_>>(),
        vec![r#"["x-defaults","restart"]"#],
        "{}",
        restart.render_text()
    );
}

#[test]
fn yaml_recovered_multi_document_and_empty_files_report_typed_gaps() {
    // A tab indent makes the grammar reject the whole document: no row
    // survives and the answer says why.
    let project = inline_project::rust_project_with_file(
        "deploy/compose.yaml",
        "services:\n\tweb:\n\t\thost: one\n",
    )
    .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["yaml"]);
    assert!(
        configuration_rows(&result).is_empty(),
        "{}",
        result.render_text()
    );
    let diagnostic =
        diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial);
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(
        diagnostic.message.contains("compose.yaml")
            && diagnostic.message.contains("malformed syntax"),
        "{diagnostic:?}"
    );

    // A Kubernetes-style multi-document stream keeps the first document's
    // rows, marks them incomplete, and names the construct it could not
    // represent.
    let project = inline_project::rust_project_with_file(
        "deploy/compose.yaml",
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
    )
    .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["kind"], &["yaml"]);
    let rows = configuration_rows(&result);
    assert_eq!(rows.len(), 1, "{}", result.render_text());
    assert_eq!(rows[0].completeness, "incomplete");
    let diagnostic =
        diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial);
    assert!(
        diagnostic.message.contains("unsupported construct"),
        "{diagnostic:?}"
    );

    // An empty file is a stream with no document: a typed gap, not a clean
    // zero.
    let project = inline_project::rust_project_with_file("deploy/compose.yaml", "").build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["yaml"]);
    assert!(configuration_rows(&result).is_empty());
    assert_eq!(
        diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial).impact,
        CodeQueryDiagnosticImpact::Incomplete
    );
}

#[test]
fn yaml_paths_stay_workspace_relative_and_both_extensions_are_discovered() {
    let project = inline_project::rust_project_with_file("deploy/compose.yaml", YAML_WITNESS)
        .file(
            PathBuf::from("ci").join("build.yml"),
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    assert_scoped_configuration_path(
        &workspace,
        CodeQuery::from_json(&json!({
            "where": ["deploy/**/*.yaml"],
            "configuration_facts": {"formats": ["yaml"], "keys": ["version"]},
            "result_detail": "full",
            "limit": 200,
        }))
        .expect("scoped configuration query"),
        "deploy/compose.yaml",
    );

    let documents = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({"formats": ["yaml"], "node_kinds": ["document"]})),
    );
    assert_eq!(
        configuration_rows(&documents)
            .iter()
            .map(|row| row.path.as_str())
            .collect::<Vec<_>>(),
        vec!["ci/build.yml", "deploy/compose.yaml"],
        "{}",
        documents.render_text()
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
fn json_paths_stay_workspace_relative_on_every_platform() {
    let project = nested_json_project();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    assert_scoped_configuration_path(
        &workspace,
        CodeQuery::from_json(&json!({
            "where": ["conf/**/*.json"],
            "configuration_facts": {"formats": ["json"], "keys": ["port"]},
            "result_detail": "full",
            "limit": 200,
        }))
        .expect("scoped configuration query"),
        "conf/app/settings.json",
    );

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

/// A production-shaped Spring Boot application document: dotted keys, both
/// separators, an escaped key, a value continued across lines, a duplicate
/// key, an empty value, comments, and unresolved placeholders.
const PROPERTIES_WITNESS: &str = "# Service settings\n\
server.host = primary.example\n\
server.host: backup.example\n\
server.hostname=near-miss.example\n\
host=bare-near-miss.example\n\
server.port=8080\n\
spring.datasource.url=jdbc:postgresql://${db.host}:${db.port:5432}/app\n\
banner\\ text = Welcome, \\\n    operator\\u0021\n\
management.endpoints=\n";

#[test]
fn properties_key_filter_returns_exact_entries_and_excludes_near_misses() {
    let project = inline_project::rust_project_with_file(
        PathBuf::from("src")
            .join("main")
            .join("resources")
            .join("application.properties"),
        PROPERTIES_WITNESS,
    )
    .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["server.host"], &["properties"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 2, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_deref(), row.occurrence, row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("server.host"), Some(1), r#"["server.host"]"#),
            (Some("server.host"), Some(2), r#"["server.host#2"]"#),
        ]
    );
    assert!(
        rows.iter().all(|row| row.format == "properties"
            && row.node_kind == "member"
            && row.role == Some("property")
            && row.scalar_kind == Some("string")
            && row.provenance == "authored"
            && row.completeness == "complete"
            && row.path == "src/main/resources/application.properties"),
        "{rows:#?}"
    );
    assert_eq!(rows[0].parent_id, rows[1].parent_id);
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].value_id, rows[1].value_id);
    assert_eq!(
        &PROPERTIES_WITNESS[rows[0].start_byte..rows[0].end_byte],
        "server.host = primary.example"
    );
    assert_eq!(
        &PROPERTIES_WITNESS[rows[1].start_byte..rows[1].end_byte],
        "server.host: backup.example"
    );

    // A dotted key is one authored segment: neither its last segment nor a
    // segment-wise route reaches it, and the bare `host` line is its own key.
    let segment_key = configuration_result(&workspace, &["host"], &["properties"]);
    let segment_rows = configuration_rows(&segment_key);
    assert_eq!(segment_rows.len(), 1, "{}", segment_key.render_text());
    assert_eq!(segment_rows[0].route, r#"["host"]"#);
    let expanded_route = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &configuration_query(json!({
            "formats": ["properties"],
            "routes": [[
                {"kind": "key", "key": "server"},
                {"kind": "key", "key": "host"}
            ]],
        })),
    );
    assert!(
        configuration_rows(&expanded_route).is_empty(),
        "{}",
        expanded_route.render_text()
    );
    assert!(
        expanded_route
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.impact != CodeQueryDiagnosticImpact::Incomplete),
        "{:?}",
        expanded_route.diagnostics
    );

    // The escaped key is queried by its decoded text and anchored at its
    // authored, continued logical line.
    let escaped = configuration_result(&workspace, &["banner text"], &["properties"]);
    let escaped_rows = configuration_rows(&escaped);
    assert_eq!(escaped_rows.len(), 1, "{}", escaped.render_text());
    assert_eq!(
        &PROPERTIES_WITNESS[escaped_rows[0].start_byte..escaped_rows[0].end_byte],
        "banner\\ text = Welcome, \\\n    operator\\u0021"
    );
}

#[test]
fn malformed_properties_escapes_report_a_typed_gap_with_surviving_rows() {
    // A `\u` escape without four hex digits fails `Properties.load`; the
    // surviving authored rows stay queryable but never read as complete.
    let project = inline_project::rust_project_with_file(
        PathBuf::from("src")
            .join("main")
            .join("resources")
            .join("application.properties"),
        "server.host=kept.example\nbroken=\\u12x\n",
    )
    .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["server.host"], &["properties"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 1, "{}", result.render_text());
    assert_eq!(rows[0].completeness, "incomplete");
    let diagnostic =
        diagnostic_with_code(&result, CodeQueryDiagnosticCode::SemanticAnalysisPartial);
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(
        diagnostic.message.contains("application.properties")
            && diagnostic.message.contains("malformed syntax"),
        "{diagnostic:?}"
    );
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
fn toml_key_filter_returns_exact_entries_and_excludes_near_misses() {
    let project =
        inline_project::rust_project_with_file("deploy/config.toml", TOML_WITNESS).build();
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
fn toml_seed_reports_exhausted_row_budget_and_honours_cancellation() {
    let project =
        inline_project::rust_project_with_file("deploy/config.toml", TOML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {"formats": ["toml"]},
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("unfiltered TOML query");
    assert_seed_reports_row_budget_and_cancellation(&workspace, &query);
}

#[test]
fn yaml_key_filter_returns_exact_entries_and_excludes_near_misses() {
    let project =
        inline_project::rust_project_with_file("deploy/compose.yaml", YAML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = configuration_result(&workspace, &["host"], &["yaml"]);
    let rows = configuration_rows(&result);

    assert_eq!(rows.len(), 3, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_deref(), row.occurrence, row.route.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("host"), Some(1), r#"["services","web","host"]"#),
            (Some("host"), Some(1), r#"["services","db","host"]"#),
            (Some("host"), Some(2), r#"["services","db","host#2"]"#),
        ]
    );
    assert!(
        rows.iter().all(|row| row.format == "yaml"
            && row.node_kind == "member"
            && row.role == Some("object-member")
            && row.scalar_kind == Some("string")
            && row.provenance == "authored"
            && row.completeness == "complete"
            && row.path.ends_with("compose.yaml")),
        "{rows:#?}"
    );
    // `hostname` and `x-defaults` share the document; neither is an exact key.
    assert!(
        rows.iter()
            .all(|row| !matches!(row.key.as_deref(), Some("hostname" | "x-defaults")))
    );
    // Same key under two services: distinct identities and distinct parents.
    // Same key twice under one service: distinct identities, one parent.
    assert_ne!(rows[0].fact_id, rows[1].fact_id);
    assert_ne!(rows[0].parent_id, rows[1].parent_id);
    assert_ne!(rows[1].fact_id, rows[2].fact_id);
    assert_eq!(rows[1].parent_id, rows[2].parent_id);
    assert_eq!(
        &YAML_WITNESS[rows[0].start_byte..rows[0].end_byte],
        "host: primary.example"
    );
    assert_eq!(
        &YAML_WITNESS[rows[2].start_byte..rows[2].end_byte],
        "host: duplicate.example"
    );
}

#[test]
fn yaml_near_miss_axes_return_no_rows_and_stay_complete() {
    let project =
        inline_project::rust_project_with_file("deploy/compose.yaml", YAML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (axis, filter) in [
        // TOML's role on a YAML mapping entry.
        (
            "role",
            json!({"formats": ["yaml"], "keys": ["host"], "roles": ["table_entry"]}),
        ),
        // The wrong scalar kind for a string value.
        (
            "scalar kind",
            json!({"formats": ["yaml"], "keys": ["host"], "scalar_kinds": ["integer"]}),
        ),
        // A nested route flattened into one dotted key.
        (
            "flattened route",
            json!({"formats": ["yaml"], "keys": ["services.web.host"]}),
        ),
        // A sequence entry's route written without its index.
        (
            "index-less route",
            json!({"formats": ["yaml"], "routes": [[
                {"kind": "key", "key": "services"},
                {"kind": "key", "key": "web"},
                {"kind": "key", "key": "volumes"},
                {"kind": "key", "key": "path"}
            ]]}),
        ),
        // A case-shifted key.
        ("case", json!({"formats": ["yaml"], "keys": ["Host"]})),
        // The alias's target entries are not reachable through the alias.
        (
            "alias expansion",
            json!({"formats": ["yaml"], "routes": [[
                {"kind": "key", "key": "services"},
                {"kind": "key", "key": "web"},
                {"kind": "key", "key": "restart"}
            ]]}),
        ),
        // Another format over the same key.
        ("format", json!({"formats": ["json"], "keys": ["host"]})),
    ] {
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &configuration_query(filter),
        );
        assert!(
            configuration_rows(&result).is_empty(),
            "{axis}: {}",
            result.render_text()
        );
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.impact != CodeQueryDiagnosticImpact::Incomplete),
            "{axis}: {:?}",
            result.diagnostics
        );
    }
}

#[test]
fn yaml_seed_reports_exhausted_row_budget_and_honours_cancellation() {
    let project =
        inline_project::rust_project_with_file("deploy/compose.yaml", YAML_WITNESS).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = configuration_query(json!({"formats": ["yaml"]}));
    assert_seed_reports_row_budget_and_cancellation(&workspace, &query);
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
fn properties_seed_reports_exhausted_row_budget_and_honours_cancellation() {
    let project = inline_project::rust_project_with_file(
        PathBuf::from("src")
            .join("main")
            .join("resources")
            .join("application.properties"),
        PROPERTIES_WITNESS,
    )
    .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {"formats": ["properties"]},
        "result_detail": "full",
        "limit": 100,
    }))
    .expect("unfiltered properties query");
    assert_seed_reports_row_budget_and_cancellation(&workspace, &query);
}
