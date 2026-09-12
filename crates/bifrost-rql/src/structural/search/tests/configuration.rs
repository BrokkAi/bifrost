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
