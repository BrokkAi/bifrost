use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, UnitExecutionResult, execute_code_query_unit,
};
use brokk_bifrost_analysis::CodeUnitIndex;
use brokk_bifrost_test_macros::hardwon;

// Explain validates execution limits without needing semantic registrations.
fn explain_admission(step: serde_json::Value, limits: CodeQueryExecutionLimits) -> bool {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({"execution_mode": "explain", "match": {"kind": "function"}, "steps": [{"op": "procedure_of"}, step]})).unwrap();
    matches!(
        execute_request_with_limits(&analyzer, &query, limits),
        CodeQueryResponse::Explain(_)
    )
}

#[test]
#[hardwon("#9179: unused RQL preflight listings left a Rust Scope read on store Output units")]
fn query_without_file_inventory_consumer_records_no_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn value() {}\n")
        .file("config.json", "{\"port\": 8080}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {"formats": ["json"], "keys": ["port"]},
        "limit": 10
    }))
    .expect("configuration query");
    let (result, ledger) = crate::analyzer::capture_query_reads(workspace.analyzer(), || {
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    });
    assert_eq!(result.results.len(), 1, "{result:#?}");
    assert!(
        !ledger
            .keys()
            .iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Scope { .. })),
        "{:?}",
        ledger.keys()
    );
}

#[test]
#[hardwon("#9179: a reused query-local file list could omit Scope from a later ledger")]
fn reused_file_inventory_replays_scope_to_each_consumer() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {"kind": "function"},
        "steps": [{"op": "procedure_of"}, {"op": "nilness_operations"}]
    }))
    .expect("relation query");
    assert!(relation_capabilities::needs_file_inventory(&query.plan));
    let inventory = QueryFileInventory::default();
    let (_, first) = crate::analyzer::capture_query_reads(&analyzer, || {
        let mut diagnostics = Vec::new();
        relation_capabilities::preflight(
            &query.plan,
            inventory.files(&analyzer, || analyzer.analyzed_files()),
            None,
            &mut diagnostics,
        );
        diagnostics
    });
    let (languages, second) = crate::analyzer::capture_query_reads(&analyzer, || {
        inventory
            .files(&analyzer, || panic!("cached inventory was listed again"))
            .iter()
            .map(crate::analyzer::common::language_for_file)
            .collect::<std::collections::HashSet<_>>()
    });
    assert!(languages.contains(&Language::Python));
    for ledger in [&first, &second] {
        assert!(
            ledger.keys().iter().any(|key| matches!(key, crate::analyzer::ReadKey::Scope { languages, .. } if languages.as_ref() == [Language::Python])),
            "{:?}",
            ledger.keys()
        );
    }
}

#[test]
#[hardwon("#9179: a stopped cached listing could be replayed as a complete empty inventory")]
fn stopped_file_inventory_refuses_each_consumer() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let _query = crate::analyzer::AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
    let inventory = QueryFileInventory::default();
    let (_, first) =
        crate::analyzer::capture_query_reads(&analyzer, || inventory.files(&analyzer, Vec::new));
    let (_, second) = crate::analyzer::capture_query_reads(&analyzer, || {
        inventory.files(&analyzer, || panic!("stopped inventory relisted"))
    });
    assert!(first.execution_dependences() > 0);
    assert!(second.execution_dependences() > 0);
}

#[test]
fn taint_projection_requires_positive_bytes() {
    // results/diagnostics.rs requires positive projected bytes.
    for value in [0, 1] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.taint.max_projected_bytes = value;
        assert_eq!(
            explain_admission(json!({"op": "taint", "taint_ref": "test:resource"}), limits),
            value == 1
        );
    }
}

#[test]
fn taint_origin_limit_accepts_the_full_documented_range() {
    // results/diagnostics.rs caps origins at 50,000.
    for value in [4096, 4097, 50000, 50001] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.taint.max_origins_per_finding = value;
        assert_eq!(
            explain_admission(json!({"op": "taint", "taint_ref": "test:resource"}), limits),
            value <= 50000
        );
    }
}

#[test]
fn value_flow_witness_limit_accepts_the_full_documented_range() {
    // results/diagnostics.rs caps witnesses at 50,000.
    for value in [4096, 4097, 50000, 50001] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.value_flow.max_witnesses = value;
        assert_eq!(
            explain_admission(
                json!({"op": "value_flow", "plan_ref": "test:resource"}),
                limits
            ),
            value <= 50000
        );
    }
}

#[test]
fn typestate_candidate_limit_accepts_one_candidate() {
    // results/diagnostics.rs requires positive candidates.
    for value in [0, 1, 2] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.typestate.max_candidates = value;
        assert_eq!(
            explain_admission(
                json!({"op": "typestate", "protocol_ref": "test:resource"}),
                limits
            ),
            value > 0
        );
    }
}

#[test]
fn unit_artifacts_preserve_workspace_diagnostic_attribution() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}, "steps": [{"op": "procedure_of"}, {"op": "typestate", "protocol_ref": "test:missing"}]})).unwrap();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert!(!unit.diagnostics.is_empty(), "{unit:?}");
    let wire = serde_json::to_value(&unit).unwrap();
    let decoded: UnitExecutionResult = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded.diagnostics[0].language, "workspace");
    let mut corrupt = wire;
    corrupt["diagnostics"][0]["language"] = json!("not-a-language");
    assert!(serde_json::from_value::<UnitExecutionResult>(corrupt).is_err());
}

#[test]
fn unit_artifacts_keep_nested_branch_diagnostics() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"union": [
        {"union": [{"match": {"kind": "function"}}, {"generation_sites": {}}]},
        {"match": {"kind": "function"}}
    ]}))
    .unwrap();
    let files = workspace.analyzer().analyzed_files();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files, &files),
    );
    assert!(!unit.diagnostics.is_empty(), "{unit:?}");
    let decoded: UnitExecutionResult =
        serde_json::from_value(serde_json::to_value(&unit).unwrap()).unwrap();
    assert!(
        decoded.diagnostics.iter().all(|d| d.branch == [0, 1]),
        "{decoded:?}"
    );
}

#[test]
fn union_units_preserve_all_leaf_contributions_before_global_limit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def first(): pass\ndef second(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = workspace.analyzer().analyzed_files();
    let query = CodeQuery::from_json(&json!({"union": [{"match": {"kind": "function"}}, {"match": {"kind": "function", "name": "second"}}], "limit": 1})).unwrap();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files, &files),
    );
    assert_eq!(
        unit.rows.len(),
        3,
        "both functions in the first leaf, second again in the second: {unit:?}"
    );
    assert!(!unit.truncated, "{unit:?}");
}

#[test]
fn semantic_file_refusal_renders_attempted_charge_before_limit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("first.py", "def first(): pass\n")
        .file("second.py", "def second(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(cfg-entry (procedure-of (function)))").unwrap();
    let mut limits = CodeQueryExecutionLimits::default();
    limits.semantic.max_materialized_files = 1;
    let result = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        limits,
    );
    let text = result.render_text();
    assert!(text.contains("charged 2 limit 1"), "{text}");
}
