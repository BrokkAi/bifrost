use super::*;

#[test]
fn call_results_correlate_with_call_shape_sites() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname='site_identity'\nversion='0.1.0'\nedition='2021'\n",
        )
        .file(
            "src/lib.rs",
            "fn acquire() -> u32 { 1 } pub fn root() { let a = acquire(); let b = acquire(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let execute = |source| {
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &CodeQuery::from_sexp(source).expect("query"),
        )
    };
    let results = execute("(call-results (call-shape (call :callee \"acquire\")))");
    let shapes = execute("(call-shape (call :callee \"acquire\"))");
    let values: Vec<_> = results
        .results
        .iter()
        .filter_map(|row| match &row.value {
            CodeQueryResultValue::CallResult { value } => Some(value),
            _ => None,
        })
        .collect();
    let sites: Vec<_> = shapes
        .results
        .iter()
        .filter_map(|row| match &row.value {
            CodeQueryResultValue::CallShape { value } => Some(value),
            _ => None,
        })
        .collect();
    assert_eq!(values.len(), 2, "{results:#?}");
    assert_eq!(sites.len(), 2, "{shapes:#?}");
    assert_ne!(values[0].site_id, values[1].site_id);
    for value in values {
        let site = sites
            .iter()
            .find(|site| site.range == value.range)
            .expect("call shape at result range");
        assert_eq!(value.site_id, site.site_id);
        assert_eq!(value.site_ast_id, site.site_ast_id);
        assert_ne!(value.site_id, value.site_ast_id);
    }
}

#[test]
fn invoked_callback_retains_proof_with_open_coverage() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname='callback_quality'\nversion='0.1.0'\nedition='2021'\n")
        .file("src/lib.rs", "fn invoke<F: FnOnce()>(callback: F) { callback(); }\nfn store<F>(callback: F) { let _stored = callback; }\npub fn root() { invoke(|| {}); store(|| {}); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": "root" },
        "steps": [{ "op": "procedure_of" }, { "op": "callees" }],
        "result_detail": "full"
    }))
    .expect("callback query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let closures: Vec<_> = result
        .results
        .iter()
        .filter_map(|row| match &row.value {
            CodeQueryResultValue::Procedure { value } if value.procedure_kind == "closure" => {
                Some(value)
            }
            _ => None,
        })
        .collect();
    assert_eq!(closures.len(), 1, "{result:#?}");
    assert_eq!(
        closures[0].evidence.proof,
        CodeQuerySemanticProof::Proven,
        "{result:#?}"
    );
    assert_eq!(
        closures[0].evidence.completeness,
        CodeQuerySemanticCompleteness::Partial,
        "{result:#?}"
    );
}
