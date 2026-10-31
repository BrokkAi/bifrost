use super::*;

#[test]
fn class_queries_require_positive_value_flow_limits() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    for op in ["class_set", "absent_member"] {
        for value in [0, 1] {
            let query = CodeQuery::from_json(&json!({"execution_mode":"explain", "match":{"kind":"function"}, "steps":[{"op":"procedure_of"},{"op":op}]})).unwrap();
            let mut limits = CodeQueryExecutionLimits::default();
            // CodeQueryValueFlowLimits::is_valid requires a positive witness limit.
            limits.value_flow.max_witnesses = value;
            let response = execute_request_with_limits(&analyzer, &query, limits);
            assert_eq!(
                matches!(response, CodeQueryResponse::Explain(_)),
                value == 1,
                "{op}: {response:?}"
            );
        }
    }
}

#[test]
fn semantic_policy_traces_preserve_the_authored_language() {
    let source = "// prefix outside selected procedure\npub fn run() { let value = 1; }\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"policy-traces\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"match":{"kind":"function","name":"run"},"steps":[{"op":"procedure_of"},{"op":"filter","where":[{"field":"id","op":"ne","value":{"string":""}}]},{"op":"file_of"}],"result_detail":"full"})).unwrap();
    let detailed = execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(detailed.evidence.len(), 1, "{detailed:?}");
    let refs: Vec<_> = detailed
        .evidence
        .iter()
        .flat_map(|row| &row.provenance)
        .flat_map(|trace| &trace.steps)
        .filter(|step| step.result.domain == DetailedCodeQueryDomain::Procedure)
        .collect();
    assert!(!refs.is_empty(), "{detailed:?}");
    for step in refs {
        let reference = &step.result;
        let DetailedCodeQueryProvenanceIdentities::Primary(Some(identity)) = &reference.identities
        else {
            panic!("{reference:?}")
        };
        let CodeQueryStableOwnerCandidate::Derived { namespace, .. } = &identity.candidate else {
            panic!("{identity:?}")
        };
        assert_eq!(namespace, "rust");
        let span = reference.byte_span.clone().unwrap();
        assert!(span.start > 0);
        assert_eq!(
            reference.source_slice_sha256,
            Some(Sha256::digest(&source.as_bytes()[span]).into())
        );
    }
}

#[test]
fn empty_python_seeds_still_require_absence_capability() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "value = 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for source in [
        "(absent-member (procedure-of (callable :name \"missing\")))",
        "(language python (absent-member (procedure-of (union (callable :name \"missing\") (callable :name \"other\")))))",
    ] {
        let query = CodeQuery::from_source(source).unwrap();
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
        );
        assert!(result.results.is_empty(), "{result:?}");
        assert!(
            result
                .render_text()
                .contains("semantic_capability_unsupported"),
            "{source}: {}",
            result.render_text()
        );
    }
}

#[test]
fn class_query_explain_requests_dispatch() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({"execution_mode":"explain", "match":{"kind":"function"}, "steps":[{"op":"procedure_of"},{"op":"class_set"}]})).unwrap();
    let response =
        execute_request_with_limits(&analyzer, &query, CodeQueryExecutionLimits::default());
    let CodeQueryResponse::Explain(explain) = response else {
        panic!("{response:?}")
    };
    assert!(
        explain
            .physical_plan
            .nodes
            .iter()
            .filter_map(|node| node.semantic_request)
            .any(|request| request.dispatch)
    );
}
