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

#[test]
fn procedure_source_owner_requires_unique_named_certified_owner() {
    fn owners(source: &str) -> Vec<Option<CodeQueryStableOwnerCandidate>> {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let provider = workspace.analyzer().structural_fact_providers()[0];
        let file = provider
            .structural_files()
            .into_iter()
            .find(|file| rel_path_string(file) == "lib.rs")
            .unwrap();
        let facts = provider.structural_facts(&file).unwrap();
        let nodes: Vec<_> = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| node.kind.satisfies(NormalizedKind::Callable))
            .collect();
        nodes
            .into_iter()
            .map(|(id, node)| {
                let seed = SeedMatch {
                    language: Language::Rust,
                    file: file.clone(),
                    facts: Arc::clone(&facts),
                    fact_match: FactMatch {
                        selected_pattern_source: Default::default(),
                        node: id as u32,
                        captures: Arc::from([]),
                        reported_range: None,
                        heuristic: None,
                    },
                    python_import: None,
                };
                procedure_source_owner(
                    workspace.analyzer(),
                    &seed,
                    &file,
                    node.range.start_byte..node.range.end_byte,
                    &mut PipelineRenderCache::default(),
                )
            })
            .collect()
    }
    let base = owners("pub fn run() {}");
    assert_eq!(base.len(), 1);
    assert!(base[0].is_some());
    assert_eq!(base, owners("// inserted unrelated line\npub fn run() {}"));
    let duplicates = owners("#[cfg(a)] fn run() {} #[cfg(b)] fn run() {}");
    assert_eq!(duplicates.len(), 2);
    assert!(duplicates.iter().all(Option::is_none));
    let closures = owners("fn run(){ let c = || 1; }");
    assert_eq!(closures.len(), 2);
    assert!(closures[0].is_some());
    assert!(closures[1].is_none());
    let scopes = owners("mod a {fn run(){}} mod b {fn run(){}}");
    assert_eq!(scopes.len(), 2);
    assert!(scopes.iter().all(Option::is_some));
    assert_ne!(scopes[0], scopes[1]);
}

#[test]
fn procedure_source_owner_certification_honors_work_and_live_cancellation() {
    let source = (0..200)
        .map(|index| format!("fn f{index}() {{"))
        .collect::<String>()
        + &"}".repeat(200);
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let provider = workspace.analyzer().structural_fact_providers()[0];
    let file = provider
        .structural_files()
        .into_iter()
        .find(|file| rel_path_string(file) == "lib.rs")
        .unwrap();
    let facts = provider.structural_facts(&file).unwrap();
    let id = facts
        .nodes()
        .iter()
        .position(|node| {
            node.name
                .is_some_and(|name| name.text(facts.source()) == "f199")
        })
        .unwrap() as u32;
    let seed = SeedMatch {
        language: Language::Rust,
        file: file.clone(),
        facts: Arc::clone(&facts),
        fact_match: FactMatch {
            selected_pattern_source: Default::default(),
            node: id,
            captures: Arc::from([]),
            reported_range: None,
            heuristic: None,
        },
        python_import: None,
    };
    let range = facts.node(id).range.start_byte..facts.node(id).range.end_byte;
    let mut bounded = PipelineRenderCache {
        procedure_owner_work: ProcedureOwnerWork::new(0, 128, None),
        ..PipelineRenderCache::default()
    };
    assert!(
        procedure_source_owner(
            workspace.analyzer(),
            &seed,
            &file,
            range.clone(),
            &mut bounded
        )
        .is_none()
    );
    assert!(bounded.procedure_owner_work.refused.is_some());
    assert!(bounded.procedure_owner_work.used <= 128);
    assert!(
        bounded.procedure_owners.is_empty(),
        "a partial scan cannot certify uniqueness"
    );

    let token = CancellationToken::cancel_after_checks_for_test(4);
    let mut cancelled = PipelineRenderCache {
        procedure_owner_work: ProcedureOwnerWork::new(0, usize::MAX, Some(token.clone())),
        ..PipelineRenderCache::default()
    };
    assert!(
        procedure_source_owner(workspace.analyzer(), &seed, &file, range, &mut cancelled).is_none()
    );
    assert!(token.cancel_after_checks_tripped_for_test());
    assert!(cancelled.procedure_owner_work.cancelled);
    assert!(cancelled.procedure_owners.is_empty());

    let expected = canonical_ast_candidate_for_node(&seed, id);
    let mut work = ProcedureOwnerWork::default();
    let actual = canonical_ast_candidate_for_node_with_visit(seed.language, &facts, id, |node| {
        work.charge(
            1 + node.kind.label().len()
                + node.name.map_or(0, |name| name.text(facts.source()).len()),
        )
    });
    assert!(expected.is_some());
    assert_eq!(
        actual, expected,
        "metering must not create a second identity encoding"
    );
}

#[test]
fn procedure_source_owner_budget_refusal_is_reported_by_the_query() {
    let source = (0..24)
        .map(|index| format!("fn f{index}() {{"))
        .collect::<String>()
        + &"}".repeat(24);
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"match":{"kind":"function","name":"f0"},"steps":[{"op":"procedure_of"},{"op":"file_of"}],"result_detail":"full"})).unwrap();
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 128,
        ..CodeQueryExecutionLimits::default()
    };
    let detailed = execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        limits,
        None,
    );
    assert!(
        detailed
            .result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic
                .exhausted_roots
                .iter()
                .any(|root| root.stage.as_deref() == Some("procedure_source_owner"))),
        "{detailed:?}"
    );
    assert!(detailed.budgeted_work.provenance_steps <= 128);
    assert!(
        detailed
            .result
            .results
            .iter()
            .flat_map(|row| &row.provenance)
            .flat_map(|trace| &trace.steps)
            .all(|step| !matches!(
                &step.result,
                CodeQueryResultRef::Procedure {
                    source_owner: Some(_),
                    ..
                }
            )),
        "{detailed:?}"
    );
}
