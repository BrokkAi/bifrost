use super::*;

#[test]
fn edited_environment_session_agrees_with_a_fresh_session() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "example.py",
            "def run():\n    before = 1\n    return before\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("example.py");
    let files = [file.clone()];
    let query = CodeQuery::from_source("(bindings)").unwrap();
    let run = |workspace: &WorkspaceAnalyzer, session: &mut CodeQueryRowFamilySession| {
        let detailed = execute_code_query_detailed_eager_index_with_row_family_session_in_scope(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            session,
            CodeQueryExecutionScope::for_seed_files(&files, &files),
        );
        assert_eq!(detailed.result.completion(), CodeQueryCompletion::Complete);
        assert!(!detailed.result.results.is_empty());
        serde_json::to_value(detailed.result).unwrap()
    };
    let mut session = CodeQueryRowFamilySession::default();
    let before = run(&workspace, &mut session);
    file.write("def run():\n    after = 2\n    return after\n")
        .unwrap();
    let edited = workspace.update(&BTreeSet::from([file]));
    let incremental = run(&edited, &mut session);
    let fresh = run(&edited, &mut CodeQueryRowFamilySession::default());
    eprintln!("before={before}\nincremental={incremental}\nfresh={fresh}");
    assert_ne!(before, fresh);
    assert_eq!(incremental, fresh);
}

#[test]
fn semantic_trace_identities_agree_with_direct_rows() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname = \"trace-identities\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
        .file("src/lib.rs", "fn first() {}\nfn second() {}\nfn third() {}\npub fn run(flag: bool) { first(); if flag { second(); } third(); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let query = |steps: serde_json::Value| {
        CodeQuery::from_json(&json!({
            "match": {"kind": "function", "name": "run"}, "steps": steps, "result_detail": "full"
        }))
        .unwrap()
    };
    let point_query = query(json!([{"op":"procedure_of"},{"op":"cfg_entry"}]));
    let points = execute_workspace(&workspace, &flow, &point_query);
    let edge_query =
        query(json!([{"op":"procedure_of"},{"op":"cfg_entry"},{"op":"cfg_successor_edges"}]));
    let edges = execute_workspace(&workspace, &flow, &edge_query);
    // Row filters retain and expose the compact references between traversals.
    let trace_query = query(json!([
        {"op":"procedure_of"},{"op":"cfg_entry"},
        {"op":"filter", "where":[{"field":"id","op":"ne","value":{"string":""}}]},
        {"op":"cfg_successor_edges"},
        {"op":"filter", "where":[{"field":"id","op":"ne","value":{"string":""}}]},
        {"op":"cfg_edge_target"},{"op":"file_of"}
    ]));
    let detailed = execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &flow,
        &trace_query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    eprintln!("points={points:#?}\nedges={edges:#?}\ndetailed={detailed:#?}");
    assert!(!points.results.is_empty(), "{points:?}");
    assert!(!edges.results.is_empty(), "{edges:?}");
    assert!(!detailed.result.results.is_empty(), "{detailed:?}");
    let targets = execute_workspace(
        &workspace,
        &flow,
        &query(json!([
            {"op":"procedure_of"},{"op":"cfg_entry"},{"op":"cfg_successor_edges"},{"op":"cfg_edge_target"}
        ])),
    );
    assert!(!targets.results.is_empty(), "{targets:?}");
    let point_ids: BTreeSet<_> = points
        .results
        .iter()
        .chain(&targets.results)
        .map(|row| {
            let CodeQueryResultValue::ProgramPoint { value } = &row.value else {
                panic!("{row:?}");
            };
            value.id.clone()
        })
        .collect();
    assert!(
        point_ids.len() >= 2,
        "entry and successor are distinct points"
    );
    let edge_ids: BTreeSet<_> = edges
        .results
        .iter()
        .map(|row| {
            let CodeQueryResultValue::ControlEdge { value } = &row.value else {
                panic!("{row:?}");
            };
            value.id.clone()
        })
        .collect();
    let mut traced_points = BTreeSet::new();
    let mut traced_edges = BTreeSet::new();
    for row in &detailed.result.results {
        for trace in &row.provenance {
            for step in &trace.steps {
                match &step.result {
                    CodeQueryResultRef::ProgramPoint { id, .. } => {
                        traced_points.insert(id.clone());
                    }
                    CodeQueryResultRef::ControlEdge {
                        id,
                        source_id,
                        target_id,
                        ..
                    } => {
                        traced_edges.insert(id.clone());
                        let edge = edges
                            .results
                            .iter()
                            .find_map(|row| match &row.value {
                                CodeQueryResultValue::ControlEdge { value } if value.id == *id => {
                                    Some(value)
                                }
                                _ => None,
                            })
                            .expect("trace edge has a direct row");
                        assert_eq!(source_id, &edge.source.id);
                        assert_eq!(target_id, &edge.target.id);
                    }
                    _ => {}
                }
            }
        }
    }
    assert_eq!(traced_points, point_ids);
    assert_eq!(traced_edges, edge_ids);
    let mut detailed_points = BTreeSet::new();
    let mut detailed_edges = BTreeSet::new();
    for step in detailed
        .evidence
        .iter()
        .flat_map(|row| &row.provenance)
        .flat_map(|trace| &trace.steps)
    {
        let set = match step.result.domain {
            DetailedCodeQueryDomain::ProgramPoint => &mut detailed_points,
            DetailedCodeQueryDomain::ControlEdge => &mut detailed_edges,
            _ => continue,
        };
        let DetailedCodeQueryProvenanceIdentities::Primary(Some(identity)) =
            &step.result.identities
        else {
            panic!("{step:?}");
        };
        let CodeQueryStableOwnerCandidate::Derived { semantic_key, .. } = &identity.candidate
        else {
            panic!("{identity:?}");
        };
        set.insert(semantic_key.clone());
    }
    assert_eq!(detailed_points, point_ids);
    assert_eq!(detailed_edges, edge_ids);
}
