use super::*;

#[test]
fn detailed_execution_aligns_evidence_hashes_owners_and_direct_work() {
    let source = r#"export function handler(input: string) {
sink(input);
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "result_detail": "full"
    }))
    .expect("query");

    let detailed =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);

    assert_eq!(detailed.result.results.len(), 1);
    assert!(
        detailed.profile.is_none(),
        "ordinary detailed execution should not pay profiling overhead"
    );
    assert_eq!(detailed.evidence.len(), 1);
    let evidence = &detailed.evidence[0];
    assert_eq!(evidence.result_index, 0);
    assert_eq!(evidence.domain, DetailedCodeQueryDomain::StructuralMatch);
    assert!(matches!(
        &evidence.key,
        DetailedCodeQueryKey::StructuralMatch {
            kind,
            analyzer_id: Some(_),
        } if kind == "call"
    ));
    let byte_span = evidence.byte_span.clone().expect("match byte span");
    assert_eq!(&source[byte_span.clone()], "sink(input)");
    assert_eq!(
        evidence.source_slice_sha256,
        Some(Sha256::digest(&source.as_bytes()[byte_span]).into())
    );
    assert!(matches!(
        &evidence.stable_owner_candidate,
        Some(CodeQueryStableOwnerCandidate {
            derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
            semantic_key,
            ..
        }) if semantic_key.contains("handler") && semantic_key.contains("sink")
    ));
    assert_eq!(detailed.work.scanned_files, 1);
    assert_eq!(
        detailed.work.scanned_source_bytes,
        u64::try_from(source.len()).expect("source length")
    );
    assert!(detailed.work.fact_nodes > 0);
    assert!(detailed.work.pipeline_rows >= 1);
    assert_eq!(detailed.work.examined_references, 0);
}

#[test]
fn detailed_file_terminal_is_artifact_only() {
    let source = "export function handler() { sink(); }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "steps": [{ "op": "file_of" }],
        "result_detail": "full"
    }))
    .expect("query");

    let detailed =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);

    assert!(matches!(
        detailed.result.results[0].value,
        CodeQueryResultValue::File { ref value } if value.path == "app.ts"
    ));
    assert_eq!(detailed.evidence[0].domain, DetailedCodeQueryDomain::File);
    assert_eq!(detailed.evidence[0].key, DetailedCodeQueryKey::File);
    assert!(detailed.evidence[0].byte_span.is_none());
    assert!(detailed.evidence[0].source_slice_sha256.is_none());
    assert!(detailed.evidence[0].stable_owner_candidate.is_none());
}

#[test]
fn detailed_execution_covers_every_semantic_terminal_domain() {
    let source = r#"export function target(payload: string) { return payload; }
export function caller() { return target("secret"); }
class Service { run() {} }
export function invoke(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let cases = [
        (
            DetailedCodeQueryDomain::Declaration,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "enclosing_decl" }],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::ReferenceSite,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "references_of", "proof": "proven" }
                ],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::CallSite,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" }
                ],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::ExpressionSite,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 }
                ],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::ReceiverAnalysis,
            json!({
                "match": { "kind": "call", "callee": { "name": "run" } },
                "steps": [{ "op": "receiver_targets" }],
                "result_detail": "full"
            }),
        ),
    ];

    for (expected_domain, query) in cases {
        let query = CodeQuery::from_json(&query).expect("query");
        let detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(
            detailed.result.results.len(),
            1,
            "terminal domain {expected_domain:?}: {}",
            detailed.result.render_text()
        );
        let evidence = &detailed.evidence[0];
        assert_eq!(evidence.domain, expected_domain);
        assert_eq!(evidence.result_index, 0);
        assert_eq!(evidence.file, file);
        assert!(evidence.byte_span.is_some());
        if expected_domain == DetailedCodeQueryDomain::ReceiverAnalysis {
            assert!(evidence.source_slice_sha256.is_none());
            assert!(evidence.stable_owner_candidate.is_none());
        } else {
            let byte_span = evidence.byte_span.clone().expect("byte span");
            assert_eq!(
                evidence.source_slice_sha256,
                Some(Sha256::digest(&source.as_bytes()[byte_span]).into())
            );
            assert!(matches!(
                evidence.stable_owner_candidate,
                Some(CodeQueryStableOwnerCandidate {
                    derivation: CodeQueryStableOwnerDerivation::AnalyzerDeclarationId,
                    ..
                })
            ));
        }
    }
}

#[test]
fn cross_file_declaration_hydration_is_charged_or_degrades_to_weak_evidence() {
    let target_source = "export function target() {}\n";
    let caller_source =
        "import { target } from './target';\nexport function caller() { target(); }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let target_file = ProjectFile::new(root.clone(), PathBuf::from("target.ts"));
    let caller_file = ProjectFile::new(root.clone(), PathBuf::from("caller.ts"));
    target_file.write(target_source).expect("write target");
    caller_file.write(caller_source).expect("write caller");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "where": ["target.ts"],
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callers", "proof": "proven" }
        ],
        "result_detail": "full"
    }))
    .expect("query");

    let complete =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);
    assert_eq!(complete.result.results.len(), 1);
    assert_eq!(
        complete.evidence[0].domain,
        DetailedCodeQueryDomain::Declaration
    );
    assert_eq!(complete.evidence[0].file, caller_file);
    assert!(complete.evidence[0].source_slice_sha256.is_some());
    assert!(complete.work.scanned_source_bytes >= caller_source.len() as u64);

    let tight_limit = usize::try_from(complete.work.scanned_source_bytes)
        .expect("work fits usize")
        .saturating_sub(1);
    let partial = execute_code_query_detailed(
        &analyzer,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: tight_limit,
            ..CodeQueryExecutionLimits::default()
        },
        None,
    );
    assert_eq!(
        partial.result.results.len(),
        1,
        "the already-produced declaration remains available"
    );
    assert_eq!(partial.evidence[0].file, caller_file);
    assert!(partial.evidence[0].source_slice_sha256.is_none());
    assert!(partial.result.truncated);
    assert!(partial.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
            && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
    }));
    assert!(partial.work.scanned_source_bytes <= tight_limit as u64);
}

#[test]
fn cross_file_call_nested_rendering_cannot_retry_an_exhausted_source() {
    let target_source = "export function target() {}\n";
    let caller_source =
        "import { target } from './target';\nexport function caller() { target(); }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("target.ts"))
        .write(target_source)
        .expect("write target");
    let caller_file = ProjectFile::new(root.clone(), PathBuf::from("caller.ts"));
    caller_file.write(caller_source).expect("write caller");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "where": ["target.ts"],
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "call_sites_to", "proof": "proven" }
        ],
        "result_detail": "full"
    }))
    .expect("query");

    let complete =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);
    assert_eq!(complete.result.results.len(), 1);
    assert_eq!(complete.evidence[0].file, caller_file);
    assert!(complete.evidence[0].source_slice_sha256.is_some());
    let tight_limit = usize::try_from(complete.work.scanned_source_bytes)
        .expect("work fits usize")
        .saturating_sub(1);

    let partial = execute_code_query_detailed(
        &analyzer,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: tight_limit,
            ..CodeQueryExecutionLimits::default()
        },
        None,
    );
    assert_eq!(partial.result.results.len(), 1);
    assert!(partial.evidence[0].source_slice_sha256.is_none());
    assert!(partial.work.scanned_source_bytes <= tight_limit as u64);
    let CodeQueryResultValue::CallSite { value } = &partial.result.results[0].value else {
        panic!("expected call-site result");
    };
    assert!(
        value.caller.node_range.is_none(),
        "nested caller rendering must use the negative cache rather than retrying"
    );
    assert!(value.callee.node_range.is_some());
    assert!(partial.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
    }));
}

#[test]
fn receiver_budget_projects_one_remaining_fact_cap_across_all_work() {
    let base = ReceiverAnalysisBudget::default();
    let bounded = receiver_budget_for_remaining_work(base, 100, usize::MAX);
    assert_eq!(bounded.max_scope_nodes, 75);
    assert_eq!(bounded.max_summary_expansions, 25);
    assert_eq!(
        bounded
            .max_scope_nodes
            .saturating_add(bounded.max_summary_expansions),
        100
    );

    let tiny = receiver_budget_for_remaining_work(base, 1, 1);
    assert!(
        tiny.max_scope_nodes
            .saturating_add(tiny.max_summary_expansions)
            <= 1
    );
    assert_eq!(tiny.max_targets, 1);

    let ample = receiver_budget_for_remaining_work(base, usize::MAX, usize::MAX);
    assert_eq!(ample, base);
}

#[test]
fn tiny_receiver_budget_returns_an_explicit_exceeded_row() {
    let source = r#"class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
const service = makeService();
service.run();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [{ "op": "receiver_targets" }]
    }))
    .expect("query");

    let result =
        execute_with_receiver_budget_for_test(&analyzer, &query, ReceiverAnalysisBudget::tiny());

    assert!(result.truncated);
    assert!(result.render_text().contains("limit -> scope_nodes"));
    assert!(matches!(
        result.results[0].value,
        CodeQueryResultValue::ReceiverAnalysis { ref value }
            if value.outcome == "exceeded_budget" && value.limit == Some("scope_nodes")
    ));

    let file_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [{ "op": "receiver_targets" }, { "op": "file_of" }]
    }))
    .expect("file query");
    let file_result = execute_with_receiver_budget_for_test(
        &analyzer,
        &file_query,
        ReceiverAnalysisBudget::tiny(),
    );
    assert!(file_result.truncated);
    assert!(matches!(
        file_result.results[0].value,
        CodeQueryResultValue::File { ref value } if value.path == "app.ts"
    ));

    let outcome_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "receiver_targets" },
            { "op": "receiver_outcome" }
        ],
        "result_detail": "full"
    }))
    .expect("outcome query");
    let outcome = execute_with_receiver_budget_for_test(
        &analyzer,
        &outcome_query,
        ReceiverAnalysisBudget::tiny(),
    );
    assert!(matches!(
        outcome.results.as_slice(),
        [CodeQueryResultItem {
            value: CodeQueryResultValue::ReceiverOutcome { value },
            ..
        }] if value.outcome == "exceeded_budget"
            && value.coverage == "truncated"
            && value.candidate_count == 0
            && value.site_id == value.id
    ));

    let evidence_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "receiver_targets" },
            { "op": "receiver_evidence" }
        ]
    }))
    .expect("evidence query");
    let evidence = execute_with_receiver_budget_for_test(
        &analyzer,
        &evidence_query,
        ReceiverAnalysisBudget::tiny(),
    );
    assert!(evidence.results.is_empty());
}

#[test]
fn receiver_evidence_rows_join_to_their_mandatory_outcome() {
    let source = r#"class Service { run() {} }
export function caller(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal| {
        CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [
                { "op": "receiver_targets" },
                { "op": terminal }
            ],
            "result_detail": "full"
        }))
        .expect("receiver row query")
    };

    let outcome = execute(&analyzer, &query("receiver_outcome"));
    let evidence = execute(&analyzer, &query("receiver_evidence"));
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcome.results[0].value else {
        panic!("expected receiver outcome")
    };
    assert_eq!(outcome.outcome, "precise");
    assert_eq!(outcome.coverage, "exhaustive");
    assert_eq!(outcome.candidate_count, 1);
    assert!(outcome.site_ast_id.is_some());
    assert_eq!(evidence.results.len(), 1, "{}", evidence.render_text());
    let CodeQueryResultValue::ReceiverEvidence { value: evidence } = &evidence.results[0].value
    else {
        panic!("expected receiver evidence")
    };
    assert_eq!(evidence.site_id, outcome.site_id);
    assert_eq!(evidence.ordinal, 0);
    assert_eq!(evidence.chain_hop, 0);
    assert_eq!(evidence.proof, "precise");
    assert_eq!(evidence.completeness, "exhaustive");
    assert!(evidence.declaration_id.is_some());
}

#[test]
fn member_occurrence_ast_id_correlates_receiver_and_resolution_rows() {
    let source = r#"class Service { run() {} }
export function caller(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal: &str| {
        let mut steps = vec![json!({ "op": terminal })];
        if terminal == "member_targets" {
            steps.push(json!({ "op": "receiver_outcome" }));
        }
        CodeQuery::from_json(&json!({
            "where": ["app.ts"],
            "occurrences": {
                "role": ["member_position"]
            },
            "steps": steps,
            "result_detail": "full"
        }))
        .expect("occurrence relation query")
    };

    let candidates = execute(&analyzer, &query("candidates_of"));
    let outcomes = execute(&analyzer, &query("member_targets"));
    let CodeQueryResultValue::ResolutionCandidate { value: candidate } =
        &candidates.results[0].value
    else {
        panic!("expected resolution candidate")
    };
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcomes.results[0].value
    else {
        panic!("expected receiver outcome")
    };
    assert_eq!(
        outcome.site_ast_id.as_deref(),
        Some(candidate.ast_id.as_str())
    );
    assert_eq!(outcome.outcome, "precise");
}

#[test]
fn receiver_factory_evidence_is_a_stable_parent_linked_chain() {
    let source = r#"class Service { run() {} }
function makeService() { return new Service(); }
export function caller() { const service = makeService(); service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "callee": { "name": "run" },
            "receiver": { "capture": "receiver" }
        },
        "steps": [
            { "op": "points_to", "capture": "receiver" },
            { "op": "receiver_evidence" }
        ],
        "result_detail": "full"
    }))
    .expect("factory evidence query");

    let first = execute(&analyzer, &query);
    let second = execute(&analyzer, &query);
    assert_eq!(first.results.len(), 2, "{}", first.render_text());
    let rows = first
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::ReceiverEvidence { value } => value,
            _ => panic!("expected receiver evidence"),
        })
        .collect::<Vec<_>>();
    assert_eq!(rows[0].evidence_kind, "factory_return");
    assert!(rows[0].factory_id.is_some());
    assert_eq!(rows[0].parent_evidence_id, None);
    assert_eq!(
        rows[1].parent_evidence_id.as_deref(),
        Some(rows[0].id.as_str())
    );
    assert_eq!(rows[1].chain_hop, 1);
    let second_ids = second
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::ReceiverEvidence { value } => value.id.as_str(),
            _ => panic!("expected receiver evidence"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        second_ids,
        rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>()
    );
}

/// An aliased receiver resolves through the alias to the same typed evidence
/// as the direct binding, and the row set is deterministic across runs.
#[test]
fn aliased_receiver_evidence_rows_are_deterministic_and_typed() {
    let source = r#"class Service { run() {} }
export function caller() { const service = new Service(); const alias = service; alias.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal| {
        CodeQuery::from_json(&json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [
                { "op": "points_to", "capture": "receiver" },
                { "op": terminal }
            ],
            "result_detail": "full"
        }))
        .expect("aliased receiver query")
    };

    let outcome = execute(&analyzer, &query("receiver_outcome"));
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcome.results[0].value else {
        panic!("expected receiver outcome")
    };
    assert_eq!(outcome.outcome, "precise", "{outcome:#?}");
    assert_eq!(outcome.coverage, "exhaustive");

    let first = execute(&analyzer, &query("receiver_evidence"));
    let second = execute(&analyzer, &query("receiver_evidence"));
    let rows = |result: &CodeQueryResult| {
        result
            .results
            .iter()
            .map(|item| match &item.value {
                CodeQueryResultValue::ReceiverEvidence { value } => {
                    (value.id.clone(), value.evidence_kind, value.ordinal)
                }
                _ => panic!("expected receiver evidence"),
            })
            .collect::<Vec<_>>()
    };
    let first_rows = rows(&first);
    assert!(!first_rows.is_empty(), "{}", first.render_text());
    assert_eq!(first_rows, rows(&second), "alias evidence must be stable");
    assert!(
        first.results.iter().any(
            |item| matches!(&item.value, CodeQueryResultValue::ReceiverEvidence { value }
                if value.evidence_kind == "allocation_site"
                    && value.declaration_fq_name.as_deref() == Some("Service"))
        ),
        "the alias resolves to the allocation of Service: {}",
        first.render_text()
    );
}

/// A receiver that may hold either of two allocation types keeps both
/// candidates visible: the outcome row is ambiguous with open coverage, and
/// each candidate type has its own evidence row.
#[test]
fn ambiguous_receiver_keeps_both_types_as_open_evidence() {
    let source = r#"class ServiceA { run() {} }
class ServiceB { run() {} }
export function caller(flag: boolean) {
  const service = flag ? new ServiceA() : new ServiceB();
  service.run();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal| {
        CodeQuery::from_json(&json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [
                { "op": "points_to", "capture": "receiver" },
                { "op": terminal }
            ],
            "result_detail": "full"
        }))
        .expect("ambiguous receiver query")
    };

    let outcome = execute(&analyzer, &query("receiver_outcome"));
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcome.results[0].value else {
        panic!("expected receiver outcome, got {}", outcome.render_text())
    };
    assert_eq!(outcome.outcome, "ambiguous", "{outcome:#?}");
    assert_eq!(
        outcome.coverage, "open",
        "an ambiguous receiver is never an exhaustive single answer: {outcome:#?}"
    );

    let evidence = execute(&analyzer, &query("receiver_evidence"));
    let types = evidence
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::ReceiverEvidence { value } => value.declaration_fq_name.clone(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        types.iter().any(|fq_name| fq_name == "ServiceA")
            && types.iter().any(|fq_name| fq_name == "ServiceB"),
        "both candidate types stay visible as evidence rows: {}",
        evidence.render_text()
    );
    assert_eq!(
        outcome.candidate_count,
        evidence.results.len(),
        "the outcome row accounts for exactly the emitted evidence rows"
    );
}

/// Every reference occurrence projects exactly one member-selection summary
/// row from the production resolver's candidate trace, and the summary's
/// selected set agrees with the ordinary get-definition answer.
#[test]
fn member_selection_summary_projects_the_production_trace() {
    let source = r#"class Service { run() {} }
class Other { run() {} }
export function caller(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "where": ["app.ts"],
        "occurrences": { "role": ["member_position"] },
        "steps": [{ "op": "member_selection" }],
        "result_detail": "full"
    }))
    .expect("member selection query");

    let first = execute(&analyzer, &query);
    let second = execute(&analyzer, &query);
    assert_eq!(first.results.len(), 1, "{}", first.render_text());
    let CodeQueryResultValue::MemberSelection { value: row } = &first.results[0].value else {
        panic!("expected member selection, got {}", first.render_text())
    };
    assert_eq!(row.member, "run");
    assert_eq!(row.outcome, "selected", "{row:#?}");
    assert!(row.selected_count >= 1);
    assert!(row.candidate_count >= row.selected_count);
    assert!(!row.site_ast_id.is_empty());
    assert!(matches!(row.trace_completeness, "full" | "selection_only"));
    match row.trace_completeness {
        "full" => assert_eq!(row.coverage, "exhaustive"),
        _ => assert_eq!(row.coverage, "open"),
    }
    let CodeQueryResultValue::MemberSelection { value: again } = &second.results[0].value else {
        panic!("expected member selection")
    };
    assert_eq!(again.id, row.id, "the summary row identity is stable");

    // The summary joins to the candidate rows it summarizes by AST identity.
    let candidates = execute(
        &analyzer,
        &CodeQuery::from_json(&json!({
            "where": ["app.ts"],
            "occurrences": { "role": ["member_position"] },
            "steps": [{ "op": "candidates_of" }],
            "result_detail": "full"
        }))
        .expect("candidate query"),
    );
    let candidate_rows = candidates
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::ResolutionCandidate { value } => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(candidate_rows.len(), row.candidate_count, "{candidates:#?}");
    assert!(
        candidate_rows
            .iter()
            .all(|candidate| candidate.ast_id == row.site_ast_id),
        "candidate rows join the summary by ast identity"
    );
}

/// An unresolvable receiver still emits its mandatory outcome row. The row
/// states `unknown` with unknown coverage and zero evidence rows, so an empty
/// evidence relation can never masquerade as a proven-empty value set.
#[test]
fn unknown_receiver_reports_one_outcome_row_with_no_evidence() {
    let source = r#"export function caller(service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal| {
        CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [
                { "op": "receiver_targets" },
                { "op": terminal }
            ],
            "result_detail": "full"
        }))
        .expect("unknown receiver query")
    };

    let outcome = execute(&analyzer, &query("receiver_outcome"));
    assert_eq!(outcome.results.len(), 1, "{}", outcome.render_text());
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcome.results[0].value else {
        panic!("expected receiver outcome, got {}", outcome.render_text())
    };
    assert_eq!(outcome.outcome, "unknown", "{outcome:#?}");
    assert_eq!(outcome.coverage, "unknown");
    assert_eq!(outcome.candidate_count, 0);
    assert!(outcome.site_ast_id.is_some());

    let evidence = execute(&analyzer, &query("receiver_evidence"));
    assert!(
        evidence.results.is_empty(),
        "an unknown site has an outcome row and zero evidence rows: {}",
        evidence.render_text()
    );
}

/// A dynamic receiver has no analyzable value set. The mandatory outcome row
/// states `unsupported` explicitly and no evidence row exists, so absence can
/// never be read as a proven-empty set.
#[test]
fn dynamic_receiver_reports_an_unsupported_outcome_row_with_no_evidence() {
    let source = r#"
namespace Demo;
public class Caller {
    public void Call(dynamic opaque) { opaque.Run(); }
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "Caller.cs")
        .write(source)
        .expect("write source");
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
    let query = |terminal| {
        CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "Run" } },
            "steps": [
                { "op": "receiver_targets" },
                { "op": terminal }
            ],
            "result_detail": "full"
        }))
        .expect("dynamic receiver query")
    };

    let outcome = execute_workspace(&workspace, &query("receiver_outcome"));
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcome.results[0].value else {
        panic!("expected receiver outcome, got {}", outcome.render_text())
    };
    assert_eq!(outcome.outcome, "unsupported", "{outcome:#?}");
    assert_eq!(outcome.coverage, "unsupported");
    assert_eq!(outcome.candidate_count, 0);
    assert_eq!(outcome.reason, Some("csharp_dynamic_receiver_unsupported"));

    let evidence = execute_workspace(&workspace, &query("receiver_evidence"));
    assert!(
        evidence.results.is_empty(),
        "an unsupported site has an outcome row and zero evidence rows: {}",
        evidence.render_text()
    );
}

#[test]
fn csharp_cross_file_receiver_step_reuses_bounded_reference_facts() {
    let definitions = r#"
namespace Demo;
public class Service {
    public void Run() {}
}
"#;
    let usage = r#"
namespace Demo;
public class Caller {
    public void Call(Service service) { service.Run(); }
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "Definitions.cs")
        .write(definitions)
        .expect("write definitions");
    ProjectFile::new(root.clone(), "Usage.cs")
        .write(usage)
        .expect("write usage");
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
    let query = CodeQuery::from_json(&json!({
        "where": ["Definitions.cs"],
        "match": { "kind": "method", "name": "Run" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of", "proof": "proven" },
            { "op": "member_targets" }
        ]
    }))
    .expect("cross-file receiver query");
    let provider = workspace
        .analyzer()
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::CSharp)
        .expect("C# structural provider");
    let extractions_before = provider.structural_extraction_count();

    let result = execute_workspace(&workspace, &query);

    assert_eq!(
        provider.structural_extraction_count(),
        extractions_before + 2,
        "the seed and reference traversal each extract their own file; receiver analysis must not perform a third extraction"
    );
    assert!(
        matches!(
            result.results.as_slice(),
            [CodeQueryResultItem {
                value: CodeQueryResultValue::ReceiverAnalysis { value },
                ..
            }] if value.outcome == "precise"
                && matches!(
                    value.member_targets.as_slice(),
                    [target] if target.fq_name == "Demo.Service.Run"
                )
        ),
        "{}",
        result.render_text()
    );
}

#[test]
fn cancelled_composed_query_retains_no_partial_rows() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write("function alpha() {}\nfunction beta() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function", "name": "alpha" } },
            { "match": { "kind": "function", "name": "beta" } }
        ]
    }))
    .expect("query");
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let result = execute_with_cancellation(
        &analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    );

    assert!(result.results.is_empty());
    assert!(result.truncated);
    assert_eq!(result.diagnostics.len(), 1);
    assert!(result.diagnostics[0].branch.is_empty());
    assert!(result.diagnostics[0].message.contains("cancelled"));
}

#[test]
fn cancellation_after_positive_rows_retains_aligned_partial_evidence() {
    let source = r#"export function caller() {
alpha();
beta();
gamma();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "result_detail": "full"
    }))
    .expect("query");

    let detailed = (2..64)
        .find_map(|checks| {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let detailed = execute_code_query_detailed(
                &analyzer,
                &query,
                CodeQueryExecutionLimits::default(),
                Some(&cancellation),
            );
            (detailed
                .result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
                && detailed.work.pipeline_rows >= 3
                && !detailed.result.results.is_empty()
                && detailed.result.results.len() < 3)
                .then_some(detailed)
        })
        .expect("a deterministic cancellation checkpoint during detailed row rendering");

    assert!(detailed.result.truncated);
    assert!(detailed.result.results.len() < 3);
    assert_eq!(detailed.result.results.len(), detailed.evidence.len());
    assert!(
        detailed
            .evidence
            .iter()
            .enumerate()
            .all(|(index, evidence)| evidence.result_index == index
                && evidence.source_slice_sha256.is_some())
    );
    assert!(detailed.work.pipeline_rows >= detailed.evidence.len() as u64);
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
}

#[test]
fn canonical_ast_keys_stay_within_the_stable_identity_limit() {
    let shallow = vec![("module", None), ("function", Some("run"))];
    let key = bounded_canonical_ast_key(&shallow).expect("shallow key");
    assert_eq!(key, serde_json::to_string(&shallow).expect("json"));

    // A chain deep enough to overflow 256 bytes verbatim (closures in
    // closures) must still produce a valid bounded key that keeps the
    // outermost and innermost context and stays deterministic.
    let deep: Vec<(&str, Option<&str>)> = (0..40)
        .map(|depth| {
            if depth % 2 == 0 {
                ("call", Some("unwrap_or_else_with_a_long_name"))
            } else {
                ("lambda", None)
            }
        })
        .collect();
    let key = bounded_canonical_ast_key(&deep).expect("bounded key");
    assert!(key.len() <= 256, "key must fit the identity limit: {key}");
    let segments: Vec<(String, Option<String>)> =
        serde_json::from_str(&key).expect("bounded key stays canonical JSON");
    assert!(
        segments.iter().any(|(kind, name)| kind == "elided"
            && name.as_deref().is_some_and(|name| name.starts_with('h'))),
        "long chains elide their middle: {key}"
    );
    assert_eq!(
        segments.first().map(|(kind, _)| kind.as_str()),
        Some("call")
    );
    assert_eq!(
        segments.last().map(|(kind, _)| kind.as_str()),
        Some("lambda")
    );
    assert_eq!(
        bounded_canonical_ast_key(&deep).expect("deterministic"),
        key
    );

    // Distinct chains must keep distinct keys even when both are elided.
    let mut other = deep.clone();
    other[20] = ("call", Some("a_different_middle_segment"));
    assert_ne!(bounded_canonical_ast_key(&other).expect("other key"), key);
}

#[test]
fn detailed_row_field_registry_covers_every_domain_without_duplicate_fields() {
    let mut labels = std::collections::HashSet::new();
    for domain in ALL_DETAILED_CODE_QUERY_DOMAINS {
        assert!(labels.insert(domain.label()), "duplicate domain label");
        assert!(
            !domain.row_fields().is_empty(),
            "{} must declare an addressable scalar surface",
            domain.label()
        );
        let mut field_names = std::collections::HashSet::new();
        for field in domain.row_fields() {
            assert!(
                field_names.insert(field.name),
                "duplicate field {}.{}",
                domain.label(),
                field.name
            );
        }
    }
}

#[test]
fn occurrence_row_projection_exposes_typed_identity_and_rejects_unknown_fields() {
    let target = CodeQueryDeclaration {
        path: "src/lib.rs".to_string(),
        language: "rust",
        kind: "function",
        fq_name: "crate::target".to_string(),
        start_line: 1,
        end_line: 1,
        signature: None,
        id: Some("decl-1".to_string()),
        node_range: None,
        semantic_model: None,
    };
    let result = CodeQueryResultValue::Occurrence {
        value: Box::new(CodeQueryOccurrence {
            id: "occurrence-1".to_string(),
            ast_id: "ast-1".to_string(),
            path: "src/lib.rs".to_string(),
            language: "rust",
            class: "reference",
            role: "call_callee",
            namespace: "value",
            range: CodeQueryRange {
                start_line: 2,
                start_column: 5,
                end_line: 2,
                end_column: 11,
            },
            start_byte: 20,
            end_byte: 26,
            enclosing_symbol: Some("crate::caller".to_string()),
            raw_spelling: "target".to_string(),
            decoded_spelling: None,
            target: CodeQueryOccurrenceTarget::Resolved {
                units: vec![target],
            },
        }),
    };
    let row = result.row();

    assert_eq!(row.domain(), DetailedCodeQueryDomain::Occurrence);
    assert_eq!(
        row.field("ast_id").expect("registered field"),
        Some(CodeQueryRowScalarRef::StableId("ast-1"))
    );
    assert_eq!(
        row.field("target_id").expect("registered field"),
        Some(CodeQueryRowScalarRef::DeclarationIdentity("decl-1"))
    );
    assert_eq!(
        row.field("target_count").expect("registered field"),
        Some(CodeQueryRowScalarRef::Integer(1))
    );

    let error = row.field("range").expect_err("ranges are not join keys");
    assert_eq!(error.domain(), DetailedCodeQueryDomain::Occurrence);
    assert_eq!(error.field(), "range");
}

#[test]
fn occurrence_row_projection_does_not_invent_one_identity_for_ambiguous_targets() {
    let declaration = |id: &str| CodeQueryDeclaration {
        path: "src/lib.rs".to_string(),
        language: "rust",
        kind: "function",
        fq_name: format!("crate::{id}"),
        start_line: 1,
        end_line: 1,
        signature: None,
        id: Some(id.to_string()),
        node_range: None,
        semantic_model: None,
    };
    let result = CodeQueryResultValue::Occurrence {
        value: Box::new(CodeQueryOccurrence {
            id: "occurrence-ambiguous".to_string(),
            ast_id: "ast-ambiguous".to_string(),
            path: "src/lib.rs".to_string(),
            language: "rust",
            class: "reference",
            role: "call_callee",
            namespace: "value",
            range: CodeQueryRange {
                start_line: 2,
                start_column: 5,
                end_line: 2,
                end_column: 11,
            },
            start_byte: 20,
            end_byte: 26,
            enclosing_symbol: None,
            raw_spelling: "target".to_string(),
            decoded_spelling: None,
            target: CodeQueryOccurrenceTarget::Resolved {
                units: vec![declaration("decl-1"), declaration("decl-2")],
            },
        }),
    };
    let row = result.row();

    assert_eq!(row.field("target_id").expect("registered field"), None);
    assert_eq!(
        row.field("target_count").expect("registered field"),
        Some(CodeQueryRowScalarRef::Integer(2))
    );
}
