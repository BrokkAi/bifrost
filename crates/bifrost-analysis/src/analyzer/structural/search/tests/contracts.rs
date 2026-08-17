use super::*;

fn diagnostic(
    code: CodeQueryDiagnosticCode,
    impact: CodeQueryDiagnosticImpact,
) -> CodeQueryDiagnostic {
    CodeQueryDiagnostic {
        code,
        impact,
        branch: Vec::new(),
        language: "workspace",
        message: "prose deliberately carries no classification words".to_string(),
    }
}

#[test]
fn execution_work_snapshot_is_the_single_budget_projection() {
    let snapshot = execution_work_snapshot(
        CodeQueryExecutionBudget {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            examined_references: 4,
            pipeline_rows: 5,
            provenance_steps: 6,
            import_files_resolved: 7,
            import_edges_resolved: 8,
        },
        CodeQuerySemanticWork::default(),
    );
    assert_eq!(
        snapshot,
        QueryOperatorWorkProfile {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            pipeline_rows: 5,
            examined_references: 4,
            provenance_steps: 6,
            import_files_resolved: 7,
            import_edges_resolved: 8,
            semantic: CodeQuerySemanticWork::default(),
        }
    );
    assert_eq!(
        public_execution_work(snapshot),
        CodeQueryExecutionWork {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            pipeline_rows: 5,
            examined_references: 4,
            semantic: CodeQuerySemanticWork::default(),
        }
    );
}

#[test]
fn semantic_execution_limits_require_each_dimension_to_be_positive() {
    let defaults = CodeQuerySemanticLimits::default();
    assert!(defaults.all_positive());

    for invalid in [
        CodeQuerySemanticLimits {
            max_materialized_files: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_source_bytes: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_rows_per_dimension: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_retained_bytes: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_traversal_steps: 0,
            ..defaults
        },
    ] {
        assert!(!invalid.all_positive());
    }
}

pub(super) fn assert_serial_profile_reconciles(profile: &QueryExecutionProfile) {
    assert_eq!(profile.format, "bifrost_code_query_execution_profile/v4");
    assert_eq!(profile.peak_concurrency, 1);
    assert_eq!(profile.scheduler.tasks_enqueued, 0);
    assert_eq!(profile.scheduler.peak_concurrency, 0);
    assert!(
        profile
            .planning_ns
            .saturating_add(profile.execution_ns)
            .saturating_add(profile.rendering_ns)
            <= profile.total_elapsed_ns,
        "named request phases must fit inside total request wall time"
    );
    for observation in &profile.operators {
        assert_eq!(
            observation.total_elapsed_ns,
            observation
                .elapsed_ns
                .saturating_add(observation.dependency_execution_ns),
            "operator self and inline dependency execution must reconcile"
        );
        assert_eq!(observation.dependency_wait_ns, 0);
        assert_eq!(observation.scheduling_overhead_ns, 0);
        assert!(observation.merge_ns <= observation.elapsed_ns);
    }
    let operator_work = profile
        .operators
        .iter()
        .fold(QueryOperatorWorkProfile::default(), |work, observation| {
            work.saturating_add(observation.work)
        });
    assert_eq!(operator_work, profile.execution_work);
    assert_eq!(
        profile
            .execution_work
            .saturating_add(profile.rendering_work),
        profile.work
    );
}

#[test]
fn public_explain_is_planning_only_and_exposes_shared_logical_dependencies() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "src/app.ts");
    file.write("class Shared {}\n").expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query =
        CodeQuery::from_sexp("(explain (union (class :name \"Shared\") (class :name \"Shared\")))")
            .expect("explain query");
    let providers = analyzer.structural_search_providers();
    let extractions_before = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();

    let CodeQueryResponse::Explain(explain) = execute_request(&analyzer, &query) else {
        panic!("explain mode must return a planning report")
    };

    let extractions_after = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();
    assert_eq!(extractions_after, extractions_before);
    assert_eq!(explain.scheduling.max_concurrency, 1);
    assert!(matches!(
        explain.scheduling.selected,
        super::super::super::execution::plan::CodeQuerySelectedScheduling::Sequential
    ));
    let shared_set = explain
        .logical_plan
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.operation,
                super::super::super::execution::plan::CodeQueryLogicalOperation::Set { .. }
            )
        })
        .expect("logical set node");
    assert_eq!(shared_set.dependencies.len(), 2);
    assert_eq!(shared_set.dependencies[0], shared_set.dependencies[1]);
}

#[test]
fn public_profile_nests_the_exact_ordered_ordinary_result() {
    let source = "class First {}\nclass Second {}\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/app.ts")
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut query =
        CodeQuery::from_json(&json!({ "match": { "kind": "class" } })).expect("results query");
    let CodeQueryResponse::Results(ordinary) = execute_request(&analyzer, &query) else {
        panic!("default mode must return ordinary results")
    };
    let ordinary_json = serde_json::to_value(&ordinary).expect("serialize ordinary result");
    assert_eq!(
        serde_json::to_value(CodeQueryResponse::Results(ordinary))
            .expect("serialize ordinary response"),
        ordinary_json,
        "default response must not add an enum envelope"
    );

    query.execution_mode = CodeQueryExecutionMode::Profile;
    let expected_explain = select_physical_plan(
        &query,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
    )
    .expect("profile query should select a plan")
    .public_explain(&query, CODE_QUERY_SCHEDULER_WORKERS);
    let CodeQueryResponse::Profile(profile) = execute_request(&analyzer, &query) else {
        panic!("profile mode must return a profile")
    };

    assert_eq!(profile.explain, expected_explain);
    assert_eq!(
        serde_json::to_value(&profile.result).expect("serialize profiled result"),
        ordinary_json
    );
    assert_eq!(profile.format, CodeQueryProfile::FORMAT);
    assert!(!profile.operators.is_empty());
    assert_eq!(profile.scheduling.peak_concurrency, 1);
    assert!(profile.scheduling.bounded_dispatch.is_none());
}

#[test]
fn response_parts_preserve_each_public_wire_shape() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/app.ts")
        .write("class Example {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut query = CodeQuery::from_json(&json!({ "match": { "kind": "class" } })).expect("query");

    for mode in [
        CodeQueryExecutionMode::Results,
        CodeQueryExecutionMode::Explain,
        CodeQueryExecutionMode::Profile,
    ] {
        query.execution_mode = mode;
        let response = execute_request(&analyzer, &query);
        let serialized = serde_json::to_value(&response).expect("serialize response");
        let pretty_report = response.render_report_pretty();
        let (actual_mode, result, report) = response.into_parts();
        assert_eq!(actual_mode, mode);
        match mode {
            CodeQueryExecutionMode::Results => {
                assert_eq!(
                    serde_json::to_value(result.expect("ordinary result"))
                        .expect("serialize ordinary result"),
                    serialized
                );
                assert!(report.is_none());
                assert!(pretty_report.is_none());
            }
            CodeQueryExecutionMode::Explain => {
                assert!(result.is_none());
                assert_eq!(report.expect("explain report"), serialized);
                assert!(
                    pretty_report
                        .expect("pretty explain report")
                        .starts_with("{\n  \"format\":")
                );
            }
            CodeQueryExecutionMode::Profile => {
                assert_eq!(
                    serde_json::to_value(result.expect("profiled result"))
                        .expect("serialize profiled result"),
                    serialized["result"]
                );
                assert_eq!(report.expect("profile report"), serialized);
                assert!(
                    pretty_report
                        .expect("pretty profile report")
                        .starts_with("{\n  \"format\":")
                );
            }
        }
    }
}

#[test]
fn shared_provenance_and_diagnostic_presentation_preserves_order_and_deduplicates() {
    let item = CodeQueryResultItem {
        value: CodeQueryResultValue::File {
            value: CodeQueryFile {
                package_fq: None,
                package_syntactic: None,
                path: "src/app.ts".to_string(),
                language: "typescript",
            },
        },
        provenance: vec![
            CodeQueryProvenance {
                branch: vec![1, 0],
                seed: CodeQueryResultRef::File {
                    path: "src/app.ts".to_string(),
                },
                steps: Vec::new(),
            },
            CodeQueryProvenance {
                branch: vec![1, 0],
                seed: CodeQueryResultRef::File {
                    path: "src/app.ts".to_string(),
                },
                steps: Vec::new(),
            },
            CodeQueryProvenance {
                branch: vec![0],
                seed: CodeQueryResultRef::File {
                    path: "src/app.ts".to_string(),
                },
                steps: Vec::new(),
            },
        ],
        provenance_truncated: true,
    };
    assert_eq!(
        item.provenance_summary().as_deref(),
        Some("provenance: 3 paths (truncated); branches 1.0, 0")
    );
    let diagnostic = CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: vec![1, 0],
        language: "typescript",
        message: "broad query".to_string(),
    };
    assert_eq!(
        diagnostic.presentation_label(),
        "advisory [broad_query] [branch 1.0]"
    );

    let rendered = CodeQueryResult {
        results: vec![item],
        truncated: false,
        diagnostics: vec![diagnostic],
    }
    .render_text();
    assert!(rendered.contains("  provenance: 3 paths (truncated); branches 1.0, 0\n"));
    assert!(rendered.contains("advisory [broad_query] [branch 1.0]: broad query\n"));
}

#[test]
fn semantic_result_contracts_serialize_render_and_retain_source_evidence() {
    let procedure_id = "11".repeat(32);
    let point_id = "22".repeat(32);
    let edge_id = "33".repeat(32);
    let target_id = "44".repeat(32);
    let path = "src/app.ts";
    let procedure_range = CodeQueryRange {
        start_line: 1,
        start_column: 1,
        end_line: 4,
        end_column: 2,
    };
    let point_range = CodeQueryRange {
        start_line: 2,
        start_column: 3,
        end_line: 2,
        end_column: 14,
    };
    let target_range = CodeQueryRange {
        start_line: 3,
        start_column: 3,
        end_line: 3,
        end_column: 10,
    };
    let complete = CodeQuerySemanticEvidence {
        proof: CodeQuerySemanticProof::Proven,
        proof_reason: None,
        completeness: CodeQuerySemanticCompleteness::Complete,
        completeness_reason: None,
    };
    let partial = CodeQuerySemanticEvidence {
        proof: CodeQuerySemanticProof::Unproven,
        proof_reason: Some("ambiguous enclosing procedure".to_string()),
        completeness: CodeQuerySemanticCompleteness::Partial,
        completeness_reason: Some("exceptional control flow is unsupported".to_string()),
    };
    let point_ref = CodeQueryProgramPointRef {
        id: point_id.clone(),
        procedure_id: procedure_id.clone(),
        path: path.to_string(),
        range: point_range,
        boundary: Some(CodeQueryProgramPointBoundary::Entry),
    };
    let target_ref = CodeQueryProgramPointRef {
        id: target_id.clone(),
        procedure_id: procedure_id.clone(),
        path: path.to_string(),
        range: target_range,
        boundary: None,
    };
    let result = CodeQueryResult {
        results: vec![
            CodeQueryResultItem {
                value: CodeQueryResultValue::Procedure {
                    value: CodeQueryProcedure {
                        id: procedure_id.clone(),
                        artifact_id: "aa".repeat(32),
                        path: path.to_string(),
                        language: "typescript",
                        procedure_kind: "function",
                        range: procedure_range,
                        evidence: complete.clone(),
                    },
                },
                provenance: Vec::new(),
                provenance_truncated: false,
            },
            CodeQueryResultItem {
                value: CodeQueryResultValue::ProgramPoint {
                    value: CodeQueryProgramPoint {
                        id: point_id.clone(),
                        procedure_id: procedure_id.clone(),
                        path: path.to_string(),
                        language: "typescript",
                        range: point_range,
                        boundary: Some(CodeQueryProgramPointBoundary::Entry),
                        event_count: 1,
                        evidence: partial.clone(),
                    },
                },
                provenance: Vec::new(),
                provenance_truncated: false,
            },
            CodeQueryResultItem {
                value: CodeQueryResultValue::ControlEdge {
                    value: Box::new(CodeQueryControlEdge {
                        id: edge_id.clone(),
                        procedure_id: procedure_id.clone(),
                        path: path.to_string(),
                        language: "typescript",
                        range: point_range,
                        edge_kind: "conditional_true",
                        source: point_ref,
                        target: target_ref,
                        evidence: complete,
                    }),
                },
                provenance: Vec::new(),
                provenance_truncated: false,
            },
        ],
        truncated: false,
        diagnostics: Vec::new(),
    };

    let serialized = serde_json::to_value(&result).expect("semantic results serialize");
    assert_eq!(serialized["results"][0]["result_type"], "procedure");
    assert_eq!(serialized["results"][1]["result_type"], "program_point");
    assert_eq!(serialized["results"][1]["boundary"], "entry");
    assert_eq!(serialized["results"][1]["evidence"]["proof"], "unproven");
    assert_eq!(
        serialized["results"][1]["evidence"]["completeness"],
        "partial"
    );
    assert_eq!(serialized["results"][2]["result_type"], "control_edge");
    assert_eq!(serialized["results"][2]["edge_kind"], "conditional_true");
    assert_eq!(serialized["results"][2]["source"]["id"], point_id);
    assert_eq!(serialized["results"][2]["target"]["id"], target_id);
    assert!(!serialized.to_string().contains("program_point_id"));
    assert!(!serialized.to_string().contains("control_edge_id"));

    let rendered = result.render_text();
    assert!(rendered.contains("[procedure; function; proven/complete]"));
    assert!(rendered.contains("[program point; entry; unproven/partial; 1 event]"));
    assert!(rendered.contains("[control edge; conditional_true; proven/complete]"));

    for reference in [
        CodeQueryResultRef::Procedure {
            id: procedure_id.clone(),
            path: path.to_string(),
            procedure_kind: "function",
            range: procedure_range,
        },
        CodeQueryResultRef::ProgramPoint {
            id: point_id.clone(),
            procedure_id: procedure_id.clone(),
            path: path.to_string(),
            range: point_range,
            boundary: Some(CodeQueryProgramPointBoundary::Entry),
        },
        CodeQueryResultRef::ControlEdge {
            id: edge_id.clone(),
            procedure_id: procedure_id.clone(),
            path: path.to_string(),
            range: point_range,
            edge_kind: "conditional_true",
            source_id: point_id.clone(),
            target_id: target_id.clone(),
        },
    ] {
        let serialized = serde_json::to_value(reference).expect("semantic reference serializes");
        assert!(serialized["id"].as_str().is_some());
        assert_eq!(serialized["path"], path);
        assert!(serialized["range"].is_object());
    }

    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root, path);
    let evidence_for = |index, domain, key: DetailedCodeQueryKey, id: &str| {
        let candidate = CodeQueryStableOwnerCandidate {
            namespace: "typescript".to_string(),
            derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
            semantic_key: id.to_string(),
        };
        DetailedCodeQueryEvidence {
            result_index: index,
            domain,
            key,
            file: file.clone(),
            byte_span: Some(0..1),
            stable_owner_candidate: Some(candidate.clone()),
            identities: DetailedCodeQueryProvenanceIdentities::Primary(Some(
                DetailedCodeQueryIdentityCandidate {
                    file: file.clone(),
                    candidate,
                },
            )),
            source_slice_sha256: Some([u8::try_from(index).unwrap(); 32]),
            provenance: Vec::new(),
        }
    };
    let detailed = DetailedCodeQueryResult {
        result,
        work: CodeQueryExecutionWork {
            pipeline_rows: 3,
            ..CodeQueryExecutionWork::default()
        },
        evidence: vec![
            evidence_for(
                0,
                DetailedCodeQueryDomain::Procedure,
                DetailedCodeQueryKey::Procedure {
                    id: procedure_id.clone(),
                },
                &procedure_id,
            ),
            evidence_for(
                1,
                DetailedCodeQueryDomain::ProgramPoint,
                DetailedCodeQueryKey::ProgramPoint {
                    id: point_id.clone(),
                    procedure_id: procedure_id.clone(),
                },
                &point_id,
            ),
            evidence_for(
                2,
                DetailedCodeQueryDomain::ControlEdge,
                DetailedCodeQueryKey::ControlEdge {
                    id: edge_id.clone(),
                    procedure_id,
                },
                &edge_id,
            ),
        ],
        profile: None,
    };
    detailed.assert_invariants();
}

#[test]
fn public_profile_retains_pre_execution_cancellation_observations() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/app.ts")
        .write("class Cancelled {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "class" }
    }))
    .expect("profile query");
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let CodeQueryResponse::Profile(profile) = execute_request_with_cancellation(
        &analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    ) else {
        panic!("pre-cancelled profile should retain its report")
    };

    assert_eq!(profile.result.completion(), CodeQueryCompletion::Cancelled);
    assert!(profile.operators.iter().any(|operator| {
        operator.result_cancelled
            || matches!(
                operator.disposition,
                super::super::super::execution::profile::CodeQueryOperatorDisposition::Cancelled
            )
    }));
}

#[test]
fn diagnostic_codes_have_exhaustive_stable_impacts_and_completion() {
    use CodeQueryDiagnosticCode as Code;
    use CodeQueryDiagnosticImpact as Impact;

    let cases = [
        (Code::InvalidPlan, Impact::Invalid),
        (Code::Cancelled, Impact::Incomplete),
        (Code::UnsupportedStructuralFeature, Impact::Incomplete),
        (Code::MissingStructuralAdapter, Impact::Incomplete),
        (Code::UnsupportedImportAnalysis, Impact::Incomplete),
        (Code::SemanticResultsOmitted, Impact::Incomplete),
        (Code::SemanticWorkspaceRequired, Impact::Incomplete),
        (Code::NoEnclosingProcedure, Impact::Advisory),
        (Code::SemanticCapabilityUnsupported, Impact::Incomplete),
        (Code::SemanticAnalysisPartial, Impact::Incomplete),
        (Code::SemanticBudgetExhausted, Impact::Incomplete),
        (Code::SemanticProviderFailed, Impact::Incomplete),
        (Code::ReceiverAnalysisPartial, Impact::Incomplete),
        (Code::ReceiverAnalysisFailed, Impact::Incomplete),
        (Code::CallRelationBudgetExhausted, Impact::Incomplete),
        (Code::CallRelationParseFailed, Impact::Incomplete),
        (Code::CallRelationCandidatesOmitted, Impact::Incomplete),
        (Code::CallRelationTargetsAmbiguous, Impact::Advisory),
        (Code::CallRelationCandidateLimit, Impact::Incomplete),
        (Code::CallRelationAnalysisFailed, Impact::Incomplete),
        (Code::ReferenceSourceBytesTruncated, Impact::Incomplete),
        (Code::ReferenceCandidateFilesTruncated, Impact::Incomplete),
        (Code::ReferenceCandidatesOmitted, Impact::Incomplete),
        (Code::ReferenceTargetsAmbiguous, Impact::Advisory),
        (Code::ReferenceCallsiteLimit, Impact::Incomplete),
        (Code::ReferenceAnalysisFailed, Impact::Incomplete),
        (Code::UsesParserUnsupported, Impact::Incomplete),
        (Code::UsesCandidateLimit, Impact::Incomplete),
        (Code::UsesTargetsAmbiguous, Impact::Advisory),
        (Code::UsesCandidatesOmitted, Impact::Incomplete),
        (Code::ExecutionBudgetExhausted, Impact::Incomplete),
        (Code::PipelineBudgetExhausted, Impact::Incomplete),
        (Code::ImportGraphBudgetExhausted, Impact::Incomplete),
        (Code::ResultLimitReached, Impact::Incomplete),
        (Code::BroadQuery, Impact::Advisory),
    ];

    for (code, impact) in cases {
        let result = CodeQueryResult {
            results: Vec::new(),
            truncated: false,
            diagnostics: vec![diagnostic(code, impact)],
        };
        let serialized = serde_json::to_value(&result).expect("serialize query result");
        assert_eq!(serialized["diagnostics"][0]["code"], code.as_str());
        assert_eq!(serialized["diagnostics"][0]["impact"], impact.as_str());
        assert!(
            result
                .render_text()
                .contains(&format!("{} [{}]", impact.as_str(), code.as_str())),
            "code {code:?} did not retain its typed label in text output"
        );
        let expected = match (code, impact) {
            (Code::InvalidPlan, _) => CodeQueryCompletion::Invalid {
                codes: vec![Code::InvalidPlan],
            },
            (Code::Cancelled, _) => CodeQueryCompletion::Cancelled,
            (_, Impact::DeclaredNonExhaustive) => {
                CodeQueryCompletion::ProvenSubset { codes: vec![code] }
            }
            (_, Impact::Incomplete) => CodeQueryCompletion::Incomplete { codes: vec![code] },
            (_, Impact::Advisory) => CodeQueryCompletion::Complete,
            (_, Impact::Invalid) => unreachable!("only InvalidPlan is invalid"),
        };
        assert_eq!(result.completion(), expected, "code {code:?}");
    }

    assert_eq!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: true,
            diagnostics: Vec::new(),
        }
        .completion(),
        CodeQueryCompletion::Incomplete { codes: Vec::new() }
    );
}

#[test]
fn typed_diagnostic_producers_cover_budget_output_and_cancellation() {
    let mut diagnostics = Vec::new();
    let budget = CodeQueryExecutionBudget::default();
    push_budget_diagnostic(&mut diagnostics, &budget);
    push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
    push_import_graph_budget_diagnostic(
        &mut diagnostics,
        &RequestLocalDirectImportGraph::default(),
    );
    push_truncation_diagnostic(&mut diagnostics, &budget, 1);
    push_broad_query_diagnostic(&mut diagnostics, &budget);

    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.impact))
            .collect::<Vec<_>>(),
        vec![
            (
                CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::PipelineBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::ResultLimitReached,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::BroadQuery,
                CodeQueryDiagnosticImpact::Advisory,
            ),
        ]
    );
    assert!(matches!(
        cancelled_query_result().completion(),
        CodeQueryCompletion::Cancelled
    ));
}

#[test]
fn call_relation_diagnostics_map_without_inspecting_messages() {
    use CallRelationDiagnosticCode as Lower;
    use CodeQueryDiagnosticCode as Code;
    use CodeQueryDiagnosticImpact as Impact;

    let cases = [
        (
            Lower::BudgetExhausted,
            Code::CallRelationBudgetExhausted,
            Impact::Incomplete,
        ),
        (
            Lower::ParseFailed,
            Code::CallRelationParseFailed,
            Impact::Incomplete,
        ),
        (
            Lower::CandidatesOmitted,
            Code::CallRelationCandidatesOmitted,
            Impact::Incomplete,
        ),
        (
            Lower::TargetsAmbiguous,
            Code::CallRelationTargetsAmbiguous,
            Impact::Advisory,
        ),
        (
            Lower::CandidateLimit,
            Code::CallRelationCandidateLimit,
            Impact::Incomplete,
        ),
        (
            Lower::AnalysisFailed,
            Code::CallRelationAnalysisFailed,
            Impact::Incomplete,
        ),
    ];
    for (lower, code, impact) in cases {
        let mapped = map_call_relation_diagnostic(
            "rust",
            CallRelationDiagnostic {
                code: lower,
                message: "same prose for every producer".to_string(),
                context: "crate::function".to_string(),
                reason_kind: (lower == Lower::AnalysisFailed)
                    .then(|| "unsupported_target_shape".to_string()),
            },
        );
        assert_eq!((mapped.code, mapped.impact), (code, impact));
    }
}

#[test]
fn call_cache_profile_uses_typed_diagnostics_for_completeness() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let unit = CodeUnit::new(
        ProjectFile::new(root, "src/missing.ts"),
        CodeUnitType::Function,
        "",
        "caller",
    );
    let mut cache = CallTraversalCache::default();
    let mut budget = CodeQueryExecutionBudget::default();
    let mut diagnostics = Vec::new();
    let mut profile = Some(QueryCacheProfile::default());

    let built = cached_call_relation(
        &analyzer,
        &unit,
        false,
        &mut cache,
        &mut budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut profile,
    );
    assert!(!built.truncated);
    assert!(!built.cancelled);
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == CallRelationDiagnosticCode::AnalysisFailed })
    );

    let replayed = cached_call_relation(
        &analyzer,
        &unit,
        false,
        &mut cache,
        &mut budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut profile,
    );
    assert_eq!(replayed.sites.len(), built.sites.len());
    assert_eq!(replayed.diagnostics, built.diagnostics);
    assert_eq!(replayed.truncated, built.truncated);
    assert_eq!(replayed.cancelled, built.cancelled);

    cache.incoming.insert(
        unit.clone(),
        CallRelationResult {
            diagnostics: vec![CallRelationDiagnostic {
                code: CallRelationDiagnosticCode::ParseFailed,
                message: "parse failed".to_string(),
                context: "caller".to_string(),
                reason_kind: None,
            }],
            ..CallRelationResult::default()
        },
    );
    let incoming = cached_call_relation(
        &analyzer,
        &unit,
        true,
        &mut cache,
        &mut budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut profile,
    );
    assert!(!incoming.truncated);
    assert!(!incoming.cancelled);

    let profile = profile.expect("cache profile");
    assert_eq!(profile.outgoing_call.lookups, 2);
    assert_eq!(profile.outgoing_call.misses, 1);
    assert_eq!(profile.outgoing_call.builds, 1);
    assert_eq!(profile.outgoing_call.incomplete_builds, 1);
    assert_eq!(profile.outgoing_call.complete_builds, 0);
    assert_eq!(profile.outgoing_call.hits, 1);
    assert_eq!(profile.outgoing_call.incomplete_hits, 1);
    assert_eq!(profile.outgoing_call.complete_hits, 0);
    assert_eq!(profile.incoming_call.lookups, 1);
    assert_eq!(profile.incoming_call.hits, 1);
    assert_eq!(profile.incoming_call.incomplete_hits, 1);
    assert_eq!(profile.incoming_call.complete_hits, 0);

    let advisory = CallRelationResult {
        diagnostics: vec![CallRelationDiagnostic {
            code: CallRelationDiagnosticCode::TargetsAmbiguous,
            message: "ambiguous".to_string(),
            context: "caller".to_string(),
            reason_kind: None,
        }],
        ..CallRelationResult::default()
    };
    assert!(call_relation_result_complete(&advisory));
}

#[test]
fn outbound_uses_missing_reference_or_definitions_is_typed_incomplete() {
    let root = std::env::temp_dir().join("bifrost-outbound-lookup-completeness");
    let file = ProjectFile::new(root, "src/app.ts");
    let definition = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
    let reference = ResolvedReferenceSite {
        path: "src/app.ts".to_string(),
        text: "target".to_string(),
        range: Range {
            start_byte: 10,
            end_byte: 16,
            start_line: 1,
            end_line: 1,
        },
        focus_start_byte: 10,
        focus_end_byte: 16,
    };
    let grouped = group_outbound_lookup_candidates(vec![
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::Ambiguous,
            reference: None,
            definitions: vec![definition],
            lexical_definition: None,
            diagnostics: Vec::new(),
        },
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::Ambiguous,
            reference: Some(reference),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        },
    ]);

    assert_eq!(grouped.omitted_sites, 2);
    assert_eq!(grouped.ambiguous_sites, 2);
    assert!(!grouped.ambiguous_candidates_complete);
    let mut diagnostics = Vec::new();
    append_outbound_lookup_diagnostics(
        &mut diagnostics,
        Language::TypeScript,
        &file,
        grouped.ambiguous_sites,
        grouped.ambiguous_candidates_complete,
        grouped.omitted_sites,
    );
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: false,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { codes }
            if codes == vec![CodeQueryDiagnosticCode::UsesCandidatesOmitted]
    ));
}

#[test]
fn outbound_uses_ambiguity_is_advisory_only_when_every_target_survives() {
    let root = std::env::temp_dir().join("bifrost-outbound-lookup-advisory");
    let file = ProjectFile::new(root, "src/app.ts");
    let mut diagnostics = Vec::new();
    append_outbound_lookup_diagnostics(&mut diagnostics, Language::TypeScript, &file, 1, true, 0);

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesTargetsAmbiguous
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Advisory);
}

#[test]
fn call_declaration_projection_reports_retained_file_scope_target_as_omitted() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let unprojectable = CodeUnit::file_scope(file.clone());
    let range = Range {
        start_byte: 0,
        end_byte: 1,
        start_line: 1,
        end_line: 1,
    };
    let declaration = DeclarationValue {
        unit: caller.clone(),
        range,
    };
    let site = CallSite {
        file,
        range,
        callee_range: range,
        caller: caller.clone(),
        callee: unprojectable,
        kind: CallSyntaxKind::Function,
        proof: UsageProof::Unproven,
        receiver: None,
        arguments: Vec::new(),
    };
    let mut cache = CallTraversalCache::default();
    cache.outgoing.insert(
        caller,
        CallRelationResult {
            sites: vec![site],
            diagnostics: vec![CallRelationDiagnostic {
                code: CallRelationDiagnosticCode::TargetsAmbiguous,
                message: "ambiguous".to_string(),
                context: "caller".to_string(),
                reason_kind: None,
            }],
            ..CallRelationResult::default()
        },
    );
    let mut diagnostics = Vec::new();

    let (expansions, exhausted) = call_declaration_expansions(
        &analyzer,
        &declaration,
        &QueryStep::Callees(CallTraversalFilter::default()),
        &CallTraversalFilter::default(),
        &mut IndexedDeclarations::default(),
        &mut cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        8,
        None,
        &mut diagnostics,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::CallRelationCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
}

#[test]
fn outbound_uses_projection_reports_unindexed_target_and_suppresses_advisory() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let declaration = DeclarationValue {
        unit: caller.clone(),
        range: Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        },
    };
    let mut cache = ReferenceTraversalCache::default();
    cache.outbound.insert(
        file.clone(),
        vec![ReferenceHit {
            file,
            range: declaration.range,
            enclosing_unit: caller,
            kind: None,
            resolved: CodeUnit::file_scope(declaration.unit.source().clone()),
            confidence: 1_000_000,
            usage_kind: UsageHitKind::Reference,
            proof: UsageProof::Unproven,
        }],
    );
    let mut diagnostics = vec![diagnostic(
        CodeQueryDiagnosticCode::UsesTargetsAmbiguous,
        CodeQueryDiagnosticImpact::Advisory,
    )];

    let (expansions, exhausted) = outbound_reference_expansions(
        &analyzer,
        &declaration,
        &ReferenceTraversalFilter::default(),
        &mut IndexedDeclarations::default(),
        &mut cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        8,
        None,
        &mut diagnostics,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
}

fn formal_call_site_value(binding: CallBindingStatus) -> CallSiteValue {
    let root = std::env::temp_dir().join("bifrost-call-input-completeness");
    let file = ProjectFile::new(root, "src/app.ts");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let callee = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "callee");
    let range = Range {
        start_byte: 0,
        end_byte: 1,
        start_line: 1,
        end_line: 1,
    };
    CallSiteValue(
        CallSite {
            file,
            range,
            callee_range: range,
            caller,
            callee,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Proven,
            receiver: None,
            arguments: vec![CallArgument {
                range,
                name: None,
                position: Some(0),
                formal_index: (binding == CallBindingStatus::Complete).then_some(0),
                formal_name: (binding == CallBindingStatus::Complete)
                    .then(|| "payload".to_string()),
                variadic: false,
                spread: false,
            }],
        },
        binding,
    )
}

#[test]
fn formal_call_input_with_unavailable_binding_is_incomplete() {
    let site = formal_call_site_value(CallBindingStatus::Unavailable);

    let (expansions, incomplete) =
        call_input_expansions(&site, &CallInputSelector::ParameterIndex(0));

    assert!(expansions.is_empty());
    assert!(incomplete);
}

#[test]
fn formal_call_input_with_known_nonmatching_binding_is_complete() {
    let site = formal_call_site_value(CallBindingStatus::Complete);

    let (missing, incomplete) = call_input_expansions(&site, &CallInputSelector::ParameterIndex(1));
    let (exact, exact_incomplete) = call_input_expansions(
        &site,
        &CallInputSelector::ParameterName("payload".to_string()),
    );

    assert!(missing.is_empty());
    assert!(!incomplete);
    assert_eq!(exact.len(), 1, "known exact bindings remain positive");
    assert!(!exact_incomplete);
}

#[test]
fn formal_call_input_with_spread_argument_is_incomplete() {
    let mut site = formal_call_site_value(CallBindingStatus::Complete);
    site.0.arguments[0].formal_index = None;
    site.0.arguments[0].formal_name = None;
    site.0.arguments[0].spread = true;

    let (expansions, incomplete) =
        call_input_expansions(&site, &CallInputSelector::ParameterIndex(0));

    assert!(expansions.is_empty());
    assert!(incomplete);
}

#[test]
fn m3_inbound_reference_distinguishes_missing_real_owner_from_file_scope() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
    let missing_owner = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let range = Range {
        start_byte: 0,
        end_byte: 1,
        start_line: 1,
        end_line: 1,
    };
    let declaration = DeclarationValue {
        unit: target.clone(),
        range,
    };
    let reference_hit = |enclosing_unit| ReferenceHit {
        file: file.clone(),
        range,
        enclosing_unit,
        kind: None,
        resolved: target.clone(),
        confidence: 1_000_000,
        usage_kind: UsageHitKind::Reference,
        proof: UsageProof::Unproven,
    };
    let filter = ReferenceTraversalFilter::default();
    let step = QueryStep::UsedBy(filter.clone());

    let mut missing_cache = ReferenceTraversalCache::default();
    missing_cache
        .inbound
        .insert(target.clone(), vec![reference_hit(missing_owner)]);
    let mut diagnostics = vec![diagnostic(
        CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
        CodeQueryDiagnosticImpact::Advisory,
    )];
    let (expansions, exhausted) = inbound_reference_expansions(
        &analyzer,
        &declaration,
        &step,
        &filter,
        &mut IndexedDeclarations::default(),
        &mut missing_cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        &mut diagnostics,
        8,
        None,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::ReferenceCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);

    let mut file_scope_cache = ReferenceTraversalCache::default();
    file_scope_cache.inbound.insert(
        target.clone(),
        vec![reference_hit(CodeUnit::file_scope(file.clone()))],
    );
    let mut diagnostics = Vec::new();
    let (expansions, exhausted) = inbound_reference_expansions(
        &analyzer,
        &declaration,
        &step,
        &filter,
        &mut IndexedDeclarations::default(),
        &mut file_scope_cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        &mut diagnostics,
        8,
        None,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(!exhausted);
    assert!(diagnostics.is_empty());
}

#[test]
fn m3_inbound_reference_bounded_samples_remain_positive_and_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let sample_hits = [
        UsageHit::new(file.clone(), 1, 0, 6, caller.clone(), 1.0, "target"),
        UsageHit::new(file, 2, 8, 14, caller, 1.0, "target"),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    let (hits, incomplete) = reference_hits_for_target(
        &analyzer,
        FuzzyResult::TooManyCallsites {
            short_name: "target".to_string(),
            total_callsites: 2,
            limit: 1,
            sample_hits,
        },
        &target,
    );

    assert!(incomplete);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].resolved, target);
    assert_eq!(hits[0].proof, UsageProof::Proven);
}

#[test]
fn outbound_uses_scan_without_indexed_source_is_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/missing.ts");
    let mut diagnostics = Vec::new();

    let (hits, exhausted) = scan_outbound_reference_hits(
        &analyzer,
        &file,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        8,
        None,
        &mut diagnostics,
    );

    assert!(hits.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
}

#[test]
fn members_projection_reports_unindexed_direct_child_as_semantic_omission() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let declaration = DeclarationValue {
        unit: CodeUnit::new(file.clone(), CodeUnitType::Class, "", "Owner"),
        range: Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        },
    };
    let mut omissions = BTreeMap::new();

    let (expansions, exhausted) = direct_member_expansions(
        &analyzer,
        &declaration,
        vec![CodeUnit::file_scope(file)],
        &mut IndexedDeclarations::default(),
        &mut CodeQueryExecutionBudget::default(),
        8,
        &mut omissions,
    );
    let mut diagnostics = Vec::new();
    append_semantic_omission_diagnostics(&mut diagnostics, &QueryStep::Members, omissions);

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: exhausted,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn hierarchy_projection_keeps_exact_rows_and_reports_unindexed_relations() {
    let source = "class Exact {}\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "src/app.ts");
    file.write(source).expect("write source");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let exact = analyzer
        .all_declarations()
        .find(|unit| unit.short_name() == "Exact")
        .expect("exact class declaration");
    let missing_file = ProjectFile::new(root, "src/missing.ts");
    let missing = CodeUnit::new(missing_file, CodeUnitType::Class, "", "Missing");
    let mut indexed = IndexedDeclarations::default();
    let mut omissions = BTreeMap::new();
    let mut exhausted = false;

    let retained = project_hierarchy_declaration(
        &analyzer,
        &exact,
        &mut indexed,
        &mut omissions,
        &mut exhausted,
    );
    let omitted = project_hierarchy_declaration(
        &analyzer,
        &missing,
        &mut indexed,
        &mut omissions,
        &mut exhausted,
    );
    let mut diagnostics = Vec::new();
    append_semantic_omission_diagnostics(
        &mut diagnostics,
        &QueryStep::Supertypes(HierarchyTraversal::Direct),
        omissions,
    );

    assert!(retained.is_some(), "an exact hierarchy row must survive");
    assert!(omitted.is_none());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: exhausted,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn enclosing_declaration_index_retains_exact_owner_and_reports_missing_real_range() {
    let root = std::env::temp_dir().join("bifrost-enclosing-declaration-completeness");
    let file = ProjectFile::new(root, "src/app.ts");
    let exact = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "exact");
    let missing = CodeUnit::new(file, CodeUnitType::Function, "", "missing");
    let exact_range = Range {
        start_byte: 0,
        end_byte: 20,
        start_line: 1,
        end_line: 2,
    };
    let seed_range = Range {
        start_byte: 5,
        end_byte: 10,
        start_line: 1,
        end_line: 1,
    };
    let mut index = EnclosingDeclarationIndex::default();
    index.retain(exact.clone(), [exact_range]);
    index.retain(missing, std::iter::empty());
    index.sort();

    let retained = index.enclosing(seed_range).expect("exact owner survives");

    assert_eq!(retained.unit, exact);
    assert!(index.projection_omitted);
    let mut diagnostics = Vec::new();
    append_semantic_omission_diagnostics(
        &mut diagnostics,
        &QueryStep::EnclosingDecl,
        BTreeMap::from([(
            (
                Language::TypeScript,
                "a real declaration in the seed file had no exact indexed range",
            ),
            1,
        )]),
    );
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: index.projection_omitted,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn enclosing_declaration_index_treats_file_scope_no_owner_as_complete() {
    let root = std::env::temp_dir().join("bifrost-enclosing-file-scope");
    let file = ProjectFile::new(root, "src/app.ts");
    let mut index = EnclosingDeclarationIndex::default();
    index.retain(CodeUnit::file_scope(file), std::iter::empty());

    assert!(index.exact.is_empty());
    assert!(!index.projection_omitted);
    assert!(
        index
            .enclosing(Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            })
            .is_none()
    );
}
use crate::analyzer::CodeUnitIndex;
