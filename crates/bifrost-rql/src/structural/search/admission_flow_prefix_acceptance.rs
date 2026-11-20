//! A published flow prefix must see the final output-only refusal state.
use super::*;
use crate::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, OracleCallContext, ProofStatus, SemanticArtifact,
    SemanticArtifactLeaseSet, SemanticBudget, SemanticExecutionBudget, SemanticRequest,
    SemanticWork, ValueFlowOracle, ValueFlowRelationKind,
};
use crate::structural::{QueryAnalysisValidationLimits, ValueFlowPlanRegistration};
use brokk_bifrost_flow::dataflow::SemanticInputStatus;
use brokk_bifrost_flow::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
};
use brokk_bifrost_test_macros::hardwon;

struct FlowPublication {
    detailed: DetailedCodeQueryResult,
    native: CodeQueryFlowEndpoint,
    native_witness: CodeQueryFlowWitness,
    semantic_used: SemanticWork,
    held: Option<HeldPressure>,
}

struct PublishFlowPrefix {
    owner: RetentionBudget,
    headroom: Option<u64>,
}

impl QueryRowsFinalizer for PublishFlowPrefix {
    type Output = FlowPublication;
    fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
        panic!("real mixed query did not execute: {result:?}")
    }
    fn finish(
        self,
        rows: ExecutedQueryRows<'_>,
        context: QueryFinalizationContext<'_, '_>,
    ) -> Self::Output {
        assert!(
            rows.owner
                .as_ref()
                .is_some_and(|owner| owner.ptr_eq(&self.owner))
        );
        assert_eq!(
            rows.execution.rows.len(),
            3,
            "real endpoint and witness prefixes, then one written argument"
        );
        assert!(!rows.execution.is_cancelled() && !rows.execution.is_truncated());
        assert!(
            rows.diagnostics.iter().all(|diagnostic| !matches!(
                diagnostic.impact,
                CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid
            )),
            "semantic execution must be complete before pressure: {:?}",
            rows.diagnostics
        );
        let PipelineValue::Semantic(SemanticPipelineValue::FlowEndpoint(endpoint)) =
            &rows.execution.rows[0].value
        else {
            panic!("the actual endpoint must be the authored union prefix")
        };
        assert!(matches!(
            rows.execution.rows[2].value,
            PipelineValue::CallArgument(_)
        ));
        let native = endpoint.public.clone();
        let PipelineValue::Semantic(SemanticPipelineValue::FlowWitness(witness)) =
            &rows.execution.rows[1].value
        else {
            panic!("the actual retained witness must follow its endpoint")
        };
        let native_witness = witness.public.clone();
        assert!(
            !native_witness.steps.is_empty(),
            "real witness steps must execute"
        );
        assert_eq!(native.status, CodeQueryFlowStatus::Complete);
        assert!(
            native.source.is_some() && native.retained_witnesses > 0,
            "a real positive witness is required: {native:?}"
        );
        let semantic_work = rows
            .state
            .semantic
            .as_ref()
            .expect("real value-flow execution")
            .work();
        let semantic_used = semantic_work.cumulative;
        // Pre-admitted Python input/IR reuse need not perform fresh source
        // work. A successful source probe is admission, not cumulative charge;
        // positive paid IR is proved below, and receipt equality keeps EVERY
        // actual work dimension, including zero source bytes.
        assert!(
            semantic_used.procedures > 0 && semantic_used.program_points > 0,
            "query-owned materialization: {semantic_work:?}"
        );
        assert!(
            semantic_work.materialization_attempts > 0
                && semantic_work.unique_materialized_files > 0,
            "real CFG materialization: {semantic_work:?}"
        );
        let held = self
            .headroom
            .map(|bytes| HeldPressure::after_execution(&self.owner, bytes));
        let detailed = PresentQueryRows.finish(rows, context);
        assert!(
            detailed
                .result
                .diagnostics
                .iter()
                .all(|diagnostic| !matches!(diagnostic,
            DiagnosticRef::Semantic(raw) if matches!(raw.impact,
                CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid))),
            "provider/source/cancel failure is not output-only pressure: {:?}",
            detailed.result.diagnostics
        );
        FlowPublication {
            detailed,
            native,
            native_witness,
            semantic_used,
            held,
        }
    }
}

struct ReceiptedFlow {
    published: FlowPublication,
    semantic: SemanticBudget,
    execution: SemanticExecutionBudget,
    leases: SemanticArtifactLeaseSet,
}

fn run_flow(
    workspace: &WorkspaceAnalyzer,
    flow: &brokk_bifrost_flow::FlowWorkspaceState,
    context: &QueryAnalysisContext,
    query: &CodeQuery,
    headroom: Option<u64>,
) -> ReceiptedFlow {
    let limits = CodeQueryExecutionLimits::default();
    let allotment = CodeQueryRootAllotment::from_execution_limits(&limits);
    let semantic = allotment.semantic_budget();
    let execution = SemanticExecutionBudget::new(limits.semantic.max_materialized_files);
    let leases = SemanticArtifactLeaseSet::new(limits.semantic.max_retained_bytes);
    let (execution_before, execution_child) =
        execution.fork_with_materialized_file_limit(limits.semantic.max_materialized_files);
    let read_scope = AnalyzerQueryScope::new(workspace.analyzer());
    let published = execute_query_rows_with_finalizer(
        workspace.analyzer(),
        read_scope.token(),
        None,
        Some(workspace),
        Some(flow.into()),
        Some(context),
        7,
        query,
        limits,
        None,
        None,
        false,
        UnionExecutionStrategy::Sequential,
        1,
        eager_structural_access_mode(),
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        Some(SemanticQueryContinuation {
            parent_scope: semantic.scope_snapshot(),
            child_semantic_limits: semantic.remaining(),
            root_allotment: allotment,
            execution_before,
            execution_child,
            artifact_leases: leases.snapshot(),
        }),
        None,
        CodeQueryExecutionScope::whole_workspace(),
        None,
        None,
        EdgeTraversalCache::default(),
        PublishFlowPrefix {
            owner: workspace.retention_budget().clone(),
            headroom,
        },
    );
    ReceiptedFlow {
        published,
        semantic,
        execution,
        leases,
    }
}

fn import_flow_receipt(run: &mut ReceiptedFlow, artifact: &Arc<SemanticArtifact>) {
    let receipt = run
        .published
        .detailed
        .take_semantic_receipt()
        .expect("real semantic receipt survives presentation");
    let (semantic, before, execution, leases) = receipt.into_parts();
    run.semantic
        .apply_child_charge(SemanticWork::default(), semantic)
        .unwrap();
    assert!(run.execution.replay_charge(&before, &execution));
    run.leases.try_apply_charge(leases, 0).unwrap();
    assert_eq!(
        run.semantic.used(),
        run.published.semantic_used,
        "output capping cannot alter the actual native semantic charge"
    );
    assert!(run.semantic.charged_artifact_count() > 0);
    assert!(
        run.semantic
            .has_charged_artifact(artifact.key().fingerprint())
    );
    // An ordinary flow row need not export physical policy-window leases;
    // positive paid identity/census is the receipt contract exercised here.
}

#[test]
#[hardwon("#14068: output-only site refusal left an already published flow endpoint Complete")]
fn mixed_real_flow_prefix_caps_after_site_refusal_without_losing_witness_or_receipt() {
    let mut literal = String::from("\n");
    literal.push_str(&format!("{}\n", "A".repeat(1023)).repeat(191));
    literal.push_str(&"A".repeat(1022));
    literal.push('\n');
    assert_eq!(literal.len(), 192 * 1024);
    let source = format!(
        "def run(value):\n    copied = value\n    result = copied\n    return result\ndef sink(value):\n    return value\ndef written():\n    sink(\"\"\"{literal}\"\"\")\n"
    );
    assert!(source.lines().all(|line| line.len() < 16000));
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut semantic = SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(
            &project.file("main.py"),
            &mut SemanticRequest::new(&mut semantic, &cancellation),
        )
        .unwrap();
    let artifact = outcome
        .available_value()
        .expect("actual source artifact")
        .clone();
    let procedure = artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("run")
        })
        .unwrap();
    let root = artifact.procedure_handle(procedure.id()).unwrap();
    let relations = workspace
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut semantic, &cancellation),
        )
        .unwrap();
    let status = SemanticInputStatus::from_outcome(&relations);
    let snapshot = relations.available_value().unwrap().clone();
    let mut assignments = snapshot
        .relations()
        .iter()
        .filter(|relation| relation.kind == ValueFlowRelationKind::Assignment)
        .collect::<Vec<_>>();
    assignments.sort_by_key(|relation| {
        let semantics = relation.point().procedure().semantics();
        let point = semantics.point(relation.point().id()).unwrap();
        semantics
            .source_mapping(point.source)
            .unwrap()
            .locator
            .anchor()
            .span()
            .start_byte()
    });
    let first = assignments.first().expect("actual source assignment");
    let last = assignments.last().expect("actual sink assignment");
    assert_ne!(first.point(), last.point());
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(first.point(), 0, ValueFlowEventKind::Source).unwrap(),
        first.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&first.source),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(last.point(), 0, ValueFlowEventKind::Sink).unwrap(),
        last.point().clone(),
        ValueFlowObservationPhase::AfterEffects,
        ValueFlowCarrier::from(&last.target),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::try_new(
        root,
        vec![ValueFlowInput::new(snapshot, status)],
        vec![],
        vec![source],
        vec![sink],
    )
    .unwrap();
    let mut registrations = ValueFlowPlanRegistrationSet::default();
    registrations
        .register(
            "test:presentation-prefix".parse().unwrap(),
            ValueFlowPlanRegistration::new(7, Arc::new(plan)),
        )
        .unwrap();
    // Both the branch proof and the mixed query execute this exact expression.
    // Registered value-flow plans alone need not materialize query-owned IR.
    let empty_cfg_source = r#"(except
        (cfg-entry (procedure-of (function :name "run")))
        (cfg-entry (procedure-of (function :name "run"))))"#;
    let empty_cfg = CodeQuery::from_sexp(empty_cfg_source).unwrap();
    let query = CodeQuery::from_sexp(&format!(
        r#"(union
        (value-flow :plan-ref test:presentation-prefix (procedure-of (function :name "run")))
        (witness (value-flow :plan-ref test:presentation-prefix (procedure-of (function :name "run"))))
        (call-arguments (call-argument-groups (call-shape (call :callee "sink"))))
        {empty_cfg_source})"#,
    )).unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let empty = execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &flow,
        &empty_cfg,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(empty.result.completion(), CodeQueryCompletion::Complete);
    assert!(empty.result.results.is_empty() && empty.evidence.is_empty());
    assert!(!empty.result.truncated);
    assert!(
        empty.work.semantic.cumulative.procedures > 0
            && empty.work.semantic.cumulative.program_points > 0,
        "the empty branch performs real query-owned CFG work: {:?}",
        empty.work
    );
    assert!(
        empty.work.semantic.materialization_attempts > 0
            && empty.work.semantic.unique_materialized_files > 0,
        "the empty branch actually materialized its source-selected IR: {:?}",
        empty.work
    );
    if let Some(request) = brokk_bifrost_analysis::analyzer::current_outer_request() {
        registrations.bind_retention_scope(&request).unwrap();
    }
    let retention = brokk_bifrost_analysis::analyzer::current_outer_request().and_then(|request| {
        brokk_bifrost_flow::value_flow::ValueFlowRetentionScope::current(&request)
    });
    let context = QueryAnalysisContext::import_registrations_and_summaries(
        &workspace,
        7,
        &ProtocolRegistrationSet::default(),
        &[],
        Some(&registrations),
        &requested_value_flow_refs(&query.plan),
        retention,
        &TaintResultRegistrationSet::default(),
        &[],
        QueryAnalysisValidationLimits::default(),
        None,
        flow.typestate_summaries(&workspace),
    )
    .unwrap();
    let mut control = run_flow(&workspace, &flow, &context, &query, None);
    assert_eq!(
        control.published.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    assert_eq!(control.published.detailed.result.results.len(), 3);
    assert_eq!(control.published.detailed.evidence.len(), 3);
    import_flow_receipt(&mut control, &artifact);

    let mut refused = run_flow(&workspace, &flow, &context, &query, Some(64 * 1024));
    assert!(matches!(
        refused.published.detailed.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert!(refused.published.detailed.result.truncated);
    assert!(matches!(
        refused.published.detailed.reuse,
        ReuseVerdict::ExecutionDependent(_)
    ));
    assert_eq!(
        refused
            .published
            .detailed
            .result
            .diagnostics
            .iter()
            .filter(|diagnostic| matches!(
                diagnostic,
                DiagnosticRef::Presentation(PresentationDiagnostic::RowsRefused)
            ))
            .count(),
        1
    );
    let [published, published_witness] = refused.published.detailed.result.results.as_slice()
    else {
        panic!(
            "the actual retained prefix must contain endpoint and witness: {:?}",
            refused.published.detailed
        )
    };
    let CodeQueryResultValue::FlowEndpoint { value } = &published.value else {
        panic!("flow prefix")
    };
    let CodeQueryResultValue::FlowWitness { value: witness } = &published_witness.value else {
        panic!("witness prefix")
    };
    assert_eq!(
        witness.as_ref(),
        &refused.published.native_witness,
        "positive witness identity and steps are untouched by output-only omission"
    );
    let mut expected = refused.published.native.clone();
    expected.status = CodeQueryFlowStatus::Partial;
    expected.reason = Some("query execution was incomplete".to_owned());
    assert_eq!(
        value.as_ref(),
        &expected,
        "only run status/reason changes; IDs, event identities and witnesses remain exact"
    );
    assert_eq!(refused.published.detailed.evidence.len(), 2);
    assert_eq!(refused.published.detailed.evidence[0].result_index, 0);
    assert_eq!(
        refused.published.detailed.evidence[0].domain,
        DetailedCodeQueryDomain::FlowEndpoint
    );
    assert_eq!(control.published.native, refused.published.native);
    assert_eq!(
        control.published.native_witness,
        refused.published.native_witness
    );
    assert_eq!(refused.published.detailed.evidence[1].result_index, 1);
    assert_eq!(
        refused.published.detailed.evidence[1].domain,
        DetailedCodeQueryDomain::FlowWitness
    );
    import_flow_receipt(&mut refused, &artifact);
    refused.published.held.take().unwrap().assert_refund();
}
