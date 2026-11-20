//! Regression for a target-seeded call whose caller text is not retained.
use super::*;

struct BudgetRun {
    execution_budget: CodeQueryExecutionBudget,
    detailed: DetailedCodeQueryResult,
    trace: WindowTrace,
    native_keys: Vec<UnitRowKey>,
    published_keys: Vec<UnitRowKey>,
}

struct RefuseCallerBytes;
struct RefuseCallerFile;

impl QueryRowsFinalizer for RefuseCallerBytes {
    type Output = BudgetRun;

    fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
        panic!("the real incoming call must execute: {result:?}")
    }

    fn finish(
        self,
        rows: ExecutedQueryRows<'_>,
        mut context: QueryFinalizationContext<'_, '_>,
    ) -> Self::Output {
        // This existing grant admits all completed execution work. Only the
        // next, real caller-source hydration is refused. No owner/cap changes
        // affect the executor or manufacture a refusal diagnostic.
        context.limits.max_scanned_source_bytes = rows
            .state
            .budget
            .scanned_source_bytes
            .saturating_add(rows.state.budget.call_scanned_source_bytes);
        observe_budget(rows, context)
    }
}

impl QueryRowsFinalizer for RefuseCallerFile {
    type Output = BudgetRun;

    fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
        panic!("the real incoming call must execute: {result:?}")
    }

    fn finish(
        self,
        rows: ExecutedQueryRows<'_>,
        mut context: QueryFinalizationContext<'_, '_>,
    ) -> Self::Output {
        context.limits.max_scanned_files = rows
            .state
            .budget
            .scanned_files
            .saturating_add(rows.state.budget.call_scanned_files);
        observe_budget(rows, context)
    }
}

fn observe_budget(
    rows: ExecutedQueryRows<'_>,
    context: QueryFinalizationContext<'_, '_>,
) -> BudgetRun {
    assert!(!rows.execution.rows.is_empty());
    assert!(!rows.execution.is_truncated());
    assert!(!rows.execution.is_cancelled());
    assert!(
        rows.diagnostics.iter().all(|diagnostic| !matches!(
            diagnostic.impact,
            CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid
        )),
        "execution must be complete before source preparation: {:?}",
        rows.diagnostics
    );
    for row in &rows.execution.rows {
        let PipelineValue::CallSite(site) = &row.value else {
            panic!("expected a real incoming call: {row:?}")
        };
        assert_eq!(site.0.file.rel_path(), std::path::Path::new("caller.py"));
        assert!(!row.traces.is_empty(), "the target seed must be retained");
        assert!(
            row.traces.iter().all(|trace| {
                trace.seed.file.rel_path() == std::path::Path::new("target.py")
                    && trace.seed.file != site.0.file
            }),
            "no caller-held facts may make the regression vacuous: {row:?}"
        );
    }
    let execution_budget = rows.state.budget;
    let native_keys = rows
        .execution
        .rows
        .iter()
        .map(|row| unit_row_key(&row.value.key()))
        .collect();
    let observer = ObserveWindows::start();
    let detailed = present_query_rows(rows, context);
    let trace = observer.finish();
    detailed.assert_invariants();
    BudgetRun {
        execution_budget,
        detailed,
        trace,
        native_keys,
        published_keys: Vec::new(),
    }
}

fn run_budget<F: QueryRowsFinalizer<Output = BudgetRun>>(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    finalizer: F,
) -> BudgetRun {
    run_budget_with_flow(workspace, query, None, finalizer)
}

fn run_budget_with_flow<F: QueryRowsFinalizer<Output = BudgetRun>>(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    flow: Option<SemanticFlowResources>,
    finalizer: F,
) -> BudgetRun {
    let read_scope = AnalyzerQueryScope::new(workspace.analyzer());
    let mut keys = Vec::new();
    let mut run = execute_query_rows_with_finalizer(
        workspace.analyzer(),
        read_scope.token(),
        None,
        Some(workspace),
        flow,
        None,
        0,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        eager_structural_access_mode(),
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        None,
        CodeQueryExecutionScope::whole_workspace(),
        Some(&mut keys),
        None,
        EdgeTraversalCache::default(),
        finalizer,
    );
    run.published_keys = keys;
    run
}

fn incoming_query() -> CodeQuery {
    CodeQuery::from_json(&serde_json::json!({
        "where": ["target.py"], "languages": ["python"],
        "match": {"kind": "function", "name": "consume"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 200, "result_detail": "compact"
    }))
    .unwrap()
}

const CALLER_SOURCE: &str =
    "from target import consume\ndef entry():\n    consume(\"payload\")\n    consume(\"second\")\n";

fn cross_file_project() -> InlineTestProject {
    // Keep the factory below local to the two hard-won paths, rather than
    // depending on another feature's published fixture or semantic pack.
    InlineTestProject::with_language(Language::Python)
        .file("target.py", "def consume(value):\n    return value\n")
        .file("caller.py", CALLER_SOURCE)
}

fn assert_real_source_budget(run: &BudgetRun, lane: &str) {
    let diagnostic = run
        .detailed
        .result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code() == CodeQueryDiagnosticCode::ExecutionBudgetExhausted)
        .expect("actual source preparation must report its own execution budget");
    assert_eq!(
        diagnostic.incompleteness(),
        Incompleteness::Operational(DerivationExecutionCause::Budget)
    );
    let DiagnosticRef::Semantic(raw) = diagnostic else {
        panic!("source hydration has a semantic execution-budget diagnostic")
    };
    assert!(
        raw.exhausted_roots.iter().any(|root| {
            root.lane == lane
                && root.stage.as_deref() == Some("source_hydration")
                && root
                    .charge
                    .as_ref()
                    .is_some_and(|charge| charge.attempted > charge.limit)
        }),
        "preserve the real hydration root witness: {raw:?}"
    );
    assert!(run.detailed.result.truncated);
    assert!(matches!(
        run.detailed.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert_ne!(run.detailed.reuse, ReuseVerdict::Content);
    assert!(
        run.detailed
            .result
            .diagnostics
            .iter()
            .all(|diagnostic| !matches!(
                diagnostic.code(),
                CodeQueryDiagnosticCode::PresentationRowsRefused
                    | CodeQueryDiagnosticCode::PresentationOwnerUnavailable
            )),
        "source budget must not invent a retained-bytes or missing-owner refusal: {:?}",
        run.detailed.result.diagnostics
    );
}

#[test]
#[hardwon(
    "#14068: refused caller text changed known incoming-call literals into not-analyzed values"
)]
fn incoming_call_source_byte_refusal_keeps_cold_and_warm_literals() {
    let project = cross_file_project().build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = incoming_query();
    let caller = project.file("caller.py");
    let mut observed_keys = None;
    // The first run has no earlier public presentation. The repeat exercises
    // the same selected generation and warm provider/read memo paths.
    for _ in 0..2 {
        let refused = run_budget(&workspace, &query, RefuseCallerBytes);
        assert_real_source_budget(&refused, "query/scanned_source_bytes");
        assert_eq!(
            refused.trace.source_loads.as_slice(),
            std::slice::from_ref(&caller),
            "one real source load, no fallback read"
        );
        assert_actual_windows(&refused.trace, std::slice::from_ref(&caller));
        assert_eq!(refused.detailed.result.results.len(), 2);
        assert_eq!(refused.detailed.evidence.len(), 2);
        assert_eq!(refused.published_keys, refused.native_keys);
        if let Some(keys) = &observed_keys {
            assert_eq!(&refused.native_keys, keys);
        }
        observed_keys = Some(refused.native_keys.clone());
        for (index, (row, expected)) in refused
            .detailed
            .result
            .results
            .iter()
            .zip(["payload", "second"])
            .enumerate()
        {
            let CodeQueryResultValue::CallSite { value } = &row.value else {
                panic!("incoming call")
            };
            assert_eq!(value.path, "caller.py");
            assert_eq!(value.arguments.len(), 1);
            let site = &value.arguments[0].site;
            assert_eq!(
                site.role,
                brokk_bifrost_tools::site_context::SiteRoleView::Argument {
                    index: 0,
                    name: None,
                },
            );
            assert_eq!(
                site.value
                    .known_str()
                    .expect("normalized literal survives text refusal")
                    .as_ref(),
                expected
            );
            assert!(matches!(
                &site.site,
                SiteLocationView::Unrendered {
                    reason: UnrenderedReason::RenderBudget,
                    ..
                }
            ));
            assert_eq!(refused.detailed.evidence[index].result_index, index);
        }
    }
    let control = run(&workspace, &query, None);
    assert_eq!(
        control.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    assert_eq!(Some(control.native_keys.clone()), observed_keys);
    for (row, expected) in control
        .detailed
        .result
        .results
        .iter()
        .zip(["payload", "second"])
    {
        let CodeQueryResultValue::CallSite { value } = &row.value else {
            panic!("incoming call")
        };
        assert_eq!(
            value.arguments[0].site.value.known_str().unwrap().as_ref(),
            expected
        );
        assert!(matches!(
            &value.arguments[0].site.site,
            SiteLocationView::Source { .. }
        ));
    }
}

#[test]
#[hardwon("#14068: a source file grant refusal fabricated budget-caused not-analyzed site values")]
fn incoming_call_source_file_refusal_withholds_without_loading_or_unknowns() {
    let project = cross_file_project().build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = incoming_query();
    let refused = run_budget(&workspace, &query, RefuseCallerFile);
    assert_real_source_budget(&refused, "query/scanned_files");
    assert_eq!(
        refused.native_keys.len(),
        2,
        "the actual incoming calls executed"
    );
    assert!(
        refused.trace.source_loads.is_empty(),
        "no source read after refusing the file grant: {:?}",
        refused.trace
    );
    assert!(
        refused.detailed.result.results.is_empty(),
        "no budget-unknown positive row"
    );
    assert!(refused.detailed.evidence.is_empty());
    assert!(refused.published_keys.is_empty());
}

struct ObserveNativeBudget;

impl QueryRowsFinalizer for ObserveNativeBudget {
    type Output = BudgetRun;

    fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
        panic!("calibration must observe actual complete native calls: {result:?}")
    }

    fn finish(
        self,
        rows: ExecutedQueryRows<'_>,
        context: QueryFinalizationContext<'_, '_>,
    ) -> Self::Output {
        // Observation only: neither this context nor any limit is modified.
        observe_budget(rows, context)
    }
}

#[test]
#[hardwon(
    "#14068: public fixed source budgets erased caller literals or published budget-unknown rows"
)]
fn public_whole_query_source_budgets_preserve_values_or_refuse_before_read() {
    let mut query = incoming_query();
    query.result_detail = CodeQueryResultDetail::Full;
    let calibration_project = cross_file_project().build();
    let calibration_workspace = calibration_project.workspace_analyzer(AnalyzerConfig::default());
    let calibration_flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let calibration = run_budget_with_flow(
        &calibration_workspace,
        &query,
        Some((&calibration_flow).into()),
        ObserveNativeBudget,
    );
    assert_eq!(
        calibration.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    assert_eq!(calibration.native_keys.len(), 2);
    let consumed = calibration.execution_budget;
    let caller_bytes = CALLER_SOURCE.len();
    assert!(caller_bytes > 1);
    let bytes = CodeQueryExecutionLimits {
        max_scanned_source_bytes: consumed
            .scanned_source_bytes
            .saturating_add(consumed.call_scanned_source_bytes)
            .saturating_add(caller_bytes / 2),
        ..CodeQueryExecutionLimits::default()
    };
    let files = CodeQueryExecutionLimits {
        max_scanned_files: consumed
            .scanned_files
            .saturating_add(consumed.call_scanned_files),
        ..CodeQueryExecutionLimits::default()
    };
    // Each public request uses a fresh equivalent workspace. The selected
    // limit is fixed before entering the public executor; no finalizer changes
    // grants or injects a diagnostic during the run under test.
    for (limits, lane) in [
        (bytes, "query/scanned_source_bytes"),
        (files, "query/scanned_files"),
    ] {
        let project = cross_file_project().build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
        let observer = ObserveWindows::start();
        let detailed = execute_code_query_detailed_eager_index_workspace(
            &workspace, &flow, &query, limits, None,
        );
        let trace = observer.finish();
        detailed.assert_invariants();
        let run = BudgetRun {
            execution_budget: consumed,
            detailed,
            trace,
            native_keys: Vec::new(),
            published_keys: Vec::new(),
        };
        assert_real_source_budget(&run, lane);
        assert!(
            run.detailed.result.diagnostics.iter().all(|diagnostic| {
                let DiagnosticRef::Semantic(raw) = diagnostic else {
                    return true;
                };
                raw.code != CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                    || raw
                        .exhausted_roots
                        .iter()
                        .all(|root| root.stage.as_deref() == Some("source_hydration"))
            }),
            "public execution must reach source hydration, not stop in seed/call scan: {:?}",
            run.detailed.result.diagnostics
        );
        if lane == "query/scanned_source_bytes" {
            assert_eq!(run.trace.source_loads, [project.file("caller.py")]);
            assert_actual_windows(&run.trace, &[project.file("caller.py")]);
            assert_eq!(run.detailed.result.results.len(), 2);
            assert_eq!(run.detailed.evidence.len(), 2);
            for ((actual, expected), text) in run
                .detailed
                .result
                .results
                .iter()
                .zip(&calibration.detailed.result.results)
                .zip(["payload", "second"])
            {
                let CodeQueryResultValue::CallSite { value: actual } = &actual.value else {
                    panic!("actual call")
                };
                let CodeQueryResultValue::CallSite { value: expected } = &expected.value else {
                    panic!("control call")
                };
                assert_eq!(actual.caller.id, expected.caller.id);
                assert!(
                    actual.caller.id.is_some(),
                    "Full caller identity must be exercised"
                );
                assert_eq!(
                    actual.callee.as_ref().and_then(|callee| callee.id.as_ref()),
                    expected
                        .callee
                        .as_ref()
                        .and_then(|callee| callee.id.as_ref())
                );
                assert!(
                    actual
                        .callee
                        .as_ref()
                        .is_some_and(|callee| callee.id.is_some())
                );
                assert_eq!(actual.arguments.len(), 1);
                assert_eq!(
                    actual.arguments[0].site.role,
                    expected.arguments[0].site.role
                );
                assert_eq!(
                    actual.arguments[0].site.value.known_str().unwrap().as_ref(),
                    text
                );
                assert_eq!(
                    actual.arguments[0].site.value,
                    expected.arguments[0].site.value
                );
                assert!(matches!(
                    &actual.arguments[0].site.site,
                    SiteLocationView::Unrendered {
                        reason: UnrenderedReason::RenderBudget,
                        ..
                    }
                ));
            }
        } else {
            assert!(
                run.trace.source_loads.is_empty(),
                "pre-read file refusal must not load source: {:?}",
                run.trace
            );
            assert!(
                run.detailed.result.results.is_empty(),
                "no budget-unknown positives"
            );
            assert!(run.detailed.evidence.is_empty());
        }
    }
}
