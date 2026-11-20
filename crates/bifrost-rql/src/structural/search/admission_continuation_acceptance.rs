//! Real continuation suffix refusal must preserve its typed envelope.
use super::*;
use crate::analyzer::AnalyzerConfig;
use crate::structural::search::admission_acceptance::HeldPressure;
use crate::structural::search::tests::inline_project::InlineTestProject;
use brokk_bifrost_core::retention_budget::RetentionBudget;
use brokk_bifrost_test_macros::hardwon;
use std::cell::RefCell;
use std::rc::Rc;

struct PressureSuffix<F> {
    finalizer: F,
    owner: RetentionBudget,
    held: Rc<RefCell<Option<HeldPressure>>>,
}

impl<F: QueryRowsFinalizer> QueryRowsFinalizer for PressureSuffix<F> {
    type Output = F::Output;

    fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
        panic!("the real suffix did not execute: {result:?}")
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
        assert!(rows.execution.rows.len() >= 2);
        assert!(
            rows.execution
                .rows
                .iter()
                .all(|row| matches!(row.value, PipelineValue::CallArgument(_)))
        );
        assert!(!rows.execution.is_cancelled() && !rows.execution.is_truncated());
        assert!(
            rows.diagnostics.iter().all(|diagnostic| !matches!(
                diagnostic.impact,
                CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid
            )),
            "semantic suffix must be complete before pressure: {:?}",
            rows.diagnostics
        );
        *self.held.borrow_mut() = Some(HeldPressure::after_execution(&self.owner, 1));
        self.finalizer.finish(rows, context)
    }
}

fn run_suffix<F: QueryRowsFinalizer>(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    finalizer: F,
) -> QueryContinuationResult<F::Output>
where
    F::Output: ContinuationRows,
{
    let mut files = workspace.analyzer().analyzed_files();
    files.sort_by(seed_file_order);
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let mut prefixes = files
        .iter()
        .map(|file| {
            let prefix = execute_intersect_prefix(
                workspace.analyzer(),
                &flow,
                Some(workspace),
                query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
            );
            assert_eq!(prefix.completion, CodeQueryCompletion::Complete);
            assert!(prefix.reads_closed && !prefix.reads.is_empty());
            assert!(prefix.operands.iter().all(|operand| !operand.is_empty()));
            prefix
        })
        .collect::<Vec<_>>();
    // Prefix capture deliberately suppresses empty-step advisories. Exercise
    // the combination API with a real informational diagnostic from ordinary
    // whole execution of this SAME authored query, supplied by its caller.
    // This input changes no prefix proof/read/work/completion field.
    let ordinary = execute_code_query_detailed_eager_index_workspace(
        workspace,
        &flow,
        query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(ordinary.result.completion(), CodeQueryCompletion::Complete);
    assert!(ordinary.result.results.len() >= 2);
    let advisory = ordinary
        .result
        .diagnostics
        .into_semantic()
        .into_iter()
        .find(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::StepProducedNoRows)
        .expect("the ordinary authored empty-filter branch emits a real advisory");
    assert_eq!(advisory.impact, CodeQueryDiagnosticImpact::Advisory);
    assert_eq!(advisory.step_op.as_deref(), Some("filter"));
    assert_eq!(
        advisory.no_rows_reason,
        Some(CodeQueryStepNoRowsReason::AllInputsFiltered)
    );
    assert_eq!(
        advisory.branch,
        [0, 1],
        "authored intersect operand0/union operand1: {advisory:?}"
    );
    prefixes
        .first_mut()
        .expect("real captured prefix")
        .diagnostics
        .push(advisory);
    continue_intersect_prefix_with_finalizer(
        workspace.analyzer(),
        &flow,
        Some(workspace),
        query,
        CodeQueryExecutionLimits::default(),
        None,
        &files,
        prefixes,
        CodeQueryExecutionScope::whole_workspace(),
        finalizer,
    )
}

#[test]
#[hardwon(
    "#14068: a continuation converted presentation refusal to a semantic-only slice and panicked"
)]
fn real_continuation_suffix_keeps_presentation_refusal_and_prefix_diagnostics() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "def sink(value):\n    return value\ndef use():\n    sink(\"first\")\n    sink(\"second\")\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(call-arguments (call-argument-groups (call-shape
        (intersect
            (union (call :callee "sink")
                (filter :where ((name eq "absent")) (call :callee "sink")))
            (call :callee "sink")))))"#,
    )
    .unwrap();
    let control = run_suffix(&workspace, &query, PresentQueryRows);
    assert_eq!(control.completion, CodeQueryCompletion::Complete);
    let control = control.detailed.expect("complete real suffix");
    assert!(control.result.results.len() >= 2);
    assert_eq!(control.result.results.len(), control.evidence.len());

    let held = Rc::new(RefCell::new(None));
    let refused = run_suffix(
        &workspace,
        &query,
        PressureSuffix {
            finalizer: PresentQueryRows,
            owner: workspace.retention_budget().clone(),
            held: held.clone(),
        },
    );
    assert!(matches!(
        refused.completion,
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert!(matches!(refused.reuse, ReuseVerdict::ExecutionDependent(_)));
    assert_eq!(
        refused
            .diagnostics
            .iter()
            .filter(|diagnostic| matches!(
                diagnostic,
                DiagnosticRef::Presentation(PresentationDiagnostic::RowsRefused)
            ))
            .count(),
        1
    );
    assert!(
        refused
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == CodeQueryDiagnosticCode::StepProducedNoRows),
        "prefix engine diagnostic must survive the carrier prepend"
    );
    // The repair must not make a semantic-only accessor silently drop a flag.
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| refused
            .diagnostics
            .semantic()))
        .is_err()
    );
    let detailed = refused
        .detailed
        .expect("the suffix executed before refusal");
    assert!(detailed.result.truncated);
    assert!(detailed.result.results.is_empty() && detailed.evidence.is_empty());
    assert_eq!(
        serde_json::to_value(&refused.diagnostics).unwrap(),
        serde_json::to_value(&detailed.result.diagnostics).unwrap()
    );
    assert_eq!(detailed.result.results.len(), detailed.evidence.len());
    held.borrow_mut().take().unwrap().assert_refund();

    // The same native suffix and prefix merge remain semantic-only on the
    // policy route; owner pressure must not manufacture a presentation flag.
    let held = Rc::new(RefCell::new(None));
    let selected = run_suffix(
        &workspace,
        &query,
        PressureSuffix {
            finalizer: ProjectSelectorRows,
            owner: workspace.retention_budget().clone(),
            held: held.clone(),
        },
    );
    assert_eq!(selected.completion, CodeQueryCompletion::Complete);
    assert_eq!(selected.reuse, ReuseVerdict::Content);
    assert!(
        selected
            .diagnostics
            .semantic()
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::StepProducedNoRows)
    );
    let merged = selected.into_merged_rows(&query);
    assert!(merged.items.len() >= 2);
    assert_eq!(merged.completion(), CodeQueryCompletion::Complete);
    held.borrow_mut().take().unwrap().assert_refund();
}
