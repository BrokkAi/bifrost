use super::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryResultRef, CodeQueryTaintFinding,
    CodeQueryTaintLimits, SemanticProcedureValue, incomplete_diagnostic,
};
use super::{DerivationExecutionCause, Incompleteness};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::structural::analysis_context::{
    QueryAnalysisContext, QueryAnalysisContextError, RegisteredTaintResult, TaintBudgetStop,
    TaintBudgetStopLane, TaintResultRef,
};

#[derive(Default)]
pub(super) struct TaintQueryState {
    diagnostics: Vec<CodeQueryDiagnostic>,
    emitted_findings: usize,
    projected_bytes: usize,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticTaintFindingValue {
    pub(super) public: CodeQueryTaintFinding,
    file: ProjectFile,
    byte_span: std::ops::Range<usize>,
}

impl TaintQueryState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn findings(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        analysis_context: Option<&QueryAnalysisContext>,
        procedure: &SemanticProcedureValue,
        taint_ref: &TaintResultRef,
        limits: CodeQueryTaintLimits,
        max_findings: usize,
        cancellation: &CancellationToken,
    ) -> Vec<SemanticTaintFindingValue> {
        if cancellation.is_cancelled() {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                Incompleteness::Operational(DerivationExecutionCause::Cancelled),
                "taint finding projection was cancelled".to_owned(),
            );
            return Vec::new();
        }
        let Some(analysis_context) = analysis_context else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedTaintResultReference,
                Incompleteness::Operational(DerivationExecutionCause::Provider),
                format!("taint result reference `{taint_ref}` was not supplied by the host"),
            );
            return Vec::new();
        };
        let Some(handle) = analysis_context.taint_result_handle(workspace.analyzer(), taint_ref)
        else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedTaintResultReference,
                Incompleteness::Operational(DerivationExecutionCause::Provider),
                format!("taint result reference `{taint_ref}` is not registered"),
            );
            return Vec::new();
        };
        let result = match analysis_context.resolve_taint_result(
            workspace_generation,
            &procedure.handle,
            handle,
        ) {
            Ok(result) => result,
            Err(error) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=session:taint detail={error:?}",
                        file!(),
                        line!()
                    )
                });
                workspace.analyzer().mark_execution_dependent();
                self.push_context_error(error);
                return Vec::new();
            }
        };
        let mut remaining_limits = limits;
        remaining_limits.max_findings = limits
            .max_findings
            .saturating_sub(self.emitted_findings)
            .min(max_findings);
        remaining_limits.max_projected_bytes = limits
            .max_projected_bytes
            .saturating_sub(self.projected_bytes);
        let retained_limits = match &result {
            RegisteredTaintResult::Live(result) => result.projection_limits(),
            RegisteredTaintResult::Output(result) => result.projection_limits,
        };
        let projection_limits = super::CodeQueryTaintProjectionLimits::new(
            remaining_limits
                .max_origins_per_finding
                .min(retained_limits.max_origins_per_finding),
            remaining_limits
                .max_witnesses_per_finding
                .min(retained_limits.max_witnesses_per_finding),
            remaining_limits
                .max_steps_per_witness
                .min(retained_limits.max_steps_per_witness),
            remaining_limits
                .max_witness_bytes
                .min(retained_limits.max_witness_bytes),
        );
        if let RegisteredTaintResult::Output(output) = &result {
            self.push_budget_stops(workspace, &output.budget_stops);
        }
        let projected = match result {
            RegisteredTaintResult::Live(result) => super::project_taint_finding_report_bounded(
                workspace,
                result.plan(),
                result.report(),
                result.projection_scope(),
                projection_limits,
                remaining_limits.max_findings,
                remaining_limits.max_projected_bytes,
                Some(cancellation),
            )
            .map_err(|error| error.to_string()),
            RegisteredTaintResult::Output(result) => {
                Ok(super::witness_projection::project_output_reports_bounded(
                    workspace,
                    result,
                    projection_limits,
                    remaining_limits.max_findings,
                    remaining_limits.max_projected_bytes,
                    Some(cancellation),
                ))
            }
        };
        let projection = match projected {
            Ok(projected) => projected,
            Err(error) => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::TaintProjectionFailed,
                    Incompleteness::Operational(DerivationExecutionCause::Provider),
                    error.to_string(),
                );
                return Vec::new();
            }
        };
        if projection.cancelled {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                Incompleteness::Operational(DerivationExecutionCause::Cancelled),
                "taint finding projection was cancelled".to_owned(),
            );
        }
        if projection.truncated {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::TaintFindingTruncated, Incompleteness::Operational(DerivationExecutionCause::Budget),
                format!(
                    "taint finding projection retained {} findings in {} bytes before reaching a query limit",
                    projection.findings.len(),
                    projection.retained_bytes,
                ),
            );
        }
        self.emitted_findings = self
            .emitted_findings
            .saturating_add(projection.findings.len());
        self.projected_bytes = self
            .projected_bytes
            .saturating_add(projection.retained_bytes);
        projection
            .findings
            .into_iter()
            .map(|projected| SemanticTaintFindingValue {
                public: projected.public,
                file: projected.file,
                byte_span: projected.byte_span,
            })
            .collect()
    }

    /// A stopped anchor's row says nothing about its flows, or only some, so the
    /// findings of a result may be missing some. Report each limit that stopped
    /// anchors, with the limit to raise and the anchors it stopped. The semantic
    /// budget keeps its own code; the truncation of findings, witnesses and
    /// attribution is a truncated finding projection; a limit of the composition
    /// itself and an undecided barrier check are a partial analysis.
    fn push_budget_stops(&mut self, workspace: &WorkspaceAnalyzer, stops: &[TaintBudgetStop]) {
        const NAMED_ANCHORS: usize = 16;
        const MAX_FAILURE_CHARS: usize = 240;
        for lane in [
            TaintBudgetStopLane::Semantic,
            TaintBudgetStopLane::CompositionProcedures,
            TaintBudgetStopLane::CompositionHops,
            TaintBudgetStopLane::CompositionCallersPerProcedure,
            TaintBudgetStopLane::FindingLimit,
            TaintBudgetStopLane::WitnessLimit,
            TaintBudgetStopLane::BarrierUndecided,
            TaintBudgetStopLane::ProviderFailed,
        ] {
            let failure = stops
                .iter()
                .find(|stop| stop.lane == lane && !stop.detail.is_empty())
                .map(|stop| {
                    stop.detail
                        .chars()
                        .take(MAX_FAILURE_CHARS)
                        .collect::<String>()
                });
            let anchors = stops
                .iter()
                .filter(|stop| stop.lane == lane)
                .map(|stop| {
                    let locator = stop
                        .anchor
                        .clone()
                        .decode()
                        .expect("validated Output anchor");
                    let file = crate::path_utils::rel_path_string(
                        &super::witness_projection::locator_file(workspace, &locator),
                    );
                    format!("{file}@{}", locator.anchor().span().start_byte())
                })
                .collect::<Vec<_>>();
            if anchors.is_empty() {
                continue;
            }
            let consequence_failure;
            let (code, effect, consequence) = match lane {
                TaintBudgetStopLane::Semantic => (
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "stopped taint composition",
                    "the findings of those anchors are not in this result",
                ),
                TaintBudgetStopLane::CompositionProcedures
                | TaintBudgetStopLane::CompositionHops
                | TaintBudgetStopLane::CompositionCallersPerProcedure => (
                    CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    "stopped taint composition",
                    "the findings of those anchors are not in this result",
                ),
                TaintBudgetStopLane::FindingLimit => (
                    CodeQueryDiagnosticCode::TaintFindingTruncated,
                    "omitted findings",
                    "this result lacks the omitted findings of those anchors",
                ),
                TaintBudgetStopLane::WitnessLimit => (
                    CodeQueryDiagnosticCode::TaintFindingTruncated,
                    "truncated witnesses or attribution",
                    "the witnesses or attribution of those anchors are partial",
                ),
                TaintBudgetStopLane::BarrierUndecided => (
                    CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    "left barrier checks omitted or undecided",
                    "the barrier decisions of those anchors are incomplete",
                ),
                TaintBudgetStopLane::ProviderFailed => {
                    consequence_failure = format!(
                        "their findings may be suppressed by a flow the search did not decide (first failure: {})",
                        failure.as_deref().unwrap_or("not recorded"),
                    );
                    (
                        CodeQueryDiagnosticCode::SemanticProviderFailed,
                        "failed a secondary taint search",
                        consequence_failure.as_str(),
                    )
                }
            };
            // A provider failure is not a budget: raising a limit does not help.
            let cause = if lane == TaintBudgetStopLane::ProviderFailed {
                DerivationExecutionCause::Provider
            } else {
                DerivationExecutionCause::Budget
            };
            let shown = anchors
                .iter()
                .take(NAMED_ANCHORS)
                .cloned()
                .collect::<Vec<_>>();
            let more = anchors.len().saturating_sub(NAMED_ANCHORS);
            self.push_diagnostic(
                code,
                Incompleteness::Operational(cause),
                format!(
                    "the {} {effect} at {} anchors ({}{}); {consequence}",
                    lane.limit_name(),
                    anchors.len(),
                    shown.join(", "),
                    if more == 0 {
                        String::new()
                    } else {
                        format!(", and {more} more")
                    },
                ),
            );
        }
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    fn push_context_error(&mut self, error: QueryAnalysisContextError) {
        let code = match error {
            QueryAnalysisContextError::UnresolvedTaintResultReference { .. } => {
                CodeQueryDiagnosticCode::UnresolvedTaintResultReference
            }
            QueryAnalysisContextError::TaintResultRootMismatch => {
                CodeQueryDiagnosticCode::TaintRootMismatch
            }
            QueryAnalysisContextError::TaintPlanReportMismatch => {
                CodeQueryDiagnosticCode::TaintPlanReportMismatch
            }
            QueryAnalysisContextError::StaleTaintResultHandle => {
                CodeQueryDiagnosticCode::TaintHandleStale
            }
            QueryAnalysisContextError::Cancelled => CodeQueryDiagnosticCode::Cancelled,
            _ => CodeQueryDiagnosticCode::TaintRegistrationStale,
        };
        self.push_diagnostic(
            code,
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            error.to_string(),
        );
    }

    fn push_diagnostic(
        &mut self,
        code: CodeQueryDiagnosticCode,
        incompleteness: Incompleteness,
        message: String,
    ) {
        self.diagnostics.push(incomplete_diagnostic(
            code,
            incompleteness,
            "all",
            message,
            Vec::new(),
        ));
    }
}

impl SemanticTaintFindingValue {
    pub(super) fn key(&self) -> &str {
        &self.public.id
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        self.byte_span.clone()
    }

    pub(super) fn public_ref(&self) -> CodeQueryResultRef {
        CodeQueryResultRef::TaintFinding {
            id: self.public.id.clone(),
            path: self.public.path.clone(),
            range: self.public.range,
        }
    }
}
