use super::witness_projection::{locator_file, public_taint_event_id};
use super::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryResultRef,
    CodeQueryTaintFinding, CodeQueryTaintLimits, SemanticProcedureValue,
};
use crate::analyzer::structural::analysis_context::{
    QueryAnalysisContext, QueryAnalysisContextError, TaintResultRef,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;

#[derive(Default)]
pub(super) struct TaintQueryState {
    diagnostics: Vec<CodeQueryDiagnostic>,
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
                "taint finding projection was cancelled".to_owned(),
            );
            return Vec::new();
        }
        let Some(analysis_context) = analysis_context else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedTaintResultReference,
                format!("taint result reference `{taint_ref}` was not supplied by the host"),
            );
            return Vec::new();
        };
        let Some(handle) = analysis_context.taint_result_handle(taint_ref) else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedTaintResultReference,
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
                self.push_context_error(error);
                return Vec::new();
            }
        };
        let locations = result
            .report()
            .findings()
            .iter()
            .map(|finding| {
                let sink = finding.key().sink();
                let locator = sink.site();
                let span = locator.anchor().span();
                (
                    public_taint_event_id(result.projection_scope(), "sink", sink),
                    (
                        locator_file(workspace, locator),
                        span.start_byte() as usize..span.end_byte() as usize,
                    ),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let projected = match result.project_findings(workspace, limits.projection_limits()) {
            Ok(projected) => projected,
            Err(error) => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::TaintProjectionFailed,
                    error.to_string(),
                );
                return Vec::new();
            }
        };
        let retained = projected.len().min(limits.max_findings).min(max_findings);
        if retained < projected.len() {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::TaintFindingTruncated,
                format!(
                    "taint finding projection retained {retained} of {} findings",
                    projected.len()
                ),
            );
        }
        projected
            .into_iter()
            .take(retained)
            .map(|public| {
                let (file, byte_span) = locations
                    .get(&public.sink_event_id)
                    .expect("projected taint finding must retain its sink location")
                    .clone();
                SemanticTaintFindingValue {
                    public,
                    file,
                    byte_span,
                }
            })
            .collect()
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
        self.push_diagnostic(code, error.to_string());
    }

    fn push_diagnostic(&mut self, code: CodeQueryDiagnosticCode, message: String) {
        self.diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "all",
            message,
        });
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
