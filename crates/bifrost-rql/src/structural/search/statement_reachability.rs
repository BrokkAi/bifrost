//! Exact statement reachability rows from production CFG entries.

use super::results::{
    CodeQueryRange, CodeQueryResultRef, CodeQueryStatementReachability, DetailedCodeQueryKey,
};
use super::*;
use crate::analyzer::semantic::LengthDelimitedDigest;
use brokk_bifrost_analysis::analyzer::read_ledger::reason as derivation_reason;
use brokk_bifrost_analysis::analyzer::semantic::{
    StatementAssessment, StatementCoordinates, StatementVerdict, statement_assessments,
};

const STATEMENT_REACHABILITY_ID_DOMAIN: &[u8] = b"bifrost.code_query.statement_reachability.v1";

#[derive(Debug, Clone)]
pub(super) struct StatementReachabilityValue {
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
    pub(super) row: CodeQueryStatementReachability,
}

fn public_range(coordinates: StatementCoordinates) -> CodeQueryRange {
    CodeQueryRange {
        start_line: coordinates.start_line,
        start_column: coordinates.start_column,
        end_line: coordinates.end_line,
        end_column: coordinates.end_column,
    }
}

fn row(
    procedure: &semantic::SemanticProcedureValue,
    assessment: StatementAssessment,
) -> PipelineExpansion {
    let procedure_id = procedure.wire_id();
    let mut digest = LengthDelimitedDigest::new(STATEMENT_REACHABILITY_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(&(assessment.range.start_byte as u64).to_le_bytes());
    digest.push(&(assessment.range.end_byte as u64).to_le_bytes());
    let (verdict, reason) = match assessment.verdict {
        StatementVerdict::Reachable => ("reachable", None),
        StatementVerdict::Unreachable => ("unreachable", None),
        StatementVerdict::Open(reason) => ("open", Some(reason.to_owned())),
    };
    pipeline_expansion(PipelineValue::StatementReachability(Box::new(
        StatementReachabilityValue {
            file: procedure.file().clone(),
            anchor: assessment.range,
            row: CodeQueryStatementReachability {
                id: digest.finish().to_string(),
                procedure_id,
                path: rel_path_string(procedure.file()),
                language: procedure
                    .handle
                    .artifact()
                    .key()
                    .language()
                    .language()
                    .config_label(),
                range: public_range(assessment.coordinates),
                statement_kind: assessment.kind,
                verdict,
                reason,
            },
        },
    )))
}

pub(super) fn detailed_key(value: &StatementReachabilityValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::StatementReachability {
        id: value.row.id.clone(),
        procedure_id: value.row.procedure_id.clone(),
    }
}

pub(super) fn result_ref(value: &StatementReachabilityValue) -> CodeQueryResultRef {
    CodeQueryResultRef::StatementReachability {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        procedure_id: value.row.procedure_id.clone(),
        statement_kind: value.row.statement_kind,
        verdict: value.row.verdict,
    }
}

fn report_open(
    analyzer: &dyn IAnalyzer,
    procedure: &semantic::SemanticProcedureValue,
    reason: &str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let (code, cause) = CodeQueryDiagnosticCode::from_execution_reason(
        CodeQueryDiagnosticCode::StatementReachabilityDerivationIncomplete,
        reason,
    );
    let mut diagnostic = super::QueryExecutionState::diagnostic(
        analyzer,
        super::incomplete_diagnostic(
            code,
            match cause {
                Some(cause) => brokk_bifrost_rql::Incompleteness::Operational(cause),
                None => brokk_bifrost_rql::Incompleteness::Content,
            },
            procedure
                .handle
                .artifact()
                .key()
                .language()
                .language()
                .config_label(),
            format!(
                "{} has open statement reachability evidence: {reason}",
                procedure.wire_id()
            ),
            Vec::new(),
        ),
        cause,
    );
    // Every statement row of a procedure is a row of the procedure's file.
    diagnostic.withheld_rows_path = Some(rel_path_string(procedure.file()));
    diagnostics.push(diagnostic);
}

pub(super) fn statement_reachability_expansions(
    workspace: &WorkspaceAnalyzer,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let assessments = statement_assessments(workspace, &procedure.handle, cancellation);
    if !assessments.complete {
        report_open(
            workspace.analyzer(),
            procedure,
            assessments
                .reason
                .unwrap_or(derivation_reason::ASSESSMENT_INCOMPLETE),
            diagnostics,
        );
        return Vec::new();
    }
    let mut rows = Vec::with_capacity(assessments.rows.len());
    for assessment in assessments.rows {
        if let StatementVerdict::Open(reason) = assessment.verdict {
            report_open(workspace.analyzer(), procedure, reason, diagnostics);
        }
        rows.push(row(procedure, assessment));
    }
    rows
}
