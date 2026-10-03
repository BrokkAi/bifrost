//! Source-loop repetition rows over exact procedure control flow.

use super::results::{
    CodeQueryLoopReason, CodeQueryLoopRelation, CodeQueryRange, CodeQueryResultRef,
    DetailedCodeQueryKey,
};
use super::*;
use crate::analyzer::semantic::LengthDelimitedDigest;
use brokk_bifrost_analysis::analyzer::{LoopCandidate, LoopCoordinates, LoopKind, loop_candidates};
use brokk_bifrost_flow::flow_state::{
    FlowStateAxis, FlowStateRequest, LoopRepeatAnswer, LoopRepeatIncompleteReason, LoopSourceKind,
    LoopSourceSite,
};

const LOOP_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.loop_relation.v1";
const LOOP_AXES: &[FlowStateAxis] = &[FlowStateAxis::DominanceRelation];

#[derive(Debug, Clone)]
pub(super) struct LoopRelationValue {
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
    pub(super) row: CodeQueryLoopRelation,
}

fn public_range(coordinates: LoopCoordinates) -> CodeQueryRange {
    CodeQueryRange {
        start_line: coordinates.start_line,
        start_column: coordinates.start_column,
        end_line: coordinates.end_line,
        end_column: coordinates.end_column,
    }
}

fn row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: LoopCandidate,
    verdict: &'static str,
    reasons: Vec<CodeQueryLoopReason>,
    repeat_edge_id: Option<String>,
) -> PipelineExpansion {
    let procedure_id = procedure.wire_id();
    let mut digest = LengthDelimitedDigest::new(LOOP_RELATION_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(&(candidate.range.start_byte as u64).to_le_bytes());
    digest.push(&(candidate.range.end_byte as u64).to_le_bytes());
    pipeline_expansion(PipelineValue::LoopRelation(Box::new(LoopRelationValue {
        file: procedure.file().clone(),
        anchor: candidate.range,
        row: CodeQueryLoopRelation {
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
            range: public_range(candidate.coordinates),
            body_range: candidate.body_coordinates.map(public_range),
            loop_kind: match candidate.kind {
                LoopKind::While => "while",
                LoopKind::For => "for",
                LoopKind::Do => "do",
            },
            verdict,
            reasons,
            repeat_edge_id,
        },
    })))
}

pub(super) fn detailed_key(value: &LoopRelationValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::LoopRelation {
        id: value.row.id.clone(),
        procedure_id: value.row.procedure_id.clone(),
    }
}

pub(super) fn result_ref(value: &LoopRelationValue) -> CodeQueryResultRef {
    CodeQueryResultRef::LoopRelation {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        procedure_id: value.row.procedure_id.clone(),
        loop_kind: value.row.loop_kind,
        verdict: value.row.verdict,
    }
}

fn report_open(
    procedure: &semantic::SemanticProcedureValue,
    reason: impl std::fmt::Debug,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: procedure
            .handle
            .artifact()
            .key()
            .language()
            .language()
            .config_label(),
        message: format!(
            "{} has open loop relation evidence: {reason:?}",
            procedure.wire_id()
        ),
        exhausted_roots: Vec::new(),
    });
}

pub(super) fn loop_relation_expansions(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut semantic::SemanticQueryContext<'_>,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let candidates = loop_candidates(workspace, &procedure.handle, cancellation);
    if !candidates.complete {
        report_open(procedure, candidates.reason, diagnostics);
        return Vec::new();
    }
    if candidates.rows.is_empty() {
        return Vec::new();
    }
    let Some(outcome) = semantic.materialized_outcome(procedure.file()) else {
        report_open(procedure, "semantic_artifact_unavailable", diagnostics);
        return candidates
            .rows
            .into_iter()
            .map(|candidate| {
                row(
                    procedure,
                    candidate,
                    "open",
                    vec![CodeQueryLoopReason::Source {
                        detail: "semantic_artifact_unavailable".into(),
                    }],
                    None,
                )
            })
            .collect();
    };
    let state = flow_state_cache.for_materialized_procedure(
        workspace,
        procedure.file(),
        outcome,
        &procedure.handle,
        cancellation,
    );
    let Some(derivation) = state
        .procedures
        .iter()
        .find(|derived| derived.procedure == procedure.handle.id())
    else {
        report_open(procedure, "flow_state_unavailable", diagnostics);
        return candidates
            .rows
            .into_iter()
            .map(|candidate| {
                row(
                    procedure,
                    candidate,
                    "open",
                    vec![CodeQueryLoopReason::Flow {
                        detail: "flow_state_unavailable".into(),
                    }],
                    None,
                )
            })
            .collect();
    };
    flow_state_cache.report_completeness(
        &procedure.wire_id(),
        procedure.handle.artifact().key().language().language(),
        &derivation.completeness,
        LOOP_AXES,
        derivation.generation,
        diagnostics,
    );
    let token = cancellation.cloned().unwrap_or_default();
    // One budget is shared by all loop sites in this procedure.
    let mut request = FlowStateRequest::new(&token);
    candidates
        .rows
        .into_iter()
        .map(|candidate| {
            if let Some(reason) = candidate.reason {
                report_open(procedure, reason, diagnostics);
                return row(
                    procedure,
                    candidate,
                    "open",
                    vec![CodeQueryLoopReason::Source {
                        detail: reason.into(),
                    }],
                    None,
                );
            }
            let site = candidate.site.expect("qualified loop has a source site");
            let kind = match site.kind {
                LoopKind::While => LoopSourceKind::While,
                LoopKind::For => LoopSourceKind::For,
                LoopKind::Do => LoopSourceKind::Do,
            };
            let answer = derivation.loop_body_reaches_own_repeat(
                &procedure.handle,
                LoopSourceSite {
                    kind,
                    loop_span: site.loop_span,
                    body_span: site.body_span,
                    condition_span: site.condition_span,
                },
                &mut request,
            );
            match answer {
                LoopRepeatAnswer::MayRepeat { edge } => row(
                    procedure,
                    candidate,
                    "excluded",
                    Vec::new(),
                    procedure
                        .handle
                        .control_edge_handle(edge)
                        .map(|edge| semantic::control_edge_wire_id(&edge)),
                ),
                LoopRepeatAnswer::NoRepeat {
                    intentional_constant_false_do: false,
                } => row(procedure, candidate, "proven", Vec::new(), None),
                LoopRepeatAnswer::NoRepeat {
                    intentional_constant_false_do: true,
                } => row(
                    procedure,
                    candidate,
                    "excluded",
                    vec![CodeQueryLoopReason::IntentionalConstantFalseDo],
                    None,
                ),
                LoopRepeatAnswer::UnreachableBody => row(
                    procedure,
                    candidate,
                    "excluded",
                    vec![CodeQueryLoopReason::UnreachableBody],
                    None,
                ),
                LoopRepeatAnswer::Open { reasons } => {
                    report_open(procedure, &reasons, diagnostics);
                    let reasons = reasons
                        .into_iter()
                        .map(|reason| match reason {
                            LoopRepeatIncompleteReason::Flow(reason) => CodeQueryLoopReason::Flow {
                                detail: format!("{reason:?}"),
                            },
                            LoopRepeatIncompleteReason::SourceJoin { stage } => {
                                CodeQueryLoopReason::SourceJoin {
                                    stage: stage.into(),
                                }
                            }
                            LoopRepeatIncompleteReason::GuardEvidence => {
                                CodeQueryLoopReason::GuardEvidence
                            }
                            LoopRepeatIncompleteReason::ControlEvidence => {
                                CodeQueryLoopReason::ControlEvidence
                            }
                        })
                        .collect();
                    row(procedure, candidate, "open", reasons, None)
                }
            }
        })
        .collect()
}
