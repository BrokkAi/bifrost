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
                LoopKind::While | LoopKind::Until => "while",
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
    analyzer: &dyn IAnalyzer,
    procedure: &semantic::SemanticProcedureValue,
    reason: impl std::fmt::Debug,
    cause: Option<DerivationExecutionCause>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let mut diagnostic = super::QueryExecutionState::diagnostic(
        analyzer,
        super::incomplete_diagnostic(
            CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete,
            procedure
                .handle
                .artifact()
                .key()
                .language()
                .language()
                .config_label(),
            format!(
                "{} has open loop relation evidence: {reason:?}",
                procedure.wire_id()
            ),
            Vec::new(),
        ),
        cause,
    );
    diagnostic.source = procedure.diagnostic_source();
    diagnostics.push(diagnostic);
}

pub(super) fn loop_relation_expansions(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut semantic::SemanticQueryContext<'_>,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let candidates = match loop_candidates(workspace, &procedure.handle, cancellation) {
        Ok(candidates) => candidates,
        Err(reason) => {
            let cause = match &reason {
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::Cancelled => Some(DerivationExecutionCause::Cancelled),
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::StoreFailure(_)
                | brokk_bifrost_analysis::analyzer::QueryReadIncomplete::StructureUnavailable(_) => Some(DerivationExecutionCause::Provider),
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(_)
                | brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ArtifactUnavailable(_)
                | brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(_) => None,
            };
            report_open(workspace.analyzer(), procedure, reason, cause, diagnostics);
            return Vec::new();
        }
    };
    if !candidates.complete {
        report_open(
            workspace.analyzer(),
            procedure,
            candidates.reason,
            candidates
                .reason
                .and_then(DerivationExecutionCause::from_reason),
            diagnostics,
        );
        return Vec::new();
    }
    if candidates.rows.is_empty() {
        return Vec::new();
    }
    let Some(outcome) = semantic.materialized_outcome(procedure.file()) else {
        report_open(
            workspace.analyzer(),
            procedure,
            "semantic_artifact_unavailable",
            Some(DerivationExecutionCause::Provider),
            diagnostics,
        );
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
        report_open(
            workspace.analyzer(),
            procedure,
            "flow_state_unavailable",
            Some(DerivationExecutionCause::Provider),
            diagnostics,
        );
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
        workspace.analyzer(),
        &procedure.wire_id(),
        Some(procedure),
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
                report_open(workspace.analyzer(), procedure, reason, None, diagnostics);
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
                LoopKind::Until => LoopSourceKind::Until,
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
                    let cause = reasons.iter().find_map(|reason| match reason {
                        LoopRepeatIncompleteReason::Flow(reason) => match reason {
                            brokk_bifrost_flow::flow_state::FlowStateIncompleteReason::Cancelled => Some(DerivationExecutionCause::Cancelled),
                            brokk_bifrost_flow::flow_state::FlowStateIncompleteReason::BudgetExhausted { .. } => Some(DerivationExecutionCause::Budget),
                            _ => None,
                        },
                        _ => None,
                    });
                    report_open(workspace.analyzer(), procedure, &reasons, cause, diagnostics);
                    let flow_reasons = reasons
                        .iter()
                        .filter_map(|reason| match reason {
                            LoopRepeatIncompleteReason::Flow(reason) => Some(reason.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    diagnostics
                        .last_mut()
                        .expect("report_open emits a diagnostic")
                        .related = procedure.related_flow_reasons(&flow_reasons);
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

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic::ContentIdentity;
    use brokk_bifrost_analysis::analyzer::store::StoreError;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, AnalyzerQueryScope, QueryReadIncomplete,
    };
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#5385: loop read failures lost their typed cause and affected source")]
    fn loop_read_failure_preserves_typed_cause_and_exact_procedure_source() {
        // Resolve the real procedure before opening a failed request, while
        // its loop-candidate cache is still cold.
        let source =
            "// header\nfunction check(flag) {\n  while (flag) { return 1; }\n  return 0;\n}\n";
        let fixture = super::super::tests::inline_project::InlineTestProject::with_language(
            Language::JavaScript,
        )
        .file("subject.js", source)
        .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let file = fixture.file("subject.js");
        let mut context = semantic::SemanticQueryContext::new(
            &workspace,
            None,
            CodeQuerySemanticLimits::default(),
        );
        let procedures = context.procedure_of_source_range(
            &file,
            Range {
                start_byte: 10,
                end_byte: source.len() - 1,
                start_line: 2,
                end_line: 5,
            },
            ContentIdentity::hash_bytes(source.as_bytes()),
        );
        let [procedure] = procedures.as_slice() else {
            panic!(
                "expected exact function procedure, got {:?}",
                procedures
                    .iter()
                    .map(|procedure| procedure.public())
                    .collect::<Vec<_>>()
            );
        };
        let expected = CodeQuerySourceSpan {
            path: "subject.js".to_owned(),
            range: CodeQueryRange {
                start_line: 2,
                start_column: 1,
                end_line: 5,
                end_column: 2,
            },
            start_byte: 10,
            end_byte: source.len() - 1,
        };
        {
            // Existing request-failure injection exercises nested cache reads;
            // this is not physical corruption or a claim about hiredis' cause.
            let scope = AnalyzerQueryScope::new(workspace.analyzer());
            let marker = "#5385 injected inherited loop read failure";
            scope.record_store_error_for_test(StoreError::new(marker));
            let failure = loop_candidates(&workspace, &procedure.handle, None)
                .expect_err("cold loop read must preserve the inherited failure");
            assert!(
                matches!(
                    &failure,
                    QueryReadIncomplete::StoreFailure(error) if error.to_string() == marker
                ),
                "{failure:?}"
            );
            let expected_detail = format!("{failure:?}");
            let mut diagnostics = Vec::new();
            let rows = loop_relation_expansions(
                &workspace,
                &mut context,
                &mut FlowStateTraversalCache::default(),
                None,
                &mut diagnostics,
                procedure,
            );
            assert!(rows.is_empty(), "failed read must not publish loop rows");
            let [diagnostic] = diagnostics.as_slice() else {
                panic!("expected one attributed read failure: {diagnostics:?}");
            };
            assert_eq!(
                diagnostic.code,
                CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete
            );
            assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
            assert!(
                diagnostic.message.contains(&expected_detail),
                "{diagnostic:?}"
            );
            assert!(
                diagnostic.message.contains("kind: Generic"),
                "{diagnostic:?}"
            );
            assert_eq!(diagnostic.source.as_ref(), Some(&expected));
            assert!(matches!(
                scope.read_completion(),
                Err(QueryReadIncomplete::StoreFailure(error)) if error.to_string() == marker
            ));
        }
        // The pre-existing syntax reason uses the same affected source without
        // being misclassified as a query-read error.
        let mut diagnostics = Vec::new();
        report_open(
            workspace.analyzer(),
            procedure,
            Some("procedure_syntax_recovery"),
            None,
            &mut diagnostics,
        );
        assert!(diagnostics[0].message.contains("procedure_syntax_recovery"));
        assert_eq!(diagnostics[0].source.as_ref(), Some(&expected));

        // Both the failed initialization above and cancellation's direct-build
        // bypass must leave the same procedure retryable in a fresh request.
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled = loop_candidates(&workspace, &procedure.handle, Some(&cancellation))
            .expect("explicit cancellation retains the direct-build path");
        assert!(!cancelled.complete);
        assert_eq!(cancelled.reason, Some("cancelled"));
        let healthy = loop_candidates(&workspace, &procedure.handle, None)
            .expect("healthy retry must not reuse failed or cancelled evidence");
        assert!(healthy.complete, "{healthy:?}");
        assert_eq!(healthy.rows.len(), 1);
        let first = workspace
            .analyzer()
            .loop_candidates_for(&workspace, &procedure.handle, None)
            .expect("successful cached read");
        let second = workspace
            .analyzer()
            .loop_candidates_for(&workspace, &procedure.handle, None)
            .expect("successful cached reread");
        assert!(std::sync::Arc::ptr_eq(&first, &second));

        let mut flow_cache = FlowStateTraversalCache::default();
        let mut control_diagnostics = Vec::new();
        let rows = loop_relation_expansions(
            &workspace,
            &mut context,
            &mut flow_cache,
            None,
            &mut control_diagnostics,
            procedure,
        );
        assert!(control_diagnostics.is_empty(), "{control_diagnostics:?}");
        assert_eq!(rows.len(), 1, "supported loop retains its result");
        let PipelineValue::LoopRelation(value) = &rows[0].value else {
            panic!("expected loop relation");
        };
        assert_eq!(value.row.verdict, "proven");
    }
}
