//! Exact assignment relations over prepared syntax and procedure-local flow.

use super::*;

use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::usages::effects::EffectCoverage;
use crate::query::{AssignmentRelationFilter, AssignmentRelationKind};
use brokk_bifrost_analysis::analyzer::{
    CAssignmentCandidate, CAssignmentSyntaxVerdict, OverwrittenLocalCandidate,
    OverwrittenLocalSourceKind, PlainAssignmentCandidate, PlainAssignmentVerdict,
    c_assignment_candidates, java_overwritten_local_candidates, js_ts_overwritten_local_candidates,
    plain_assignment_candidates,
};
use brokk_bifrost_flow::flow_state::{
    BindingInitializationAnswer, FlowCertainty, FlowRelation, FlowStateAxis, FlowStateCompleteness,
    FlowStateDerivation, FlowStateIncompleteReason, FlowStateRequest, FlowSubject,
    OverwrittenUnreadAnswer, SameEvaluationAnswer, StateEventClass, StateEventRow,
};

const ASSIGNMENT_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.assignment_relation.v1";
const ASSIGNMENT_RELATION_AXES: &[FlowStateAxis] = &[
    FlowStateAxis::BindingEvents,
    FlowStateAxis::ReachingRelation,
    FlowStateAxis::SameEvaluationRelation,
];
const OVERWRITTEN_UNREAD_AXES: &[FlowStateAxis] = &[
    FlowStateAxis::BindingEvents,
    FlowStateAxis::ReachingRelation,
];

fn plain_c_candidate(candidate: CAssignmentCandidate) -> PlainAssignmentCandidate {
    PlainAssignmentCandidate {
        points: candidate.point.into_iter().collect(),
        target: candidate.target,
        rhs_value: candidate.rhs_value,
        range: candidate.range,
        rhs_range: candidate.rhs_range,
        rhs_identifier_range: None,
        next_assignment_start: candidate.next_assignment_start,
        swap_type: None,
        verdict: match candidate.verdict {
            CAssignmentSyntaxVerdict::Supported => PlainAssignmentVerdict::Supported,
            CAssignmentSyntaxVerdict::Excluded => PlainAssignmentVerdict::Excluded,
            CAssignmentSyntaxVerdict::Unknown => PlainAssignmentVerdict::Unknown,
        },
        storage_kind: candidate.storage_kind,
        reason: candidate.reason,
    }
}

pub(super) fn assignment_relation_expansions(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut semantic::SemanticQueryContext<'_>,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
    filter: &AssignmentRelationFilter,
) -> Vec<PipelineExpansion> {
    let mut expansions = if filter.includes(AssignmentRelationKind::SelfAssignment)
        || filter.includes(AssignmentRelationKind::FailedSwap)
    {
        ordinary_assignment_relation_expansions(
            workspace,
            semantic,
            flow_state_cache,
            cancellation,
            diagnostics,
            procedure,
            filter,
        )
    } else {
        Vec::new()
    };
    if filter.includes(AssignmentRelationKind::OverwrittenUnread) {
        expansions.extend(overwritten_unread_expansions(
            workspace,
            semantic,
            flow_state_cache,
            cancellation,
            diagnostics,
            procedure,
        ));
    }
    expansions
}

fn ordinary_assignment_relation_expansions(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut semantic::SemanticQueryContext<'_>,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
    filter: &AssignmentRelationFilter,
) -> Vec<PipelineExpansion> {
    let dialect = procedure.handle.artifact().key().language();
    let language = dialect.language();
    let pilot = matches!(
        language,
        Language::Java | Language::JavaScript | Language::TypeScript | Language::Python
    );
    let self_selected = filter.includes(AssignmentRelationKind::SelfAssignment);
    let swap_selected = filter.includes(AssignmentRelationKind::FailedSwap);
    let self_supported = pilot || dialect == crate::analyzer::LanguageDialect::CppC;
    let swap_supported = pilot || dialect == crate::analyzer::LanguageDialect::CppC;
    let mut unsupported = Vec::new();
    if self_selected && !self_supported {
        unsupported.push(AssignmentRelationKind::SelfAssignment.label());
    }
    if swap_selected && !swap_supported {
        unsupported.push(AssignmentRelationKind::FailedSwap.label());
    }
    if !unsupported.is_empty() {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} has unsupported assignment relations {unsupported:?} for dialect {}",
                procedure.wire_id(),
                dialect.stable_label()
            ),
            exhausted_roots: Vec::new(),
        });
    }
    if !(self_selected && self_supported || swap_selected && swap_supported) {
        return Vec::new();
    }
    let candidates = if dialect == crate::analyzer::LanguageDialect::CppC {
        let candidates = c_assignment_candidates(workspace, &procedure.handle, cancellation);
        brokk_bifrost_analysis::analyzer::PlainAssignmentCandidates {
            rows: candidates.rows.into_iter().map(plain_c_candidate).collect(),
            complete: candidates.complete,
            reason: candidates.reason,
        }
    } else {
        plain_assignment_candidates(workspace, &procedure.handle, cancellation)
    };
    if !candidates.complete {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} has incomplete assignment syntax qualification ({})",
                procedure.wire_id(),
                candidates.reason.unwrap_or("unknown")
            ),
            exhausted_roots: Vec::new(),
        });
    }
    if candidates.rows.is_empty() {
        return Vec::new();
    }
    let self_selected = self_selected && self_supported;
    let pairs = if swap_selected && swap_supported {
        candidates
            .rows
            .iter()
            .enumerate()
            .filter_map(|(first, candidate)| {
                let start = candidate.next_assignment_start?;
                let second = candidates
                    .rows
                    .binary_search_by_key(&start, |row| row.range.start_byte)
                    .ok()?;
                debug_assert!(second == 0 || candidates.rows[second - 1].range.start_byte != start);
                debug_assert!(
                    second + 1 == candidates.rows.len()
                        || candidates.rows[second + 1].range.start_byte != start
                );
                Some((first, second))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if !self_selected && pairs.is_empty() {
        return Vec::new();
    }
    if candidates
        .rows
        .iter()
        .all(|candidate| candidate.verdict == PlainAssignmentVerdict::Excluded)
    {
        return candidates
            .rows
            .into_iter()
            .filter(|_| self_selected)
            .map(|candidate| {
                row(
                    procedure,
                    candidate,
                    None,
                    "excluded",
                    "exact",
                    EffectCoverage::Exhaustive,
                    None,
                )
            })
            .collect();
    }

    let Some(outcome) = semantic.materialized_outcome(procedure.file()) else {
        let expansions = unavailable_expansions(
            procedure,
            &candidates.rows,
            &pairs,
            self_selected,
            "semantic_artifact_unavailable",
        );
        report_open_candidates(procedure, &expansions, diagnostics);
        return expansions;
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
        let expansions = unavailable_expansions(
            procedure,
            &candidates.rows,
            &pairs,
            self_selected,
            "flow_state_unavailable",
        );
        report_open_candidates(procedure, &expansions, diagnostics);
        return expansions;
    };
    let is_c = dialect == crate::analyzer::LanguageDialect::CppC;
    let proof_complete = if is_c {
        flow_state_cache.report_completeness(
            &procedure.wire_id(),
            language,
            &derivation.completeness,
            ASSIGNMENT_RELATION_AXES,
            derivation.generation,
            diagnostics,
        );
        candidates.complete
            && ASSIGNMENT_RELATION_AXES
                .iter()
                .all(|axis| derivation.completeness.covers(*axis))
    } else {
        // The same-evaluation, reaching, and initialization proofs below
        // scope lowering gaps to each assignment. Only a procedure-wide hole
        // in the binding events blocks every candidate. A declared binding
        // that is never established cannot supply a proven write or an
        // initialized read, so it needs no procedure-wide block.
        let reasons = derivation
            .completeness
            .reasons()
            .iter()
            .filter(|reason| {
                reason.blocks(FlowStateAxis::BindingEvents)
                    && !matches!(
                        reason,
                        FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        let binding_events_complete = reasons.is_empty();
        if !binding_events_complete {
            flow_state_cache.report_completeness(
                &procedure.wire_id(),
                language,
                &FlowStateCompleteness::Incomplete { reasons },
                &[FlowStateAxis::BindingEvents],
                derivation.generation,
                diagnostics,
            );
        }
        candidates.complete && binding_events_complete
    };

    let mut expansions = if self_selected {
        candidates
            .rows
            .iter()
            .cloned()
            .map(|candidate| {
                if is_c {
                    qualify_c_candidate(procedure, derivation, proof_complete, candidate)
                } else {
                    qualify_candidate(procedure, derivation, proof_complete, candidate)
                }
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for (first, second) in pairs {
        if let Some(pair) = qualify_failed_swap(
            procedure,
            derivation,
            proof_complete,
            &candidates.rows[first],
            &candidates.rows[second],
        ) {
            expansions.push(pair);
        }
    }
    report_open_candidates(procedure, &expansions, diagnostics);
    expansions
}

fn overwritten_unread_expansions(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut semantic::SemanticQueryContext<'_>,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let dialect = procedure.handle.artifact().key().language();
    if !matches!(
        dialect.language(),
        Language::Java | Language::JavaScript | Language::TypeScript
    ) {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: dialect.language().config_label(),
            message: format!(
                "{} has unsupported overwritten-unread assignment relation for dialect {}",
                procedure.wire_id(),
                dialect.stable_label()
            ),
            exhausted_roots: Vec::new(),
        });
        return Vec::new();
    }
    let candidates = match dialect.language() {
        Language::Java => {
            java_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
        }
        Language::JavaScript | Language::TypeScript => {
            js_ts_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
        }
        _ => unreachable!("dialect was validated"),
    };
    if !candidates.complete {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: dialect.language().config_label(),
            message: format!(
                "{} has incomplete overwritten-local syntax qualification ({})",
                procedure.wire_id(),
                candidates.reason.unwrap_or("unknown")
            ),
            exhausted_roots: Vec::new(),
        });
    }
    if candidates.rows.is_empty() {
        return Vec::new();
    }
    let Some(outcome) = semantic.materialized_outcome(procedure.file()) else {
        let expansions = candidates
            .rows
            .into_iter()
            .map(|candidate| {
                overwritten_row(
                    procedure,
                    candidate,
                    "unknown",
                    "unknown",
                    EffectCoverage::Open,
                    Some("semantic_artifact_unavailable"),
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();
        report_open_candidates(procedure, &expansions, diagnostics);
        return expansions;
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
        let expansions = candidates
            .rows
            .into_iter()
            .map(|candidate| {
                overwritten_row(
                    procedure,
                    candidate,
                    "unknown",
                    "unknown",
                    EffectCoverage::Open,
                    Some("flow_state_unavailable"),
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();
        report_open_candidates(procedure, &expansions, diagnostics);
        return expansions;
    };
    flow_state_cache.report_completeness(
        &procedure.wire_id(),
        dialect.language(),
        &derivation.completeness,
        OVERWRITTEN_UNREAD_AXES,
        derivation.generation,
        diagnostics,
    );
    let uncancelled = CancellationToken::new();
    let mut request = FlowStateRequest::new(cancellation.unwrap_or(&uncancelled));
    let mut expansions = Vec::with_capacity(candidates.rows.len());
    for candidate in candidates.rows {
        match candidate.verdict {
            PlainAssignmentVerdict::Excluded => {
                expansions.push(overwritten_row(
                    procedure,
                    candidate,
                    "excluded",
                    "exact",
                    EffectCoverage::Exhaustive,
                    None,
                    Vec::new(),
                ));
                continue;
            }
            PlainAssignmentVerdict::Unknown => {
                expansions.push(overwritten_row(
                    procedure,
                    candidate,
                    "unknown",
                    "unknown",
                    EffectCoverage::Open,
                    None,
                    Vec::new(),
                ));
                continue;
            }
            PlainAssignmentVerdict::Supported => {}
        }
        let Some(target) = candidate.target.filter(|_| !candidate.points.is_empty()) else {
            expansions.push(overwritten_row(
                procedure,
                candidate,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                Some("semantic_join_missing"),
                Vec::new(),
            ));
            continue;
        };
        // A source assignment can have several cleanup-path copies. A source
        // finding needs the overwrite proof for every reachable copy; a read
        // on any one copy is sufficient to retain the source assignment.
        let mut replacements = Vec::new();
        let mut has_proven_copy = false;
        let mut counterexample = None;
        let mut incomplete = None;
        for &point in &candidate.points {
            let Some(write) = unique_establishment(derivation, point, target) else {
                incomplete = Some("assignment_establishment_ambiguous");
                continue;
            };
            if matches!(
                dialect.language(),
                Language::JavaScript | Language::TypeScript
            ) && candidate.source_kind == OverwrittenLocalSourceKind::PlainAssignment
            {
                match derivation
                    .binding_initialization_before_establishment(&procedure.handle, write.event)
                {
                    BindingInitializationAnswer::Proven => {}
                    BindingInitializationAnswer::Unreachable => continue,
                    BindingInitializationAnswer::MayBeUninitialized
                    | BindingInitializationAnswer::Open { .. } => {
                        incomplete = Some("target_initialization_unproved");
                        continue;
                    }
                }
            }
            match derivation.overwritten_unread_local(&procedure.handle, write.event, &mut request)
            {
                OverwrittenUnreadAnswer::Proven { replacement_events } => {
                    has_proven_copy = true;
                    replacements.extend(replacement_events);
                }
                OverwrittenUnreadAnswer::ReadBeforeOverwrite { .. } => {
                    counterexample = Some("read_before_overwrite");
                }
                OverwrittenUnreadAnswer::PathWithoutOverwrite => {
                    counterexample = Some("path_without_overwrite");
                }
                OverwrittenUnreadAnswer::Unreachable => {}
                OverwrittenUnreadAnswer::Open { reasons } => {
                    incomplete = Some("overwrite_proof_open");
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: dialect.language().config_label(),
                        message: format!(
                            "{} has open overwritten-unread proof at {:?}: {reasons:?}",
                            procedure.wire_id(),
                            candidate.range,
                        ),
                        exhausted_roots: Vec::new(),
                    });
                }
            }
        }
        let expansion = if let Some(reason) = incomplete {
            overwritten_row(
                procedure,
                candidate,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                Some(reason),
                Vec::new(),
            )
        } else if let Some(reason) = counterexample {
            overwritten_row(
                procedure,
                candidate,
                "excluded",
                "exact",
                EffectCoverage::Exhaustive,
                Some(reason),
                Vec::new(),
            )
        } else if has_proven_copy {
            replacements.sort_unstable();
            replacements.dedup();
            overwritten_row(
                procedure,
                candidate,
                "overwritten_unread",
                "exact",
                EffectCoverage::Exhaustive,
                None,
                replacements
                    .into_iter()
                    .map(|event| derivation.event(event).clone())
                    .collect(),
            )
        } else {
            overwritten_row(
                procedure,
                candidate,
                "excluded",
                "exact",
                EffectCoverage::Exhaustive,
                Some("unreachable_write"),
                Vec::new(),
            )
        };
        expansions.push(expansion);
    }
    report_open_candidates(procedure, &expansions, diagnostics);
    expansions
}

fn overwritten_row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: OverwrittenLocalCandidate,
    verdict: &'static str,
    proof: &'static str,
    coverage: EffectCoverage,
    reason: Option<&'static str>,
    replacement_events: Vec<brokk_bifrost_flow::flow_state::StateEventRow>,
) -> PipelineExpansion {
    let storage_kind = if candidate.verdict == PlainAssignmentVerdict::Supported {
        "ordinary_local"
    } else {
        "unknown"
    };
    let mut expansion = row(
        procedure,
        PlainAssignmentCandidate {
            points: candidate.points,
            target: candidate.target,
            rhs_value: candidate.rhs_value,
            range: candidate.range,
            rhs_range: None,
            rhs_identifier_range: None,
            next_assignment_start: None,
            swap_type: None,
            verdict: candidate.verdict,
            storage_kind,
            reason: candidate.reason,
        },
        None,
        verdict,
        proof,
        coverage,
        reason,
    );
    let PipelineValue::AssignmentRelation(value) = &mut expansion.value else {
        unreachable!("row constructs an assignment relation")
    };
    value.relation_kind = "overwritten_unread";
    let mut digest = LengthDelimitedDigest::new(ASSIGNMENT_RELATION_ID_DOMAIN);
    digest.push(value.id.as_bytes());
    digest.push(value.relation_kind.as_bytes());
    value.id = digest.finish().to_string();
    value.replacement_events = replacement_events;
    expansion
}

fn unavailable_expansions(
    procedure: &semantic::SemanticProcedureValue,
    candidates: &[PlainAssignmentCandidate],
    pairs: &[(usize, usize)],
    self_selected: bool,
    reason: &'static str,
) -> Vec<PipelineExpansion> {
    let mut expansions = if self_selected {
        candidates
            .iter()
            .cloned()
            .map(|candidate| {
                row(
                    procedure,
                    candidate,
                    None,
                    "unknown",
                    "unknown",
                    EffectCoverage::Open,
                    Some(reason),
                )
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for &(first, second) in pairs {
        expansions.push(swap_row(
            procedure,
            &candidates[first],
            &candidates[second],
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some(reason),
        ));
    }
    expansions
}

fn report_open_candidates(
    procedure: &semantic::SemanticProcedureValue,
    expansions: &[PipelineExpansion],
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let mut open_reasons = expansions
        .iter()
        .filter_map(|expansion| match &expansion.value {
            PipelineValue::AssignmentRelation(value) if value.coverage == EffectCoverage::Open => {
                Some(value.reason.unwrap_or("unknown"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    open_reasons.sort_unstable();
    open_reasons.dedup();
    if !open_reasons.is_empty() {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
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
                "{} has open assignment-relation candidates: {open_reasons:?}",
                procedure.wire_id()
            ),
            exhausted_roots: Vec::new(),
        });
    }
}

/// Qualify one C candidate. C proves its prior definition by an exact unique
/// reaching origin over a completely covered procedure.
fn qualify_c_candidate(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    flow_complete: bool,
    candidate: PlainAssignmentCandidate,
) -> PipelineExpansion {
    match candidate.verdict {
        PlainAssignmentVerdict::Excluded => {
            return row(
                procedure,
                candidate,
                None,
                "excluded",
                "exact",
                EffectCoverage::Exhaustive,
                None,
            );
        }
        PlainAssignmentVerdict::Unknown => {
            return row(
                procedure,
                candidate,
                None,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                None,
            );
        }
        PlainAssignmentVerdict::Supported => {}
    }
    if !flow_complete {
        return row(
            procedure,
            candidate,
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("flow_state_incomplete"),
        );
    }
    let (&[point], Some(target), Some(rhs_range)) = (
        candidate.points.as_slice(),
        candidate.target,
        candidate.rhs_range,
    ) else {
        return row(
            procedure,
            candidate,
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("semantic_join_missing"),
        );
    };
    let Some(establishment) = unique_establishment(derivation, point, target) else {
        return row(
            procedure,
            candidate,
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("assignment_establishment_ambiguous"),
        );
    };
    let reads = derivation
        .relations
        .iter()
        .filter(|relation| {
            relation.relation == FlowRelation::SameEvaluation
                && relation.certainty == FlowCertainty::Exact
                && relation.source_event == establishment.event
        })
        .filter_map(|relation| derivation.events.get(relation.target_event))
        .filter(|event| {
            event.event_class == StateEventClass::Read
                && matches!(event.subject, FlowSubject::Binding { .. })
                && (same_range(&event.site.range, &rhs_range)
                    || candidate
                        .rhs_identifier_range
                        .as_ref()
                        .is_some_and(|identifier| same_range(&event.site.range, identifier)))
        })
        .collect::<Vec<_>>();
    let Some(read) = reads.first() else {
        return row(
            procedure,
            candidate,
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("rhs_read_join_ambiguous"),
        );
    };
    let rhs_binding = read.subject.value();
    if reads
        .iter()
        .any(|other| other.subject.value() != rhs_binding)
    {
        return row(
            procedure,
            candidate,
            Some(read.value),
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("rhs_read_join_ambiguous"),
        );
    }
    if rhs_binding != target {
        return row(
            procedure,
            candidate,
            Some(read.value),
            "different",
            "exact",
            EffectCoverage::Exhaustive,
            Some("different_binding"),
        );
    }

    let reaching = reads
        .iter()
        .map(|read| {
            derivation
                .relations
                .iter()
                .filter(|relation| {
                    relation.relation == FlowRelation::Reaching
                        && relation.target_event == read.event
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if reaching.iter().all(|relations| {
        relations.len() == 1
            && relations[0].certainty == FlowCertainty::Exact
            && relations[0].source_event != establishment.event
    }) {
        return row(
            procedure,
            candidate,
            Some(read.value),
            "self_assignment",
            "exact",
            EffectCoverage::Exhaustive,
            None,
        );
    }
    if reaching.iter().all(Vec::is_empty) {
        return row(
            procedure,
            candidate,
            Some(read.value),
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("initialization_unproved"),
        );
    }
    row(
        procedure,
        candidate,
        Some(read.value),
        "unknown",
        "unknown",
        EffectCoverage::Open,
        Some("prior_definition_not_exact"),
    )
}

/// Qualify one Java, JavaScript, TypeScript, or Python candidate.
///
/// Every lowered copy of the assignment must read the target binding itself
/// in its own evaluation, and the target must be initialized at that read.
/// Only gaps that can reach this evaluation or this binding's initialization
/// keep the candidate open; a gap elsewhere in the procedure does not.
fn qualify_candidate(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    flow_complete: bool,
    candidate: PlainAssignmentCandidate,
) -> PipelineExpansion {
    match candidate.verdict {
        PlainAssignmentVerdict::Excluded => {
            return row(
                procedure,
                candidate,
                None,
                "excluded",
                "exact",
                EffectCoverage::Exhaustive,
                None,
            );
        }
        PlainAssignmentVerdict::Unknown => {
            return row(
                procedure,
                candidate,
                None,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                None,
            );
        }
        PlainAssignmentVerdict::Supported => {}
    }
    if !flow_complete {
        return row(
            procedure,
            candidate,
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("flow_state_incomplete"),
        );
    }
    let Some(target) = candidate.target.filter(|_| !candidate.points.is_empty()) else {
        return row(
            procedure,
            candidate,
            None,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some("semantic_join_missing"),
        );
    };
    let mut proven_read = None;
    let mut open = None;
    for &point in &candidate.points {
        let Some(establishment) = unique_establishment(derivation, point, target) else {
            return row(
                procedure,
                candidate,
                None,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                Some("assignment_establishment_ambiguous"),
            );
        };
        let Ok(reads) = rhs_reads(procedure, derivation, &candidate, establishment) else {
            return row(
                procedure,
                candidate,
                None,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                Some("same_evaluation_open"),
            );
        };
        let Some(read) = reads.first() else {
            return row(
                procedure,
                candidate,
                None,
                "unknown",
                "unknown",
                EffectCoverage::Open,
                Some("rhs_read_join_ambiguous"),
            );
        };
        let rhs_binding = read.subject.value();
        if reads
            .iter()
            .any(|other| other.subject.value() != rhs_binding)
        {
            return row(
                procedure,
                candidate,
                Some(read.value),
                "unknown",
                "unknown",
                EffectCoverage::Open,
                Some("rhs_read_join_ambiguous"),
            );
        }
        if rhs_binding != target {
            return row(
                procedure,
                candidate,
                Some(read.value),
                "different",
                "exact",
                EffectCoverage::Exhaustive,
                Some("different_binding"),
            );
        }
        for read in &reads {
            match derivation.binding_initialization_at_read(&procedure.handle, read.event) {
                BindingInitializationAnswer::Proven => proven_read = Some(read.value),
                BindingInitializationAnswer::Unreachable => {}
                BindingInitializationAnswer::MayBeUninitialized => {
                    open.get_or_insert((read.value, "initialization_unproved"));
                }
                BindingInitializationAnswer::Open { .. } => {
                    open = Some((read.value, "initialization_proof_open"));
                }
            }
        }
    }
    if let Some((read, reason)) = open {
        return row(
            procedure,
            candidate,
            Some(read),
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some(reason),
        );
    }
    let Some(read) = proven_read else {
        return row(
            procedure,
            candidate,
            None,
            "excluded",
            "exact",
            EffectCoverage::Exhaustive,
            Some("unreachable_read"),
        );
    };
    row(
        procedure,
        candidate,
        Some(read),
        "self_assignment",
        "exact",
        EffectCoverage::Exhaustive,
        None,
    )
}

fn qualify_failed_swap(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    flow_complete: bool,
    first: &PlainAssignmentCandidate,
    second: &PlainAssignmentCandidate,
) -> Option<PipelineExpansion> {
    if first.verdict == PlainAssignmentVerdict::Excluded
        || second.verdict == PlainAssignmentVerdict::Excluded
    {
        return None;
    }
    let open = |rhs_read, reason| {
        Some(swap_row(
            procedure,
            first,
            second,
            rhs_read,
            "unknown",
            "unknown",
            EffectCoverage::Open,
            Some(reason),
        ))
    };
    if first.verdict == PlainAssignmentVerdict::Unknown
        || second.verdict == PlainAssignmentVerdict::Unknown
    {
        return open(None, "assignment_pair_unqualified");
    }
    let (first_target, second_target) = (first.target?, second.target?);
    if first_target == second_target {
        return None;
    }
    if !flow_complete {
        return open(None, "flow_state_incomplete");
    }
    let Some(first_writes) = first
        .points
        .iter()
        .map(|point| unique_establishment(derivation, *point, first_target))
        .collect::<Option<Vec<_>>>()
        .filter(|writes| !writes.is_empty())
    else {
        return open(None, "first_write_unproved");
    };
    let Some(second_writes) = second
        .points
        .iter()
        .map(|point| unique_establishment(derivation, *point, second_target))
        .collect::<Option<Vec<_>>>()
        .filter(|writes| !writes.is_empty())
    else {
        return open(None, "second_write_unproved");
    };
    // Each lowered copy of the second assignment must read the value that
    // its own copy of the first assignment wrote. An exact reaching row
    // proves that the first write dominates the read with no other write
    // between them. The two statements are adjacent in one block, so no
    // source construct can transfer control between them.
    let mut proven_read = None;
    for second_write in second_writes {
        let second_read = match rhs_reads(procedure, derivation, second, second_write) {
            Ok(reads) => match reads.as_slice() {
                [read] => *read,
                _ => return open(None, "second_read_unproved"),
            },
            Err(_) => return open(None, "same_evaluation_open"),
        };
        if second_read.subject
            != (FlowSubject::Binding {
                value: first_target,
            })
        {
            return None;
        }
        let reaching = derivation
            .relations
            .iter()
            .filter(|relation| {
                relation.relation == FlowRelation::Reaching
                    && relation.target_event == second_read.event
            })
            .collect::<Vec<_>>();
        let first_write = match reaching.as_slice() {
            [relation] if relation.certainty == FlowCertainty::Exact => first_writes
                .iter()
                .find(|write| write.event == relation.source_event),
            _ => None,
        };
        let Some(first_write) = first_write else {
            return open(Some(second_read.value), "ordered_write_unproved");
        };
        let first_read = match rhs_reads(procedure, derivation, first, first_write) {
            Ok(reads) => match reads.as_slice() {
                [read] => *read,
                _ => return open(Some(second_read.value), "first_read_unproved"),
            },
            Err(_) => return open(Some(second_read.value), "same_evaluation_open"),
        };
        if first_read.subject
            != (FlowSubject::Binding {
                value: second_target,
            })
        {
            return None;
        }
        if procedure.handle.artifact().key().language().language() == Language::Java
            && (first.swap_type.is_none() || first.swap_type != second.swap_type)
        {
            return open(Some(second_read.value), "assignment_conversion_unproved");
        }
        match derivation.binding_initialization_at_read(&procedure.handle, first_read.event) {
            BindingInitializationAnswer::Proven => proven_read = Some(second_read.value),
            BindingInitializationAnswer::Unreachable => {}
            BindingInitializationAnswer::MayBeUninitialized => {
                return open(
                    Some(second_read.value),
                    "first_value_initialization_unproved",
                );
            }
            BindingInitializationAnswer::Open { .. } => {
                return open(Some(second_read.value), "initialization_proof_open");
            }
        }
    }
    Some(swap_row(
        procedure,
        first,
        second,
        Some(proven_read?),
        "failed_swap",
        "exact",
        EffectCoverage::Exhaustive,
        None,
    ))
}

#[allow(clippy::too_many_arguments)]
fn swap_row(
    procedure: &semantic::SemanticProcedureValue,
    first: &PlainAssignmentCandidate,
    second: &PlainAssignmentCandidate,
    rhs_read: Option<crate::analyzer::semantic::ValueId>,
    verdict: &'static str,
    proof: &'static str,
    coverage: EffectCoverage,
    reason: Option<&'static str>,
) -> PipelineExpansion {
    let mut pair = first.clone();
    pair.range.end_byte = second.range.end_byte;
    pair.range.end_line = second.range.end_line;
    let mut expansion = row(procedure, pair, rhs_read, verdict, proof, coverage, reason);
    let PipelineValue::AssignmentRelation(value) = &mut expansion.value else {
        unreachable!("row constructs an assignment relation")
    };
    value.relation_kind = "failed_swap";
    expansion
}

fn unique_establishment(
    derivation: &FlowStateDerivation,
    point: crate::analyzer::semantic::ProgramPointId,
    target: crate::analyzer::semantic::ValueId,
) -> Option<&StateEventRow> {
    let mut events = derivation.events.iter().filter(|event| {
        event.point == point
            && event.event_class == StateEventClass::Establish
            && event.subject == FlowSubject::Binding { value: target }
    });
    let event = events.next()?;
    events.next().is_none().then_some(event)
}

/// The binding reads spelled by the candidate's RHS that feed this copy of
/// the assignment. A read that feeds another lowered copy is omitted. An open
/// same-evaluation account returns its reasons.
fn rhs_reads<'a>(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &'a FlowStateDerivation,
    candidate: &PlainAssignmentCandidate,
    establishment: &StateEventRow,
) -> Result<Vec<&'a StateEventRow>, Vec<FlowStateIncompleteReason>> {
    let Some(rhs) = candidate.rhs_range.as_ref() else {
        return Ok(Vec::new());
    };
    let mut reads = Vec::new();
    for read in derivation
        .relations
        .iter()
        .filter(|relation| {
            relation.relation == FlowRelation::SameEvaluation
                && relation.certainty == FlowCertainty::Exact
                && relation.source_event == establishment.event
        })
        .filter_map(|relation| derivation.events.get(relation.target_event))
        .filter(|event| {
            event.event_class == StateEventClass::Read
                && matches!(event.subject, FlowSubject::Binding { .. })
                && (same_range(&event.site.range, rhs)
                    || candidate
                        .rhs_identifier_range
                        .as_ref()
                        .is_some_and(|identifier| same_range(&event.site.range, identifier)))
        })
    {
        match derivation.read_feeds_establishment(
            &procedure.handle,
            read.event,
            establishment.event,
        ) {
            SameEvaluationAnswer::Closed => reads.push(read),
            SameEvaluationAnswer::Outside => {}
            SameEvaluationAnswer::Open { reasons } => return Err(reasons),
        }
    }
    Ok(reads)
}

#[allow(clippy::too_many_arguments)]
fn row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: PlainAssignmentCandidate,
    rhs_read: Option<crate::analyzer::semantic::ValueId>,
    verdict: &'static str,
    proof: &'static str,
    coverage: EffectCoverage,
    reason: Option<&'static str>,
) -> PipelineExpansion {
    let procedure_id = procedure.wire_id();
    let assignment_point_id = candidate.points.first().and_then(|&point| {
        procedure
            .handle
            .point_handle(point)
            .map(|handle| semantic::program_point_wire_id(&handle))
    });
    let mut digest = LengthDelimitedDigest::new(ASSIGNMENT_RELATION_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(&(candidate.range.start_byte as u64).to_le_bytes());
    digest.push(&(candidate.range.end_byte as u64).to_le_bytes());
    digest.push(verdict.as_bytes());
    pipeline_expansion(PipelineValue::AssignmentRelation(Box::new(
        AssignmentRelationValue {
            file: procedure.file().clone(),
            range: candidate.range,
            ast_id: None,
            id: digest.finish().to_string(),
            procedure_id,
            assignment_point_id,
            target_value_id: candidate.target.map(|value| u64::from(value.get())),
            rhs_value_id: rhs_read
                .or(candidate.rhs_value)
                .map(|value| u64::from(value.get())),
            relation_kind: "self_assignment",
            storage_kind: candidate.storage_kind,
            verdict,
            proof,
            coverage,
            reason: reason.or((candidate.reason != "qualified").then_some(candidate.reason)),
            replacement_events: Vec::new(),
        },
    )))
}

fn same_range(left: &Range, right: &Range) -> bool {
    left.start_byte == right.start_byte && left.end_byte == right.end_byte
}
