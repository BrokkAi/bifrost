//! Exact assignment relations over prepared syntax and procedure-local flow.

use super::*;
use brokk_bifrost_analysis::analyzer::declaration_range::DeclarationNameRangeContext;
use brokk_bifrost_analysis::analyzer::read_ledger::reason as derivation_reason;
use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source_exact_token_focus;
use std::cell::OnceCell;

use crate::analyzer::semantic::{
    BindingOriginIndex, LengthDelimitedDigest, MemoryAccessKind, MemoryLocationKind,
    SemanticCapability, SemanticEffect, SemanticGapKind, SemanticGapSubject, SemanticValueKind,
    SourceMappingKind,
};
use crate::analyzer::usages::effects::EffectCoverage;
use crate::query::{AssignmentRelationFilter, AssignmentRelationKind};
use brokk_bifrost_analysis::analyzer::{
    OverwrittenLocalCandidate, OverwrittenLocalSourceKind, PlainAssignmentCandidate,
    PlainAssignmentVerdict, go_overwritten_local_candidates, java_overwritten_local_candidates,
    js_ts_overwritten_local_candidates, plain_assignment_candidates,
    python_overwritten_local_candidates, single_target_overwritten_local_candidates,
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

// One procedure's undecided occurrence anchors and their batched answers.
#[derive(Default)]
struct NonbindingDefinitions {
    declaration_names: OnceCell<DeclarationNameRangeContext>,
    outcomes: HashMap<(usize, usize), Option<DefinitionLookupOutcome>>,
    deferred: bool,
}

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
    if filter.includes(AssignmentRelationKind::SelfInitializer) {
        expansions.extend(
            super::initializer_relations::initializer_relation_expansions(
                workspace,
                flow_state_cache,
                cancellation,
                diagnostics,
                procedure,
            ),
        );
    }
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

/// Whether this language dialect publishes the requested assignment relation.
///
/// Keep this predicate next to the expansion dispatch so query preflight and
/// row execution cannot drift into disagreeing support claims.
pub(super) fn supports_relation(
    dialect: crate::analyzer::LanguageDialect,
    relation: AssignmentRelationKind,
) -> bool {
    let language = dialect.language();
    let cpp_family = matches!(
        dialect,
        crate::analyzer::LanguageDialect::CppC
            | crate::analyzer::LanguageDialect::Standard(Language::Cpp)
    );
    match relation {
        AssignmentRelationKind::SelfInitializer => cpp_family,
        AssignmentRelationKind::SelfAssignment | AssignmentRelationKind::FailedSwap => {
            matches!(
                language,
                Language::Java
                    | Language::JavaScript
                    | Language::TypeScript
                    | Language::Python
                    | Language::CSharp
                    | Language::Kotlin
                    | Language::Go
                    | Language::Scala
                    | Language::Rust
                    | Language::Php
                    | Language::Ruby
            ) || cpp_family
        }
        AssignmentRelationKind::OverwrittenUnread => {
            matches!(
                language,
                Language::Java
                    | Language::JavaScript
                    | Language::TypeScript
                    | Language::Python
                    | Language::Go
                    | Language::CSharp
                    | Language::Kotlin
                    | Language::Rust
                    | Language::Scala
                    | Language::Php
                    | Language::Ruby
            ) || cpp_family
        }
    }
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
    let self_selected = filter.includes(AssignmentRelationKind::SelfAssignment);
    let swap_selected = filter.includes(AssignmentRelationKind::FailedSwap);
    let self_supported = supports_relation(dialect, AssignmentRelationKind::SelfAssignment);
    let swap_supported = supports_relation(dialect, AssignmentRelationKind::FailedSwap);
    let cpp_family = matches!(
        dialect,
        crate::analyzer::LanguageDialect::CppC
            | crate::analyzer::LanguageDialect::Standard(Language::Cpp)
    );
    let mut unsupported = Vec::new();
    if self_selected && !self_supported {
        unsupported.push(AssignmentRelationKind::SelfAssignment.label());
    }
    if swap_selected && !swap_supported {
        unsupported.push(AssignmentRelationKind::FailedSwap.label());
    }
    if !unsupported.is_empty() {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: procedure.diagnostic_source(),
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
            withheld_rows_path: Some(rel_path_string(procedure.file())),
        });
    }
    if !(self_selected && self_supported || swap_selected && swap_supported) {
        return Vec::new();
    }
    let candidates = if cpp_family {
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
        if DerivationExecutionCause::from_reason(
            candidates.reason.unwrap_or(derivation_reason::UNKNOWN),
        )
        .is_some()
        {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=candidate_derivation detail={:?}",
                    file!(),
                    line!(),
                    candidates.reason
                )
            });
            workspace.analyzer().mark_execution_dependent();
        }
        diagnostics.push(super::QueryExecutionState::diagnostic(
            workspace.analyzer(),
            CodeQueryDiagnostic {
                related: Vec::new(),
                source: procedure.diagnostic_source(),
                code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{} has incomplete assignment syntax qualification ({})",
                    procedure.wire_id(),
                    candidates.reason.unwrap_or(derivation_reason::UNKNOWN)
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: Some(rel_path_string(procedure.file())),
            },
            CodeQueryDiagnosticCode::from_execution_reason(
                CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                candidates.reason.unwrap_or(derivation_reason::UNKNOWN),
            )
            .1,
        ));
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
                (candidate.verdict != PlainAssignmentVerdict::Excluded
                    && candidates.rows[second].verdict != PlainAssignmentVerdict::Excluded)
                    .then_some((first, second))
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
    let (proof_complete, proof_reasons) = if cpp_family {
        // An unrelated local that has no establishment is handled by each
        // candidate's initialization proof below. It must not hide a
        // separately initialized ordinary binding in the same C/C++ procedure
        // (for example, a volatile pointer sibling in one declaration).
        let reasons = derivation
            .completeness
            .reasons()
            .iter()
            .filter(|reason| {
                ASSIGNMENT_RELATION_AXES
                    .iter()
                    .any(|axis| reason.blocks(*axis))
                    && !matches!(
                        reason,
                        FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        let completeness = if reasons.is_empty() {
            FlowStateCompleteness::Complete
        } else {
            FlowStateCompleteness::Incomplete {
                reasons: reasons.clone(),
            }
        };
        (
            candidates.complete
                && completeness.covers(FlowStateAxis::BindingEvents)
                && completeness.covers(FlowStateAxis::ReachingRelation)
                && completeness.covers(FlowStateAxis::SameEvaluationRelation),
            reasons,
        )
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
        (candidates.complete && binding_events_complete, reasons)
    };

    let uncancelled = CancellationToken::new();
    let mut request = FlowStateRequest::new(cancellation.unwrap_or(&uncancelled));
    let mut definitions = NonbindingDefinitions::default();
    let mut deferred = Vec::new();
    let mut expansions = if self_selected {
        candidates
            .rows
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, candidate)| {
                definitions.deferred = false;
                let expansion = if cpp_family {
                    qualify_c_candidate(
                        procedure,
                        derivation,
                        proof_complete,
                        candidate,
                        &mut request,
                    )
                } else {
                    qualify_candidate(
                        workspace,
                        &mut definitions,
                        procedure,
                        derivation,
                        proof_complete,
                        candidate,
                        &mut request,
                    )
                };
                if definitions.deferred {
                    deferred.push(index);
                }
                expansion
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    // First qualification leaves undecided static loads open. Resolve all
    // their distinct occurrence anchors together, then retry only those rows.
    if !deferred.is_empty() {
        let anchors = definitions.outcomes.keys().copied().collect::<Vec<_>>();
        let requests = anchors
            .iter()
            .map(|&(start_byte, end_byte)| DefinitionLookupRequest {
                file: procedure.file().clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(end_byte),
            })
            .collect();
        let outcomes = resolve_definition_batch_with_source_exact_token_focus(
            workspace.analyzer(),
            requests,
            procedure.file().clone(),
            Arc::from(procedure.source_text()),
            cancellation,
        );
        for (anchor, outcome) in anchors.into_iter().zip(outcomes) {
            definitions.outcomes.insert(anchor, Some(outcome));
        }
        // Cancelled resolution leaves the first pass's open rows intact.
        for index in deferred {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                break;
            }
            expansions[index] = qualify_candidate(
                workspace,
                &mut definitions,
                procedure,
                derivation,
                proof_complete,
                candidates.rows[index].clone(),
                &mut request,
            );
        }
    }
    for (first, second) in pairs {
        if let Some(pair) = qualify_failed_swap(
            procedure,
            derivation,
            proof_complete,
            &candidates.rows[first],
            &candidates.rows[second],
            &mut request,
        ) {
            expansions.push(pair);
        }
    }
    // #6409: excluded or identity-decided self/swap candidates need no global
    // flow proof. Same-binding self assignments keep their scoped establishment,
    // same-evaluation and initialization proofs. Report global axes only when
    // a surviving candidate actually consults procedure-wide completeness.
    if expansions.iter().any(|expansion| {
        matches!(&expansion.value, PipelineValue::AssignmentRelation(value)
            if value.reason == Some("flow_state_incomplete"))
    }) {
        let completeness = if proof_reasons.is_empty() {
            FlowStateCompleteness::Complete
        } else {
            FlowStateCompleteness::Incomplete {
                reasons: proof_reasons.clone(),
            }
        };
        let diagnostic_start = diagnostics.len();
        flow_state_cache.report_completeness(
            workspace.analyzer(),
            &procedure.wire_id(),
            Some(procedure),
            language,
            &completeness,
            if cpp_family {
                ASSIGNMENT_RELATION_AXES
            } else {
                &[FlowStateAxis::BindingEvents]
            },
            derivation.generation,
            diagnostics,
        );
        // These diagnostics withhold this procedure's candidate rows, and `row`
        // builds every assignment row in the procedure's file.
        for diagnostic in &mut diagnostics[diagnostic_start..] {
            diagnostic.withheld_rows_path = Some(rel_path_string(procedure.file()));
        }
    }
    let proof_related = procedure.related_flow_reasons(&proof_reasons);
    for expansion in &mut expansions {
        if let PipelineValue::AssignmentRelation(value) = &mut expansion.value
            && value.reason == Some("flow_state_incomplete")
        {
            value.related.extend(proof_related.iter().cloned());
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
    let cpp_family = matches!(
        dialect,
        crate::analyzer::LanguageDialect::CppC
            | crate::analyzer::LanguageDialect::Standard(Language::Cpp)
    );
    if !supports_relation(dialect, AssignmentRelationKind::OverwrittenUnread) {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: procedure.diagnostic_source(),
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
            withheld_rows_path: Some(rel_path_string(procedure.file())),
        });
        return Vec::new();
    }
    let mut candidates = if cpp_family {
        cpp_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
    } else {
        match dialect.language() {
            Language::Java => {
                java_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
            }
            Language::JavaScript | Language::TypeScript => {
                js_ts_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
            }
            Language::Python => {
                python_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
            }
            Language::Go => {
                go_overwritten_local_candidates(workspace, &procedure.handle, cancellation)
            }
            Language::CSharp
            | Language::Kotlin
            | Language::Rust
            | Language::Scala
            | Language::Php
            | Language::Ruby => single_target_overwritten_local_candidates(
                workspace,
                &procedure.handle,
                cancellation,
            ),
            _ => unreachable!("dialect was validated"),
        }
    };
    // C/C++ macro and in-procedure preprocessing facts are procedure-wide.
    // Keep every otherwise supported row open when either fact is present;
    // the flow graph alone cannot prove that the source write was the one
    // lowered by the analyzer.
    if cpp_family && !candidates.complete {
        let reason = candidates
            .reason
            .unwrap_or("syntax_qualification_incomplete");
        for candidate in &mut candidates.rows {
            if candidate.verdict == PlainAssignmentVerdict::Supported {
                candidate.verdict = PlainAssignmentVerdict::Unknown;
                candidate.reason = reason;
            }
        }
    }
    if !candidates.complete {
        if DerivationExecutionCause::from_reason(
            candidates.reason.unwrap_or(derivation_reason::UNKNOWN),
        )
        .is_some()
        {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=candidate_derivation detail={:?}",
                    file!(),
                    line!(),
                    candidates.reason
                )
            });
            workspace.analyzer().mark_execution_dependent();
        }
        diagnostics.push(super::QueryExecutionState::diagnostic(
            workspace.analyzer(),
            CodeQueryDiagnostic {
                related: Vec::new(),
                source: procedure.diagnostic_source(),
                code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: dialect.language().config_label(),
                message: format!(
                    "{} has incomplete overwritten-local syntax qualification ({})",
                    procedure.wire_id(),
                    candidates.reason.unwrap_or(derivation_reason::UNKNOWN)
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: Some(rel_path_string(procedure.file())),
            },
            CodeQueryDiagnosticCode::from_execution_reason(
                CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                candidates.reason.unwrap_or(derivation_reason::UNKNOWN),
            )
            .1,
        ));
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
                    derivation_reason::UNKNOWN,
                    derivation_reason::UNKNOWN,
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
                    derivation_reason::UNKNOWN,
                    derivation_reason::UNKNOWN,
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
        workspace.analyzer(),
        &procedure.wire_id(),
        Some(procedure),
        dialect.language(),
        &derivation.overwrite_observation_completeness(&procedure.handle),
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
                    derivation_reason::UNKNOWN,
                    derivation_reason::UNKNOWN,
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
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
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
        let mut incomplete_reasons = Vec::new();
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
                match derivation.binding_initialization_before_establishment(
                    &procedure.handle,
                    write.event,
                    &mut request,
                ) {
                    BindingInitializationAnswer::Proven => {}
                    BindingInitializationAnswer::Unreachable => continue,
                    BindingInitializationAnswer::MayBeUninitialized => {
                        incomplete = Some("target_initialization_unproved");
                        continue;
                    }
                    BindingInitializationAnswer::Open { reasons } => {
                        incomplete_reasons.extend(reasons);
                        incomplete = Some("target_initialization_unproved");
                        continue;
                    }
                }
            }
            let answer =
                derivation.overwritten_unread_local(&procedure.handle, write.event, &mut request);
            match answer {
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
                    incomplete_reasons.extend(reasons.iter().cloned());
                    let cause = reasons.iter().find_map(|reason| match reason {
                        brokk_bifrost_flow::flow_state::FlowStateIncompleteReason::Cancelled => Some(DerivationExecutionCause::Cancelled),
                        brokk_bifrost_flow::flow_state::FlowStateIncompleteReason::BudgetExhausted { .. } => Some(DerivationExecutionCause::Budget),
                        _ => None,
                    });
                    if request.refusal_count() > 0 {
                        brokk_bifrost_core::profiling::note_with(|| {
                            format!(
                                "policy.units unbounded origin={}:{} cause=budget:cfg",
                                file!(),
                                line!()
                            )
                        });
                        workspace.analyzer().mark_execution_dependent();
                    }
                    diagnostics.push(super::QueryExecutionState::diagnostic(
                        workspace.analyzer(),
                        CodeQueryDiagnostic {
                            related: procedure.related_flow_reasons(&reasons),
                            source: procedure.diagnostic_source(),
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
                            withheld_rows_path: Some(rel_path_string(procedure.file())),
                        },
                        cause,
                    ));
                }
            }
        }
        let expansion = if let Some(reason) = incomplete {
            overwritten_row(
                procedure,
                candidate,
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
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
        expansions.push(with_flow_reasons(expansion, procedure, &incomplete_reasons));
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
        derivation_reason::UNKNOWN
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
                    derivation_reason::UNKNOWN,
                    derivation_reason::UNKNOWN,
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
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
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
                Some(value.reason.unwrap_or(derivation_reason::UNKNOWN))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    open_reasons.sort_unstable();
    open_reasons.dedup();
    if !open_reasons.is_empty() {
        let mut diagnostic = super::incomplete_diagnostic(
            CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            procedure
                .handle
                .artifact()
                .key()
                .language()
                .language()
                .config_label(),
            format!(
                "{} has open assignment-relation candidates: {open_reasons:?}",
                procedure.wire_id()
            ),
            Vec::new(),
        );
        diagnostic.source = procedure.diagnostic_source();
        let mut seen = HashSet::default();
        diagnostic.related = expansions
            .iter()
            .filter_map(|expansion| match &expansion.value {
                PipelineValue::AssignmentRelation(value)
                    if value.coverage == EffectCoverage::Open =>
                {
                    Some(&value.related)
                }
                _ => None,
            })
            .flatten()
            .filter(|related| seen.insert((*related).clone()))
            .cloned()
            .collect();
        diagnostic.withheld_rows_path = Some(rel_path_string(procedure.file()));
        diagnostics.push(diagnostic);
    }
}

fn with_flow_reasons(
    mut expansion: PipelineExpansion,
    procedure: &semantic::SemanticProcedureValue,
    reasons: &[brokk_bifrost_flow::flow_state::FlowStateIncompleteReason],
) -> PipelineExpansion {
    let PipelineValue::AssignmentRelation(value) = &mut expansion.value else {
        unreachable!("assignment qualification returns an assignment row")
    };
    value
        .related
        .extend(procedure.related_flow_reasons(reasons));
    expansion
}

/// Qualify one C candidate. C proves its prior definition by an exact unique
/// reaching origin over a completely covered procedure.
fn qualify_c_candidate(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    flow_complete: bool,
    candidate: PlainAssignmentCandidate,
    request: &mut FlowStateRequest<'_>,
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
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
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
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
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
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
            EffectCoverage::Open,
            Some("semantic_join_missing"),
        );
    };
    let Some(establishment) = unique_establishment(derivation, point, target) else {
        return row(
            procedure,
            candidate,
            None,
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
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
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
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
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
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
    let mut initialization_reasons = Vec::new();
    if reaching.iter().all(Vec::is_empty)
        && matches!(procedure.handle.semantics().value(target), Some(value) if matches!(&value.kind, SemanticValueKind::Parameter { .. }))
    {
        match derivation.binding_initialization_at_read(&procedure.handle, read.event, request) {
            BindingInitializationAnswer::Proven => {
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
            BindingInitializationAnswer::Open { reasons } => initialization_reasons = reasons,
            BindingInitializationAnswer::Unreachable
            | BindingInitializationAnswer::MayBeUninitialized => {}
        }
    }
    if reaching.iter().all(Vec::is_empty) {
        return with_flow_reasons(
            row(
                procedure,
                candidate,
                Some(read.value),
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
                EffectCoverage::Open,
                Some("initialization_unproved"),
            ),
            procedure,
            &initialization_reasons,
        );
    }
    row(
        procedure,
        candidate,
        Some(read.value),
        derivation_reason::UNKNOWN,
        derivation_reason::UNKNOWN,
        EffectCoverage::Open,
        Some("prior_definition_not_exact"),
    )
}

/// Qualify one supported non-C assignment candidate.
///
/// Every lowered copy of the assignment must read the target binding itself
/// in its own evaluation, and the target must be initialized at that read.
/// Only gaps that can reach this evaluation or this binding's initialization
/// keep the candidate open; a gap elsewhere in the procedure does not.
fn qualify_candidate(
    workspace: &WorkspaceAnalyzer,
    definitions: &mut NonbindingDefinitions,
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    flow_complete: bool,
    candidate: PlainAssignmentCandidate,
    request: &mut FlowStateRequest<'_>,
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
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
                EffectCoverage::Open,
                None,
            );
        }
        PlainAssignmentVerdict::Supported => {}
    }
    // #6409: binding identity precedes procedure-wide event completeness.
    // Distinct identities refute self-assignment immediately. Equal identities
    // still need every existing per-point and initialization proof below.
    let origins = BindingOriginIndex::from_semantics(procedure.handle.semantics());
    let identities =
        exact_assignment_bindings(derivation, &origins, &candidate).filter(|&(target, rhs)| {
            binding_identities_are_closed(procedure, derivation, &origins, &[target, rhs])
        });
    if let Some((target, rhs)) = identities
        && target != rhs
    {
        let rhs_read = candidate.rhs_value;
        return row(
            procedure,
            candidate,
            rhs_read,
            "different",
            "exact",
            EffectCoverage::Exhaustive,
            Some("different_binding"),
        );
    }
    if identities.is_none() && !flow_complete {
        return row(
            procedure,
            candidate,
            None,
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
            EffectCoverage::Open,
            Some("flow_state_incomplete"),
        );
    }
    let Some(target) = candidate.target.filter(|_| !candidate.points.is_empty()) else {
        return row(
            procedure,
            candidate,
            None,
            derivation_reason::UNKNOWN,
            derivation_reason::UNKNOWN,
            EffectCoverage::Open,
            Some("semantic_join_missing"),
        );
    };
    let mut proven_read = None;
    let mut open = None;
    let mut open_reasons = Vec::new();
    for &point in &candidate.points {
        let Some(establishment) = unique_establishment(derivation, point, target) else {
            return row(
                procedure,
                candidate,
                None,
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
                EffectCoverage::Open,
                Some("assignment_establishment_ambiguous"),
            );
        };
        let reads = match rhs_reads(procedure, derivation, &candidate, establishment) {
            Ok(reads) => reads,
            Err(reasons) => {
                return with_flow_reasons(
                    row(
                        procedure,
                        candidate,
                        None,
                        derivation_reason::UNKNOWN,
                        derivation_reason::UNKNOWN,
                        EffectCoverage::Open,
                        Some("same_evaluation_open"),
                    ),
                    procedure,
                    &reasons,
                );
            }
        };
        let Some(read) = reads.first() else {
            if nonbinding_rhs_is_exact(
                workspace,
                definitions,
                procedure,
                &candidate,
                &origins,
                establishment,
            ) {
                let rhs = Some(establishment.value);
                return row(
                    procedure,
                    candidate,
                    rhs,
                    "different",
                    "exact",
                    EffectCoverage::Exhaustive,
                    Some("different_binding"),
                );
            }
            return row(
                procedure,
                candidate,
                None,
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
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
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
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
            match derivation.binding_initialization_at_read(&procedure.handle, read.event, request)
            {
                BindingInitializationAnswer::Proven => proven_read = Some(read.value),
                BindingInitializationAnswer::Unreachable => {}
                BindingInitializationAnswer::MayBeUninitialized => {
                    open.get_or_insert((read.value, "initialization_unproved"));
                }
                BindingInitializationAnswer::Open { reasons } => {
                    open_reasons.extend(reasons);
                    open = Some((read.value, "initialization_proof_open"));
                }
            }
        }
    }
    if let Some((read, reason)) = open {
        return with_flow_reasons(
            row(
                procedure,
                candidate,
                Some(read),
                derivation_reason::UNKNOWN,
                derivation_reason::UNKNOWN,
                EffectCoverage::Open,
                Some(reason),
            ),
            procedure,
            &open_reasons,
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
    request: &mut FlowStateRequest<'_>,
) -> Option<PipelineExpansion> {
    if first.verdict == PlainAssignmentVerdict::Excluded
        || second.verdict == PlainAssignmentVerdict::Excluded
    {
        return None;
    }
    let open =
        |rhs_read,
         reason,
         reasons: &[brokk_bifrost_flow::flow_state::FlowStateIncompleteReason]| {
            Some(with_flow_reasons(
                swap_row(
                    procedure,
                    first,
                    second,
                    rhs_read,
                    derivation_reason::UNKNOWN,
                    derivation_reason::UNKNOWN,
                    EffectCoverage::Open,
                    Some(reason),
                ),
                procedure,
                reasons,
            ))
        };
    if first.verdict == PlainAssignmentVerdict::Unknown
        || second.verdict == PlainAssignmentVerdict::Unknown
    {
        return open(None, "assignment_pair_unqualified", &[]);
    }
    let (first_target, second_target) = (first.target?, second.target?);
    if first_target == second_target {
        return None;
    }
    if failed_swap_is_refuted(procedure, derivation, first, second) {
        return None;
    }
    if !flow_complete {
        return open(None, "flow_state_incomplete", &[]);
    }
    let Some(first_writes) = first
        .points
        .iter()
        .map(|point| unique_establishment(derivation, *point, first_target))
        .collect::<Option<Vec<_>>>()
        .filter(|writes| !writes.is_empty())
    else {
        return open(None, "first_write_unproved", &[]);
    };
    let Some(second_writes) = second
        .points
        .iter()
        .map(|point| unique_establishment(derivation, *point, second_target))
        .collect::<Option<Vec<_>>>()
        .filter(|writes| !writes.is_empty())
    else {
        return open(None, "second_write_unproved", &[]);
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
                _ => return open(None, "second_read_unproved", &[]),
            },
            Err(reasons) => return open(None, "same_evaluation_open", &reasons),
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
            return open(Some(second_read.value), "ordered_write_unproved", &[]);
        };
        let first_read = match rhs_reads(procedure, derivation, first, first_write) {
            Ok(reads) => match reads.as_slice() {
                [read] => *read,
                _ => return open(Some(second_read.value), "first_read_unproved", &[]),
            },
            Err(reasons) => return open(Some(second_read.value), "same_evaluation_open", &reasons),
        };
        if first_read.subject
            != (FlowSubject::Binding {
                value: second_target,
            })
        {
            return None;
        }
        if matches!(
            procedure.handle.artifact().key().language().language(),
            Language::Java | Language::CSharp
        ) && (first.swap_type.is_none() || first.swap_type != second.swap_type)
        {
            return open(
                Some(second_read.value),
                "assignment_conversion_unproved",
                &[],
            );
        }
        match derivation.binding_initialization_at_read(
            &procedure.handle,
            first_read.event,
            request,
        ) {
            BindingInitializationAnswer::Proven => proven_read = Some(second_read.value),
            BindingInitializationAnswer::Unreachable => {}
            BindingInitializationAnswer::MayBeUninitialized => {
                return open(
                    Some(second_read.value),
                    "first_value_initialization_unproved",
                    &[],
                );
            }
            BindingInitializationAnswer::Open { reasons } => {
                return open(
                    Some(second_read.value),
                    "initialization_proof_open",
                    &reasons,
                );
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

fn failed_swap_is_refuted(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    first: &PlainAssignmentCandidate,
    second: &PlainAssignmentCandidate,
) -> bool {
    let semantics = procedure.handle.semantics();
    let origins = BindingOriginIndex::from_semantics(semantics);
    let (Some((first_target, first_rhs)), Some((second_target, second_rhs))) = (
        exact_assignment_bindings(derivation, &origins, first),
        exact_assignment_bindings(derivation, &origins, second),
    ) else {
        return false;
    };
    if first_rhs == second_target && second_rhs == first_target {
        return false;
    }
    if !binding_identities_are_closed(
        procedure,
        derivation,
        &origins,
        &[first_target, second_target, first_rhs, second_rhs],
    ) {
        return false;
    }
    // #6409: a Point pattern/LocalFlow gap can hide a shadow between the two
    // statements of a swap. The IR has no lexical scope for it, so treat an
    // earlier such gap as enclosing even if it could be a sibling scope.
    // Self-assignment deliberately omits this blocker: inside one plain
    // target = rhs statement nothing can occur between its read and write,
    // and a shadow before it renames both sides alike. Initialization remains
    // a separate scoped proof for a same-binding self-assignment.
    !semantics.gaps().iter().any(|gap| {
        gap.subject == SemanticGapSubject::Point
            && (gap.capability == SemanticCapability::LocalFlow
                || (gap.kind == SemanticGapKind::Unsupported
                    && gap.capability == SemanticCapability::Values))
            && semantics.source_mapping(gap.source).is_none_or(|mapping| {
                mapping.kind != SourceMappingKind::Exact
                    || mapping.locator.anchor().span().start_byte() as usize
                        <= second.range.end_byte
            })
    })
}

/// Unique structured target and retained RHS read identities, never spelling.
fn exact_assignment_bindings(
    derivation: &FlowStateDerivation,
    origins: &BindingOriginIndex,
    candidate: &PlainAssignmentCandidate,
) -> Option<(
    crate::analyzer::semantic::ValueId,
    crate::analyzer::semantic::ValueId,
)> {
    let target = candidate.target?;
    let binding = origins.unique_binding_origin(candidate.rhs_value?)?;
    let rhs = candidate
        .rhs_identifier_range
        .as_ref()
        .or(candidate.rhs_range.as_ref())?;
    let mut reads = derivation
        .events
        .iter()
        .filter(|event| {
            event.event_class == StateEventClass::Read && same_range(&event.site.range, rhs)
        })
        .peekable();
    (reads.peek().is_some()
        && reads.all(|read| {
            read.subject == FlowSubject::Binding { value: binding }
                && origins.unique_binding_origin(read.value) == Some(binding)
        }))
    .then_some((target, binding))
}

/// #6409: assignment relations compare binding identities before reaching or
/// initialization proofs. All selected bindings need unique self-origins and
/// exact retained read joins from exact_assignment_bindings. A Value-subject
/// Values gap concerns content or Copy/move semantics, not which binding a read
/// denotes; its kind and ValueFlow/Aliasing impacts cannot equate distinct
/// bindings. Exempt it only when its binding has a unique self-origin.
/// Assignments gaps still hide targets. Whole-procedure gaps, missing origins
/// and non-lowering binding-event evidence keep identity open. This predicate
/// proves identity alone; it discharges no initialization or crossed-pair gap.
fn binding_identities_are_closed(
    procedure: &semantic::SemanticProcedureValue,
    derivation: &FlowStateDerivation,
    origins: &BindingOriginIndex,
    bindings: &[crate::analyzer::semantic::ValueId],
) -> bool {
    if derivation.completeness.reasons().iter().any(|reason| {
        reason.blocks(FlowStateAxis::BindingEvents)
            && !matches!(
                reason,
                FlowStateIncompleteReason::LoweringGap { .. }
                    | FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
            )
    }) || bindings
        .iter()
        .any(|binding| origins.unique_binding_origin(*binding) != Some(*binding))
    {
        return false;
    }
    !procedure
        .handle
        .semantics()
        .gaps()
        .iter()
        .any(|gap| match gap.subject {
            _ if gap.capability == SemanticCapability::Assignments => true,
            SemanticGapSubject::Value(value) => {
                bindings.contains(&value)
                    && !(gap.capability == SemanticCapability::Values
                        && origins.unique_binding_origin(value) == Some(value))
            }
            SemanticGapSubject::Procedure => true,
            _ => false,
        })
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

// Static storage is shared across procedures, so it is not a per-procedure
// state event: inventing reads without local establishments would change reaching
// and overwrite answers. Prove this distinct RHS directly from its own IR load.
fn nonbinding_rhs_is_exact(
    workspace: &WorkspaceAnalyzer,
    definitions: &mut NonbindingDefinitions,
    procedure: &semantic::SemanticProcedureValue,
    candidate: &PlainAssignmentCandidate,
    origins: &BindingOriginIndex,
    establishment: &StateEventRow,
) -> bool {
    let semantics = procedure.handle.semantics();
    let Some(rhs) = candidate
        .rhs_identifier_range
        .as_ref()
        .or(candidate.rhs_range.as_ref())
    else {
        return false;
    };
    let mut value_id = establishment.value;
    let mut visited = HashSet::default();
    loop {
        if !visited.insert(value_id) {
            return false;
        }
        let value = semantics
            .value(value_id)
            .expect("validated assignment value");
        let mapping = semantics
            .source_mapping(value.source)
            .expect("validated value mapping");
        let span = mapping.locator.anchor().span();
        let matches = |range: &Range| {
            span.start_byte() as usize == range.start_byte
                && span.end_byte() as usize == range.end_byte
        };
        if mapping.kind != SourceMappingKind::Exact
            || !(matches(rhs) || candidate.rhs_range.as_ref().is_some_and(matches))
            || value.kind.is_binding()
        {
            return false;
        }
        if value.kind.is_constant() {
            return true;
        }
        let mut loads = semantics
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Static,
                    location,
                    result,
                } if result == value_id => Some(location),
                _ => None,
            });
        if let Some(location) = loads.next() {
            if loads.next().is_some() {
                return false;
            }
            let Some(target) = candidate.target.and_then(|target| semantics.value(target)) else {
                return false;
            };
            let target_name = match &target.kind {
                SemanticValueKind::Parameter { name, .. } => name.as_deref(),
                SemanticValueKind::Local => {
                    semantics.source_mapping(target.source).and_then(|mapping| {
                        let span = mapping.locator.anchor().span();
                        // qualify_local_write already proved this selects the
                        // local declaration's identifier, not its parent syntax.
                        procedure
                            .source_text()
                            .get(span.start_byte() as usize..span.end_byte() as usize)
                    })
                }
                _ => None,
            };
            if target_name.is_none()
                || target_name == procedure.source_text().get(rhs.start_byte..rhs.end_byte)
            {
                // A static load for the local target's own spelling indicates
                // a lowering binding failure, not distinct bindings. Go's
                // `x := x` shadowing idiom never reaches here: go_plain_write
                // admits only assignment statements as candidates.
                return false;
            }
            let Some(MemoryLocationKind::Static { member }) = semantics
                .memory_location(location)
                .map(|location| &location.kind)
            else {
                return false;
            };
            if member.path() != semantics.locator().path() {
                return false;
            }
            let Some(declaration) = super::dispatch::declaration_at_locator(
                workspace.analyzer(),
                member,
                procedure.file(),
            ) else {
                return false;
            };
            let names = definitions.declaration_names.get_or_init(|| {
                DeclarationNameRangeContext::new(
                    procedure.file(),
                    procedure.source_text().to_owned(),
                )
            });
            let anchor = member.anchor().span();
            if names
                .name_ranges(workspace.analyzer(), &declaration)
                .iter()
                .any(|range| {
                    range.start_byte == anchor.start_byte() as usize
                        && range.end_byte == anchor.end_byte() as usize
                })
            {
                return true;
            }
            // Some adapters can only anchor static storage at its occurrence.
            // Use the same structured definition lookup as the former
            // concurrency provider, then verify the declaration's own anchor.
            let outcome = definitions
                .outcomes
                .entry((anchor.start_byte() as usize, anchor.end_byte() as usize))
                .or_default();
            let Some(outcome) = outcome.as_ref() else {
                definitions.deferred = true;
                return false;
            };
            if outcome.status != DefinitionLookupStatus::Resolved
                || !outcome.diagnostics.is_empty()
                || outcome.lexical_definition.is_some()
            {
                return false;
            }
            let [resolved] = outcome.definitions.as_slice() else {
                return false;
            };
            // Go var and const both lower to module-scope Field; constants
            // cannot alias local storage. An unqualified identifier cannot
            // denote a struct field: that requires a selector.
            if !resolved.is_field() || resolved.package_name() != declaration.package_name() {
                return false;
            }
            let Some(source) = workspace.analyzer().indexed_source(resolved.source()) else {
                return false;
            };
            let resolved_names =
                DeclarationNameRangeContext::new(resolved.source(), source.to_string());
            return resolved_names
                .name_ranges(workspace.analyzer(), resolved)
                .iter()
                .any(|range| {
                    super::dispatch::declaration_at_byte_range(
                        workspace.analyzer(),
                        range.start_byte..range.end_byte,
                        resolved.source(),
                    )
                    .as_ref()
                        == Some(resolved)
                });
        }
        // Follow only a unique producer chain (for example Go's assignment
        // conversion). Multiple inputs, cycles and unknown leaves prove nothing.
        let mut predecessors = origins.value_predecessors(value_id);
        let Some(predecessor) = predecessors.next() else {
            return false;
        };
        if predecessors.next().is_some() {
            return false;
        }
        value_id = predecessor;
    }
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
            related: Vec::new(),
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

use brokk_bifrost_cpp_analysis::analyzer::CAssignmentCandidate;
use brokk_bifrost_cpp_analysis::analyzer::CAssignmentSyntaxVerdict;
use brokk_bifrost_cpp_analysis::analyzer::c_assignment_candidates;
use brokk_bifrost_cpp_analysis::analyzer::cpp_overwritten_local_candidates;

#[cfg(test)]
mod tests {
    use super::super::tests::inline_project::InlineTestProject;
    use super::*;
    use crate::analyzer::AnalyzerConfig;

    #[test]
    fn static_rhs_with_the_local_targets_spelling_stays_ambiguous() {
        // Replay a broken lowering: the assignment writes a local END, but
        // its RHS still loads the class's static END. Correct lowering cannot
        // produce this combination, so retain a separate local to retarget
        // the prepared write and its derived establishment in this witness.
        let source = "class Sample { static final char END = 'z'; char check() { char x = 'a'; x = END; char END = 'b'; return END; } }";
        let project = InlineTestProject::new().file("Sample.java", source).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("Sample.java");
        let mut context = semantic::SemanticQueryContext::new(
            &workspace,
            None,
            CodeQuerySemanticLimits::default(),
        );
        let offset = source.find("x = END").unwrap();
        let mut procedures = context.procedure_of_source_range(
            &file,
            Range {
                start_byte: offset,
                end_byte: offset + "x = END".len(),
                start_line: 0,
                end_line: 0,
            },
            ContentIdentity::hash_bytes(source.as_bytes()),
        );
        assert_eq!(procedures.len(), 1);
        let procedure = procedures.pop().unwrap();
        let outcome = context.materialized_outcome(&file).unwrap();
        let mut cache = FlowStateTraversalCache::default();
        let state =
            cache.for_materialized_procedure(&workspace, &file, outcome, &procedure.handle, None);
        let derivation = state
            .procedures
            .iter()
            .find(|row| row.procedure == procedure.handle.id())
            .unwrap();
        let mut candidate = plain_assignment_candidates(&workspace, &procedure.handle, None)
            .rows
            .into_iter()
            .find(|row| row.range.start_byte == offset)
            .unwrap();
        let mut definitions = NonbindingDefinitions::default();
        let cancellation = CancellationToken::new();
        let mut request = FlowStateRequest::new(&cancellation);
        let ordinary = qualify_candidate(
            &workspace,
            &mut definitions,
            &procedure,
            derivation,
            true,
            candidate.clone(),
            &mut request,
        );
        let PipelineValue::AssignmentRelation(ordinary) = ordinary.value else {
            panic!("relation");
        };
        assert_eq!(
            (ordinary.verdict, ordinary.reason),
            ("different", Some("different_binding"))
        );
        let target = procedure
            .handle
            .semantics()
            .values()
            .iter()
            .find(|value| {
                value.kind == SemanticValueKind::Local && {
                    let span = procedure
                        .handle
                        .semantics()
                        .source_mapping(value.source)
                        .unwrap()
                        .locator
                        .anchor()
                        .span();
                    &source[span.start_byte() as usize..span.end_byte() as usize] == "END"
                }
            })
            .unwrap()
            .id;
        let previous = candidate.target.replace(target).unwrap();
        let mut derivation = derivation.clone();
        let establishment = derivation
            .events
            .iter_mut()
            .find(|event| {
                candidate.points.contains(&event.point)
                    && event.event_class == StateEventClass::Establish
                    && event.subject == FlowSubject::Binding { value: previous }
            })
            .unwrap();
        establishment.subject = FlowSubject::Binding { value: target };
        let guarded = qualify_candidate(
            &workspace,
            &mut definitions,
            &procedure,
            &derivation,
            true,
            candidate,
            &mut request,
        );
        let PipelineValue::AssignmentRelation(guarded) = guarded.value else {
            panic!("relation");
        };
        assert_eq!(
            (
                guarded.verdict,
                guarded.reason,
                guarded.proof,
                guarded.coverage
            ),
            (
                "unknown",
                Some("rhs_read_join_ambiguous"),
                "unknown",
                EffectCoverage::Open
            )
        );
    }
}
