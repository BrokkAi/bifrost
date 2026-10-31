//! C/C++ local self-initializer relations.
//!
//! Syntax identifies the declaration and the evaluated initializer access;
//! exact binding/value identity comes from the flow-state derivation. This
//! keeps the relation honest when either side is unavailable and avoids making
//! a generic assignment row stand in for an evaluated initializer child.

use super::*;

use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::usages::effects::EffectCoverage;

use brokk_bifrost_flow::flow_state::{FlowStateAxis, FlowSubject, StateEventClass, StateEventRow};

const INITIALIZER_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.self_initializer.v1";
const INITIALIZER_RELATION_AXES: &[FlowStateAxis] = &[FlowStateAxis::BindingEvents];

pub(super) fn initializer_relation_expansions(
    workspace: &WorkspaceAnalyzer,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &semantic::SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let dialect = procedure.handle.artifact().key().language();
    if !super::assignment_relations::supports_relation(
        dialect,
        crate::query::AssignmentRelationKind::SelfInitializer,
    ) {
        // The shared query preflight reports this unsupported relation even
        // when the seed has no procedure rows. Keep the expansion itself
        // language-safe as well: this producer is C/C++-owned and must never
        // silently probe Java or another adapter's procedure handle.
        return Vec::new();
    }
    let candidates = cpp_initializer_candidates(workspace, &procedure.handle, cancellation);
    if !candidates.complete {
        if DerivationExecutionCause::from_reason(
            candidates
                .reason
                .unwrap_or(brokk_bifrost_analysis::analyzer::read_ledger::reason::UNKNOWN),
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
            CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
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
                    "{} has incomplete C/C++ initializer syntax qualification ({})",
                    procedure.wire_id(),
                    candidates
                        .reason
                        .unwrap_or(brokk_bifrost_analysis::analyzer::read_ledger::reason::UNKNOWN)
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }),
            CodeQueryDiagnosticCode::from_execution_reason(
                CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                candidates
                    .reason
                    .unwrap_or(brokk_bifrost_analysis::analyzer::read_ledger::reason::UNKNOWN),
            )
            .1,
        ));
    }
    if candidates.rows.is_empty() {
        return Vec::new();
    }
    let Some((file_state, procedure_index, procedure_id, _file)) = row_relations::seed_derivation(
        workspace,
        flow_state_cache,
        procedure,
        INITIALIZER_RELATION_AXES,
        cancellation,
        diagnostics,
    ) else {
        return candidates
            .rows
            .into_iter()
            .map(|candidate| unknown_row(procedure, candidate, "flow_state_unavailable"))
            .collect();
    };
    let derivation = &file_state.procedures[procedure_index];
    let flow_complete = derivation.completeness.covers(FlowStateAxis::BindingEvents);
    let syntax_complete = candidates.complete;
    candidates
        .rows
        .into_iter()
        .map(|candidate| {
            if candidate.verdict != CppInitializerSyntaxVerdict::Supported {
                return syntax_row(procedure, candidate, syntax_complete);
            }
            if !syntax_complete || !flow_complete {
                return unknown_row(procedure, candidate, "initializer_evidence_incomplete");
            }
            let Some(establishment) = find_establishment(derivation, &candidate) else {
                return unknown_row(procedure, candidate, "binding_establishment_unproved");
            };
            let Some(read) = find_read(derivation, establishment, &candidate) else {
                return unknown_row(procedure, candidate, "initializer_read_unproved");
            };
            exact_row(procedure, candidate, establishment, read, &procedure_id)
        })
        .collect()
}

fn find_establishment<'a>(
    derivation: &'a brokk_bifrost_flow::flow_state::FlowStateDerivation,
    candidate: &CppInitializerCandidate,
) -> Option<&'a StateEventRow> {
    let mut matches = derivation.events.iter().filter(|event| {
        event.event_class == StateEventClass::Establish
            && matches!(event.subject, FlowSubject::Binding { .. })
            && contains_range(&candidate.declaration_range, &event.site.range)
    });
    let establishment = matches.next()?;
    matches.next().is_none().then_some(establishment)
}

fn find_read<'a>(
    derivation: &'a brokk_bifrost_flow::flow_state::FlowStateDerivation,
    establishment: &StateEventRow,
    candidate: &CppInitializerCandidate,
) -> Option<&'a StateEventRow> {
    let FlowSubject::Binding { value } = &establishment.subject else {
        unreachable!("initializer establishment is a binding event");
    };
    let mut matches = derivation.events.iter().filter(|event| {
        event.event_class == StateEventClass::Read
            && event.subject == (FlowSubject::Binding { value: *value })
            && event.site.range == candidate.access_range
    });
    let read = matches.next()?;
    matches.next().is_none().then_some(read)
}

fn exact_row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: CppInitializerCandidate,
    establishment: &StateEventRow,
    read: &StateEventRow,
    procedure_id: &str,
) -> PipelineExpansion {
    let target_value_id = match &establishment.subject {
        FlowSubject::Binding { value } => u64::from(value.get()),
        FlowSubject::Property { .. } => unreachable!("initializer target is a local binding"),
    };
    let assignment_point_id = procedure
        .handle
        .point_handle(establishment.point)
        .map(|handle| semantic::program_point_wire_id(&handle));
    let mut digest = LengthDelimitedDigest::new(INITIALIZER_RELATION_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(&(candidate.declaration_range.start_byte as u64).to_le_bytes());
    digest.push(&(candidate.declaration_range.end_byte as u64).to_le_bytes());
    digest.push(&(candidate.access_range.start_byte as u64).to_le_bytes());
    digest.push(&(candidate.access_range.end_byte as u64).to_le_bytes());
    let mut value = AssignmentRelationValue {
        related: Vec::new(),
        file: procedure.file().clone(),
        range: candidate.declaration_range,
        ast_id: read
            .site
            .ast_id
            .clone()
            .or_else(|| establishment.site.ast_id.clone()),
        id: digest.finish().to_string(),
        procedure_id: procedure_id.to_owned(),
        assignment_point_id,
        target_value_id: Some(target_value_id),
        rhs_value_id: Some(u64::from(read.value.get())),
        relation_kind: "self_initializer",
        storage_kind: candidate.storage_kind,
        verdict: "self_initializer",
        proof: "exact",
        coverage: EffectCoverage::Exhaustive,
        reason: None,
        replacement_events: Vec::new(),
    };
    // The row's range is the declaration, while the source-backed AST join is
    // the read event's exact child. Keep the latter available to detailed
    // consumers through the stable ast_id without changing the shared row
    // shape.
    value.ast_id = read.site.ast_id.clone().or(value.ast_id);
    pipeline_expansion(PipelineValue::AssignmentRelation(Box::new(value)))
}

fn syntax_row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: CppInitializerCandidate,
    syntax_complete: bool,
) -> PipelineExpansion {
    let (verdict, proof, coverage) = match candidate.verdict {
        CppInitializerSyntaxVerdict::Excluded => (
            "excluded",
            "exact",
            if syntax_complete {
                EffectCoverage::Exhaustive
            } else {
                EffectCoverage::Open
            },
        ),
        CppInitializerSyntaxVerdict::Unknown => ("unknown", "unknown", EffectCoverage::Open),
        CppInitializerSyntaxVerdict::Supported => unreachable!("supported syntax uses flow join"),
    };
    let reason = candidate.reason;
    relation_row(procedure, candidate, verdict, proof, coverage, Some(reason))
}

fn unknown_row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: CppInitializerCandidate,
    reason: &'static str,
) -> PipelineExpansion {
    relation_row(
        procedure,
        candidate,
        "unknown",
        "unknown",
        EffectCoverage::Open,
        Some(reason),
    )
}

fn relation_row(
    procedure: &semantic::SemanticProcedureValue,
    candidate: CppInitializerCandidate,
    verdict: &'static str,
    proof: &'static str,
    coverage: EffectCoverage,
    reason: Option<&'static str>,
) -> PipelineExpansion {
    let procedure_id = procedure.wire_id();
    let mut digest = LengthDelimitedDigest::new(INITIALIZER_RELATION_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(&(candidate.declaration_range.start_byte as u64).to_le_bytes());
    digest.push(&(candidate.declaration_range.end_byte as u64).to_le_bytes());
    digest.push(&(candidate.access_range.start_byte as u64).to_le_bytes());
    digest.push(&(candidate.access_range.end_byte as u64).to_le_bytes());
    digest.push(verdict.as_bytes());
    pipeline_expansion(PipelineValue::AssignmentRelation(Box::new(
        AssignmentRelationValue {
            related: Vec::new(),
            file: procedure.file().clone(),
            range: candidate.declaration_range,
            ast_id: None,
            id: digest.finish().to_string(),
            procedure_id,
            assignment_point_id: None,
            target_value_id: None,
            rhs_value_id: None,
            relation_kind: "self_initializer",
            storage_kind: candidate.storage_kind,
            verdict,
            proof,
            coverage,
            reason,
            replacement_events: Vec::new(),
        },
    )))
}

fn contains_range(container: &Range, value: &Range) -> bool {
    container.start_byte <= value.start_byte && value.end_byte <= container.end_byte
}

use brokk_bifrost_cpp_analysis::analyzer::CppInitializerCandidate;
use brokk_bifrost_cpp_analysis::analyzer::CppInitializerSyntaxVerdict;
use brokk_bifrost_cpp_analysis::analyzer::cpp_initializer_candidates;
