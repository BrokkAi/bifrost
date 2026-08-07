//! The execution adapter between the query engine and the lexical-environment
//! and resolution-trace producers (#1474, Milestone 4).
//!
//! Three row families arrive here: lexical scopes and bindings, from the
//! per-file environment derivation, and resolution candidates, from the
//! opt-in trace join on occurrence rows. All three follow the occurrence
//! precedent -- plain pipeline values derived on demand and memoised per
//! request, never semantic-artifact backed.
//!
//! The honesty rule the domain exists for lives here as well: an axis the
//! file's adapter does not answer becomes an `Incomplete` diagnostic, and a
//! trace that reports only its selections becomes one too whenever a query
//! actually depends on rejections. An empty answer is never silently a
//! complete one.

use super::super::lexical_environment::{
    BindingRow, EnvironmentCompleteness, EnvironmentFileResult, EnvironmentIncompleteReason,
    ScopeRow, environment_for_file,
};
use super::super::occurrence_rows::{
    OccurrenceDerivationOptions, OccurrenceFileResult, OccurrenceRow,
    occurrences_for_file_with_options,
};
use super::super::occurrences::OccurrenceRole;
use super::super::query::{BindingFilter, CandidateFilter, ScopeFilter};
use super::super::resolution::EnvironmentAxis;
use super::results::{
    CodeQueryBinding, CodeQueryCandidateHop, CodeQueryCandidateRef, CodeQueryDeclaration,
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryImportBinder,
    CodeQueryLexicalScope, CodeQueryRange, CodeQueryResolutionCandidate,
};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::usages::get_definition::trace::HierarchyHopRecord;
use crate::analyzer::usages::get_definition::{
    ResolutionTraceResult, TraceCandidate, TraceCandidateRef,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

/// Domain separator for a lexical scope row's stable id.
const SCOPE_ID_DOMAIN: &[u8] = b"bifrost.code_query.lexical_scope.v1";
/// Domain separator for a binding row's stable id.
const BINDING_ID_DOMAIN: &[u8] = b"bifrost.code_query.binding.v1";
/// Domain separator for a resolution-candidate row's stable id.
const CANDIDATE_ID_DOMAIN: &[u8] = b"bifrost.code_query.resolution_candidate.v1";
/// Domain separator for a candidate-hierarchy hop row's stable id.
const CANDIDATE_HOP_ID_DOMAIN: &[u8] = b"bifrost.code_query.candidate_hop.v1";

/// Per-request memo of derived environments plus the diagnostics already
/// reported, so one file is derived once and one axis gap is reported once.
#[derive(Default)]
pub(super) struct EnvironmentTraversalCache {
    files: HashMap<ProjectFile, Arc<EnvironmentFileResult>>,
    traced: HashMap<ProjectFile, Arc<OccurrenceFileResult>>,
    reported: HashSet<(ProjectFile, CodeQueryDiagnosticCode)>,
    reported_axes: HashSet<(Language, EnvironmentAxis)>,
}

impl EnvironmentTraversalCache {
    /// Derive (or replay) one file's lexical environment.
    ///
    /// `environment_for_file` takes no cancellation token because it resolves
    /// no definitions, so this never returns `None`; the cost is one facts
    /// lookup, one re-parse and two linear walks, paid once per file.
    pub(super) fn environment_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Arc<EnvironmentFileResult> {
        if let Some(cached) = self.files.get(file) {
            return Arc::clone(cached);
        }
        let derived = Arc::new(environment_for_file(analyzer, file));
        self.files.insert(file.clone(), Arc::clone(&derived));
        derived
    }

    /// Derive (or replay) one file's occurrence rows *with* resolution traces.
    ///
    /// This is a second derivation, not a reuse of the occurrence cache: a
    /// trace costs a full resolution batch per file, so a query that never
    /// asks for candidates must never pay for one.
    pub(super) fn traced_occurrences_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Arc<OccurrenceFileResult>> {
        if let Some(cached) = self.traced.get(file) {
            return Some(Arc::clone(cached));
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = occurrences_for_file_with_options(
            analyzer,
            file,
            OccurrenceDerivationOptions::WITH_CANDIDATES,
            &token,
        )
        .ok()?;
        let derived = Arc::new(derived);
        self.traced.insert(file.clone(), Arc::clone(&derived));
        Some(derived)
    }

    /// Turn one file's environment completeness into typed diagnostics, scoped
    /// to the axes the query actually depends on.
    ///
    /// A file whose adapter records no structured import target is still
    /// authoritative about its scopes, so a `scopes` query over it must not be
    /// reported incomplete.
    pub(super) fn report_completeness(
        &mut self,
        file: &ProjectFile,
        result: &EnvironmentFileResult,
        required: &[EnvironmentAxis],
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let EnvironmentCompleteness::Incomplete { reasons, .. } = &result.completeness else {
            return;
        };
        let language = crate::analyzer::common::language_for_file(file);
        for axis in required {
            if result.completeness.covers(*axis) {
                continue;
            }
            let unsupported = reasons.iter().any(|reason| {
                matches!(reason, EnvironmentIncompleteReason::AxisUnsupported(other) if other == axis)
            });
            let code = if unsupported {
                CodeQueryDiagnosticCode::EnvironmentAxisUnsupported
            } else {
                CodeQueryDiagnosticCode::EnvironmentDerivationIncomplete
            };
            if unsupported {
                // An unsupported axis is a property of the adapter, so it is
                // reported once per language rather than once per file.
                if !self.reported_axes.insert((language, *axis)) {
                    continue;
                }
                diagnostics.push(CodeQueryDiagnostic {
                    code,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: language.config_label(),
                    message: format!(
                        "structural adapter for {} does not support lexical environment axis(es): {}",
                        language.config_label(),
                        axis.label()
                    ),
                });
                continue;
            }
            if !self.reported.insert((file.clone(), code)) {
                continue;
            }
            diagnostics.push(CodeQueryDiagnostic {
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{} has an incomplete lexical environment ({}); its {} rows are not the whole set",
                    super::rel_path_string(file),
                    reasons
                        .iter()
                        .map(incomplete_reason_label)
                        .collect::<Vec<_>>()
                        .join(", "),
                    axis.label()
                ),
            });
        }
    }

    /// Report that a language's resolver reports only its selections, whenever
    /// the query depends on rejections being present.
    pub(super) fn report_trace_completeness(
        &mut self,
        file: &ProjectFile,
        trace: &ResolutionTraceResult,
        filter: &CandidateFilter,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        if trace.completeness.covers_rejections() || !filter.depends_on_rejections() {
            return;
        }
        let language = crate::analyzer::common::language_for_file(file);
        let code = CodeQueryDiagnosticCode::ResolutionTraceIncomplete;
        if !self.reported.insert((file.clone(), code)) {
            return;
        }
        diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "resolver for {} records only selected candidates ({}); an absent rejection row says nothing",
                language.config_label(),
                trace.completeness.label()
            ),
        });
    }
}

fn incomplete_reason_label(reason: &EnvironmentIncompleteReason) -> &'static str {
    match reason {
        EnvironmentIncompleteReason::AxisUnsupported(_) => "axis unsupported",
        EnvironmentIncompleteReason::NoStructuralAdapter => "no structural adapter",
        EnvironmentIncompleteReason::FactsUnavailable => "no structural facts",
        EnvironmentIncompleteReason::SyntaxUnavailable => "source did not parse",
        EnvironmentIncompleteReason::BindingActivationUnknown => {
            "an activation interval could not be stated"
        }
        EnvironmentIncompleteReason::ImportTargetUnstructured => {
            "an import records no structured target"
        }
    }
}

/// One lexical scope row travelling through the pipeline.
///
/// The whole file result travels with the row because ancestry (`scope-of`,
/// `scope-ancestors`) and the bindings of a scope are answered from it, and a
/// derived environment is shared rather than cloned per row.
#[derive(Debug, Clone)]
pub(super) struct ScopeValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<EnvironmentFileResult>,
    pub(super) index: u32,
}

impl ScopeValue {
    pub(super) fn row(&self) -> &ScopeRow {
        self.result.scope(self.index)
    }

    pub(super) fn key(&self) -> ScopeKey {
        ScopeKey {
            file: self.file.clone(),
            index: self.index,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(SCOPE_ID_DOMAIN);
        digest.push(row.content_identity.as_bytes());
        digest.push(&row.index.to_le_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ScopeKey {
    pub(super) file: ProjectFile,
    pub(super) index: u32,
}

/// One binding row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct BindingValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<EnvironmentFileResult>,
    pub(super) index: usize,
    /// `true` when the row was emitted as a binding the reaching binding
    /// shadows. A shadowed row is a distinct answer from the same binding
    /// reached in its own right, so it keys separately.
    pub(super) shadowed: bool,
    /// The AST identity of the occurrence whose reaching binding this row is,
    /// present exactly on rows the `reaching-binding` step produced. It is part
    /// of the dedup key because one binding reached from two occurrences is two
    /// answers, and a consumer that captured one of those tokens must be able
    /// to tell them apart.
    pub(super) reached_from: Option<String>,
}

impl BindingValue {
    pub(super) fn row(&self) -> &BindingRow {
        &self.result.bindings[self.index]
    }

    pub(super) fn key(&self) -> BindingKey {
        BindingKey {
            file: self.file.clone(),
            index: self.index,
            shadowed: self.shadowed,
            reached_from: self.reached_from.clone(),
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(BINDING_ID_DOMAIN);
        digest.push(row.content_identity.as_bytes());
        digest.push(&row.range.start_byte.to_le_bytes());
        digest.push(&row.range.end_byte.to_le_bytes());
        digest.push(row.name.as_bytes());
        digest.push(row.kind.label().as_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct BindingKey {
    pub(super) file: ProjectFile,
    pub(super) index: usize,
    pub(super) shadowed: bool,
    pub(super) reached_from: Option<String>,
}

/// One resolution-candidate row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct CandidateValue {
    /// The reference occurrence whose resolution this candidate explains.
    pub(super) occurrence: Arc<OccurrenceRow>,
    pub(super) candidate: Arc<TraceCandidate>,
    pub(super) ordinal: usize,
    pub(super) completeness: crate::analyzer::usages::get_definition::TraceCompleteness,
}

impl CandidateValue {
    pub(super) fn key(&self) -> CandidateKey {
        CandidateKey {
            file: self.occurrence.file.clone(),
            node: self.occurrence.node,
            role: self.occurrence.role,
            ordinal: self.ordinal,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.occurrence.file
    }

    pub(super) fn id(&self) -> String {
        candidate_row_id(&self.occurrence, self.ordinal)
    }
}

/// The stable id of one resolution-candidate row.
///
/// Hop rows derive their `candidate_id` through this same function rather than
/// through a parallel scheme, so `candidate_hop.candidate_id` is string-equal
/// to the `resolution_candidate.id` of the candidate the hop belongs to and an
/// RQLP join between the two domains lands.
fn candidate_row_id(occurrence: &OccurrenceRow, ordinal: usize) -> String {
    let mut digest = LengthDelimitedDigest::new(CANDIDATE_ID_DOMAIN);
    digest.push(occurrence.content_identity.as_bytes());
    digest.push(&occurrence.node.to_le_bytes());
    digest.push(occurrence.role.label().as_bytes());
    digest.push(&ordinal.to_le_bytes());
    digest.finish().to_string()
}

/// One hierarchy hop of one traced member candidate, travelling through the
/// pipeline.
#[derive(Debug, Clone)]
pub(super) struct CandidateHopValue {
    /// The reference occurrence whose resolution the owning candidate explains.
    pub(super) occurrence: Arc<OccurrenceRow>,
    /// The owning candidate's ordinal in its reference's trace, which is what
    /// makes `candidate_id` equal to that candidate row's own id.
    pub(super) ordinal: usize,
    pub(super) hop: Arc<HierarchyHopRecord>,
}

impl CandidateHopValue {
    pub(super) fn key(&self) -> CandidateHopKey {
        CandidateHopKey {
            file: self.occurrence.file.clone(),
            node: self.occurrence.node,
            role: self.occurrence.role,
            ordinal: self.ordinal,
            hop: self.hop.hop,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.occurrence.file
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(CANDIDATE_HOP_ID_DOMAIN);
        digest.push(self.occurrence.content_identity.as_bytes());
        digest.push(&self.occurrence.node.to_le_bytes());
        digest.push(self.occurrence.role.label().as_bytes());
        digest.push(&self.ordinal.to_le_bytes());
        digest.push(&self.hop.hop.to_le_bytes());
        digest.finish().to_string()
    }

    pub(super) fn candidate_id(&self) -> String {
        candidate_row_id(&self.occurrence, self.ordinal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CandidateHopKey {
    pub(super) file: ProjectFile,
    pub(super) node: u32,
    pub(super) role: OccurrenceRole,
    pub(super) ordinal: usize,
    pub(super) hop: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CandidateKey {
    pub(super) file: ProjectFile,
    pub(super) node: u32,
    pub(super) role: OccurrenceRole,
    pub(super) ordinal: usize,
}

/// Scope indices of one file result that satisfy a filter, in pre-order.
pub(super) fn select_scopes<'rows>(
    result: &'rows EnvironmentFileResult,
    filter: &'rows ScopeFilter,
) -> impl Iterator<Item = u32> + 'rows {
    result
        .scopes
        .iter()
        .filter(|scope| filter.matches(scope.anchor.kind()))
        .map(|scope| scope.index)
}

/// Binding indices of one file result that satisfy a filter, in source order.
pub(super) fn select_bindings<'rows>(
    result: &'rows EnvironmentFileResult,
    filter: &'rows BindingFilter,
) -> impl Iterator<Item = usize> + 'rows {
    result
        .bindings
        .iter()
        .enumerate()
        .filter(|(_, binding)| filter.matches(binding.kind, &binding.name, binding.hoisting))
        .map(|(index, _)| index)
}

/// The axes a scope query depends on.
pub(super) const SCOPE_QUERY_AXES: &[EnvironmentAxis] = &[EnvironmentAxis::Scopes];
/// The axes a binding query depends on. Scopes are included because a binding
/// row names its declaring scope, so a file without scopes has no binding rows
/// to speak of either.
pub(super) const BINDING_QUERY_AXES: &[EnvironmentAxis] =
    &[EnvironmentAxis::Scopes, EnvironmentAxis::BindingIntervals];

/// The public projection of one scope row.
pub(super) fn public_scope(value: &ScopeValue, range: CodeQueryRange) -> CodeQueryLexicalScope {
    let row = value.row();
    CodeQueryLexicalScope {
        id: value.id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        index: row.index,
        kind: row.anchor.kind().map(|kind| kind.label()),
        range,
        start_byte: row.range.start_byte,
        end_byte: row.range.end_byte,
        parent_index: row.parent_scope,
    }
}

/// The public projection of one binding row.
pub(super) fn public_binding(value: &BindingValue, range: CodeQueryRange) -> CodeQueryBinding {
    let row = value.row();
    CodeQueryBinding {
        id: value.id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        name: row.name.clone(),
        kind: row.kind.label(),
        hoisting: row.hoisting.label(),
        namespace: row.namespace().label(),
        range,
        start_byte: row.range.start_byte,
        end_byte: row.range.end_byte,
        activation_start_byte: row.activation.start_byte,
        activation_end_byte: row.activation.end_byte,
        declaring_scope_index: row.declaring_scope,
        source_order: row.source_order,
        visibility: row.visibility.label(),
        import: row.import.as_ref().map(|import| CodeQueryImportBinder {
            local_name: import.local_name.clone(),
            alias: import.alias.clone(),
            target_segments: import.target_segments.clone(),
            wildcard: import.wildcard,
            wildcard_ambiguous: import.wildcard_ambiguous,
            boundary: import.boundary.label(),
        }),
        shadowed: value.shadowed,
        reached_from_ast_id: value.reached_from.clone(),
    }
}

/// The public projection of one candidate row, minus the declaration rendering
/// its `Unit` shape needs, which only the engine can do.
pub(super) fn public_candidate(
    value: &CandidateValue,
    range: CodeQueryRange,
    candidate: CodeQueryCandidateRef,
    canonical_member_id: Option<String>,
    owner: Option<CodeQueryDeclaration>,
) -> CodeQueryResolutionCandidate {
    let row = &value.occurrence;
    let trace = &value.candidate;
    let member = trace.member.as_deref();
    CodeQueryResolutionCandidate {
        id: value.id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        range,
        start_byte: row.range.start_byte,
        end_byte: row.range.end_byte,
        ordinal: value.ordinal,
        tier: trace.tier.map(|tier| tier.label()),
        outcome: trace.outcome.label(),
        rejection_reason: trace.outcome.rejection().map(|reason| reason.label()),
        boundary: trace.boundary.label(),
        visibility: trace.visibility.label(),
        trace_completeness: value.completeness.label(),
        candidate,
        external_target: trace.external_target.clone(),
        canonical_member_id,
        owner,
        hierarchy_depth: member.map(|member| member.hierarchy_depth),
        dispatch_tier: member.map(|member| member.dispatch_tier.label()),
        applicability: member.map(|member| member.applicability.label()),
    }
}

/// The public projection of one hierarchy-hop row, minus the declaration
/// rendering its endpoints need, which only the engine can do.
pub(super) fn public_candidate_hop(
    value: &CandidateHopValue,
    range: CodeQueryRange,
    from: Option<CodeQueryDeclaration>,
    to: Option<CodeQueryDeclaration>,
) -> CodeQueryCandidateHop {
    let row = &value.occurrence;
    CodeQueryCandidateHop {
        id: value.id(),
        candidate_id: value.candidate_id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        range,
        start_byte: row.range.start_byte,
        end_byte: row.range.end_byte,
        hop: value.hop.hop,
        relation: value.hop.relation.label(),
        from,
        to,
    }
}

/// The candidate shapes that carry no workspace declaration, expressed once so
/// `candidate-target` and the projection agree about which rows it can answer.
pub(super) fn candidate_unit(candidate: &TraceCandidateRef) -> Option<&crate::analyzer::CodeUnit> {
    match candidate {
        TraceCandidateRef::Unit(unit) => Some(unit),
        TraceCandidateRef::Lexical(_)
        | TraceCandidateRef::Binding { .. }
        | TraceCandidateRef::ImportBinder { .. }
        | TraceCandidateRef::ExternalRoute { .. } => None,
    }
}
