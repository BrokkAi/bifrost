//! Solve receiver scopes before using dynamic writes as absence evidence.

use super::correlations::CorrelationError;
use super::field_slots::{FieldSlotIndex, receiver_values};
use super::plan::{ProcedureRefinements, TypeFlowDiscovery, TypeFlowPlanError};
use super::refinement_sources::DefinitionSources;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, DynamicFieldNameSet, IcfgProvider,
    ProcedureHandle, ProcedurePortHandle, ProgramPointHandle, ProgramPointId, SemanticArtifact,
    SemanticBudget, SemanticEffect, SemanticProcedureReference, SemanticRequest, SourceSite,
    SourceSiteKind, TypeFlowAdapter, UnknownReason, ValueId, WorkspaceIcfgProvider,
};
use crate::dataflow::{DataflowRequest, SolverBudget};
use crate::hash::HashSet;
use crate::value_flow::{
    ClosureLimits, ValueFlowCache, ValueFlowCarrier, ValueFlowSourceId, WorkspaceValueFlowProvider,
    solve_value_flow_with_summaries,
};

#[derive(Debug, Clone)]
pub(super) struct PendingDynamicWrite {
    pub procedure: SemanticProcedureReference,
    pub names: DynamicFieldNameSet,
    pub site: SourceSite,
    prepared: PreparedWrite,
}

impl PendingDynamicWrite {
    pub(super) fn new(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        procedure: &ProcedureHandle,
        receiver: Option<ValueId>,
        names: DynamicFieldNameSet,
        site: SourceSite,
    ) -> Self {
        let prepared = prepare_write(
            workspace,
            adapter,
            &ResolvedDynamicWrite {
                procedure: procedure.clone(),
                receiver,
                site: site.clone(),
            },
        );
        Self {
            procedure: SemanticProcedureReference::of(procedure),
            names,
            site,
            prepared,
        }
    }
}

struct ResolvedDynamicWrite {
    procedure: ProcedureHandle,
    receiver: Option<ValueId>,
    site: SourceSite,
}

/// Plain receiver facts captured while only the write's owning file is live.
#[derive(Debug, Clone)]
struct PreparedWrite {
    structural: StructuralWriteReceiverBound,
    receiver_field: Option<(ClassIdentity, Box<str>)>,
    interference: StructuralWriteReceiverBound,
    explicitly_unbounded: bool,
    receiver_bound: Option<ClassIdentity>,
    observation: Option<WriteObservationReference>,
}

#[derive(Debug, Clone)]
struct WriteObservationReference {
    point: ProgramPointId,
    event: Option<usize>,
    receiver: ValueId,
}

impl WriteObservationReference {
    fn resolve(&self, procedure: &ProcedureHandle) -> WriteObservation {
        let point = procedure
            .point_handle(self.point)
            .expect("same-revision write point is live");
        match self.event {
            Some(event) => WriteObservation::Event {
                point,
                event,
                carrier: ValueFlowCarrier::for_value(
                    procedure
                        .value_handle(self.receiver)
                        .expect("same-revision write receiver is live"),
                ),
            },
            None => WriteObservation::ReceiverEntry {
                point,
                carrier: ValueFlowCarrier::Port(
                    ProcedurePortHandle::receiver(procedure.clone())
                        .expect("a proven receiver has an entry port"),
                ),
            },
        }
    }
}

fn materialize_reference(
    workspace: &WorkspaceAnalyzer,
    reference: &SemanticProcedureReference,
    current_file: &mut Option<std::sync::Arc<SemanticArtifact>>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureHandle, TypeFlowPlanError> {
    if current_file
        .as_ref()
        .is_none_or(|artifact| artifact.key() != &reference.key)
    {
        // Replace the previous file before lowering the next one. Root closures
        // retain their own handles only until that root's survey returns.
        *current_file = None;
        let file = brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator(
            workspace,
            &reference.locator,
        )
        .ok_or(TypeFlowPlanError::RootRelationsUnavailable)?;
        let outcome = workspace
            .materialize_program_semantics(&file, &mut SemanticRequest::new(budget, cancellation))
            .map_err(TypeFlowPlanError::Discovery)?;
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        let artifact = outcome.available_value().ok_or_else(|| {
            outcome.budget_exceeded().map_or(
                TypeFlowPlanError::RootRelationsUnavailable,
                TypeFlowPlanError::RefinementBudget,
            )
        })?;
        if artifact.key() != &reference.key {
            return Err(TypeFlowPlanError::RootRelationsUnavailable);
        }
        *current_file = Some(std::sync::Arc::clone(artifact));
    }
    let artifact = current_file
        .as_ref()
        .expect("reference resolution mounted its file");
    let id = artifact
        .procedure_id(&reference.locator)
        .ok_or(TypeFlowPlanError::RootRelationsUnavailable)?;
    Ok(artifact
        .procedure_handle(id)
        .expect("a retained procedure has a handle"))
}

/// Why an arbitrary-name mutation prevents an absence proof at another site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicWriteEvidence {
    pub site: SourceSite,
    /// Why receiver identity is incomplete. A separate scope bit determines
    /// whether that uncertainty is global or constrained by `bounds`.
    pub reason: Option<UnknownReason>,
}

impl DynamicWriteEvidence {
    /// A stable source location suitable for a conditional finding sentence.
    pub fn location(&self) -> String {
        let path = crate::analyzer::semantic::WorkspaceRelativePath::try_from_path(
            self.site.file.rel_path(),
        )
        .expect("a workspace write has a portable relative path");
        let position = self.site.span.start();
        format!(
            "{}:{}:{}",
            path.as_str(),
            position.line() + 1,
            position.byte_column() + 1
        )
    }

    pub fn origin(&self) -> String {
        let path = crate::analyzer::semantic::WorkspaceRelativePath::try_from_path(
            self.site.file.rel_path(),
        )
        .expect("a workspace write has a portable relative path");
        let position = self.site.span.start();
        let scope = self
            .reason
            .as_ref()
            .map_or_else(|| "bounded".to_owned(), ToString::to_string);
        format!(
            "unknown:dynamic_field_write:{scope}:{}:{}:{}",
            path.as_str(),
            position.line() + 1,
            position.byte_column() + 1
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScopedDynamicWrite {
    /// Receiver classes observed exactly at a write site.
    pub classes: Vec<ClassIdentity>,
    /// Structural upper bounds for unknown receiver alternatives.
    pub bounds: Vec<ClassIdentity>,
    /// An unbounded receiver alternative can affect any class.
    pub global: bool,
    /// Names this write can install, independent of its receiver scope.
    pub names: DynamicFieldNameSet,
    pub evidence: DynamicWriteEvidence,
}

impl ScopedDynamicWrite {
    pub fn open(site: SourceSite, names: DynamicFieldNameSet, reason: UnknownReason) -> Self {
        Self {
            classes: Vec::new(),
            bounds: Vec::new(),
            global: true,
            names,
            evidence: DynamicWriteEvidence {
                site,
                reason: Some(reason),
            },
        }
    }

    pub fn affects(
        &self,
        class: &ClassIdentity,
        hierarchy: &crate::analyzer::semantic::ClassHierarchy,
        member: &str,
    ) -> bool {
        let can_install_member = match &self.names {
            DynamicFieldNameSet::Exact(names) => names.iter().any(|name| name.as_ref() == member),
            DynamicFieldNameSet::Prefix(prefix) => member.starts_with(prefix.as_ref()),
            DynamicFieldNameSet::Any => true,
            DynamicFieldNameSet::None => false,
        };
        can_install_member && self.receiver_affects(class, hierarchy)
    }

    /// Removals cannot make an absent member present, but can still make an
    /// existing member's slot contents uncertain.
    pub fn may_change_slot_contents(
        &self,
        class: &ClassIdentity,
        hierarchy: &crate::analyzer::semantic::ClassHierarchy,
        member: &str,
    ) -> bool {
        (matches!(&self.names, DynamicFieldNameSet::None)
            && self.receiver_affects(class, hierarchy))
            || self.affects(class, hierarchy, member)
    }

    fn receiver_affects(
        &self,
        class: &ClassIdentity,
        hierarchy: &crate::analyzer::semantic::ClassHierarchy,
    ) -> bool {
        self.global
            || self.classes.contains(class)
            || self.bounds.iter().any(|bound| {
                bound == class || hierarchy.unresolved_base || hierarchy.ancestors.contains(bound)
            })
    }
}

/// The program point and event index at which a dynamic write is observed.
///
/// A write lowered as a call is observed at that call's invoke event; one
/// lowered as a store is observed at the first store inside its source span.
fn observation_point(write: &ResolvedDynamicWrite) -> Option<(ProgramPointId, usize)> {
    let semantics = write.procedure.semantics();
    let call = semantics.call_sites().iter().find_map(|call| {
        (semantics.source_mapping(call.source)?.locator.anchor().span() == write.site.span).then(
            || {
                (
                    call.point,
                    semantics
                        .point(call.point)
                        .expect("live call point")
                        .events
                        .iter()
                        .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call.id))
                        .expect("a call owns its invoke event"),
                )
            },
        )
    });
    call.or_else(|| {
        semantics.points().iter().find_map(|point| {
            point.events.iter().enumerate().find_map(|(index, event)| {
                if !matches!(event.effect, SemanticEffect::MemoryStore { .. }) {
                    return None;
                }
                let span = semantics
                    .source_mapping(event.source)?
                    .locator
                    .anchor()
                    .span();
                (write.site.span.start_byte() <= span.start_byte()
                    && span.end_byte() <= write.site.span.end_byte())
                .then_some((point.id, index))
            })
        })
    })
}

enum WriteObservation {
    Event {
        point: ProgramPointHandle,
        event: usize,
        carrier: ValueFlowCarrier,
    },
    ReceiverEntry {
        point: ProgramPointHandle,
        carrier: ValueFlowCarrier,
    },
}

#[derive(Debug, Clone)]
enum StructuralWriteReceiverBound {
    NotApplicable,
    Bounded(Vec<ClassIdentity>),
    Unbounded(UnknownReason),
}

fn dynamic_type_write_receiver_bounds(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    write: &ResolvedDynamicWrite,
) -> StructuralWriteReceiverBound {
    let Some(receiver) = write.receiver else {
        return StructuralWriteReceiverBound::NotApplicable;
    };
    match adapter.dynamic_type_write_receiver_bounds(
        workspace,
        &write.procedure,
        receiver,
        write.site.span,
    ) {
        Ok(Some(bounds)) => StructuralWriteReceiverBound::Bounded(bounds),
        Ok(None) => StructuralWriteReceiverBound::NotApplicable,
        Err(reason) => StructuralWriteReceiverBound::Unbounded(reason),
    }
}

fn non_escaping_nested_write_receiver_bounds(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    write: &ResolvedDynamicWrite,
) -> StructuralWriteReceiverBound {
    let Some(receiver) = write.receiver else {
        return StructuralWriteReceiverBound::NotApplicable;
    };
    match adapter.non_escaping_nested_write_receiver_bounds(
        workspace,
        &write.procedure,
        receiver,
        write.site.span,
    ) {
        Ok(Some(bounds)) => StructuralWriteReceiverBound::Bounded(bounds),
        Ok(None) => StructuralWriteReceiverBound::NotApplicable,
        Err(reason) => StructuralWriteReceiverBound::Unbounded(reason),
    }
}

fn field_value_write_receiver_bounds(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    slots: &FieldSlotIndex,
    writes: &[PendingDynamicWrite],
    prepared: &[&PreparedWrite],
    index: usize,
) -> StructuralWriteReceiverBound {
    let Some((owner, member)) = &prepared[index].receiver_field else {
        return StructuralWriteReceiverBound::NotApplicable;
    };
    let Some(slot) = slots.slot(workspace, adapter, owner, member) else {
        return StructuralWriteReceiverBound::Unbounded(UnknownReason::FieldSlotIncomplete);
    };
    let hierarchy = adapter.class_hierarchy(workspace, owner);
    for (other, facts) in writes.iter().zip(prepared) {
        if other.site == writes[index].site
            || !dynamic_names_may_change_member(&other.names, member)
            || facts.receiver_field.is_some()
        {
            continue;
        }
        let StructuralWriteReceiverBound::Bounded(bounds) = &facts.interference else {
            return StructuralWriteReceiverBound::Unbounded(UnknownReason::DynamicFieldWrite);
        };
        if facts.explicitly_unbounded
            || bounds.iter().any(|bound| {
                bound == owner
                    || hierarchy.ancestors.contains(bound)
                    || hierarchy
                        .descendants
                        .as_ref()
                        .is_some_and(|descendants| descendants.contains(bound))
            })
        {
            return StructuralWriteReceiverBound::Unbounded(UnknownReason::DynamicFieldWrite);
        }
    }
    let mut bounds = Vec::new();
    let mut stores = HashSet::default();
    for (_, site) in &slot.atoms {
        if !stores.insert((site.file.clone(), site.span)) {
            continue;
        }
        match adapter.field_store_value_bounds(workspace, &site.file, site.span, member) {
            Ok(Some(classes)) => {
                for class in classes {
                    if !bounds.contains(&class) {
                        bounds.push(class);
                    }
                }
            }
            Ok(None) => {
                return StructuralWriteReceiverBound::Unbounded(UnknownReason::FieldSlotIncomplete);
            }
            Err(reason) => return StructuralWriteReceiverBound::Unbounded(reason),
        }
    }
    if stores.is_empty() {
        StructuralWriteReceiverBound::Unbounded(UnknownReason::FieldSlotIncomplete)
    } else {
        StructuralWriteReceiverBound::Bounded(bounds)
    }
}

fn dynamic_names_may_change_member(names: &DynamicFieldNameSet, member: &str) -> bool {
    match names {
        DynamicFieldNameSet::Exact(names) => names.iter().any(|name| name.as_ref() == member),
        DynamicFieldNameSet::Prefix(prefix) => member.starts_with(prefix.as_ref()),
        DynamicFieldNameSet::Any => true,
        // A removal cannot install a class, but it can invalidate this field's stored value.
        DynamicFieldNameSet::None => true,
    }
}

fn prepare_write(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    write: &ResolvedDynamicWrite,
) -> PreparedWrite {
    let structural = match dynamic_type_write_receiver_bounds(workspace, adapter, write) {
        StructuralWriteReceiverBound::NotApplicable => {
            non_escaping_nested_write_receiver_bounds(workspace, adapter, write)
        }
        bound => bound,
    };
    let receiver_bound =
        adapter.dynamic_write_receiver_bound(workspace, &write.procedure, write.site.span);
    let interference = match &structural {
        StructuralWriteReceiverBound::NotApplicable => receiver_bound.clone().map_or(
            StructuralWriteReceiverBound::Unbounded(UnknownReason::DynamicFieldWrite),
            |class| StructuralWriteReceiverBound::Bounded(vec![class]),
        ),
        StructuralWriteReceiverBound::Bounded(classes) => {
            StructuralWriteReceiverBound::Bounded(classes.clone())
        }
        StructuralWriteReceiverBound::Unbounded(reason) => {
            StructuralWriteReceiverBound::Unbounded(reason.clone())
        }
    };
    let receivers = receiver_values(&write.procedure);
    let stable =
        !receivers.is_empty() && adapter.receiver_binding_is_stable(workspace, &write.procedure);
    let observation = write.receiver.and_then(|receiver| {
        if stable && receivers.contains(&receiver) {
            Some(WriteObservationReference {
                point: write.procedure.semantics().entry_point(),
                event: None,
                receiver,
            })
        } else {
            observation_point(write).map(|(point, event)| WriteObservationReference {
                point,
                event: Some(event),
                receiver,
            })
        }
    });
    let receiver_bound = receiver_bound.or_else(|| {
        (stable
            && write
                .receiver
                .is_some_and(|receiver| receivers.contains(&receiver)))
        .then(|| adapter.enclosing_class(workspace, &write.procedure))
        .flatten()
    });
    PreparedWrite {
        structural,
        interference,
        observation,
        receiver_bound,
        receiver_field: adapter.dynamic_write_receiver_field(
            workspace,
            &write.procedure,
            write.site.span,
        ),
        explicitly_unbounded: adapter.dynamic_write_receiver_is_explicitly_unbounded(
            workspace,
            &write.procedure,
            write.site.span,
        ),
    }
}

impl WriteObservation {
    fn point(&self) -> &ProgramPointHandle {
        match self {
            Self::Event { point, .. } | Self::ReceiverEntry { point, .. } => point,
        }
    }
}

struct DynamicCallerCandidates {
    roots: HashSet<SemanticProcedureReference>,
    unbounded: Vec<(usize, String)>,
}

/// A nested callable can mint a semantic procedure without a declaration row
/// of its own, so `enclosing_code_unit` returns the declaration that lexically
/// owns it. Accept a direct name match first, then the nearest declaration
/// segment below any trailing callable segments. A procedure that mints a
/// declaration must still name the unit it encloses.
fn enclosing_unit_owns(
    unit: &brokk_bifrost_analysis::analyzer::CodeUnit,
    reference: &SemanticProcedureReference,
) -> bool {
    use brokk_bifrost_analysis::analyzer::semantic::DeclarationSegmentKind;

    if unit.is_file_scope() {
        return false;
    }
    let segments = reference.locator.declaration().segments();
    if segments.last().and_then(|segment| segment.name()) == Some(unit.identifier()) {
        return true;
    }
    segments
        .iter()
        .rev()
        .find(|segment| {
            !matches!(
                segment.kind(),
                DeclarationSegmentKind::LocalFunction
                    | DeclarationSegmentKind::Lambda
                    | DeclarationSegmentKind::Closure
                    | DeclarationSegmentKind::AnonymousCallable
            )
        })
        .is_some_and(|segment| {
            matches!(
                segment.kind(),
                DeclarationSegmentKind::Function
                    | DeclarationSegmentKind::Method
                    | DeclarationSegmentKind::Constructor
            ) && segment.name() == Some(unit.identifier())
        })
}

/// The result and the name-based reverse edges live only for this prepass.
/// No executable artifacts are retained by candidate selection.
fn candidate_roots(
    workspace: &WorkspaceAnalyzer,
    procedures: &[SemanticProcedureReference],
    writes: &[PendingDynamicWrite],
    cancellation: &CancellationToken,
) -> Result<DynamicCallerCandidates, String> {
    use crate::hash::HashMap;
    use brokk_bifrost_analysis::analyzer::usages::UsageProofAuthority;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::{
        CallRelationDiagnosticCode, CallRelationLimits, CallRelationService,
    };
    use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shapes_in_file;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, CodeUnit, QueryScope, Range};

    let analyzer = workspace.analyzer();
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut roots_by_unit: HashMap<CodeUnit, Vec<&SemanticProcedureReference>> = HashMap::default();
    let mut units_by_reference = HashMap::default();
    let mut files = HashSet::default();
    let mut unmapped_roots = HashSet::default();
    for reference in procedures
        .iter()
        .chain(writes.iter().map(|write| &write.procedure))
    {
        let file = brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator(
            workspace,
            &reference.locator,
        )
        .ok_or_else(|| format!("file unavailable for {:?}", reference.locator))?;
        files.insert(file.clone());
        let span = reference.locator.anchor().span();
        let range = Range {
            start_byte: span.start_byte() as usize,
            end_byte: span.end_byte() as usize,
            start_line: span.start().line() as usize,
            end_line: span.end().line() as usize,
        };
        if let Some(unit) = analyzer
            .enclosing_code_unit(&file, &range)
            .filter(|unit| enclosing_unit_owns(unit, reference))
        {
            roots_by_unit
                .entry(unit.clone())
                .or_default()
                .push(reference);
            units_by_reference.insert(reference, unit);
        } else {
            // An anonymous or synthetic root might not have a declaration row.
            // It remains eligible for completed walks; a write without a declaration
            // is caller-unbounded.
            unmapped_roots.insert(reference.clone());
        }
    }
    // Incoming usages resolve import aliases and retain unproven dispatch.
    // Supplement them with every same-name structured call, including receiver
    // expressions whose types the usage resolver cannot classify yet.
    let mut callers_by_name: HashMap<String, Vec<CodeUnit>> = HashMap::default();
    for file in files {
        if cancellation.is_cancelled() {
            return Err("cancelled while reading call shapes".to_owned());
        }
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(&file))
            .ok_or_else(|| format!("call index unavailable for {file:?}"))?;
        for report in call_shapes_in_file(&facts, &file, usize::MAX) {
            let Some(name) = report.outcome.callee_name else {
                continue;
            };
            let caller = analyzer
                .enclosing_code_unit(&file, &report.outcome.range)
                .ok_or_else(|| {
                    format!(
                        "call enclosing declaration unavailable: file={file:?} callee={name:?} range={:?}",
                        report.outcome.range
                    )
                })?;
            callers_by_name.entry(name).or_default().push(caller);
        }
    }
    // Multiple write sites can share their entire caller frontier. Retain only
    // this query's plain caller outcomes, never syntax or executable artifacts.
    let mut incoming_by_unit: HashMap<CodeUnit, Result<Vec<CodeUnit>, String>> = HashMap::default();
    struct Walk {
        write_index: usize,
        frontier: Vec<CodeUnit>,
        seen: HashSet<CodeUnit>,
        roots: HashSet<SemanticProcedureReference>,
        failure: Option<String>,
    }
    let mut walks = Vec::new();
    let mut candidates = HashSet::default();
    let mut unbounded = Vec::new();
    for (write_index, write) in writes.iter().enumerate() {
        if let Some(unit) = units_by_reference.get(&write.procedure) {
            walks.push(Walk {
                write_index,
                frontier: vec![unit.clone()],
                seen: HashSet::default(),
                roots: unmapped_roots.clone(),
                failure: None,
            });
        } else {
            unbounded.push((
                write_index,
                format!("write enclosing declaration unavailable: {:?}", write.site),
            ));
        }
    }
    let limits = CallRelationLimits {
        max_files: usize::MAX,
        max_source_bytes: 256 * 1024 * 1024,
        max_candidates: DYNAMIC_SURVEY_MAX_INCOMING,
    };
    for depth in 0..=DYNAMIC_SURVEY_MAX_PROCEDURES {
        if cancellation.is_cancelled() {
            for walk in &mut walks {
                if walk.failure.is_none() && !walk.frontier.is_empty() {
                    walk.failure = Some("cancelled during reverse caller walk".to_owned());
                }
            }
            break;
        }
        let mut needed = HashSet::default();
        let mut level_units = HashSet::default();
        for walk in walks.iter_mut().filter(|walk| walk.failure.is_none()) {
            walk.frontier.retain(|unit| walk.seen.insert(unit.clone()));
            for unit in &walk.frontier {
                if let Some(roots) = roots_by_unit.get(unit) {
                    walk.roots.extend(roots.iter().map(|root| (*root).clone()));
                }
                if depth == DYNAMIC_SURVEY_MAX_PROCEDURES {
                    walk.failure = Some(format!(
                        "reverse caller depth budget {} reached at {unit:?}",
                        DYNAMIC_SURVEY_MAX_PROCEDURES
                    ));
                    break;
                }
                level_units.insert(unit.clone());
                if !incoming_by_unit.contains_key(unit) {
                    needed.insert(unit.clone());
                }
            }
        }
        if level_units.is_empty() {
            break;
        }
        let mut needed: Vec<_> = needed.into_iter().collect();
        needed.sort();
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "type_flow.dynamic_store_caller_level level={depth} procedures={} batch={}",
                level_units.len(),
                needed.len()
            )
        });
        let incoming = CallRelationService::incoming_batch_with_unproven_limit(
            analyzer,
            scope.token(),
            &needed,
            limits,
            DYNAMIC_SURVEY_MAX_INCOMING,
            Some(cancellation),
        );
        assert_eq!(incoming.len(), needed.len());
        for (unit, incoming) in needed.iter().zip(incoming) {
            let result = (|| -> Result<Vec<CodeUnit>, String> {
                // Legacy incoming lookup appends outgoing diagnostics while recovering
                // self-recursive calls suppressed by usages. Such an omission can only
                // hide a self-edge, and this node is already visited. Compare complete
                // structured diagnostics with the same outgoing operation rather than
                // interpreting their text or dropping a genuine incoming omission.
                let recursive = (incoming.proof_authority == UsageProofAuthority::Legacy
                    && incoming.diagnostics.iter().any(|diagnostic| {
                        diagnostic.code == CallRelationDiagnosticCode::CandidatesOmitted
                    }))
                .then(|| {
                    CallRelationService::outgoing_bounded(
                        analyzer,
                        scope.token(),
                        unit,
                        limits,
                        Some(cancellation),
                    )
                });
                if incoming.cancelled
                    || incoming.truncated
                    || incoming.diagnostics.iter().any(|diagnostic| {
                        diagnostic.code != CallRelationDiagnosticCode::TargetsAmbiguous
                            && !(diagnostic.code == CallRelationDiagnosticCode::CandidatesOmitted
                                && recursive.as_ref().is_some_and(|result| {
                                    !result.cancelled
                                        && !result.truncated
                                        && result.diagnostics.contains(diagnostic)
                                }))
                    })
                {
                    return Err(format!(
                        "reverse callers unavailable for {unit:?}: cancelled={} truncated={} diagnostics={:?}",
                        incoming.cancelled, incoming.truncated, incoming.diagnostics
                    ));
                }
                Ok(incoming.sites.into_iter().map(|site| site.caller).collect())
            })();
            incoming_by_unit.insert(unit.clone(), result);
        }
        for walk in walks.iter_mut().filter(|walk| walk.failure.is_none()) {
            let mut next = Vec::new();
            for unit in &walk.frontier {
                match incoming_by_unit
                    .get(unit)
                    .expect("every level target was queried")
                {
                    Ok(callers) => next.extend(callers.iter().cloned()),
                    Err(reason) => {
                        walk.failure = Some(reason.clone());
                        break;
                    }
                }
                if let Some(callers) = callers_by_name.get(unit.identifier()) {
                    if callers.len() > DYNAMIC_SURVEY_MAX_INCOMING {
                        walk.failure = Some(format!(
                            "same-name incoming candidates omitted={} limit={} procedure={unit:?}",
                            callers.len() - DYNAMIC_SURVEY_MAX_INCOMING,
                            DYNAMIC_SURVEY_MAX_INCOMING,
                        ));
                        break;
                    }
                    next.extend(callers.iter().cloned());
                }
            }
            walk.frontier = next;
        }
    }
    for walk in walks {
        if let Some(reason) = walk.failure {
            unbounded.push((walk.write_index, reason));
        } else {
            candidates.extend(walk.roots);
        }
    }
    unbounded.sort_by_key(|(index, _)| *index);
    Ok(DynamicCallerCandidates {
        roots: candidates,
        unbounded,
    })
}

const DYNAMIC_SURVEY_MAX_PROCEDURES: usize = 128;
const DYNAMIC_SURVEY_MAX_INCOMING: usize = 4096;

/// Each candidate procedure is an entry context, just as in the public
/// workspace solve. Root-parameter unknowns supply no concrete workspace
/// callers; their actual arguments are observed in the callers' closures.
/// Other unknown expressions are open effects, never an empty class set.
#[allow(clippy::too_many_arguments)]
pub(super) fn survey_references(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    slots: &FieldSlotIndex,
    procedures: &[SemanticProcedureReference],
    writes: &[PendingDynamicWrite],
    value_flow_cache: ValueFlowCache,
    budget: &mut SemanticBudget,
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
) -> Result<Vec<ScopedDynamicWrite>, TypeFlowPlanError> {
    let _timing = brokk_bifrost_core::profiling::scope("type_flow.dynamic_store_survey");
    let prepared = writes
        .iter()
        .map(|write| &write.prepared)
        .collect::<Vec<_>>();
    let structural_write_bounds = prepared
        .iter()
        .enumerate()
        .map(|(index, facts)| match &facts.structural {
            StructuralWriteReceiverBound::NotApplicable => field_value_write_receiver_bounds(
                workspace, adapter, slots, writes, &prepared, index,
            ),
            StructuralWriteReceiverBound::Bounded(classes) => {
                StructuralWriteReceiverBound::Bounded(classes.clone())
            }
            StructuralWriteReceiverBound::Unbounded(reason) => {
                StructuralWriteReceiverBound::Unbounded(reason.clone())
            }
        })
        .collect::<Vec<_>>();
    let provider = WorkspaceIcfgProvider::new(workspace);
    let discovery = WorkspaceValueFlowProvider::with_oracle(
        provider.oracle().clone(),
        provider.behavior_identity(),
        value_flow_cache.clone(),
    );
    let mut effects = writes
        .iter()
        .zip(&structural_write_bounds)
        .map(|(write, structural_bound)| {
            let mut effect = ScopedDynamicWrite {
                classes: Vec::new(),
                bounds: Vec::new(),
                global: false,
                names: write.names.clone(),
                evidence: DynamicWriteEvidence {
                    site: write.site.clone(),
                    reason: None,
                },
            };
            match structural_bound {
                StructuralWriteReceiverBound::NotApplicable => {}
                StructuralWriteReceiverBound::Bounded(classes) => {
                    apply_dynamic_receiver_bounds(workspace, adapter, &mut effect, classes);
                }
                StructuralWriteReceiverBound::Unbounded(reason) => {
                    open_global(&mut effect, reason.clone());
                }
            }
            effect
        })
        .collect::<Vec<_>>();
    for (effect, facts) in effects.iter_mut().zip(&prepared) {
        if facts.explicitly_unbounded {
            open_global(effect, UnknownReason::OpenTypeBound);
        }
    }
    let structural_receiver_bounds = prepared
        .iter()
        .map(|facts| facts.receiver_bound.clone())
        .collect::<Vec<_>>();
    // A write whose receiver reaches a root parameter takes its identity from
    // an actual argument supplied by some caller. A candidate whose survey
    // failed may have carried that caller, so such a write cannot be trusted as
    // bounded once any candidate failed. A receiver built in place, or the
    // enclosing procedure's own `self`, is bounded by the surveyed root alone.
    let mut caller_dependent = vec![false; writes.len()];
    // The first reason a root's own survey could not be completed. It scopes
    // to the writes that could depend on the roots it did not observe, never
    // to every write in the workspace.
    let mut survey_failure: Option<UnknownReason> = None;
    // These memoized refinements contain identities and plain facts, not handles.
    // Overlapping root closures can reuse them without pinning their artifacts.
    let mut refinements = ProcedureRefinements::default();
    let mut current_file = None;
    let mut incomplete_roots = Vec::new();
    let candidate_started = std::time::Instant::now();
    let (candidates, caller_unbounded) =
        match candidate_roots(workspace, procedures, writes, cancellation) {
            Ok(result) => (result.roots, result.unbounded),
            Err(reason) => (
                HashSet::default(),
                (0..writes.len())
                    .map(|index| (index, reason.clone()))
                    .collect(),
            ),
        };
    for (index, reason) in &caller_unbounded {
        let write = &writes[*index];
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "type_flow.dynamic_store_caller_unbounded site={:?} procedure={:?} reason={reason:?}",
                write.site, write.procedure
            )
        });
        open_or_bound(
            workspace,
            adapter,
            &mut effects[*index],
            structural_receiver_bounds[*index].as_ref(),
            UnknownReason::UnmodeledLoad,
        );
    }
    let caller_unbounded_count = caller_unbounded.len();
    let candidate_seconds = candidate_started.elapsed().as_secs_f64();
    let candidate_count = procedures
        .iter()
        .filter(|reference| candidates.contains(*reference))
        .count();
    let skipped_count = procedures.len() - candidate_count;
    brokk_bifrost_core::profiling::note_with(|| {
        let roots: Vec<_> = procedures
            .iter()
            .filter(|reference| candidates.contains(*reference))
            .map(|reference| {
                (
                    reference.locator.path(),
                    reference
                        .locator
                        .declaration()
                        .segments()
                        .iter()
                        .map(|segment| {
                            (
                                segment.kind(),
                                segment.name(),
                                segment.anchor().span(),
                                segment.sibling_ordinal(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        format!("type_flow.dynamic_store_candidate_roots roots={roots:?}")
    });
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "type_flow.dynamic_store_candidates candidates={candidate_count} skipped={skipped_count} caller_unbounded_sites={caller_unbounded_count} candidate_seconds={candidate_seconds:.9}"
        )
    });
    let mut discovery_seconds = 0.0;
    let mut plan_seconds = 0.0;
    for reference in procedures {
        if !candidates.contains(reference) {
            continue;
        }
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        // A structural receiver proof is already complete. A global effect
        // cannot be narrowed by another root, and only unhandled writes need
        // the value-flow survey.
        if writes
            .iter()
            .zip(&effects)
            .zip(&structural_write_bounds)
            .all(|((_, effect), bound)| {
                effect.global || !matches!(bound, StructuralWriteReceiverBound::NotApplicable)
            })
        {
            break;
        }
        // The previous root's closure and resolver source sessions have
        // returned. Keep the owning file pinned between roots of that file.
        budget.release_transient_residency();
        let root = match materialize_reference(
            workspace,
            reference,
            &mut current_file,
            budget,
            cancellation,
        ) {
            Ok(root) => root,
            Err(TypeFlowPlanError::Cancelled) => return Err(TypeFlowPlanError::Cancelled),
            Err(error) => {
                survey_failure.get_or_insert(UnknownReason::IncompleteRoot);
                for (index, write) in writes.iter().enumerate() {
                    if &write.procedure == reference {
                        caller_dependent[index] = true;
                    }
                }
                eprintln!(
                    "[bifrost] type_flow.incomplete_root reference={reference:?} reason={error:?}"
                );
                incomplete_roots.push((reference, format!("{error:?}")));
                continue;
            }
        };
        let discovery_started = std::time::Instant::now();
        let discovered = TypeFlowDiscovery::new(
            &root,
            &discovery,
            ClosureLimits {
                max_procedures: DYNAMIC_SURVEY_MAX_PROCEDURES,
            },
            budget,
            cancellation,
        );
        discovery_seconds += discovery_started.elapsed().as_secs_f64();
        let plan_started = std::time::Instant::now();
        let planned = discovered.and_then(|discovered| {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            // Planning cannot repair failed discovery. Preserve the same
            // unsurveyed-caller uncertainty without building class seeds or
            // correlations that the post-plan boundary check would discard.
            if let Some(reason) = discovered.discovery_boundary() {
                survey_failure.get_or_insert(reason);
                mark_unsurveyed(writes, &root, &mut caller_dependent);
                return Ok(None);
            }
            // Open effects cannot narrow again. Only pending writes can make
            // this root's class seeds or solve contribute further evidence.
            if discovered.excludes_procedures(
                writes
                    .iter()
                    .zip(&effects)
                    .zip(&structural_write_bounds)
                    .filter_map(|((write, effect), bound)| {
                        (!effect.global
                            && matches!(bound, StructuralWriteReceiverBound::NotApplicable))
                        .then_some(&write.procedure)
                    }),
            ) {
                return Ok(None);
            }
            let demands = writes
                .iter()
                .zip(&prepared)
                .zip(&structural_write_bounds)
                .filter_map(|((write, facts), bound)| {
                    if !matches!(bound, StructuralWriteReceiverBound::NotApplicable) {
                        return None;
                    }
                    let procedure = discovered.procedure_reference(&write.procedure)?;
                    let observation = facts.observation.as_ref()?.resolve(procedure);
                    Some(match observation {
                        WriteObservation::Event { carrier, .. }
                        | WriteObservation::ReceiverEntry { carrier, .. } => carrier,
                    })
                })
                .collect::<Vec<_>>();
            discovered
                .demanding(demands)
                .into_plan(
                    workspace,
                    adapter,
                    slots,
                    budget,
                    cancellation,
                    &mut refinements,
                )
                .map(Some)
        });
        plan_seconds += plan_started.elapsed().as_secs_f64();
        let plan = match planned {
            Ok(Some(plan)) => plan,
            Ok(None) => continue,
            Err(TypeFlowPlanError::Cancelled) => return Err(TypeFlowPlanError::Cancelled),
            // A failed discovery may have omitted a path to a surveyed write.
            // Record it and survey the remaining roots; the writes this root
            // could have reached are opened once every root has been seen.
            Err(error) => {
                incomplete_roots.push((reference, format!("{error:?}")));
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                survey_failure.get_or_insert(UnknownReason::IncompleteRoot);
                mark_unsurveyed(writes, &root, &mut caller_dependent);
                continue;
            }
        };
        if let Some(reason) = plan.discovery_boundary() {
            survey_failure.get_or_insert(reason);
            mark_unsurveyed(writes, &root, &mut caller_dependent);
            continue;
        }
        let mounted = writes
            .iter()
            .map(|write| {
                plan.value_flow().mounted_procedures().find(|procedure| {
                    procedure.artifact().key() == &write.procedure.key
                        && procedure.semantics().locator() == &write.procedure.locator
                        && plan.value_flow().has_snapshot(procedure)
                })
            })
            .collect::<Vec<_>>();
        let observations = mounted
            .iter()
            .zip(&prepared)
            .zip(&structural_write_bounds)
            .map(|((procedure, facts), bound)| {
                if !matches!(bound, StructuralWriteReceiverBound::NotApplicable) {
                    return None;
                }
                facts
                    .observation
                    .as_ref()
                    .zip(*procedure)
                    .map(|(observation, procedure)| observation.resolve(procedure))
            })
            .collect::<Vec<_>>();
        if !mounted
            .iter()
            .zip(&structural_write_bounds)
            .any(|(procedure, bound)| {
                procedure.is_some() && matches!(bound, StructuralWriteReceiverBound::NotApplicable)
            })
        {
            continue;
        }
        let mut request = DataflowRequest::new(solver_budget, cancellation);
        let result = match solve_value_flow_with_summaries(
            &root,
            &provider,
            plan.value_flow(),
            budget,
            &mut request,
        ) {
            Ok(result) => result,
            Err(error) => {
                incomplete_roots.push((reference, format!("{error:?}")));
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                survey_failure.get_or_insert(UnknownReason::IncompleteRoot);
                mark_unsurveyed(writes, &root, &mut caller_dependent);
                continue;
            }
        };
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        if !result.result().termination().is_fixed_point() {
            survey_failure.get_or_insert(UnknownReason::SolverBudget);
            mark_unsurveyed(writes, &root, &mut caller_dependent);
            continue;
        }
        // The evidence index is built for exactly the points this survey asks
        // about, so the observation each write resolves to is settled first.
        let mut queried = HashSet::default();
        for (((procedure, observation), effect), structural_bound) in mounted
            .iter()
            .zip(&observations)
            .zip(&effects)
            .zip(&structural_write_bounds)
        {
            if matches!(
                structural_bound,
                StructuralWriteReceiverBound::NotApplicable
            ) && procedure.is_some()
                && !effect.global
                && let Some(observation) = observation
            {
                queried.insert(observation.point().clone());
            }
        }
        let evidence = match DefinitionSources::new(&result, queried, budget, cancellation) {
            Ok(evidence) => evidence,
            Err(CorrelationError::Cancelled { .. }) => return Err(TypeFlowPlanError::Cancelled),
            Err(CorrelationError::Budget(_)) => {
                survey_failure.get_or_insert(UnknownReason::SemanticBudget);
                mark_unsurveyed(writes, &root, &mut caller_dependent);
                continue;
            }
        };
        for (index, (effect, structural_bound)) in
            effects.iter_mut().zip(&structural_write_bounds).enumerate()
        {
            if !matches!(
                structural_bound,
                StructuralWriteReceiverBound::NotApplicable
            ) || mounted[index].is_none()
                || effect.global
            {
                continue;
            }
            let Some(observation) = &observations[index] else {
                open_or_bound(
                    workspace,
                    adapter,
                    effect,
                    structural_receiver_bounds[index].as_ref(),
                    UnknownReason::UnmodeledLoad,
                );
                continue;
            };
            let observed = match observation {
                WriteObservation::Event {
                    point,
                    event,
                    carrier,
                } => evidence.before(
                    plan.value_flow(),
                    point,
                    *event,
                    carrier,
                    budget,
                    cancellation,
                ),
                WriteObservation::ReceiverEntry { point, carrier } => {
                    evidence.after(plan.value_flow(), point, carrier, budget, cancellation)
                }
            };
            let sources = match observed {
                Ok(Some(sources)) => sources,
                Ok(None) => {
                    open_or_bound(
                        workspace,
                        adapter,
                        effect,
                        structural_receiver_bounds[index].as_ref(),
                        UnknownReason::UnmodeledLoad,
                    );
                    continue;
                }
                Err(CorrelationError::Cancelled { .. }) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                Err(CorrelationError::Budget(_)) => {
                    open_or_bound(
                        workspace,
                        adapter,
                        effect,
                        structural_receiver_bounds[index].as_ref(),
                        UnknownReason::SemanticBudget,
                    );
                    continue;
                }
            };
            let mut identity_observed = false;
            for (source, uncertain) in sources {
                if plan.is_member_surface_source(source) {
                    continue;
                }
                identity_observed = true;
                let atom = plan.atom(source);
                if uncertain {
                    effect.evidence.reason = Some(UnknownReason::UncertainFlow);
                    let source_is_bounded = match atom {
                        ClassAtom::Class(_) => {
                            matches!(
                                plan.source_site(source).kind,
                                SourceSiteKind::DeclaredParameter | SourceSiteKind::RootReceiver
                            ) || class_source_has_open_type_bound(&plan, source)
                                || structural_receiver_bounds[index].is_some()
                        }
                        ClassAtom::Unknown(UnknownReason::SelfReceiver)
                        | ClassAtom::Unknown(UnknownReason::OpenTypeBound) => true,
                        ClassAtom::Unknown(_) => structural_receiver_bounds[index].is_some(),
                    };
                    effect.global |= !source_is_bounded;
                }
                match atom {
                    ClassAtom::Class(class) => {
                        if !effect.classes.contains(class) {
                            effect.classes.push(class.clone());
                        }
                        if let Some(bound) = structural_receiver_bounds[index].as_ref() {
                            // Retain proven call-site receiver classes as well
                            // as the structural fallback. An unbound method
                            // call can supply an object outside its lexical
                            // class, so observed classes remain authoritative.
                            add_bound(workspace, adapter, effect, bound);
                        } else if matches!(
                            plan.source_site(source).kind,
                            SourceSiteKind::DeclaredParameter | SourceSiteKind::RootReceiver
                        ) || class_source_has_open_type_bound(&plan, source)
                        {
                            add_bound(workspace, adapter, effect, class);
                        }
                    }

                    ClassAtom::Unknown(UnknownReason::SelfReceiver) => {
                        let source_procedure = plan
                            .value_flow()
                            .source(source)
                            .expect("a retained source belongs to the plan")
                            .point()
                            .procedure();
                        if let Some(class) = adapter.enclosing_class(workspace, source_procedure) {
                            add_bound(workspace, adapter, effect, &class);
                        } else {
                            open_global(effect, UnknownReason::SelfReceiver);
                        }
                    }
                    // The identity comes from an actual argument at some
                    // caller of this root, observed when that caller is itself
                    // surveyed as a root.
                    ClassAtom::Unknown(UnknownReason::RootParameter) => {
                        caller_dependent[index] = true;
                        if let Some(class) = structural_receiver_bounds[index].as_ref() {
                            add_bound(workspace, adapter, effect, class);
                        }
                    }
                    ClassAtom::Unknown(UnknownReason::OpenTypeBound) => {
                        // Preserve the declared bound even if a guard excluded
                        // its concrete atom. Constructor replacement bounds
                        // make no subclass promise and remain explicitly open.
                        let bounded =
                            add_open_type_bound_sources(workspace, adapter, &plan, source, effect);
                        if !bounded {
                            open_or_bound(
                                workspace,
                                adapter,
                                effect,
                                structural_receiver_bounds[index].as_ref(),
                                UnknownReason::OpenTypeBound,
                            );
                        }
                    }
                    ClassAtom::Unknown(reason) => open_or_bound(
                        workspace,
                        adapter,
                        effect,
                        structural_receiver_bounds[index].as_ref(),
                        reason.clone(),
                    ),
                }
            }
            if !identity_observed {
                open_or_bound(
                    workspace,
                    adapter,
                    effect,
                    structural_receiver_bounds[index].as_ref(),
                    UnknownReason::UnmodeledLoad,
                );
            }
        }
    }
    current_file.take();
    budget.release_resident();
    brokk_bifrost_core::profiling::note_with(|| {
        let (transfers, profiles, sessions) = provider.cached_artifact_bytes();
        format!(
            "type_flow.dynamic_store_survey candidates={candidate_count} skipped={skipped_count} caller_unbounded_sites={caller_unbounded_count} candidate_seconds={candidate_seconds:.9} survey_value_flow_discovery_seconds={discovery_seconds:.9} survey_plan_construction_seconds={plan_seconds:.9} survey_dispatch_materialization_seconds={:.9} prepared_pool_artifact_bytes={} value_flow_cached_artifact_bytes={} incoming_actuals_artifact_bytes={} icfg_transfers_artifact_bytes={transfers} icfg_profiles_artifact_bytes={profiles} icfg_sessions_artifact_bytes={sessions}",
            provider.oracle().dispatch_materialization_seconds(),
            discovery.prepared_pool_artifact_bytes(),
            value_flow_cache.artifact_bytes(),
            provider.oracle().incoming_actuals_artifact_bytes()
        )
    });
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "type_flow.dynamic_store_survey incomplete_roots={} records={incomplete_roots:?}",
            incomplete_roots.len(),
        )
    });
    if let Some(reason) = survey_failure {
        for (index, effect) in effects.iter_mut().enumerate() {
            if !effect.global
                && matches!(
                    &structural_write_bounds[index],
                    StructuralWriteReceiverBound::NotApplicable
                )
                && (effect.classes.is_empty() || caller_dependent[index])
            {
                open_or_bound(
                    workspace,
                    adapter,
                    effect,
                    structural_receiver_bounds[index].as_ref(),
                    reason.clone(),
                );
            }
        }
    }
    for effect in &mut effects {
        effect.classes.sort_by(super::field_slots::class_order);
        effect.bounds.sort_by(super::field_slots::class_order);
        effect.bounds.dedup();
    }
    Ok(effects)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn survey(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    slots: &FieldSlotIndex,
    procedures: &[ProcedureHandle],
    writes: &[PendingDynamicWrite],
    value_flow_cache: ValueFlowCache,
    budget: &mut SemanticBudget,
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
) -> Result<Vec<ScopedDynamicWrite>, TypeFlowPlanError> {
    survey_references(
        workspace,
        adapter,
        slots,
        &procedures
            .iter()
            .map(SemanticProcedureReference::of)
            .collect::<Vec<_>>(),
        writes,
        value_flow_cache,
        budget,
        solver_budget,
        cancellation,
    )
}

/// A write in a root whose own survey failed was never observed at its own
/// entry, where its receiver parameters read as root parameters. Treat it as
/// caller-dependent so the recorded failure opens it.
fn mark_unsurveyed(
    writes: &[PendingDynamicWrite],
    root: &ProcedureHandle,
    caller_dependent: &mut [bool],
) {
    for (index, write) in writes.iter().enumerate() {
        if write.procedure == SemanticProcedureReference::of(root) {
            caller_dependent[index] = true;
        }
    }
}

/// A `ClassWithOpenBound` seed gives its class and open remainder the same
/// source range. Retained generic iteration values use `Unknown` source sites,
/// so keep their class atom as a receiver bound just as for parameter seeds.
fn class_source_has_open_type_bound(
    plan: &super::plan::TypeFlowPlan,
    source: ValueFlowSourceId,
) -> bool {
    let origin = plan.source_site(source);
    origin.kind == SourceSiteKind::Unknown
        && plan.value_flow().sources().any(|(candidate, _)| {
            let site = plan.source_site(candidate);
            site.file == origin.file
                && site.span == origin.span
                && matches!(
                    plan.atom(candidate),
                    ClassAtom::Unknown(UnknownReason::OpenTypeBound)
                )
        })
}

/// Add class seeds paired with one `OpenTypeBound` source at the same syntax
/// site. Declared parameters use `DeclaredParameter` sites; structured loop
/// element seeds use `Unknown` sites.
fn add_open_type_bound_sources(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    plan: &super::plan::TypeFlowPlan,
    source: ValueFlowSourceId,
    effect: &mut ScopedDynamicWrite,
) -> bool {
    let origin = plan.source_site(source);
    let mut bounded = false;
    for (candidate, _) in plan.value_flow().sources() {
        let site = plan.source_site(candidate);
        if site.file == origin.file
            && site.span == origin.span
            && matches!(
                site.kind,
                SourceSiteKind::DeclaredParameter | SourceSiteKind::Unknown
            )
            && let ClassAtom::Class(class) = plan.atom(candidate)
        {
            add_bound(workspace, adapter, effect, class);
            bounded = true;
        }
    }
    bounded
}

/// Record what a write's receiver can be when an observation failed: the
/// structural bound its own `self` states, or the honest open reason when the
/// receiver has no such bound.
fn open_or_bound(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    effect: &mut ScopedDynamicWrite,
    structural_class: Option<&ClassIdentity>,
    reason: UnknownReason,
) {
    match structural_class {
        Some(class) => add_bound(workspace, adapter, effect, class),
        None => open_global(effect, reason),
    }
}

fn add_bound(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    effect: &mut ScopedDynamicWrite,
    class: &ClassIdentity,
) {
    let hierarchy = adapter.class_hierarchy(workspace, class);
    if matches!(class, ClassIdentity::External { .. }) || hierarchy.unresolved_base {
        open_global(effect, UnknownReason::OpenTypeBound);
        return;
    }
    if !effect.bounds.contains(class) {
        effect.bounds.push(class.clone());
    }
}

fn apply_dynamic_receiver_bounds(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    effect: &mut ScopedDynamicWrite,
    classes: &[ClassIdentity],
) {
    if classes
        .iter()
        .any(|class| adapter.class_hierarchy(workspace, class).unresolved_base)
    {
        open_global(effect, UnknownReason::OpenTypeBound);
        return;
    }
    effect.bounds.extend(classes.iter().cloned());
}

fn open_global(effect: &mut ScopedDynamicWrite, reason: UnknownReason) {
    effect.global = true;
    effect.evidence.reason = Some(reason);
}
