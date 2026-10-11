//! Solve receiver scopes before using dynamic writes as absence evidence.

use super::correlations::CorrelationError;
use super::field_slots::{FieldSlotIndex, receiver_values};
use super::plan::{ProcedureRefinements, TypeFlowDiscovery, TypeFlowPlanError};
use super::refinement_sources::DefinitionSources;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, DynamicFieldNameSet, IcfgProvider,
    ProcedureHandle, ProcedurePortHandle, ProgramPointHandle, ProgramPointId, SemanticBudget,
    SemanticEffect, SourceSite, SourceSiteKind, TypeFlowAdapter, UnknownReason, ValueId,
    WorkspaceIcfgProvider,
};
use crate::dataflow::{DataflowRequest, SolverBudget};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    ClosureLimits, ValueFlowCache, ValueFlowCarrier, ValueFlowSourceId, WorkspaceValueFlowProvider,
    solve_value_flow_with_summaries,
};

#[derive(Debug, Clone)]
pub(super) struct PendingDynamicWrite {
    pub procedure: ProcedureHandle,
    pub receiver: Option<ValueId>,
    pub names: DynamicFieldNameSet,
    pub site: SourceSite,
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
fn observation_point(write: &PendingDynamicWrite) -> Option<(ProgramPointId, usize)> {
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

enum StructuralWriteReceiverBound {
    NotApplicable,
    Bounded(Vec<ClassIdentity>),
    Unbounded(UnknownReason),
}

fn dynamic_type_write_receiver_bounds(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    write: &PendingDynamicWrite,
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
    write: &PendingDynamicWrite,
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
    write: &PendingDynamicWrite,
) -> StructuralWriteReceiverBound {
    let Some((owner, member)) =
        adapter.dynamic_write_receiver_field(workspace, &write.procedure, write.site.span)
    else {
        return StructuralWriteReceiverBound::NotApplicable;
    };
    let Some(slot) = slots.slot(&owner, &member) else {
        return StructuralWriteReceiverBound::Unbounded(UnknownReason::FieldSlotIncomplete);
    };
    let hierarchy = adapter.class_hierarchy(workspace, &owner);
    for other in writes {
        if other.site == write.site || !dynamic_names_may_change_member(&other.names, &member) {
            continue;
        }
        if adapter
            .dynamic_write_receiver_field(workspace, &other.procedure, other.site.span)
            .is_some()
        {
            continue;
        }
        if adapter.dynamic_write_receiver_is_explicitly_unbounded(
            workspace,
            &other.procedure,
            other.site.span,
        ) {
            return StructuralWriteReceiverBound::Unbounded(UnknownReason::DynamicFieldWrite);
        }
        let mut bounds = None;
        if let Some(receiver) = other.receiver {
            match adapter.dynamic_type_write_receiver_bounds(
                workspace,
                &other.procedure,
                receiver,
                other.site.span,
            ) {
                Ok(Some(classes)) => bounds = Some(classes),
                Ok(None) => {}
                Err(_) => {
                    return StructuralWriteReceiverBound::Unbounded(
                        UnknownReason::DynamicFieldWrite,
                    );
                }
            }
            if bounds.is_none() {
                match adapter.non_escaping_nested_write_receiver_bounds(
                    workspace,
                    &other.procedure,
                    receiver,
                    other.site.span,
                ) {
                    Ok(Some(classes)) => bounds = Some(classes),
                    Ok(None) => {}
                    Err(_) => {
                        return StructuralWriteReceiverBound::Unbounded(
                            UnknownReason::DynamicFieldWrite,
                        );
                    }
                }
            }
        }
        if bounds.is_none() {
            bounds = adapter
                .dynamic_write_receiver_bound(workspace, &other.procedure, other.site.span)
                .map(|class| vec![class]);
        }
        let Some(bounds) = bounds else {
            return StructuralWriteReceiverBound::Unbounded(UnknownReason::DynamicFieldWrite);
        };
        if bounds.is_empty() {
            continue;
        }
        if bounds.iter().any(|bound| {
            bound == &owner
                || hierarchy.ancestors.contains(bound)
                || hierarchy
                    .descendants
                    .as_ref()
                    .is_some_and(|descendants| descendants.contains(bound))
        }) {
            return StructuralWriteReceiverBound::Unbounded(UnknownReason::DynamicFieldWrite);
        }
    }
    let mut bounds = Vec::new();
    let mut stores = HashSet::default();
    for (_, site) in &slot.atoms {
        if !stores.insert((site.file.clone(), site.span)) {
            continue;
        }
        match adapter.field_store_value_bounds(workspace, &site.file, site.span, &member) {
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

fn structural_write_receiver_bounds(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    slots: &FieldSlotIndex,
    writes: &[PendingDynamicWrite],
    write: &PendingDynamicWrite,
) -> StructuralWriteReceiverBound {
    match dynamic_type_write_receiver_bounds(workspace, adapter, write) {
        StructuralWriteReceiverBound::NotApplicable => {
            match non_escaping_nested_write_receiver_bounds(workspace, adapter, write) {
                StructuralWriteReceiverBound::NotApplicable => {
                    field_value_write_receiver_bounds(workspace, adapter, slots, writes, write)
                }
                bounded_or_unbounded => bounded_or_unbounded,
            }
        }
        bounded_or_unbounded => bounded_or_unbounded,
    }
}

impl WriteObservation {
    fn point(&self) -> &ProgramPointHandle {
        match self {
            Self::Event { point, .. } | Self::ReceiverEntry { point, .. } => point,
        }
    }
}

/// Each workspace procedure is an entry context, just as in the public
/// workspace solve. Root-parameter unknowns supply no concrete workspace
/// callers; their actual arguments are observed in the callers' closures.
/// Other unknown expressions are open effects, never an empty class set.
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
    let structural_write_bounds = writes
        .iter()
        .map(|write| structural_write_receiver_bounds(workspace, adapter, slots, writes, write))
        .collect::<Vec<_>>();
    let provider = WorkspaceIcfgProvider::new(workspace);
    let discovery = WorkspaceValueFlowProvider::with_oracle(
        provider.oracle().clone(),
        provider.behavior_identity(),
        value_flow_cache,
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
    for (effect, write) in effects.iter_mut().zip(writes) {
        if adapter.dynamic_write_receiver_is_explicitly_unbounded(
            workspace,
            &write.procedure,
            write.site.span,
        ) {
            open_global(effect, UnknownReason::OpenTypeBound);
        }
    }
    // An immutable receiver has the same identity before an unsupported
    // continuation as at the write. Observe its entry port, including actual
    // unbound-call arguments; the enclosing class alone is not that proof.
    let mut stable_receivers = HashMap::default();
    let observations = writes
        .iter()
        .zip(&structural_write_bounds)
        .map(|(write, structural_bound)| {
            if !matches!(
                structural_bound,
                StructuralWriteReceiverBound::NotApplicable
            ) {
                return None;
            }
            let receiver = write.receiver?;
            let stable = stable_receivers
                .entry(write.procedure.durable_key())
                .or_insert_with(|| {
                    let receivers = receiver_values(&write.procedure);
                    if !receivers.is_empty()
                        && adapter.receiver_binding_is_stable(workspace, &write.procedure)
                    {
                        receivers
                    } else {
                        HashSet::default()
                    }
                });
            if stable.contains(&receiver) {
                let entry = write.procedure.semantics().entry_point();
                Some(WriteObservation::ReceiverEntry {
                    point: write.procedure.point_handle(entry).expect("entry is live"),
                    carrier: ValueFlowCarrier::Port(
                        ProcedurePortHandle::receiver(write.procedure.clone())
                            .expect("a proven receiver has an entry port"),
                    ),
                })
            } else {
                let (point, event) = observation_point(write)?;
                Some(WriteObservation::Event {
                    point: write
                        .procedure
                        .point_handle(point)
                        .expect("write point is live"),
                    event,
                    carrier: ValueFlowCarrier::for_value(
                        write
                            .procedure
                            .value_handle(receiver)
                            .expect("adapter receiver is live"),
                    ),
                })
            }
        })
        .collect::<Vec<_>>();
    // A write through the enclosing procedure's own stable receiver is bounded
    // by that procedure's class whatever any single root observes: `self`
    // names an instance of the declaring class or one of its descendants,
    // which is the same bound the `SelfReceiver` arm below records. Keeping
    // that bound where an observation fails scopes the write to its own
    // hierarchy instead of reopening every class in the workspace, which one
    // unobservable `setattr` in an unrelated module otherwise does.
    let structural_receiver_bounds = writes
        .iter()
        .map(|write| {
            adapter
                .dynamic_write_receiver_bound(workspace, &write.procedure, write.site.span)
                .or_else(|| {
                    let receiver = write.receiver?;
                    stable_receivers
                        .get(&write.procedure.durable_key())
                        .filter(|stable| stable.contains(&receiver))?;
                    adapter.enclosing_class(workspace, &write.procedure)
                })
        })
        .collect::<Vec<_>>();
    let survey_demands = observations
        .iter()
        .zip(&structural_write_bounds)
        .filter_map(|(observation, structural_bound)| {
            if !matches!(
                structural_bound,
                StructuralWriteReceiverBound::NotApplicable
            ) {
                return None;
            }
            match observation.as_ref()? {
                WriteObservation::Event { carrier, .. }
                | WriteObservation::ReceiverEntry { carrier, .. } => Some(carrier.clone()),
            }
        })
        .collect::<Vec<_>>();
    // A write whose receiver reaches a root parameter takes its identity from
    // an actual argument supplied by some caller. A root whose survey failed
    // may have carried that caller, so such a write cannot be trusted as
    // bounded once any root failed. A receiver built in place, or the
    // enclosing procedure's own `self`, is bounded by the surveyed root alone.
    let mut caller_dependent = vec![false; writes.len()];
    // The first reason a root's own survey could not be completed. It scopes
    // to the writes that could depend on the roots it did not observe, never
    // to every write in the workspace.
    let mut survey_failure: Option<UnknownReason> = None;
    // The surveyed roots overlap, and they share one ledger, so one procedure's
    // refinements are derived and charged once for the whole survey.
    let mut refinements = ProcedureRefinements::default();
    for root in procedures {
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
        let plan = match TypeFlowDiscovery::new(
            root,
            &discovery,
            ClosureLimits {
                max_procedures: 128,
            },
            budget,
            cancellation,
        )
        .and_then(|discovered| {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            // Planning cannot repair failed discovery. Preserve the same
            // unsurveyed-caller uncertainty without building class seeds or
            // correlations that the post-plan boundary check would discard.
            if let Some(reason) = discovered.discovery_boundary() {
                survey_failure.get_or_insert(reason);
                mark_unsurveyed(writes, root, &mut caller_dependent);
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
            discovered
                .demanding(survey_demands.iter().cloned())
                .into_plan(
                    workspace,
                    adapter,
                    slots,
                    budget,
                    cancellation,
                    &mut refinements,
                )
                .map(Some)
        }) {
            Ok(Some(plan)) => plan,
            Ok(None) => continue,
            Err(TypeFlowPlanError::Cancelled) => return Err(TypeFlowPlanError::Cancelled),
            // A failed discovery may have omitted a path to a surveyed write.
            // Record it and survey the remaining roots; the writes this root
            // could have reached are opened once every root has been seen.
            Err(_) => {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                survey_failure.get_or_insert(UnknownReason::IncompleteRoot);
                mark_unsurveyed(writes, root, &mut caller_dependent);
                continue;
            }
        };
        if let Some(reason) = plan.discovery_boundary() {
            survey_failure.get_or_insert(reason);
            mark_unsurveyed(writes, root, &mut caller_dependent);
            continue;
        }
        if !writes
            .iter()
            .zip(&structural_write_bounds)
            .any(|(write, bound)| {
                matches!(bound, StructuralWriteReceiverBound::NotApplicable)
                    && plan.value_flow().has_snapshot(&write.procedure)
            })
        {
            continue;
        }
        let mut request = DataflowRequest::new(solver_budget, cancellation);
        let result = match solve_value_flow_with_summaries(
            root,
            &provider,
            plan.value_flow(),
            budget,
            &mut request,
        ) {
            Ok(result) => result,
            Err(_) => {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                survey_failure.get_or_insert(UnknownReason::IncompleteRoot);
                mark_unsurveyed(writes, root, &mut caller_dependent);
                continue;
            }
        };
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        if !result.result().termination().is_fixed_point() {
            survey_failure.get_or_insert(UnknownReason::SolverBudget);
            mark_unsurveyed(writes, root, &mut caller_dependent);
            continue;
        }
        // The evidence index is built for exactly the points this survey asks
        // about, so the observation each write resolves to is settled first.
        let mut queried = HashSet::default();
        for (((write, observation), effect), structural_bound) in writes
            .iter()
            .zip(&observations)
            .zip(&effects)
            .zip(&structural_write_bounds)
        {
            if matches!(
                structural_bound,
                StructuralWriteReceiverBound::NotApplicable
            ) && plan.value_flow().has_snapshot(&write.procedure)
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
                mark_unsurveyed(writes, root, &mut caller_dependent);
                continue;
            }
        };
        for (index, ((write, effect), structural_bound)) in writes
            .iter()
            .zip(&mut effects)
            .zip(&structural_write_bounds)
            .enumerate()
        {
            if !matches!(
                structural_bound,
                StructuralWriteReceiverBound::NotApplicable
            ) || !plan.value_flow().has_snapshot(&write.procedure)
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

/// A write in a root whose own survey failed was never observed at its own
/// entry, where its receiver parameters read as root parameters. Treat it as
/// caller-dependent so the recorded failure opens it.
fn mark_unsurveyed(
    writes: &[PendingDynamicWrite],
    root: &ProcedureHandle,
    caller_dependent: &mut [bool],
) {
    for (index, write) in writes.iter().enumerate() {
        if write.procedure.durable_key() == root.durable_key() {
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
