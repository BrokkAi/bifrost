//! Solve receiver scopes before using dynamic writes as absence evidence.

use super::correlations::CorrelationError;
use super::field_slots::FieldSlotIndex;
use super::plan::{ProcedureRefinements, TypeFlowPlan, TypeFlowPlanError};
use super::refinement_sources::DefinitionSources;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, IcfgProvider, ProcedureHandle, ProgramPointId,
    SemanticBudget, SemanticEffect, SourceSite, SourceSiteKind, TypeFlowAdapter, UnknownReason,
    ValueId, WorkspaceIcfgProvider,
};
use crate::dataflow::{DataflowRequest, SolverBudget};
use crate::hash::HashSet;
use crate::value_flow::{
    ClosureLimits, ValueFlowCache, ValueFlowCarrier, WorkspaceValueFlowProvider,
    solve_value_flow_with_summaries,
};

#[derive(Debug, Clone)]
pub(super) struct PendingDynamicWrite {
    pub procedure: ProcedureHandle,
    pub receiver: Option<ValueId>,
    pub site: SourceSite,
}

/// Why an arbitrary-name mutation prevents an absence proof at another site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicWriteEvidence {
    pub site: SourceSite,
    /// None means the receiver set is bounded. Some names the open boundary.
    pub reason: Option<UnknownReason>,
}

impl DynamicWriteEvidence {
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
    pub classes: Vec<ClassIdentity>,
    pub evidence: DynamicWriteEvidence,
}

impl ScopedDynamicWrite {
    pub fn open(site: SourceSite, reason: UnknownReason) -> Self {
        Self {
            classes: Vec::new(),
            evidence: DynamicWriteEvidence {
                site,
                reason: Some(reason),
            },
        }
    }

    pub fn affects(&self, class: &ClassIdentity) -> bool {
        self.evidence.reason.is_some() || self.classes.contains(class)
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
    budget: &mut SemanticBudget,
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
) -> Result<Vec<ScopedDynamicWrite>, TypeFlowPlanError> {
    let provider = WorkspaceIcfgProvider::new(workspace);
    let discovery = WorkspaceValueFlowProvider::with_oracle(
        provider.oracle().clone(),
        provider.behavior_identity(),
        ValueFlowCache::default(),
    );
    let mut effects = writes
        .iter()
        .map(|write| ScopedDynamicWrite {
            classes: Vec::new(),
            evidence: DynamicWriteEvidence {
                site: write.site.clone(),
                reason: None,
            },
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
        // Every write is already open; no further root can narrow one.
        if effects
            .iter()
            .all(|effect| effect.evidence.reason.is_some())
        {
            break;
        }
        let plan = match TypeFlowPlan::build(
            workspace,
            adapter,
            slots,
            root,
            &discovery,
            ClosureLimits {
                max_procedures: 128,
            },
            budget,
            cancellation,
            &mut refinements,
        ) {
            Ok(plan) => plan,
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
            .any(|write| plan.value_flow().has_snapshot(&write.procedure))
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
        let observations = writes
            .iter()
            .zip(&effects)
            .map(|(write, effect)| {
                (plan.value_flow().has_snapshot(&write.procedure)
                    && effect.evidence.reason.is_none())
                .then(|| observation_point(write))
                .flatten()
            })
            .collect::<Vec<_>>();
        let mut queried = HashSet::default();
        for (write, observation) in writes.iter().zip(&observations) {
            if let Some((point, _)) = observation {
                queried.insert(
                    write
                        .procedure
                        .point_handle(*point)
                        .expect("write point is live"),
                );
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
        for (index, (write, effect)) in writes.iter().zip(&mut effects).enumerate() {
            if !plan.value_flow().has_snapshot(&write.procedure) || effect.evidence.reason.is_some()
            {
                continue;
            }
            let (Some(receiver), Some((point, event))) = (write.receiver, observations[index])
            else {
                effect.evidence.reason = Some(UnknownReason::UnmodeledLoad);
                continue;
            };
            let carrier = ValueFlowCarrier::Value(
                write
                    .procedure
                    .value_handle(receiver)
                    .expect("adapter receiver is live"),
            );
            let point = write
                .procedure
                .point_handle(point)
                .expect("write point is live");
            let sources = match evidence.before(
                plan.value_flow(),
                &point,
                event,
                &carrier,
                budget,
                cancellation,
            ) {
                Ok(Some(sources)) => sources,
                Ok(None) => {
                    effect.evidence.reason = Some(UnknownReason::UnmodeledLoad);
                    continue;
                }
                Err(CorrelationError::Cancelled { .. }) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                Err(CorrelationError::Budget(_)) => {
                    effect.evidence.reason = Some(UnknownReason::SemanticBudget);
                    continue;
                }
            };
            let mut identity_observed = false;
            for (source, uncertain) in sources {
                if plan.is_member_surface_source(source) {
                    continue;
                }
                identity_observed = true;
                if uncertain {
                    effect.evidence.reason = Some(UnknownReason::UncertainFlow);
                }
                match plan.atom(source) {
                    ClassAtom::Class(class) => {
                        if !effect.classes.contains(class) {
                            effect.classes.push(class.clone());
                        }
                        if plan.source_site(source).kind == SourceSiteKind::DeclaredParameter {
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
                            effect.evidence.reason = Some(UnknownReason::SelfReceiver);
                        }
                    }
                    // The identity comes from an actual argument at some
                    // caller of this root, observed when that caller is itself
                    // surveyed as a root.
                    ClassAtom::Unknown(UnknownReason::RootParameter) => {
                        caller_dependent[index] = true;
                    }
                    ClassAtom::Unknown(UnknownReason::OpenTypeBound) => {
                        // Preserve the declared bound even if a guard excluded
                        // its concrete atom. Constructor replacement bounds
                        // make no subclass promise and remain explicitly open.
                        let origin = plan.source_site(source);
                        let mut bounded = false;
                        for (candidate, _) in plan.value_flow().sources() {
                            let site = plan.source_site(candidate);
                            if site.file == origin.file
                                && site.span == origin.span
                                && site.kind == SourceSiteKind::DeclaredParameter
                                && let ClassAtom::Class(class) = plan.atom(candidate)
                            {
                                add_bound(workspace, adapter, effect, class);
                                bounded = true;
                            }
                        }
                        if !bounded {
                            effect.evidence.reason = Some(UnknownReason::OpenTypeBound);
                        }
                    }
                    ClassAtom::Unknown(reason) => effect.evidence.reason = Some(reason.clone()),
                }
            }
            if !identity_observed {
                effect.evidence.reason = Some(UnknownReason::UnmodeledLoad);
            }
        }
    }
    if let Some(reason) = survey_failure {
        for (index, effect) in effects.iter_mut().enumerate() {
            if effect.evidence.reason.is_none()
                && (effect.classes.is_empty() || caller_dependent[index])
            {
                effect.evidence.reason = Some(reason.clone());
            }
        }
    }
    for effect in &mut effects {
        effect.classes.sort_by(super::field_slots::class_order);
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

fn add_bound(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    effect: &mut ScopedDynamicWrite,
    class: &ClassIdentity,
) {
    if !effect.classes.contains(class) {
        effect.classes.push(class.clone());
    }
    match adapter.class_hierarchy(workspace, class).descendants {
        Some(descendants) => {
            for descendant in descendants {
                if !effect.classes.contains(&descendant) {
                    effect.classes.push(descendant);
                }
            }
        }
        None => effect.evidence.reason = Some(UnknownReason::OpenTypeBound),
    }
}
