//! Solve receiver scopes before using dynamic writes as absence evidence.

use super::correlations::CorrelationError;
use super::field_slots::FieldSlotIndex;
use super::plan::{TypeFlowPlan, TypeFlowPlanError};
use super::refinement_sources::DefinitionSources;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, IcfgProvider, ProcedureHandle, SemanticBudget,
    SemanticEffect, SourceSite, SourceSiteKind, TypeFlowAdapter, UnknownReason, ValueId,
    WorkspaceIcfgProvider,
};
use crate::dataflow::{DataflowRequest, SolverBudget};
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
    for root in procedures {
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
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
        ) {
            Ok(plan) => plan,
            Err(TypeFlowPlanError::Cancelled) => return Err(TypeFlowPlanError::Cancelled),
            // A failed discovery may have omitted a path to any surveyed write.
            Err(_) => {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                for effect in &mut effects {
                    effect.evidence.reason = Some(UnknownReason::IncompleteRoot);
                }
                break;
            }
        };
        if let Some(reason) = plan.discovery_boundary() {
            for effect in &mut effects {
                effect.evidence.reason = Some(reason.clone());
            }
            break;
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
                for effect in &mut effects {
                    effect.evidence.reason = Some(UnknownReason::IncompleteRoot);
                }
                break;
            }
        };
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        if !result.result().termination().is_fixed_point() {
            for effect in &mut effects {
                effect.evidence.reason = Some(UnknownReason::SolverBudget);
            }
            break;
        }
        let evidence = match DefinitionSources::new(&result, budget, cancellation) {
            Ok(evidence) => evidence,
            Err(CorrelationError::Cancelled { .. }) => return Err(TypeFlowPlanError::Cancelled),
            Err(CorrelationError::Budget(_)) => {
                for effect in &mut effects {
                    effect.evidence.reason = Some(UnknownReason::SemanticBudget);
                }
                break;
            }
        };
        for (write, effect) in writes.iter().zip(&mut effects) {
            if !plan.value_flow().has_snapshot(&write.procedure) || effect.evidence.reason.is_some()
            {
                continue;
            }
            let semantics = write.procedure.semantics();
            let observation = semantics.call_sites().iter().find_map(|call| {
                (semantics.source_mapping(call.source)?.locator.anchor().span() == write.site.span)
                    .then(|| (call.point, semantics.point(call.point).expect("live call point").events.iter()
                        .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call.id))
                        .expect("a call owns its invoke event")))
            });
            let observation = observation.or_else(|| {
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
            });
            let (Some(receiver), Some((point, event))) = (write.receiver, observation) else {
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
                    ClassAtom::Unknown(UnknownReason::RootParameter) => {}
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
    for effect in &mut effects {
        effect.classes.sort_by(super::field_slots::class_order);
    }
    Ok(effects)
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
