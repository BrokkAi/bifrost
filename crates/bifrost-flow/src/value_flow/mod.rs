//! Diagnostic-neutral direct and indirect value-flow analysis.

use crate::analyzer::Language;
use crate::analyzer::semantic::{ProcedureSemantics, SemanticEffect, ValueId};
use crate::hash::{HashMap, HashSet};
use std::collections::VecDeque;

mod backward_client;
mod client;
mod discovery;
mod model;
mod plan;
mod planned;
mod pointer;
mod provider;
mod result;
mod source_derivation;

/// Languages whose production semantic adapters have source-backed parity
/// across the direct solver, JSON CodeQuery, and RQL public routes.
pub const DIRECT_VALUE_FLOW_READY_LANGUAGES: [Language; 12] = [
    Language::Java,
    Language::Go,
    Language::Cpp,
    Language::JavaScript,
    Language::TypeScript,
    Language::Python,
    Language::Rust,
    Language::Php,
    Language::Scala,
    Language::CSharp,
    Language::Ruby,
    Language::Kotlin,
];

pub use backward_client::{
    BackwardValueFlowFact, BackwardValueFlowMeeting, BackwardValueFlowPhase,
    BackwardValueFlowResult, BackwardValueFlowSinkOutcome, BackwardValueFlowSolveError,
    solve_value_flow_backward_with_snapshot,
};
pub use client::{
    ValueFlowFact, ValueFlowProblem, ValueFlowSnapshotResult, ValueFlowSolveError,
    ValueFlowUncertainty, solve_value_flow_on_snapshot, solve_value_flow_summaries_on_snapshot,
    solve_value_flow_with_summaries, solve_value_flow_with_witnesses,
};
pub(crate) use client::{
    invalidates_source as rule_invalidates_source, kills_target as rule_kills_target,
};
pub(crate) use client::{
    solve_value_flow_entry_with_reusable_summaries, solve_value_flow_with_reusable_summaries,
};
pub use discovery::{
    BindingCoverage, CallSiteCoverage, ClosureCutDecider, ClosureLimits, ContextualClosureLimits,
    ContextualDiscoveredClosure, ContextualDispatchCoverage, DiscoveredClosure, DispatchStatus,
    DurableCallSiteKey, DurableProcedureKey, HydratedProcedureSurface, SkipReason,
    discover_closure, discover_closure_with, discover_closure_with_cuts,
    discover_contextual_closure,
};
pub(crate) use model::semantic_locator_heap_bytes;
pub use model::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowCarrierKey, ValueFlowEventKey,
    ValueFlowEventKind, ValueFlowModelError, ValueFlowObservationPhase, ValueFlowPortKey,
    ValueFlowScopedRootKind, ValueFlowSelectorKey, ValueFlowSinkId, ValueFlowSinkSpec,
    ValueFlowSourceId, ValueFlowSourceSpec,
};
pub use plan::{
    AuthoredArmClosure, CallerContentLocation, CallerContentLocations, ValueFlowCuratedCallModel,
    ValueFlowEdgeKillSpec, ValueFlowIncompleteCause, ValueFlowInput, ValueFlowLocalRuleSpec,
    ValueFlowPlan, ValueFlowPlanError, ValueFlowPlanLimits, ValueFlowReturnedCallable,
    ValueFlowSummaryLocationBinding, actual_argument_index_for_formal, authored_call_closures,
    caller_content_locations, closes_as_resolved_constructor,
};
pub(crate) use plan::{ValueFlowCarrierSummaryIdentity, ValueFlowSourceBehaviorIdentity};
pub use planned::{
    ValueFlowCanonicalMeeting, ValueFlowDirectionPlan, ValueFlowDirectionPlanError,
    ValueFlowPlannedEvidence, ValueFlowPlannedResult, ValueFlowPlannedSolveError,
    ValueFlowSnapshotObservationBindings, adapt_value_flow_summary_result,
    plan_value_flow_direction, plan_value_flow_direction_with_requirements,
    solve_value_flow_planned, solve_value_flow_planned_backward, solve_value_flow_planned_forward,
};
pub use pointer::{
    PointerBounds, PointerInvalidationWitness, PointerProvenanceAccess,
    PointerProvenanceAdditionalFacts, PointerProvenanceOrigin, PointerProvenancePlan,
    PointerProvenanceResult, PointerScopeEndWitness, solve_pointer_provenance_on_snapshot,
};
pub(crate) use provider::{DispatchReadCollector, ProcedureDispatchRead};
pub use provider::{
    ValueFlowCache, ValueFlowCacheStatsSnapshot, ValueFlowProvider, WorkspaceValueFlowProvider,
};
pub use result::{
    ValueFlowMayStatus, ValueFlowMeeting, ValueFlowSinkOutcome, ValueFlowSummaryResult,
};
pub use source_derivation::{
    NormalResultTransferPartition, SourceDependencyIdentity, SourceDerivationError,
    SourceDerivationFile, SourceDerivationFrontier, SourceDerivationInput, SourceDerivationLimits,
    SourceDerivationResult, SourceDerivationWork, SourceEntrypointRange, SourceEntrypointStatus,
    SourceReadCoverage, TransferEvidence, TransferPartitionSource, TransferPartitionStatus,
    derive_source_normal_result,
};

enum SinkMeetingOutcome<'result, Meeting> {
    Reached(Box<[&'result Meeting]>),
    NotReached,
    Inconclusive,
}

/// Follow structured assignments and value-flow relations from a set of
/// values. The closure is local to one procedure and one caller query.
pub(crate) fn identity_alias_closure(
    semantics: &ProcedureSemantics,
    seeds: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    let mut successors = HashMap::<ValueId, Vec<ValueId>>::default();
    for point in semantics.points() {
        for event in &point.events {
            let (source, target) = match event.effect {
                SemanticEffect::Assignment { target, value } => (value, target),
                SemanticEffect::ValueFlow { source, target, .. } => (source, target),
                _ => continue,
            };
            successors.entry(source).or_default().push(target);
        }
    }
    let mut aliases = seeds.clone();
    let mut pending = seeds.iter().copied().collect::<VecDeque<_>>();
    while let Some(source) = pending.pop_front() {
        for target in successors.get(&source).into_iter().flatten() {
            if aliases.insert(*target) {
                pending.push_back(*target);
            }
        }
    }
    aliases
}

fn sink_meeting_outcome<'result, Meeting>(
    meetings: &'result [Meeting],
    sink: ValueFlowSinkId,
    complete: bool,
    meeting_sink: impl Fn(&Meeting) -> ValueFlowSinkId,
) -> SinkMeetingOutcome<'result, Meeting> {
    let meetings = meetings
        .iter()
        .filter(|meeting| meeting_sink(meeting) == sink)
        .collect::<Vec<_>>();
    if !meetings.is_empty() {
        SinkMeetingOutcome::Reached(meetings.into_boxed_slice())
    } else if complete {
        SinkMeetingOutcome::NotReached
    } else {
        SinkMeetingOutcome::Inconclusive
    }
}
