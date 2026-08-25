//! Diagnostic-neutral direct and indirect value-flow analysis.

use crate::analyzer::Language;

mod backward_client;
mod client;
mod model;
mod plan;
mod planned;
mod provider;
mod result;

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
pub(crate) use client::kills_target as rule_kills_target;
pub use client::{
    ValueFlowFact, ValueFlowProblem, ValueFlowSolveError, ValueFlowUncertainty,
    solve_value_flow_with_summaries, solve_value_flow_with_witnesses,
};
pub(crate) use model::semantic_locator_heap_bytes;
pub use model::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowCarrierKey, ValueFlowEventKey,
    ValueFlowEventKind, ValueFlowModelError, ValueFlowObservationPhase, ValueFlowPortKey,
    ValueFlowScopedRootKind, ValueFlowSelectorKey, ValueFlowSinkId, ValueFlowSinkSpec,
    ValueFlowSourceId, ValueFlowSourceSpec,
};
pub(crate) use plan::ValueFlowCarrierSummaryIdentity;
pub use plan::{
    AuthoredArmClosure, ValueFlowCuratedCallModel, ValueFlowIncompleteCause, ValueFlowInput,
    ValueFlowPlan, ValueFlowPlanError, ValueFlowPlanLimits, ValueFlowSummaryLocationBinding,
};
pub use planned::{
    ValueFlowCanonicalMeeting, ValueFlowDirectionPlan, ValueFlowDirectionPlanError,
    ValueFlowPlannedEvidence, ValueFlowPlannedResult, ValueFlowPlannedSolveError,
    ValueFlowSnapshotObservationBindings, adapt_value_flow_summary_result,
    plan_value_flow_direction, plan_value_flow_direction_with_requirements,
    solve_value_flow_planned, solve_value_flow_planned_backward, solve_value_flow_planned_forward,
};
pub use provider::{ValueFlowCache, ValueFlowProvider, WorkspaceValueFlowProvider};
pub use result::{
    ValueFlowMayStatus, ValueFlowMeeting, ValueFlowMustStatus, ValueFlowSinkOutcome,
    ValueFlowSummaryResult,
};
