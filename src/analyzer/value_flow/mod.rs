//! Diagnostic-neutral direct and indirect value-flow analysis.

mod client;
mod model;
mod plan;
mod result;

pub use client::{
    ValueFlowFact, ValueFlowProblem, ValueFlowSolveError, ValueFlowUncertainty,
    solve_value_flow_with_summaries, solve_value_flow_with_witnesses,
};
pub use model::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowCarrierKey, ValueFlowEventKey,
    ValueFlowEventKind, ValueFlowModelError, ValueFlowObservationPhase, ValueFlowPortKey,
    ValueFlowScopedRootKind, ValueFlowSelectorKey, ValueFlowSinkId, ValueFlowSinkSpec,
    ValueFlowSourceId, ValueFlowSourceSpec,
};
pub(crate) use plan::ValueFlowCarrierSummaryIdentity;
pub use plan::{
    ValueFlowCuratedCallModel, ValueFlowInput, ValueFlowPlan, ValueFlowPlanError,
    ValueFlowPlanLimits, ValueFlowSummaryLocationBinding,
};
pub use result::{
    ValueFlowMayStatus, ValueFlowMeeting, ValueFlowMustStatus, ValueFlowSinkOutcome,
    ValueFlowSummaryResult,
};
