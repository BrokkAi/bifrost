//! Diagnostic-neutral direct and indirect value-flow analysis.

use crate::analyzer::Language;

mod client;
mod model;
mod plan;
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
    ValueFlowCuratedCallModel, ValueFlowInput, ValueFlowPlan, ValueFlowPlanError,
    ValueFlowPlanLimits, ValueFlowSummaryLocationBinding,
};
pub use result::{
    ValueFlowMayStatus, ValueFlowMeeting, ValueFlowMustStatus, ValueFlowSinkOutcome,
    ValueFlowSummaryResult,
};
