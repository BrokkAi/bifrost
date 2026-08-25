//! Set-oriented, diagnostic-neutral taint analysis over the shared IDE kernel.

mod client;
mod finding;
mod model;
mod plan;
mod planned;
mod production;
mod summary;

pub use client::{
    TaintBackwardFact, TaintBackwardFlowProblem, TaintBackwardHit, TaintBackwardResult,
    TaintEdgeFunction, TaintFact, TaintFlowProblem, TaintSolveError, TaintSummaryResult,
    plan_taint_batch_direction, solve_taint_batch_backward, solve_taint_batch_with_summaries,
    solve_taint_batch_with_witnesses,
};
pub use finding::{
    TaintFinding, TaintFindingCollectionLimits, TaintFindingEntry, TaintFindingError,
    TaintFindingKey, TaintFindingReport, TaintOriginFindingEvidence, TaintOriginStatus,
    TaintWitnessTruncationCause, collect_taint_findings, collect_taint_findings_with_limits,
};
pub use model::{
    MAX_TAINT_CLASSES, SourceClassId, SourceEventKey, TaintClassSet, TaintModelError,
    TaintUniverse, TaintUniverseHash,
};
pub use plan::{
    TaintAnalysisPlan, TaintBatch, TaintBatchCompatibilityKey, TaintBatchPlanner, TaintPlanError,
    TaintPolicyPlan, TaintPolicyProjection, TaintPropagationSemanticsId, TaintSanitizerBinding,
    TaintSinkBinding, TaintSourceBinding, TaintTransformBinding,
};
pub use planned::{
    TaintCanonicalFinding, TaintPlannedEvidence, TaintPlannedResult, TaintPlannedSolveError,
    canonical_taint_findings_from_backward, canonical_taint_findings_from_forward,
    solve_taint_planned,
};
pub use production::{
    ProductionTaintAnalysisResult, ProductionTaintPhaseMetrics, TaintProjectionLimits,
};
pub use summary::{
    CarrierSummaryKey, CompleteTaintTransferSummaryRepository, StableSinkObserver,
    StableSourceGenerator, StableTaintClassSet, StableTaintEdgeFunction, StableTaintFact,
    TaintObservedPort, TaintPathEvidence, TaintPropagationEventMatchKey,
    TaintPropagationSemanticsVersion, TaintSemanticSummarySet, TaintSinkObserverMatchKey,
    TaintSummaryPublicationError, TaintSummaryPublicationOutcome, TaintTransferRow,
    TaintTransferSummary, TaintTransferSummaryCacheStatus, TaintTransferSummaryError,
    TaintTransferSummaryKey, TaintTransferSummaryRepositoryLimits, TaintTransferSummarySolveError,
    TaintTransferSummarySolveResult, solve_taint_with_reusable_summaries,
};
