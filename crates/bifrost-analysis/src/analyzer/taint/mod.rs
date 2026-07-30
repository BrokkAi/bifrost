//! Set-oriented, diagnostic-neutral taint analysis over the shared IDE kernel.

mod client;
mod finding;
mod model;
mod plan;
mod summary;

pub use client::{
    TaintEdgeFunction, TaintFact, TaintFlowProblem, TaintSolveError, TaintSummaryResult,
    solve_taint_batch_with_summaries, solve_taint_batch_with_witnesses,
};
pub use finding::{
    TaintFinding, TaintFindingCollectionLimits, TaintFindingEntry, TaintFindingError,
    TaintFindingKey, TaintFindingReport, TaintOriginFindingEvidence, TaintOriginStatus,
    collect_taint_findings, collect_taint_findings_with_limits,
};
pub use model::{
    MAX_TAINT_CLASSES, SourceClassId, SourceEventKey, TaintClassSet, TaintModelError,
    TaintUniverse, TaintUniverseHash,
};
pub use plan::{
    TaintAnalysisPlan, TaintBatch, TaintBatchCompatibilityKey, TaintBatchPlanner, TaintPlanError,
    TaintPolicyPlan, TaintPolicyProjection, TaintSanitizerBinding, TaintSinkBinding,
    TaintSourceBinding, TaintTransformBinding,
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
