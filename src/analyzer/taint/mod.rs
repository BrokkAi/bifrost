//! Set-oriented, diagnostic-neutral taint analysis over the shared IDE kernel.

mod client;
mod finding;
mod model;
mod plan;

pub use client::{
    TaintEdgeFunction, TaintFact, TaintFlowProblem, TaintSolveError, TaintSummaryResult,
    solve_taint_batch_with_summaries, solve_taint_batch_with_witnesses,
};
pub use finding::{
    TaintFinding, TaintFindingError, TaintFindingKey, TaintFindingReport, TaintOriginStatus,
    collect_taint_findings,
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
