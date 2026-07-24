//! Deterministic distributive data-flow propagation over semantic ICFGs.
//!
//! One runner consumes context-expanded nodes and edges already published by an
//! `IcfgSnapshot`. A second runner starts from a procedure and converges through
//! query-local entry-to-exit summaries, including recursive calls. Both retain
//! input uncertainty, solver termination, budgets, and concrete path quality.
//! Witnesses, IDE edge functions, and domain-specific clients remain separate
//! follow-up work.

mod budget;
mod direct;
mod input;
mod problem;
mod quality;
mod result;
mod summary;
mod summary_result;
mod tabulation;
mod transfer;

pub use budget::{
    DataflowRequest, SolverBudget, SolverBudgetDimension, SolverBudgetExceeded, SolverWork,
};
pub use direct::{DirectFact, DirectFlowProblem};
pub use input::{DataflowError, IcfgInputStatus, IcfgSolveInput};
pub use problem::{
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowOutput, DataflowSeed,
    DistributiveDataflowProblem, FactId,
};
pub use quality::{PathQuality, PathQualityFrontier};
pub use result::{DataflowCoverage, DataflowResult, ReachedFact, SolverTermination};
pub use summary::{SummarySolveInput, solve_with_summaries};
pub use summary_result::{
    SummaryBoundary, SummaryBoundaryKind, SummaryCoverage, SummaryDataflowError,
    SummaryDataflowResult, SummaryEdge, SummaryEntry, SummaryMetrics, SummaryReachedFact,
    SummarySemanticStatus, TabulationEndSummary,
};
pub use tabulation::solve;
