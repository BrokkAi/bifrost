//! Bounded, deterministic data-flow propagation over semantic ICFG snapshots.
//!
//! The first solver slice operates on the context-expanded nodes and edges
//! already published by `IcfgSnapshot`. It supports finite distributive
//! may-data-flow clients while keeping input uncertainty, solver termination,
//! budgets, and reached path quality explicit. Reusable procedure summaries,
//! witnesses, IDE edge functions, and domain-specific clients remain separate
//! follow-up work.

mod budget;
mod direct;
mod input;
mod problem;
mod quality;
mod result;
mod tabulation;

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
pub use tabulation::solve;
