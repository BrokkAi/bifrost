//! Bounded, deterministic data-flow propagation over semantic ICFG snapshots.
//!
//! The first solver slice operates on the context-expanded nodes and edges
//! already published by `IcfgSnapshot`. It supports finite distributive
//! may-data-flow clients while keeping input uncertainty, solver termination,
//! budgets, and reached path quality explicit. Reusable procedure summaries,
//! witnesses, IDE edge functions, and domain-specific clients remain separate
//! follow-up work.

mod direct;
mod outcome;
mod problem;
mod tabulation;

pub use direct::{DirectFact, DirectFlowProblem};
pub use outcome::{
    DataflowCoverage, DataflowError, DataflowRequest, DataflowResult, IcfgInputStatus,
    IcfgSolveInput, PathQuality, PathQualityFrontier, ReachedFact, SolverBudget,
    SolverBudgetDimension, SolverBudgetExceeded, SolverTermination, SolverWork,
};
pub use problem::{DataflowEdge, DataflowSeed, DistributiveDataflowProblem, FactId};
pub use tabulation::solve;
