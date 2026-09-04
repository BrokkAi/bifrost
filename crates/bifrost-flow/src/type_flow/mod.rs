//! Whole-program class-set type propagation over the value-flow solver.
//!
//! One class atom is seeded per class-producing site (constructor calls,
//! literals, container literals, declared parameters) and one explicit
//! Unknown source per value the engine cannot classify; every member access
//! is a sink. The existing value-flow solver then answers, per member access
//! and per root procedure, which classes the receiver may hold -- with
//! call-site precision, because the solver's tabulation is context-sensitive
//! per entry fact. The per-language facts the engine cannot derive from the
//! semantic IR come from a [`crate::analyzer::semantic::TypeFlowAdapter`];
//! the solver itself is shared with every flow client.
//!
//! The discipline is honest absence: a class set containing any Unknown is
//! `partial` and produces no finding, and `inconclusive`/`no_information`
//! are never read as an empty or absent class set.

mod field_slots;
mod plan;
mod report;
mod solve;

pub use field_slots::{FieldSlot, FieldSlotIndex};
pub use plan::{MemberAccessSite, SourceSite, SourceSiteKind, TypeFlowPlan, TypeFlowPlanError};
pub use report::{TypeFlowReport, solve_type_flow_workspace};
pub use solve::{
    AbsentMemberFinding, ClassSetStatus, ReceiverClassSet, TypeFlowError, TypeFlowRootResult,
    solve_type_flow_for_root,
};
