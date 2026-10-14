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

mod binding_refinement;
mod correlations;
mod dynamic_stores;
mod field_refinement;
mod field_slots;
mod plan;
mod refinement_sources;
mod report;
mod solve;
mod summary;

pub(crate) use correlations::{
    CorrelationError, analyze_correlations_with_observations, guard_condition_bindings,
};

use crate::analyzer::semantic::{CancellationToken, ClassSeed, SemanticBudget, ValueId};
use crate::hash::{HashMap, HashSet};

pub(super) fn class_seed_has_open_bound(seed: &ClassSeed) -> bool {
    matches!(
        seed,
        ClassSeed::ClassWithOpenBound(_) | ClassSeed::ClassesWithOpenBound(_)
    )
}

pub(super) fn copy_tracked_value<T: Clone>(
    values: &mut HashMap<ValueId, T>,
    source: ValueId,
    target: ValueId,
    tracked: &HashSet<ValueId>,
) {
    if source == target || !tracked.contains(&target) {
        return;
    }
    if let Some(value) = values.get(&source).cloned() {
        values.insert(target, value);
    } else {
        values.remove(&target);
    }
}

pub(super) fn tracked_copy_sources(
    sources_of: &HashMap<ValueId, Vec<ValueId>>,
    queried: HashSet<ValueId>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<HashSet<ValueId>, correlations::CorrelationError> {
    let mut tracked = queried;
    let mut pending = tracked.iter().copied().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        correlations::check_cancelled(Some(cancellation))?;
        correlations::charge_entries(budget, 1)?;
        let Some(sources) = sources_of.get(&target) else {
            continue;
        };
        correlations::charge_entries(budget, sources.len())?;
        for &source in sources {
            if tracked.insert(source) {
                pending.push(source);
            }
        }
    }
    Ok(tracked)
}

fn is_assignment_transfer_marker(
    point: &crate::analyzer::semantic::ProgramPoint,
    event_index: usize,
    source: crate::analyzer::semantic::ValueId,
    target: crate::analyzer::semantic::ValueId,
) -> bool {
    event_index > 0
        && matches!(
            &point.events[event_index - 1].effect,
            crate::analyzer::semantic::SemanticEffect::Assignment {
                target: previous_target,
                value: previous_value,
            } if *previous_target == target && *previous_value == source
        )
}

fn mapping_span(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> crate::analyzer::semantic::SourceSpan {
    procedure
        .semantics()
        .source_mapping(source)
        .expect("a retained IR row's source mapping is live")
        .locator
        .anchor()
        .span()
}

pub use crate::analyzer::semantic::{SourceSite, SourceSiteKind};
pub use dynamic_stores::DynamicWriteEvidence;
pub use field_slots::{
    FieldSlot, FieldSlotIndex, FieldSlotIndexAcquisitionKind, FieldSlotIndexCache,
    FieldSlotIndexMissReason, active_semantic_model_pack_digest,
};
pub use plan::{
    MemberAccessSite, ProcedureDispatchReadContract, ProcedureRefinements, TypeFlowPlan,
    TypeFlowPlanError, TypeFlowSitePurpose,
};
pub use report::{TypeFlowReport, TypeFlowRootSolverExhaustion, solve_type_flow_workspace};
pub use solve::{
    AbsentMemberFinding, AbsentMemberProof, ClassSetStatus, FeedbackLimits, ReceiverClassSet,
    RootExhaustedLane, RootIncompleteEvidence, SemanticExhaustionStage, TypeFlowError,
    TypeFlowRootPersistenceRejection, TypeFlowRootPersistenceStatus, TypeFlowRootResult,
    TypeFlowSolveAttempt, TypeFlowSolvePhase, solve_type_flow_for_root,
    solve_type_flow_for_root_with_refinements, sort_unknown_reasons,
};
pub use summary::{TypeFlowSummaryProfile, TypeFlowSummaryState};
