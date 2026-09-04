//! Solve one root's class-set plan and interpret every sink.
//!
//! The value-flow meetings at a member-access sink become a
//! [`ReceiverClassSet`]: the classes of the sources that reached it, the
//! Unknown reasons of the sources that reached it, and a status. The finding
//! rule fires only when the set has no Unknown: every class that provably
//! lacks the accessed member produces an [`AbsentMemberFinding`] carrying the
//! site, the class, the origin site that introduced the class, the root, and
//! the witness path. A set with any Unknown reports `partial` (or
//! `inconclusive`) and produces no finding, so a guess is never presented as
//! a bug. A root method receiver may be known under the workspace-closed-world
//! rule: its enclosing workspace class has no known workspace descendants,
//! unresolved base, or dynamic-attribute hook. External subclasses are outside
//! that rule, matching workspace member lookup's existing boundary.

use std::error::Error;
use std::fmt;

use brokk_bifrost_core::profiling;

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    ClassAtom, ClassIdentity, IcfgProvider, MemberLookup, ProcedureHandle, SemanticBudget,
    TypeFlowAdapter, UnknownReason,
};
use crate::dataflow::{
    DataflowRequest, PathQuality, SolverTermination, SummaryWitness, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use crate::value_flow::{
    ClosureLimits, ValueFlowCarrier, ValueFlowMeeting, ValueFlowSinkId, ValueFlowSinkOutcome,
    ValueFlowSolveError, ValueFlowSummaryResult, solve_value_flow_with_witnesses,
};

use super::FieldSlotIndex;
use super::plan::{
    MemberAccessSite, SourceSite, TypeFlowPlan, TypeFlowPlanError, uncovered_reason,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassSetStatus {
    Known,
    Partial,
    NoInformation,
    Inconclusive,
}

impl ClassSetStatus {
    /// Every status label, in enum declaration order. Row-field registries
    /// read this so the publishable value set cannot drift from the enum.
    pub const LABELS: &[&str] = &["known", "partial", "no_information", "inconclusive"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Partial => "partial",
            Self::NoInformation => "no_information",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// The weaker of two statuses: an inconclusive answer means the site was
    /// not fully answered, a partial answer means some value was unclassified,
    /// and a known answer outranks only no information at all.
    pub const fn weakest(self, other: Self) -> Self {
        const fn rank(status: ClassSetStatus) -> u8 {
            match status {
                ClassSetStatus::Inconclusive => 3,
                ClassSetStatus::Partial => 2,
                ClassSetStatus::Known => 1,
                ClassSetStatus::NoInformation => 0,
            }
        }
        if rank(self) >= rank(other) {
            self
        } else {
            other
        }
    }
}

/// The classes and Unknown reasons that reached one member access under one
/// root, plus the status a consumer may act on.
#[derive(Debug, Clone)]
pub struct ReceiverClassSet {
    pub site: MemberAccessSite,
    pub classes: Vec<(ClassIdentity, SourceSite)>,
    pub unknown: Vec<UnknownReason>,
    pub status: ClassSetStatus,
}

/// A member access whose receiver provably holds a class that does not
/// declare the member.
#[derive(Debug, Clone)]
pub struct AbsentMemberFinding {
    pub root: ProcedureHandle,
    pub site: MemberAccessSite,
    pub class: ClassIdentity,
    pub origin: SourceSite,
    pub witness: Option<SummaryWitness>,
}

/// Everything one root's solve concluded.
#[derive(Debug)]
pub struct TypeFlowRootResult {
    pub root: ProcedureHandle,
    pub class_sets: Vec<ReceiverClassSet>,
    pub findings: Vec<AbsentMemberFinding>,
    /// The completeness contract later consumers (#2943, #2945, #2949) build
    /// on: the root is complete exactly when its solve saw no cancellation,
    /// no provider failure on the root, and no solver-budget exhaustion. A
    /// provider failure on the root never reaches interpretation (the plan
    /// build fails first), and cancellation and solver-budget exhaustion both
    /// terminate the solver before a fixed point, so this is
    /// `termination().is_fixed_point()`. Boundary-only incompleteness -- an
    /// open dispatch arm, a callee the closure never mounted, the closure
    /// procedure cap -- still terminates at a fixed point and is expressed
    /// per sink through the Unknown reasons, never through this flag.
    pub complete: bool,
    /// The semantic-work budget was exhausted while this root was discovered
    /// or solved: a typed `ExceededBudget` rode the solve's semantic-input
    /// boundaries. Executors surface this as their
    /// `semantic_budget_exhausted` diagnostic.
    pub semantic_budget_exhausted: bool,
}

/// Why one root's class-set solve could not run.
#[derive(Debug)]
pub enum TypeFlowError {
    Plan(TypeFlowPlanError),
    Solve(ValueFlowSolveError),
    Io(std::io::Error),
    Cancelled,
}

impl fmt::Display for TypeFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => error.fmt(formatter),
            Self::Solve(error) => write!(formatter, "type-flow solve failed: {error}"),
            Self::Io(error) => write!(formatter, "type-flow workspace enumeration failed: {error}"),
            Self::Cancelled => formatter.write_str("type-flow solve was cancelled"),
        }
    }
}

impl Error for TypeFlowError {}

impl From<TypeFlowPlanError> for TypeFlowError {
    fn from(error: TypeFlowPlanError) -> Self {
        Self::Plan(error)
    }
}

impl From<ValueFlowSolveError> for TypeFlowError {
    fn from(error: ValueFlowSolveError) -> Self {
        Self::Solve(error)
    }
}

/// Build the plan for `root`, solve it against `provider`, and interpret
/// every member-access sink.
#[allow(clippy::too_many_arguments)]
pub fn solve_type_flow_for_root<Provider: IcfgProvider + ?Sized>(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    root: &ProcedureHandle,
    provider: &Provider,
    limits: ClosureLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TypeFlowRootResult, TypeFlowError> {
    let plan = TypeFlowPlan::build(
        workspace,
        adapter,
        field_slots,
        root,
        limits,
        semantic_budget,
        request.cancellation,
    )?;
    let result = {
        let _scope = profiling::scope("type_flow.solve");
        solve_value_flow_with_witnesses(
            root,
            provider,
            plan.value_flow(),
            WitnessRetentionLimits::new(1)
                .expect("one alternative is a valid witness retention limit"),
            semantic_budget,
            request,
        )?
    };
    Ok(interpret(workspace, adapter, root, &plan, &result))
}

fn interpret(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    root: &ProcedureHandle,
    plan: &TypeFlowPlan,
    result: &ValueFlowSummaryResult,
) -> TypeFlowRootResult {
    let termination = result.result().termination();
    let complete = termination.is_fixed_point();
    let semantic_budget_exhausted = plan.field_slot_semantic_budget_exhausted()
        || plan
            .value_flow()
            .public_semantic_status(result.result())
            .budget_exceeded()
            .is_some();
    let mut class_sets = Vec::new();
    let mut findings = Vec::new();
    for (sink_id, _) in plan.value_flow().sinks() {
        let site = plan.sink(sink_id).clone();
        let set = match result.sink_outcome(sink_id) {
            ValueFlowSinkOutcome::Reached(meetings) => reached_class_set(
                workspace,
                adapter,
                site,
                plan,
                result,
                &meetings,
                root,
                &mut findings,
            ),
            ValueFlowSinkOutcome::NotReached if complete => ReceiverClassSet {
                site,
                classes: Vec::new(),
                unknown: Vec::new(),
                status: ClassSetStatus::NoInformation,
            },
            // An unreached sink under an incomplete root must name why; an
            // empty reason vector would read as a clean no-information
            // answer. `sink_outcome` gates `NotReached` on a complete result
            // today, so the `NotReached` half of this arm is the contract
            // holding the line if that gate ever widens.
            ValueFlowSinkOutcome::NotReached | ValueFlowSinkOutcome::Inconclusive => {
                ReceiverClassSet {
                    site,
                    classes: Vec::new(),
                    unknown: vec![unreached_reason(
                        plan,
                        sink_id,
                        termination,
                        semantic_budget_exhausted,
                    )],
                    status: ClassSetStatus::Inconclusive,
                }
            }
        };
        class_sets.push(set);
    }
    TypeFlowRootResult {
        root: root.clone(),
        class_sets,
        findings,
        complete,
        semantic_budget_exhausted,
    }
}

/// The reason one unreached sink carries under an incomplete root. A solver
/// stop outranks every finer attribution (past it, even the coverage records
/// may be partial), then semantic-budget evidence, then the boundary the
/// closure's coverage names for the call that produced the sink's receiver,
/// and only then the honest fallback: the root is incomplete and the closure
/// does not say why.
fn unreached_reason(
    plan: &TypeFlowPlan,
    sink: ValueFlowSinkId,
    termination: SolverTermination,
    semantic_budget_exhausted: bool,
) -> UnknownReason {
    if termination.budget_exceeded().is_some() {
        return UnknownReason::SolverBudget;
    }
    if semantic_budget_exhausted {
        return UnknownReason::SemanticBudget;
    }
    let spec = plan
        .value_flow()
        .sink(sink)
        .expect("interpret iterates the plan's own sinks");
    // Only a receiver a call directly produced can be attributed to that
    // call's coverage; anything else (a parameter, a load, a local chain) is
    // the root's incompleteness the closure does not explain.
    if let ValueFlowCarrier::Value(value) = spec.carrier()
        && let Some(call) = TypeFlowPlan::call_producing(value.procedure(), value.id())
        && let Some(reason) = uncovered_reason(plan.coverage_of(value.procedure(), call))
    {
        return reason;
    }
    UnknownReason::IncompleteRoot
}

#[allow(clippy::too_many_arguments)]
fn reached_class_set(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    site: MemberAccessSite,
    plan: &TypeFlowPlan,
    result: &ValueFlowSummaryResult,
    meetings: &[&ValueFlowMeeting],
    root: &ProcedureHandle,
    findings: &mut Vec<AbsentMemberFinding>,
) -> ReceiverClassSet {
    // Parallel vecs: `classes[i]` was introduced by `class_meetings[i]`.
    let mut classes: Vec<(ClassIdentity, SourceSite)> = Vec::new();
    let mut class_meetings: Vec<&ValueFlowMeeting> = Vec::new();
    let mut unknown: Vec<UnknownReason> = Vec::new();
    for meeting in meetings {
        if meeting.is_uncertain() {
            push_reason(&mut unknown, UnknownReason::UncertainFlow);
        }
        match plan.atom(meeting.source()) {
            ClassAtom::Class(identity) => {
                if !classes.iter().any(|(existing, _)| existing == identity) {
                    classes.push((identity.clone(), plan.source_site(meeting.source()).clone()));
                    class_meetings.push(meeting);
                }
            }
            ClassAtom::Unknown(reason) => push_reason(&mut unknown, *reason),
        }
    }
    let mut status = if !unknown.is_empty() {
        ClassSetStatus::Partial
    } else if classes.is_empty() {
        ClassSetStatus::NoInformation
    } else {
        ClassSetStatus::Known
    };
    if status == ClassSetStatus::Known {
        // The finding rule asks the adapter about every class before any
        // finding is emitted: one Unknown lookup turns the whole set partial
        // and no finding reports a guess.
        let mut absent: Vec<usize> = Vec::new();
        for (index, (identity, _)) in classes.iter().enumerate() {
            match adapter.member_lookup(workspace, identity, &site.member) {
                MemberLookup::Present => {}
                MemberLookup::Absent => absent.push(index),
                MemberLookup::Unknown(reason) => push_reason(&mut unknown, reason),
            }
        }
        if unknown.is_empty() {
            for index in absent {
                let (identity, origin) = &classes[index];
                findings.push(AbsentMemberFinding {
                    root: root.clone(),
                    site: site.clone(),
                    class: identity.clone(),
                    origin: origin.clone(),
                    witness: best_witness(result, class_meetings[index]),
                });
            }
        } else {
            status = ClassSetStatus::Partial;
        }
    }
    ReceiverClassSet {
        site,
        classes,
        unknown,
        status,
    }
}

fn push_reason(reasons: &mut Vec<UnknownReason>, reason: UnknownReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// The witness at the best path quality the meeting retained, when one was.
fn best_witness(
    result: &ValueFlowSummaryResult,
    meeting: &ValueFlowMeeting,
) -> Option<SummaryWitness> {
    let qualities = meeting.path_qualities();
    let quality = [
        PathQuality::PROVEN_COMPLETE,
        PathQuality::PROVEN_PARTIAL,
        PathQuality::UNPROVEN_COMPLETE,
        PathQuality::UNPROVEN_PARTIAL,
    ]
    .into_iter()
    .find(|quality| qualities.contains(*quality))
    .expect("a meeting retains at least one path quality");
    let _scope = profiling::scope("type_flow.witness_reconstruction");
    result
        .witness_for_meeting(meeting, quality, WitnessReconstructionLimits::default())
        .ok()
}
