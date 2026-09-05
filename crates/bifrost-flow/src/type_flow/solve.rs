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
use std::sync::Arc;

use brokk_bifrost_core::profiling;

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    ClassAtom, ClassIdentity, DispatchHint, DispatchHintCallSiteKey, DispatchHintSet,
    DispatchHints, IcfgProvider, MemberAccessKind, MemberDeclaration, MemberLookup,
    ProcedureHandle, SemanticBudget, SourceSite, TypeFlowAdapter, UnknownReason,
    WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::dataflow::{
    DataflowRequest, PathQuality, SolverTermination, SummaryWitness, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use crate::value_flow::{
    ClosureLimits, ValueFlowCache, ValueFlowCarrier, ValueFlowMeeting, ValueFlowSinkId,
    ValueFlowSinkOutcome, ValueFlowSolveError, ValueFlowSummaryResult, WorkspaceValueFlowProvider,
    solve_value_flow_with_reusable_summaries, solve_value_flow_with_witnesses,
};

use super::FieldSlotIndex;
use super::plan::{MemberAccessSite, TypeFlowPlan, TypeFlowPlanError, uncovered_reason};
use super::summary::{PreparedClassSetSummaries, TypeFlowSummaryState};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverClassSet {
    pub site: MemberAccessSite,
    pub classes: Vec<(ClassIdentity, SourceSite)>,
    /// Exact declarations that proved a class in `classes` has this member.
    /// Retained so feedback consumes the same lookup verdict that authorized
    /// the Known set instead of repeating a language query.
    pub member_declarations: Vec<(ClassIdentity, MemberDeclaration)>,
    pub unknown: Vec<UnknownReason>,
    pub status: ClassSetStatus,
}

/// A member access whose receiver provably holds a class that does not
/// declare the member.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Cross-root procedure-summary lookups served by a reusable class-set
    /// relation while computing this result.
    pub reusable_summary_hits: usize,
    /// Cross-root procedure-summary entry facts that had no reusable relation.
    pub reusable_summary_misses: usize,
    /// Complete leaf entry relations newly published for later roots.
    pub published_summaries: usize,
}

/// Why one root's class-set solve could not run.
#[derive(Debug)]
pub enum TypeFlowError {
    Plan(TypeFlowPlanError),
    Solve(ValueFlowSolveError),
    Io(std::io::Error),
    Cancelled,
}

/// Bound on discover-plan-solve passes for one root. One pass preserves the
/// pre-feedback behavior; later passes consume receiver hints derived from the
/// preceding result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FeedbackLimits {
    max_iterations: usize,
}

impl FeedbackLimits {
    pub fn new(max_iterations: usize) -> Self {
        assert!(
            max_iterations > 0,
            "type-flow feedback requires at least one solve iteration"
        );
        Self { max_iterations }
    }

    pub const fn max_iterations(self) -> usize {
        self.max_iterations
    }
}

impl Default for FeedbackLimits {
    fn default() -> Self {
        Self::new(3)
    }
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

/// Repeatedly build and solve `root` against one captured semantic-model
/// snapshot, feeding Known receiver classes into the next iteration's
/// immutable dispatch hints until the table stops changing or the bound is
/// reached.
#[allow(clippy::too_many_arguments)]
pub fn solve_type_flow_for_root(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    root: &ProcedureHandle,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    limits: ClosureLimits,
    feedback_limits: FeedbackLimits,
    value_flow_cache: ValueFlowCache,
    summary_state: TypeFlowSummaryState,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TypeFlowRootResult, TypeFlowError> {
    let mut dispatch_hints = DispatchHints::empty();
    let mut previous = None;
    for iteration in 0..feedback_limits.max_iterations() {
        // A feedback pass is a speculative refinement of the preceding
        // result. Stage its semantic charges so an exhausted refinement can
        // fall back to that sound result without both degrading the answer
        // and consuming work for a pass whose output is discarded.
        let mut iteration_budget = semantic_budget.clone();
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            workspace,
            active_semantic_model_snapshot.clone(),
            dispatch_hints.clone(),
        );
        let discovery_provider = WorkspaceValueFlowProvider::with_oracle(
            provider.oracle().clone(),
            provider.behavior_identity(),
            value_flow_cache.clone(),
        );
        let plan = TypeFlowPlan::build(
            workspace,
            adapter,
            field_slots,
            root,
            &discovery_provider,
            limits,
            &mut iteration_budget,
            request.cancellation,
        )?;
        let mut summaries = PreparedClassSetSummaries::new(
            summary_state.clone(),
            workspace,
            &plan,
            field_slots,
            provider.behavior_identity(),
        );
        let mut interpreted;
        if summaries.has_reusable_rows() {
            // Reusable rows currently retain reachability and path quality,
            // not witness fragments. Run the cheap symbolic trial without a
            // witness sidecar. If it produces a finding, discard its staged
            // budgets and run the exact witness-producing path; otherwise no
            // consumer can observe the missing sidecar, so commit the trial.
            let mut trial_solver_budget = request.budget.clone();
            let mut trial_request =
                DataflowRequest::new(&mut trial_solver_budget, request.cancellation)
                    .with_query_plan_config(request.query_plan_config());
            let mut trial_semantic_budget = iteration_budget.clone();
            let trial_result = {
                let _scope = profiling::scope("type_flow.solve");
                solve_value_flow_with_reusable_summaries(
                    root,
                    &provider,
                    &mut summaries,
                    plan.value_flow(),
                    WitnessRetentionLimits::disabled(),
                    &mut trial_semantic_budget,
                    &mut trial_request,
                )?
            };
            let metrics = trial_result.result().metrics();
            let trial_interpreted = interpret(workspace, adapter, root, &plan, &trial_result);
            if metrics.reusable_summary_hits > 0 && trial_interpreted.findings.is_empty() {
                *request.budget = trial_solver_budget;
                iteration_budget = trial_semantic_budget;
                interpreted = trial_interpreted;
                interpreted.reusable_summary_hits = metrics.reusable_summary_hits;
                interpreted.reusable_summary_misses = metrics.reusable_summary_misses;
                interpreted.published_summaries =
                    summaries.publish_complete(&trial_result, request.cancellation);
            } else {
                let result = {
                    let _scope = profiling::scope("type_flow.solve");
                    solve_value_flow_with_witnesses(
                        root,
                        &provider,
                        plan.value_flow(),
                        WitnessRetentionLimits::new(1)
                            .expect("one alternative is a valid witness retention limit"),
                        &mut iteration_budget,
                        request,
                    )?
                };
                interpreted = interpret(workspace, adapter, root, &plan, &result);
                interpreted.reusable_summary_hits = metrics.reusable_summary_hits;
                interpreted.reusable_summary_misses = metrics.reusable_summary_misses;
                interpreted.published_summaries =
                    summaries.publish_complete(&result, request.cancellation);
            }
        } else {
            let result = {
                let _scope = profiling::scope("type_flow.solve");
                solve_value_flow_with_witnesses(
                    root,
                    &provider,
                    plan.value_flow(),
                    WitnessRetentionLimits::new(1)
                        .expect("one alternative is a valid witness retention limit"),
                    &mut iteration_budget,
                    request,
                )?
            };
            interpreted = interpret(workspace, adapter, root, &plan, &result);
            interpreted.published_summaries =
                summaries.publish_complete(&result, request.cancellation);
        }
        if interpreted.semantic_budget_exhausted || !interpreted.complete {
            if let Some(previous) = previous {
                return Ok(previous);
            }
            *semantic_budget = iteration_budget;
            return Ok(interpreted);
        }
        *semantic_budget = iteration_budget;
        let next_hints = dispatch_hints.with_updates(dispatch_hint_updates(&plan, &interpreted));
        if next_hints.digest() == dispatch_hints.digest()
            || iteration + 1 == feedback_limits.max_iterations()
        {
            return Ok(interpreted);
        }
        previous = Some(interpreted);
        dispatch_hints = next_hints;
    }
    unreachable!("FeedbackLimits requires at least one iteration")
}

fn dispatch_hint_updates(plan: &TypeFlowPlan, result: &TypeFlowRootResult) -> Vec<DispatchHintSet> {
    let mut updates = Vec::new();
    for set in &result.class_sets {
        if set.status != ClassSetStatus::Known || set.site.kind != MemberAccessKind::Call {
            continue;
        }
        let call = set
            .site
            .call
            .expect("a call-shaped member sink retains its call-site ID");
        if uncovered_reason(plan.coverage_of(&set.site.procedure, call))
            != Some(UnknownReason::UnresolvedCall)
        {
            continue;
        }
        let hints = set
            .member_declarations
            .iter()
            .map(|(class, declaration)| {
                let origin = set
                    .classes
                    .iter()
                    .find(|(candidate, _)| candidate == class)
                    .map(|(_, origin)| origin.clone())
                    .expect("a retained member declaration belongs to the receiver class set");
                DispatchHint::new(declaration.clone(), class.clone(), origin)
            })
            .collect::<Vec<_>>();
        if hints.is_empty() {
            continue;
        }
        updates.push(DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&set.site.procedure, call),
            hints,
            true,
            set.classes.len() == 1,
        ));
    }
    updates
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
                member_declarations: Vec::new(),
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
                    member_declarations: Vec::new(),
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
    let mut distinct_findings: Vec<AbsentMemberFinding> = Vec::new();
    for finding in findings {
        if let Some(existing) = distinct_findings.iter_mut().find(|existing| {
            existing.site.file == finding.site.file
                && existing.site.span == finding.site.span
                && existing.site.member == finding.site.member
                && existing.class == finding.class
        }) {
            if existing.witness.is_none() && finding.witness.is_some() {
                existing.witness = finding.witness;
            }
        } else {
            distinct_findings.push(finding);
        }
    }
    TypeFlowRootResult {
        root: root.clone(),
        class_sets,
        findings: distinct_findings,
        complete,
        semantic_budget_exhausted,
        reusable_summary_hits: 0,
        reusable_summary_misses: 0,
        published_summaries: 0,
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
    let mut member_declarations = Vec::new();
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
                MemberLookup::Present(declaration) => {
                    member_declarations.push((identity.clone(), declaration));
                }
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
        member_declarations,
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
