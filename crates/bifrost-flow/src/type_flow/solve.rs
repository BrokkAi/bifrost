//! Solve one root's class-set plan and interpret every sink.
//!
//! The value-flow meetings at a member-access sink become a
//! [`ReceiverClassSet`]: the classes of the sources that reached it, the
//! Unknown reasons of the sources that reached it, and a status. The finding
//! rule fires only when the set has no Unknown: every class that provably
//! lacks the accessed member produces an [`AbsentMemberFinding`] carrying the
//! site, the class, the origin site that introduced the class, the root, and
//! the witness path. A set with any Unknown reports `partial` (or
//! `inconclusive`) and produces no Proven finding, so a guess is never
//! presented as a bug. A partial set whose remainders only say that some other
//! value may also reach the site can still produce an
//! [`AbsentMemberProof::Conditional`] finding for a class whose arrival and
//! member absence are both proven; the finding names those remainders.
//! A root method receiver may be known under the workspace-closed-world
//! rule: its enclosing workspace class has no known workspace descendants,
//! unresolved base, or dynamic-attribute hook. External subclasses are outside
//! that rule, matching workspace member lookup's existing boundary.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use brokk_bifrost_core::profiling;

use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, GenKillFacts, dominators, reaching_definitions,
};
use crate::analyzer::semantic::type_flow::DispatchHintProof;
use crate::analyzer::semantic::{
    CancellationToken, CandidateCoverage, ClassAtom, ClassIdentity, ClassSeed,
    ConstructorResultEvidence, ConstructorResultOrigin, ControlEdgeKind, DispatchHint,
    DispatchHintCallSiteKey, DispatchHintSet, DispatchHints, ExactResultProducer, IcfgProvider,
    MemberAccessKind, MemberLookup, MemberLookupHit, MemberReceiverQuery, ProcedureHandle,
    ProgramPointId, SemanticBudget, SemanticBudgetExceeded, SemanticEffect, SemanticValueKind,
    SourceMappingKind, SourceSite, SourceSiteKind, SourceSpan, TypeFlowAdapter, UnknownReason,
    ValueFlowKind, ValueId, WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{AnalyzerQueryScope, ProjectFile, WorkspaceAnalyzer};
use crate::dataflow::{
    DataflowRequest, PathQuality, SolverBudget, SolverBudgetExceeded, SolverTermination,
    SolverWork, SummaryWitness, SummaryWitnessError, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    ClosureLimits, DurableProcedureKey, ValueFlowCache, ValueFlowCarrier, ValueFlowMeeting,
    ValueFlowSinkId, ValueFlowSinkOutcome, ValueFlowSolveError, ValueFlowSummaryResult,
    WorkspaceValueFlowProvider, solve_value_flow_with_reusable_summaries,
    solve_value_flow_with_summaries, solve_value_flow_with_witnesses,
};

use super::FieldSlotIndex;
use super::field_slots::{MemberStoreEvidence, class_order};
use super::plan::{
    MemberAccessSite, ProcedureRefinements, SourceRefinement, TypeFlowPlan, TypeFlowPlanError,
    TypeFlowSitePurpose, uncovered_reason,
};
use super::refinement_sources::DefinitionSources;
use super::summary::{
    ClassSetAcquisitionCuts, PreparedClassSetSummaries, TypeFlowSummaryProfile,
    TypeFlowSummaryState,
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

/// The classes and Unknown reasons that reached one typed class-set site under
/// one root, plus the status a consumer may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverClassSet {
    pub site: MemberAccessSite,
    pub classes: Vec<(ClassIdentity, SourceSite)>,
    /// One exact call or access result that introduced this receiver.
    /// Conservative value flow can add other meetings from the producer's
    /// inputs; consumers must independently prove the stable local binding,
    /// exact producer, and exhaustive member lookup before using this origin.
    pub constructor_origin: Option<ConstructorResultOrigin>,
    /// The exact call or access result passed the language's stable-local
    /// receiver proof. Consumers may use this only with exhaustive dispatch.
    pub exact_result_receiver_proven: bool,
    /// Exact declarations that proved a class in `classes` has this member.
    /// Retained so feedback consumes the same lookup verdict that authorized
    /// the Known set instead of repeating a language query.
    pub member_declarations: Vec<(ClassIdentity, MemberLookupHit)>,
    /// Unknown value-flow atoms or uncertain meetings, separated from
    /// member-lookup uncertainty so a consumer can use another structured
    /// member inventory without treating it as a complete class set.
    pub flow_unknown: Vec<UnknownReason>,
    pub unknown: Vec<UnknownReason>,
    pub dynamic_writes: Vec<super::dynamic_stores::DynamicWriteEvidence>,
    pub status: ClassSetStatus,
}

/// A member access with complete receiver classes and an admitted value
/// alternative whose class does not declare the member. Membership inferred
/// only by guarding an unmodeled producer is insufficient. This is not a proof
/// that every control-flow condition on a runtime path is jointly feasible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsentMemberFinding {
    pub root: ProcedureHandle,
    pub site: MemberAccessSite,
    pub class: ClassIdentity,
    pub origin: SourceSite,
    /// The independently reconstructed evidence for this Proven finding.
    ///
    /// A retention-truncated marker is an `Ok` witness with an explicit
    /// truncation cause. An `Err` preserves why evidence could not be
    /// reconstructed without weakening the finding's class-set proof.
    pub witness: Result<SummaryWitness, SummaryWitnessError>,
    pub proof: AbsentMemberProof,
    /// Later accesses masked by the first failing access, in stable source order.
    pub also_fails_at: Vec<(ProjectFile, SourceSpan)>,
}

/// How strongly an [`AbsentMemberFinding`] is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbsentMemberProof {
    /// The receiver set is complete: every value that reaches the site is
    /// classified, so the class is one of a closed set of alternatives.
    Proven,
    /// The class certainly reaches the site and lacks the member, but other
    /// receiver values may remain unclassified, a listed global dynamic write
    /// may install the member, or a declared parameter may rely on a single
    /// closed workspace-class annotation. `remainders` is the sorted set of
    /// Unknown reasons the receiver set carried.
    Conditional {
        remainders: Vec<UnknownReason>,
        unbounded_dynamic_writes: Vec<super::dynamic_stores::DynamicWriteEvidence>,
    },
}

impl AbsentMemberProof {
    /// Every tier label, in enum declaration order. Row-field registries read
    /// this so the publishable value set cannot drift from the enum.
    pub const LABELS: &[&str] = &["proven", "conditional"];

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Conditional { .. } => "conditional",
        }
    }

    pub const fn is_proven(&self) -> bool {
        matches!(self, Self::Proven)
    }
}

/// Whether one live root result may be persisted by a higher projection
/// layer without promoting request-local failure into a durable answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeFlowRootPersistenceStatus {
    Eligible,
    Ineligible(TypeFlowRootPersistenceRejection),
}

/// Engine-owned reason a root result must not cross a request boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeFlowRootPersistenceRejection {
    SolverIncomplete,
    SemanticBudget,
    ProviderFailure,
    FeedbackFallback,
}

impl TypeFlowRootPersistenceStatus {
    fn from_solve(
        complete: bool,
        semantic_budget_exhausted: bool,
        provider_failure_observed: bool,
    ) -> Self {
        if semantic_budget_exhausted {
            Self::Ineligible(TypeFlowRootPersistenceRejection::SemanticBudget)
        } else if !complete {
            Self::Ineligible(TypeFlowRootPersistenceRejection::SolverIncomplete)
        } else if provider_failure_observed {
            Self::Ineligible(TypeFlowRootPersistenceRejection::ProviderFailure)
        } else {
            Self::Eligible
        }
    }
}

#[derive(Debug, Default)]
struct TypeFlowRootPersistenceTracker {
    provider_failure_observed: bool,
}

impl TypeFlowRootPersistenceTracker {
    fn observe_provider_failure(&mut self, observed: bool) {
        self.provider_failure_observed |= observed;
    }

    fn status(
        &self,
        complete: bool,
        semantic_budget_exhausted: bool,
    ) -> TypeFlowRootPersistenceStatus {
        TypeFlowRootPersistenceStatus::from_solve(
            complete,
            semantic_budget_exhausted,
            self.provider_failure_observed,
        )
    }
}

impl TypeFlowRootResult {
    /// The first typed semantic charge this root could not pay, when any lane
    /// named one.
    fn semantic_exhaustion(&self) -> Option<SemanticBudgetExceeded> {
        self.incomplete_evidence
            .lanes
            .iter()
            .find_map(|lane| match lane {
                RootExhaustedLane::Semantic { exceeded, .. } => *exceeded,
                RootExhaustedLane::Solver(_) | RootExhaustedLane::Cancelled => None,
            })
    }

    fn mark_feedback_fallback(&mut self) {
        self.persistence_status = Self::feedback_fallback_status();
    }

    const fn feedback_fallback_status() -> TypeFlowRootPersistenceStatus {
        TypeFlowRootPersistenceStatus::Ineligible(
            TypeFlowRootPersistenceRejection::FeedbackFallback,
        )
    }
}

/// The stage of one root's solve that could not pay a semantic charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticExhaustionStage {
    /// The workspace field-slot index the plan read.
    FieldSlotIndex,
    /// Guard-binding, correlation, or field refinement during the plan build,
    /// including the source-refinement rounds that rebuild the plan.
    PlanRefinement,
    /// The value-flow solve of the root's plan.
    ValueFlowSolve,
}

impl SemanticExhaustionStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FieldSlotIndex => "field_slot_index",
            Self::PlanRefinement => "plan_refinement",
            Self::ValueFlowSolve => "value_flow_solve",
        }
    }
}

/// The role of one independently bounded solver run inside a root's type-flow
/// transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeFlowSolvePhase {
    ExploratoryRefinement,
    RefinedPlan,
    SummaryMaintenance,
    ReusableTrial,
    Witness,
}

impl TypeFlowSolvePhase {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExploratoryRefinement => "exploratory_refinement",
            Self::RefinedPlan => "refined_plan",
            Self::SummaryMaintenance => "summary_maintenance",
            Self::ReusableTrial => "reusable_trial",
            Self::Witness => "witness",
        }
    }
}

/// One lane that stopped a root short of a complete answer.
///
/// Every variant names the exact charge that failed where the charge was
/// typed. `Semantic { exceeded: None }` is the one lane the producing code
/// does not type today: the field-slot index's transient resolver-budget
/// stop, which records no dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootExhaustedLane {
    /// The dataflow solver stopped before a fixed point on one solver lane.
    Solver(SolverBudgetExceeded),
    /// The solve was cancelled before a fixed point.
    Cancelled,
    /// A semantic-work lane was exhausted in one stage of the root's solve.
    Semantic {
        stage: SemanticExhaustionStage,
        exceeded: Option<SemanticBudgetExceeded>,
    },
}

/// Why one root retained incomplete evidence, kept per lane rather than as a
/// count so a consumer can attribute the root without an instrumented build.
///
/// Empty exactly when the root reached a fixed point and paid every semantic
/// charge its plan and solve asked for.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RootIncompleteEvidence {
    /// Every lane that stopped this root, in the order the solve observed
    /// them: the solver stop first, then the semantic stages.
    pub lanes: Vec<RootExhaustedLane>,
    /// The feedback iteration whose plan produced this evidence, counting
    /// from zero.
    pub feedback_iteration: usize,
}

impl RootIncompleteEvidence {
    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }
}

/// Work and termination detail for one independently bounded solver run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeFlowSolveAttempt {
    pub phase: TypeFlowSolvePhase,
    pub work: SolverWork,
    pub budget_exhaustion: Option<SolverBudgetExceeded>,
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
    /// Complete ordered collection of independently bounded solver runs made
    /// while producing this root result.
    pub solver_attempts: Vec<TypeFlowSolveAttempt>,
    /// The semantic-work budget was exhausted while this root was discovered
    /// or solved: a typed `ExceededBudget` rode the solve's semantic-input
    /// boundaries. Executors surface this as their
    /// `semantic_budget_exhausted` diagnostic.
    pub semantic_budget_exhausted: bool,
    /// Engine-owned durable-publication gate. Stable typed open boundaries
    /// remain eligible; transient provider failures, resource exhaustion,
    /// incomplete solves, and feedback fallback do not.
    pub persistence_status: TypeFlowRootPersistenceStatus,
    /// The lanes that stopped this root, empty when it answered completely.
    /// `complete` and `semantic_budget_exhausted` are this evidence reduced
    /// to the two booleans their consumers already branch on.
    pub incomplete_evidence: RootIncompleteEvidence,
    /// Cross-root procedure-summary lookups served by a reusable class-set
    /// relation while computing this result.
    pub reusable_summary_hits: usize,
    /// Cross-root procedure-summary entry facts that had no reusable relation.
    pub reusable_summary_misses: usize,
    /// Witnessless trials whose exact Zero-entry root relation was restored
    /// from a reusable class-set summary.
    pub reusable_root_summary_hits: usize,
    /// Root-summary hits rejected because at least one current plan sink had
    /// no remapped Meeting. Such a missing row cannot distinguish a fresh
    /// `NotReached` result from an inconclusive one, so the root is solved
    /// normally instead.
    pub reusable_root_summary_observation_rejections: usize,
    /// Complete reusable entry relations whose semantic content was newly
    /// published or replaced. An attachment-only durable provenance refresh
    /// is excluded; when persistence is unavailable, a new in-memory relation
    /// is counted instead.
    pub published_summaries: usize,
    /// Typed attribution for summary preparation, lookup, and publication
    /// paths that could not reuse or retain a relation.
    pub summary_profile: TypeFlowSummaryProfile,
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
    let mut refinements = ProcedureRefinements::default();
    solve_type_flow_for_root_with_refinements(
        workspace,
        adapter,
        field_slots,
        root,
        active_semantic_model_snapshot,
        limits,
        feedback_limits,
        value_flow_cache,
        summary_state,
        semantic_budget,
        request,
        &mut refinements,
    )
}

/// Solve one root while reusing successful procedure-local refinement
/// components from the caller-owned request cache.
///
/// The cache is deliberately limited to this request. It contains only pure,
/// identity-keyed derivations; plans, failures, cancellation, budgets, hints,
/// cuts, and results remain owned by this solve. Each semantic ledger still
/// pays a reused component's measured work once through the existing
/// `reused_or_derived` accounting.
#[allow(clippy::too_many_arguments)]
pub fn solve_type_flow_for_root_with_refinements(
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
    refinements: &mut ProcedureRefinements,
) -> Result<TypeFlowRootResult, TypeFlowError> {
    let _semantic_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        active_semantic_model_snapshot.clone(),
    );
    let _cancellation_scope =
        AnalyzerQueryScope::with_cancellation(workspace.analyzer(), request.cancellation);
    let mut dispatch_hints = DispatchHints::empty();
    /// The last complete feedback iteration, kept with the plan that produced
    /// it. Receiver hints reach the solve only by changing the plan the next
    /// iteration builds, so an iteration that rebuilds the same plan cannot
    /// reach a different result.
    struct CompletedIteration {
        result: TypeFlowRootResult,
        plan: TypeFlowPlan,
    }
    let mut previous: Option<CompletedIteration> = None;
    /// A source-refinement round's witnessless solve and its interpretation,
    /// retained because the round that followed it rebuilt the same plan.
    struct RefinedPlanSolve {
        result: ValueFlowSummaryResult,
        interpreted: TypeFlowRootResult,
        budget: SolverBudget,
        attempt_index: usize,
    }
    let mut summary_profile = TypeFlowSummaryProfile::default();
    // Publication eligibility is a property of the whole feedback/retry
    // transaction, not only the final plan. A transient provider error can
    // disappear on a later uncached lookup, but the request that observed it
    // still must not turn its eventual result into a durable answer.
    let mut persistence = TypeFlowRootPersistenceTracker::default();
    // Observation rejection is request-total telemetry. A selective cut retry
    // or feedback iteration must not erase a root probe that already fell back
    // without charging solver work.
    let mut root_summary_observation_rejections = 0usize;
    let root_solver_limits = request.budget.limits();
    let query_plan_config = request.query_plan_config();
    let mut solver_attempts = Vec::new();
    // Every plan attempt in this solve reuses the caller-owned procedure-local
    // refinements. Keeping the cache outside the root solve also lets
    // overlapping roots in one request share successful derivations.
    for iteration in 0..feedback_limits.max_iterations() {
        // A feedback pass is a speculative refinement of the preceding
        // result. Stage its semantic charges so an exhausted refinement can
        // fall back to that sound result without both degrading the answer
        // and consuming work for a pass whose output is discarded.
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
        let mut acquisition_cuts = ClassSetAcquisitionCuts::new(
            summary_state.clone(),
            workspace,
            &discovery_provider,
            provider.behavior_identity(),
            field_slots,
            HashSet::<DurableProcedureKey>::default(),
        );
        let mut require_full_plan = false;
        // The plan this iteration actually solves, before source refinement
        // mutates it. It is the whole input to everything the iteration does
        // next, so it is what the next iteration compares against. A plan
        // attempt can be abandoned (a selective summary-cut retry rebuilds the
        // plan), and an abandoned attempt never solved its plan, so the
        // assignment below happens on every attempt. Comparing against an
        // abandoned attempt's plan would report a difference the solve never
        // observed and re-solve an iteration whose plan is unchanged.
        let mut solved_plan: Option<TypeFlowPlan> = None;
        let (plan, mut interpreted, iteration_budget, maintenance, publication_writes) = 'plan_attempt: loop {
            let mut iteration_budget = semantic_budget.clone();
            let plan_result = if !require_full_plan {
                TypeFlowPlan::build_with_summary_cuts(
                    workspace,
                    adapter,
                    field_slots,
                    root,
                    &discovery_provider,
                    limits,
                    &mut iteration_budget,
                    request.cancellation,
                    refinements,
                    &mut acquisition_cuts,
                )
            } else {
                TypeFlowPlan::build(
                    workspace,
                    adapter,
                    field_slots,
                    root,
                    &discovery_provider,
                    limits,
                    &mut iteration_budget,
                    request.cancellation,
                    refinements,
                )
            };
            let plan_cache_writes = discovery_provider.take_retained_writes();
            let mut plan = match plan_result {
                Ok(plan) => plan,
                Err(error) => {
                    if plan_cache_writes {
                        *semantic_budget = iteration_budget;
                    }
                    return Err(error.into());
                }
            };
            if plan_cache_writes {
                *semantic_budget = iteration_budget.clone();
            }
            if iteration + 1 < feedback_limits.max_iterations() {
                solved_plan = Some(plan.clone());
            }
            if !require_full_plan
                && previous
                    .as_ref()
                    .is_some_and(|completed| completed.plan.feedback_fixpoint_matches(&plan))
            {
                // The updated hints reached the plan without changing any
                // input the solve or `interpret` reads. Refinement, the
                // witness solve, and `interpret` all read this plan, so
                // repeating them would repeat the previous iteration's
                // work for the previous iteration's answer. That is the
                // feedback fixpoint: stop here and keep the result already
                // computed. The staged plan-build charge is discarded with
                // the rest of this speculative pass unless it retained
                // cache writes, which the branch above already committed.
                let completed =
                    previous.expect("the identical plan came from a completed iteration");
                return Ok(completed.result);
            }
            // The refinement round that reproduced the plan, with the solve
            // and interpretation it produced. Refinement rebuilds the plan
            // from each round's evidence; when the rebuild reproduces the
            // plan, the round already solved the plan the rest of this
            // iteration reads.
            let mut fixed_point_solve: Option<RefinedPlanSolve> = None;
            if plan.needs_source_refinement() && !plan.refinement_budget_exhausted() {
                if plan.has_summary_cuts() {
                    *semantic_budget = iteration_budget;
                    require_full_plan = true;
                    continue 'plan_attempt;
                }
                let mut refinement_solve_phase = TypeFlowSolvePhase::ExploratoryRefinement;
                fixed_point_solve = loop {
                    // Collect complete may-source evidence before deriving any
                    // exclusions. This trial never publishes reusable summaries.
                    // It is an independent solve, so it receives the root's
                    // unchanged per-solve limits on a zero-used child ledger.
                    let mut refinement_solver_budget = SolverBudget::new(root_solver_limits);
                    let mut refinement_request =
                        DataflowRequest::new(&mut refinement_solver_budget, request.cancellation)
                            .with_query_plan_config(query_plan_config);
                    let preliminary = solve_value_flow_with_summaries(
                        root,
                        &provider,
                        plan.value_flow(),
                        &mut iteration_budget,
                        &mut refinement_request,
                    )?;
                    let attempt_index = record_solver_attempt(
                        &mut solver_attempts,
                        refinement_solve_phase,
                        &preliminary,
                        refinement_solver_budget.used(),
                    );
                    refinement_solve_phase = TypeFlowSolvePhase::RefinedPlan;
                    let preliminary_status = interpret(
                        workspace,
                        adapter,
                        field_slots,
                        root,
                        &plan,
                        &preliminary,
                        &solver_attempts,
                    );
                    if !preliminary_status.complete || preliminary_status.semantic_budget_exhausted
                    {
                        if preliminary_status.semantic_budget_exhausted {
                            plan.mark_refinement_budget_exhausted(
                                preliminary_status.semantic_exhaustion(),
                            );
                        }
                        let interpreted = interpret(
                            workspace,
                            adapter,
                            field_slots,
                            root,
                            &plan,
                            &preliminary,
                            &solver_attempts,
                        );
                        break 'plan_attempt (
                            plan,
                            interpreted,
                            iteration_budget,
                            Default::default(),
                            false,
                        );
                    }
                    let refinement = DefinitionSources::new(
                        &preliminary,
                        plan.source_refinement_points(),
                        &mut iteration_budget,
                        request.cancellation,
                    )
                    .map_err(TypeFlowPlanError::from)
                    .and_then(|evidence| {
                        plan.refine_sources(
                            workspace,
                            adapter,
                            field_slots,
                            &evidence,
                            &mut iteration_budget,
                            request.cancellation,
                        )
                    });
                    match refinement {
                        Ok(SourceRefinement::Unchanged) => {
                            break Some(RefinedPlanSolve {
                                result: preliminary,
                                interpreted: preliminary_status,
                                budget: refinement_solver_budget,
                                attempt_index,
                            });
                        }
                        Ok(SourceRefinement::Settled) => break None,
                        Ok(SourceRefinement::Refined) => {}
                        Err(TypeFlowPlanError::RefinementBudget(exceeded)) => {
                            plan.mark_refinement_budget_exhausted(Some(exceeded));
                            break None;
                        }
                        Err(error) => {
                            *semantic_budget = iteration_budget;
                            return Err(error.into());
                        }
                    }
                    if request.cancellation.is_cancelled() {
                        return Err(TypeFlowPlanError::Cancelled.into());
                    }
                };
            }
            if plan.refinement_budget_exhausted() {
                let mut solve_budget = SolverBudget::new(root_solver_limits);
                let mut solve_request =
                    DataflowRequest::new(&mut solve_budget, request.cancellation)
                        .with_query_plan_config(query_plan_config);
                let result = solve_value_flow_with_summaries(
                    root,
                    &provider,
                    plan.value_flow(),
                    &mut iteration_budget,
                    &mut solve_request,
                )?;
                record_solver_attempt(
                    &mut solver_attempts,
                    TypeFlowSolvePhase::RefinedPlan,
                    &result,
                    solve_budget.used(),
                );
                let interpreted = interpret(
                    workspace,
                    adapter,
                    field_slots,
                    root,
                    &plan,
                    &result,
                    &solver_attempts,
                );
                break 'plan_attempt (
                    plan,
                    interpreted,
                    iteration_budget,
                    Default::default(),
                    false,
                );
            }
            persistence.observe_provider_failure(plan.provider_failure_observed());
            let cut_manifest = if require_full_plan {
                Default::default()
            } else {
                acquisition_cuts.take_manifest()
            };
            let mut summaries = PreparedClassSetSummaries::new_with_cuts(
                summary_state.clone(),
                workspace,
                &plan,
                field_slots,
                provider.behavior_identity(),
                cut_manifest,
            );
            if summaries.take_retained_publication_writes() {
                // Semantic component publication happens during construction,
                // before maintenance owns a solver budget of its own.
                *semantic_budget = iteration_budget.clone();
            }
            let mut maintenance_solver_budget = SolverBudget::new(root_solver_limits);
            let mut maintenance_request =
                DataflowRequest::new(&mut maintenance_solver_budget, request.cancellation)
                    .with_query_plan_config(query_plan_config);
            let mut maintenance_semantic_budget = iteration_budget.clone();
            let stabilized = summaries.stabilize_demanded_closure(
                root,
                &provider,
                &mut maintenance_semantic_budget,
                &mut maintenance_request,
            );
            // Closure stabilization can fail after publishing complete descendant
            // rows or rebinding equal-output provenance. The retained writes are
            // safe cache improvements, but their work must remain charged even
            // when the ordinary root path takes over.
            if maintenance_solver_budget.used() != SolverWork::default()
                || summaries.maintenance_solver_budget_exhaustion().is_some()
            {
                solver_attempts.push(TypeFlowSolveAttempt {
                    phase: TypeFlowSolvePhase::SummaryMaintenance,
                    work: maintenance_solver_budget.used(),
                    budget_exhaustion: summaries.maintenance_solver_budget_exhaustion(),
                });
            }
            iteration_budget = maintenance_semantic_budget;
            summaries.finish_maintenance_publications();
            if summaries.retained_maintenance_writes() {
                // The outer feedback pass is also speculative. A later fallback
                // to `previous` may discard its ordinary solve, but it must
                // not discard the plan and maintenance charges behind cache
                // writes that remain observable.
                *semantic_budget = iteration_budget.clone();
            }
            if !stabilized {
                summaries.prepare_fallback_after_maintenance();
            }
            let mut interpreted;
            if let Some(mut fixed) = fixed_point_solve
                && fixed.interpreted.findings.is_empty()
            {
                // The last refinement round solved this plan: its rebuild
                // reproduced the plan, so nothing the solve reads changed
                // after it ran. A trial or witness solve here would charge
                // this root's ledger a second time for the relation that
                // solve already produced. No sink produced a finding, so no
                // witness is owed, which is the condition the reusable trial
                // commits its own witnessless result under.
                assert!(
                    !plan.has_summary_cuts(),
                    "a source-refined plan carries no summary cuts"
                );
                interpreted = fixed.interpreted;
                let mut fixed_request =
                    DataflowRequest::new(&mut fixed.budget, request.cancellation)
                        .with_query_plan_config(query_plan_config);
                interpreted.published_summaries =
                    summaries.publish_complete(&fixed.result, &mut fixed_request);
                solver_attempts[fixed.attempt_index].work = fixed_request.budget.used();
            } else {
                // Establish findings before allocating witness paths, including
                // on a cold root with no reusable summaries. A finding-free
                // relation owes no witness; retaining paths eagerly can exhaust
                // the witness budget without producing anything to explain.
                // Findings still require the exact strict witness solve below.
                // Retain semantic charges for provider caches warmed by this
                // trial, even when its staged solver result is discarded.
                let has_reusable_rows = summaries.has_reusable_rows();
                let mut trial_solver_budget = SolverBudget::new(root_solver_limits);
                let mut trial_request =
                    DataflowRequest::new(&mut trial_solver_budget, request.cancellation)
                        .with_query_plan_config(query_plan_config);
                let mut trial_semantic_budget = iteration_budget.clone();
                let trial_result = {
                    let _scope = profiling::scope("type_flow.solve");
                    if has_reusable_rows {
                        solve_value_flow_with_reusable_summaries(
                            root,
                            &provider,
                            &mut summaries,
                            plan.value_flow(),
                            WitnessRetentionLimits::disabled(),
                            &mut trial_semantic_budget,
                            &mut trial_request,
                        )
                    } else {
                        solve_value_flow_with_summaries(
                            root,
                            &provider,
                            plan.value_flow(),
                            &mut trial_semantic_budget,
                            &mut trial_request,
                        )
                    }
                };
                let trial_publication_writes = summaries.take_retained_publication_writes();
                let trial_result = match trial_result {
                    Ok(result) => result,
                    Err(error) if error.mandatory_summary_cut_miss().is_some() => {
                        let failed = error
                            .mandatory_summary_cut_miss()
                            .expect("the guarded error names its failed cut");
                        assert!(
                            plan.is_summary_cut(failed),
                            "a mandatory summary miss names a cut in the current plan"
                        );
                        assert!(
                            acquisition_cuts.disable_cut(failed),
                            "each mandatory summary miss disables a new durable cut"
                        );
                        // Discovery and the symbolic trial populate shared
                        // semantic/value-flow caches. Their work is observable
                        // by the selective retry, whose cache hits can therefore
                        // be cheaper; retain the semantic charge even though the
                        // speculative cut plan itself is discarded.
                        *semantic_budget = trial_semantic_budget;
                        summary_profile = summary_profile.saturating_add(summaries.profile());
                        root_summary_observation_rejections = root_summary_observation_rejections
                            .saturating_add(summaries.root_observation_rejections());
                        continue 'plan_attempt;
                    }
                    Err(error) => {
                        if trial_publication_writes {
                            *semantic_budget = trial_semantic_budget;
                        }
                        return Err(error.into());
                    }
                };
                let trial_attempt_index = record_solver_attempt(
                    &mut solver_attempts,
                    TypeFlowSolvePhase::ReusableTrial,
                    &trial_result,
                    trial_request.budget.used(),
                );
                if trial_publication_writes {
                    *semantic_budget = trial_semantic_budget.clone();
                }
                let metrics = trial_result.result().metrics();
                let trial_interpreted = interpret(
                    workspace,
                    adapter,
                    field_slots,
                    root,
                    &plan,
                    &trial_result,
                    &solver_attempts,
                );
                // Whether the trial consumed a reusable row does not change
                // what it computed: with no hit it solved the whole plan
                // itself, and that is the same plan and the same relation the
                // witness solve would produce. Only a finding owes a witness,
                // so a witnessless trial with no finding is this iteration's
                // solve however many rows it reused. Requiring a hit here
                // charged the root's ledger twice for one answer.
                if trial_interpreted.findings.is_empty() {
                    iteration_budget = trial_semantic_budget;
                    interpreted = trial_interpreted;
                    interpreted.reusable_summary_hits = metrics.reusable_summary_hits;
                    interpreted.reusable_summary_misses = metrics.reusable_summary_misses;
                    interpreted.reusable_root_summary_hits = metrics.reusable_root_summary_hits;
                    interpreted.reusable_root_summary_observation_rejections =
                        summaries.root_observation_rejections();
                    interpreted.published_summaries =
                        summaries.publish_complete(&trial_result, &mut trial_request);
                    solver_attempts[trial_attempt_index].work = trial_request.budget.used();
                } else {
                    if plan.has_summary_cuts() {
                        // The witnessless trial can warm shared semantic cache
                        // entries before a finding requires a fresh full plan.
                        *semantic_budget = trial_semantic_budget;
                        require_full_plan = true;
                        summary_profile = summary_profile.saturating_add(summaries.profile());
                        root_summary_observation_rejections = root_summary_observation_rejections
                            .saturating_add(summaries.root_observation_rejections());
                        continue 'plan_attempt;
                    }
                    // The witnessless trial can also warm the provider-owned
                    // ICFG cache when no cut retry is needed. The witness solve
                    // observes those zero-work replays, so retain the semantic
                    // charge that originally produced them.
                    iteration_budget = trial_semantic_budget;
                    let mut witness_solver_budget = SolverBudget::new(root_solver_limits);
                    let mut witness_request =
                        DataflowRequest::new(&mut witness_solver_budget, request.cancellation)
                            .with_query_plan_config(query_plan_config);
                    let result = {
                        let _scope = profiling::scope("type_flow.solve");
                        let result = solve_value_flow_with_witnesses(
                            root,
                            &provider,
                            plan.value_flow(),
                            WitnessRetentionLimits::new(1)
                                .expect("one alternative is a valid witness retention limit"),
                            &mut iteration_budget,
                            &mut witness_request,
                        );
                        result?
                    };
                    let witness_attempt_index = record_solver_attempt(
                        &mut solver_attempts,
                        TypeFlowSolvePhase::Witness,
                        &result,
                        witness_request.budget.used(),
                    );
                    interpreted = interpret(
                        workspace,
                        adapter,
                        field_slots,
                        root,
                        &plan,
                        &result,
                        &solver_attempts,
                    );
                    interpreted.reusable_summary_hits = metrics.reusable_summary_hits;
                    interpreted.reusable_summary_misses = metrics.reusable_summary_misses;
                    interpreted.reusable_root_summary_hits = metrics.reusable_root_summary_hits;
                    interpreted.reusable_root_summary_observation_rejections =
                        summaries.root_observation_rejections();
                    interpreted.published_summaries =
                        summaries.publish_complete(&result, &mut witness_request);
                    solver_attempts[witness_attempt_index].work = witness_request.budget.used();
                }
            }
            let maintenance = summaries.maintenance_metrics();
            summary_profile = summary_profile.saturating_add(summaries.profile());
            root_summary_observation_rejections = root_summary_observation_rejections
                .saturating_add(summaries.root_observation_rejections());
            interpreted.reusable_root_summary_observation_rejections =
                root_summary_observation_rejections;
            interpreted.persistence_status =
                persistence.status(interpreted.complete, interpreted.semantic_budget_exhausted);
            let publication_writes = summaries.take_retained_publication_writes();
            break (
                plan,
                interpreted,
                iteration_budget,
                maintenance,
                publication_writes,
            );
        };
        interpreted.reusable_summary_hits = interpreted
            .reusable_summary_hits
            .saturating_add(maintenance.hits);
        interpreted.reusable_summary_misses = interpreted
            .reusable_summary_misses
            .saturating_add(maintenance.misses);
        interpreted.published_summaries = interpreted
            .published_summaries
            .saturating_add(maintenance.publications);
        interpreted.summary_profile = summary_profile;
        interpreted.incomplete_evidence.feedback_iteration = iteration;
        interpreted.solver_attempts = solver_attempts.clone();
        if interpreted.semantic_budget_exhausted || !interpreted.complete {
            if let Some(completed) = previous {
                let mut previous = completed.result;
                if publication_writes {
                    // The returned result comes from an earlier feedback pass,
                    // but this pass published cache state that later queries
                    // can observe. Retain the work that produced those writes.
                    *semantic_budget = iteration_budget;
                }
                previous.summary_profile = summary_profile;
                previous.reusable_root_summary_observation_rejections =
                    root_summary_observation_rejections;
                previous.solver_attempts = solver_attempts;
                previous.mark_feedback_fallback();
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
        previous = Some(CompletedIteration {
            result: interpreted,
            plan: solved_plan.expect("a continuing iteration retained the plan it solved"),
        });
        dispatch_hints = next_hints;
    }
    unreachable!("FeedbackLimits requires at least one iteration")
}

fn dispatch_hint_updates(plan: &TypeFlowPlan, result: &TypeFlowRootResult) -> Vec<DispatchHintSet> {
    let mut updates = Vec::new();
    for set in &result.class_sets {
        if set.site.purpose != TypeFlowSitePurpose::MemberAccess
            || !matches!(set.status, ClassSetStatus::Known | ClassSetStatus::Partial)
            || set.site.kind != MemberAccessKind::Call
        {
            continue;
        }
        let call = set
            .site
            .call
            .expect("a call-shaped member sink retains its call-site ID");
        let coverage = plan.coverage_of(&set.site.procedure, call);
        let uncovered = uncovered_reason(coverage);
        if uncovered != Some(UnknownReason::UnresolvedCall)
            && !(uncovered == Some(UnknownReason::Truncated)
                && coverage.is_some_and(|coverage| coverage.complete_receiver_hint_refinable))
        {
            continue;
        }
        let exhaustive =
            dispatch_hints_exhaustive(&set.member_declarations, set.classes.len(), set.status);
        let exact_return_origin_proven = set.constructor_origin.as_ref().is_some_and(|origin| {
            let origin_covers_receiver = origin.classes.iter().all(|class| {
                set.classes
                    .iter()
                    .any(|(receiver_class, _)| receiver_class == class)
            }) && set
                .classes
                .iter()
                .all(|(class, _)| origin.classes.contains(class));
            origin_covers_receiver
                && matches!(
                    origin.source.kind,
                    SourceSiteKind::ExactCallResult | SourceSiteKind::ExactAccessResult
                )
                && set.exact_result_receiver_proven
        });
        let receiver_classes_share_constructor_source =
            set.classes.first().is_some_and(|(_, first)| {
                first.kind == SourceSiteKind::ConstructorCall
                    && set.classes.iter().all(|(_, source)| source == first)
            });
        let receiver_origins_proven =
            exact_return_origin_proven || receiver_classes_share_constructor_source;
        let proof = if exhaustive && receiver_origins_proven {
            DispatchHintProof::Proven
        } else {
            DispatchHintProof::Unproven
        };
        let hints = set
            .member_declarations
            .iter()
            .map(|(class, hit)| {
                let origin = set
                    .classes
                    .iter()
                    .find(|(candidate, _)| candidate == class)
                    .map(|(_, origin)| origin.clone())
                    .expect("a retained member declaration belongs to the receiver class set");
                DispatchHint::new(hit.declaration.clone(), class.clone(), origin)
            })
            .collect::<Vec<_>>();
        if hints.is_empty() {
            continue;
        }
        updates.push(DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&set.site.procedure, call),
            hints,
            exhaustive,
            proof,
        ));
    }
    updates
}

fn dispatch_hints_exhaustive(
    declarations: &[(ClassIdentity, MemberLookupHit)],
    receiver_class_count: usize,
    status: ClassSetStatus,
) -> bool {
    status == ClassSetStatus::Known
        && receiver_class_count > 0
        && declarations.len() == receiver_class_count
        && declarations
            .iter()
            .all(|(_, hit)| hit.dispatch_coverage == CandidateCoverage::Exhaustive)
}

fn interpret(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    root: &ProcedureHandle,
    plan: &TypeFlowPlan,
    result: &ValueFlowSummaryResult,
    solver_attempts: &[TypeFlowSolveAttempt],
) -> TypeFlowRootResult {
    let termination = result.result().termination();
    // A dynamic-write survey boundary is carried per slot: a write that
    // carries a reason affects every class, so `member_store_evidence` answers
    // `Unknown` wherever it could apply. It is not a property of this root and
    // must not decide completion.
    let complete = termination.is_fixed_point() && !plan.refinement_budget_exhausted();
    let value_flow_exhaustion = plan
        .value_flow()
        .public_semantic_status(result.result())
        .budget_exceeded();
    let semantic_budget_exhausted =
        plan.field_slot_semantic_budget_exhausted() || value_flow_exhaustion.is_some();
    // The lanes that stopped this root, kept typed so a consumer can name the
    // exact charge instead of re-running the solve under instrumentation.
    let mut lanes = Vec::new();
    match termination {
        SolverTermination::ExceededBudget(exceeded) => {
            lanes.push(RootExhaustedLane::Solver(exceeded));
        }
        SolverTermination::Cancelled => lanes.push(RootExhaustedLane::Cancelled),
        SolverTermination::FixedPoint => {}
    }
    if plan.field_slot_semantic_exhausted() {
        lanes.push(RootExhaustedLane::Semantic {
            stage: SemanticExhaustionStage::FieldSlotIndex,
            exceeded: plan.field_slot_semantic_exhaustion(),
        });
    }
    if plan.refinement_budget_exhausted() {
        lanes.push(RootExhaustedLane::Semantic {
            stage: SemanticExhaustionStage::PlanRefinement,
            exceeded: plan.refinement_exhaustion(),
        });
    }
    if let Some(exceeded) = value_flow_exhaustion {
        lanes.push(RootExhaustedLane::Semantic {
            stage: SemanticExhaustionStage::ValueFlowSolve,
            exceeded: Some(exceeded),
        });
    }
    debug_assert_eq!(
        lanes.is_empty(),
        complete && !semantic_budget_exhausted,
        "an incomplete or exhausted root must name at least one lane: {lanes:?}"
    );
    let mut class_sets = Vec::new();
    let mut findings = Vec::new();
    for (sink_id, _) in plan.value_flow().sinks() {
        let site = plan.sink(sink_id).clone();
        let mut set = match result.sink_outcome(sink_id) {
            ValueFlowSinkOutcome::Reached(meetings) => reached_class_set(
                workspace,
                adapter,
                field_slots,
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
                constructor_origin: None,
                exact_result_receiver_proven: false,
                member_declarations: Vec::new(),
                flow_unknown: Vec::new(),
                unknown: Vec::new(),
                dynamic_writes: Vec::new(),
                status: ClassSetStatus::NoInformation,
            },
            // An unreached sink under an incomplete root must name why; an
            // empty reason vector would read as a clean no-information
            // answer. `sink_outcome` gates `NotReached` on a complete result
            // today, so the `NotReached` half of this arm is the contract
            // holding the line if that gate ever widens.
            ValueFlowSinkOutcome::NotReached | ValueFlowSinkOutcome::Inconclusive => {
                let reason =
                    unreached_reason(plan, sink_id, termination, semantic_budget_exhausted);
                ReceiverClassSet {
                    site,
                    classes: Vec::new(),
                    constructor_origin: None,
                    exact_result_receiver_proven: false,
                    member_declarations: Vec::new(),
                    dynamic_writes: Vec::new(),
                    flow_unknown: vec![reason.clone()],
                    unknown: vec![reason],
                    status: ClassSetStatus::Inconclusive,
                }
            }
        };
        if plan.refinement_budget_exhausted() {
            push_reason(&mut set.unknown, UnknownReason::SemanticBudget);
            set.status = ClassSetStatus::Inconclusive;
        }
        class_sets.push(set);
    }
    if plan.refinement_budget_exhausted() {
        findings.clear();
    }
    let mut distinct_findings: Vec<AbsentMemberFinding> = Vec::new();
    for finding in findings {
        if let Some(existing) = distinct_findings.iter_mut().find(|existing| {
            existing.site.file == finding.site.file
                && existing.site.span == finding.site.span
                && existing.site.member == finding.site.member
                && existing.class == finding.class
        }) {
            prefer_retained_finding(existing, finding);
        } else {
            distinct_findings.push(finding);
        }
    }
    collapse_absent_member_findings(&mut distinct_findings);
    TypeFlowRootResult {
        root: root.clone(),
        class_sets,
        findings: distinct_findings,
        complete,
        solver_attempts: solver_attempts.to_vec(),
        semantic_budget_exhausted,
        persistence_status: TypeFlowRootPersistenceStatus::from_solve(
            complete,
            semantic_budget_exhausted,
            plan.provider_failure_observed(),
        ),
        incomplete_evidence: RootIncompleteEvidence {
            lanes,
            feedback_iteration: 0,
        },
        reusable_summary_hits: 0,
        reusable_summary_misses: 0,
        reusable_root_summary_hits: 0,
        reusable_root_summary_observation_rejections: 0,
        published_summaries: 0,
        summary_profile: TypeFlowSummaryProfile::default(),
    }
}

fn record_solver_attempt(
    attempts: &mut Vec<TypeFlowSolveAttempt>,
    phase: TypeFlowSolvePhase,
    result: &ValueFlowSummaryResult,
    work: SolverWork,
) -> usize {
    let index = attempts.len();
    attempts.push(TypeFlowSolveAttempt {
        phase,
        work,
        budget_exhaustion: result.result().termination().budget_exceeded(),
    });
    index
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

fn constructor_result_evidence(
    workspace: &WorkspaceAnalyzer,
    plan: &TypeFlowPlan,
    procedure: &ProcedureHandle,
    meetings: &[&ValueFlowMeeting],
) -> ConstructorResultEvidence {
    let has_constructor_origin = meetings.iter().any(|meeting| {
        plan.source_site(meeting.source()).kind == SourceSiteKind::ConstructorCall
            && !plan.class_source_is_open_bound(meeting.source())
    });
    if has_constructor_origin {
        let has_local_constructor_call = meetings.iter().any(|meeting| {
            let source = plan.source_site(meeting.source());
            source.kind == SourceSiteKind::ConstructorCall
                && !plan.class_source_is_open_bound(meeting.source())
                && procedure.semantics().call_sites().iter().any(|call| {
                    procedure
                        .semantics()
                        .source_mapping(call.source)
                        .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
                        .is_some_and(|mapping| {
                            mapping.locator.anchor().span() == source.span
                                && crate::analyzer::semantic::type_flow::file_for_locator(
                                    workspace,
                                    &mapping.locator,
                                )
                                .as_ref()
                                    == Some(&source.file)
                        })
                })
        });
        // A constructor source in a callee summary is not a direct constructor
        // result in this receiver's procedure. Leave its ordinary dispatch path
        // unchanged; constructor evidence must belong to this exact procedure.
        if !has_local_constructor_call {
            return ConstructorResultEvidence::None;
        }
        let Some(first) = meetings.first() else {
            return ConstructorResultEvidence::Ambiguous;
        };
        let source_id = first.source();
        let ClassAtom::Class(class) = plan.atom(source_id) else {
            return ConstructorResultEvidence::Ambiguous;
        };
        if plan.class_source_is_open_bound(source_id) {
            return ConstructorResultEvidence::Ambiguous;
        }
        let source = plan.source_site(source_id);
        // This is a constructor-identity candidate, not a claim that the flow
        // solver proved the local receiver path. Adapters must prove that path
        // from their binding facts before using this origin to close dispatch.
        // Keep an unproven but unambiguous same-source meeting as a candidate;
        // uncertain or mixed-origin meetings remain ambiguous here.
        if source.kind != SourceSiteKind::ConstructorCall
            || meetings.iter().any(|meeting| {
                meeting.source() != source_id
                    || meeting.is_uncertain()
                    || !matches!(plan.atom(meeting.source()), ClassAtom::Class(candidate) if candidate == class)
            })
        {
            return ConstructorResultEvidence::Ambiguous;
        }
        let calls = procedure
            .semantics()
            .call_sites()
            .iter()
            .filter(|call| {
                procedure
                    .semantics()
                    .source_mapping(call.source)
                    .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
                    .is_some_and(|mapping| {
                        mapping.locator.anchor().span() == source.span
                            && crate::analyzer::semantic::type_flow::file_for_locator(
                                workspace,
                                &mapping.locator,
                            )
                            .as_ref()
                                == Some(&source.file)
                    })
            })
            .collect::<Vec<_>>();
        let [call] = calls.as_slice() else {
            return ConstructorResultEvidence::Ambiguous;
        };
        let results = call.normal_result_values().collect::<Vec<_>>();
        let [result] = results.as_slice() else {
            return ConstructorResultEvidence::Ambiguous;
        };
        return ConstructorResultEvidence::Unique(ConstructorResultOrigin {
            classes: vec![class.clone()].into_boxed_slice(),
            producer: ExactResultProducer::Call(call.id),
            result: *result,
            source: source.clone(),
        });
    }

    let exact_call_meetings = meetings
        .iter()
        .copied()
        .filter(|meeting| {
            plan.source_site(meeting.source()).kind == SourceSiteKind::ExactCallResult
        })
        .collect::<Vec<_>>();
    if let Some(first_meeting) = exact_call_meetings.first() {
        let source = plan.source_site(first_meeting.source());
        if exact_call_meetings.iter().any(|meeting| {
            meeting.is_uncertain()
                || plan.source_site(meeting.source()) != source
                || !matches!(plan.atom(meeting.source()), ClassAtom::Class(_))
        }) {
            return ConstructorResultEvidence::Ambiguous;
        }
        let classes = exact_call_meetings
            .iter()
            .map(|meeting| match plan.atom(meeting.source()) {
                ClassAtom::Class(class) => class.clone(),
                ClassAtom::Unknown(_) => unreachable!("exact call meetings were checked"),
            })
            .collect::<Vec<_>>();
        let ClassSeed::Classes(classes) = ClassSeed::classes(classes) else {
            unreachable!("a source class meeting yields a non-empty class set")
        };
        let calls = procedure
            .semantics()
            .call_sites()
            .iter()
            .filter(|call| {
                procedure
                    .semantics()
                    .source_mapping(call.source)
                    .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
                    .is_some_and(|mapping| {
                        mapping.locator.anchor().span() == source.span
                            && crate::analyzer::semantic::type_flow::file_for_locator(
                                workspace,
                                &mapping.locator,
                            )
                            .as_ref()
                                == Some(&source.file)
                    })
            })
            .collect::<Vec<_>>();
        let [call] = calls.as_slice() else {
            return ConstructorResultEvidence::Ambiguous;
        };
        let results = call.normal_result_values().collect::<Vec<_>>();
        let [result] = results.as_slice() else {
            return ConstructorResultEvidence::Ambiguous;
        };
        return ConstructorResultEvidence::Unique(ConstructorResultOrigin {
            classes,
            producer: ExactResultProducer::Call(call.id),
            result: *result,
            source: source.clone(),
        });
    }

    let Some(first) = meetings.first() else {
        return ConstructorResultEvidence::None;
    };
    let source = plan.source_site(first.source());
    if source.kind != SourceSiteKind::ExactAccessResult {
        return ConstructorResultEvidence::None;
    }
    let mut classes = Vec::with_capacity(meetings.len());
    if meetings.iter().any(|meeting| {
        let meeting_source = plan.source_site(meeting.source());
        if meeting_source != source || meeting.is_uncertain() {
            return true;
        }
        match plan.atom(meeting.source()) {
            ClassAtom::Class(class) => {
                classes.push(class.clone());
                false
            }
            ClassAtom::Unknown(_) => true,
        }
    }) {
        return ConstructorResultEvidence::Ambiguous;
    }
    let ClassSeed::Classes(classes) = ClassSeed::classes(classes) else {
        unreachable!("an exact access meeting yields a non-empty class set")
    };
    let exact_source = |mapping_id| {
        procedure
            .semantics()
            .source_mapping(mapping_id)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
            .is_some_and(|mapping| {
                mapping.locator.anchor().span() == source.span
                    && crate::analyzer::semantic::type_flow::file_for_locator(
                        workspace,
                        &mapping.locator,
                    )
                    .as_ref()
                        == Some(&source.file)
            })
    };
    let loads = procedure
        .semantics()
        .points()
        .iter()
        .flat_map(|point| {
            point.events.iter().filter_map(|event| {
                let SemanticEffect::MemoryLoad {
                    location, result, ..
                } = event.effect
                else {
                    return None;
                };
                exact_source(event.source).then_some((point.id, location, result))
            })
        })
        .collect::<Vec<_>>();
    let [(point, location, result)] = loads.as_slice() else {
        return ConstructorResultEvidence::Ambiguous;
    };
    ConstructorResultEvidence::Unique(ConstructorResultOrigin {
        classes,
        producer: ExactResultProducer::MemoryLoad {
            point: *point,
            location: *location,
        },
        result: *result,
        source: source.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn reached_class_set(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    site: MemberAccessSite,
    plan: &TypeFlowPlan,
    result: &ValueFlowSummaryResult,
    meetings: &[&ValueFlowMeeting],
    root: &ProcedureHandle,
    findings: &mut Vec<AbsentMemberFinding>,
) -> ReceiverClassSet {
    let constructor = constructor_result_evidence(workspace, plan, &site.procedure, meetings);
    let constructor_origin = match &constructor {
        ConstructorResultEvidence::Unique(origin) => Some(origin.clone()),
        ConstructorResultEvidence::None | ConstructorResultEvidence::Ambiguous => None,
    };
    let exact_result_receiver_proven = if let Some(origin) = constructor_origin.as_ref()
        && matches!(
            origin.source.kind,
            SourceSiteKind::ExactCallResult | SourceSiteKind::ExactAccessResult
        )
        && let Some(call_id) = site.call
        && let Some(call) = site.procedure.semantics().call_site(call_id)
    {
        adapter.exact_result_receiver_is_stable(
            workspace,
            &site.procedure,
            site.receiver,
            call,
            origin,
        )
    } else {
        false
    };
    let exact_result_source = constructor_origin
        .as_ref()
        .filter(|_| exact_result_receiver_proven)
        .map(|origin| origin.source.clone());
    let effective_meetings = if let Some(source) = exact_result_source.as_ref() {
        meetings
            .iter()
            .copied()
            .filter(|meeting| {
                let candidate = plan.source_site(meeting.source());
                matches!(
                    candidate.kind,
                    SourceSiteKind::ExactCallResult | SourceSiteKind::ExactAccessResult
                ) && candidate.file == source.file
                    && candidate.span == source.span
            })
            .collect::<Vec<_>>()
    } else {
        meetings.to_vec()
    };
    // An exact callable-result claim proves the receiver's runtime class even
    // when its value-flow summary transfers actual values into the result.
    // Keep those transfers for data-flow consumers; ignore them here only
    // after the adapter proves the exact local receiver binding.
    // Each class alternative keeps whether any exact origin reached it;
    // identity deduplication must not erase an exact origin beside a bound.
    let mut classes: Vec<(ClassIdentity, SourceSite, bool)> = Vec::new();
    let mut class_meetings: Vec<&ValueFlowMeeting> = Vec::new();
    let mut member_declarations = Vec::new();
    let mut flow_unknown: Vec<UnknownReason> = Vec::new();
    let mut unknown: Vec<UnknownReason> = Vec::new();
    let mut dynamic_writes = Vec::new();
    for meeting in &effective_meetings {
        if meeting.is_uncertain() {
            push_reason(&mut unknown, UnknownReason::UncertainFlow);
            push_reason(&mut flow_unknown, UnknownReason::UncertainFlow);
        }
        match plan.atom(meeting.source()) {
            ClassAtom::Class(identity) => {
                let source_site = plan.source_site(meeting.source());
                let exact_origin = !plan.class_source_is_open_bound(meeting.source());
                if let Some(index) = classes
                    .iter()
                    .position(|(existing, _, _)| existing == identity)
                {
                    let existing_site = &classes[index].1;
                    let existing_has_exact_origin = classes[index].2;
                    let candidate_key = plan
                        .value_flow()
                        .source(meeting.source())
                        .expect("a meeting source belongs to the value-flow plan")
                        .key();
                    let existing_key = plan
                        .value_flow()
                        .source(class_meetings[index].source())
                        .expect("a retained meeting source belongs to the value-flow plan")
                        .key();
                    // Fact interning order differs between fresh propagation
                    // and bulk summary replay. Choose one stable representative
                    // origin per class independently of that order so class-set
                    // rows and finding witnesses remain exact. A guard arm
                    // proves a class without producing the value, so it yields
                    // to any site that did produce one.
                    let prefer_exact_origin = exact_origin && !existing_has_exact_origin;
                    let same_origin_quality = exact_origin == existing_has_exact_origin
                        && narrowing_guard_rank(source_site)
                            .cmp(&narrowing_guard_rank(existing_site))
                            .then_with(|| source_site.file.cmp(&existing_site.file))
                            .then_with(|| source_site.span.cmp(&existing_site.span))
                            .then_with(|| candidate_key.cmp(existing_key))
                            .is_lt();
                    classes[index].2 |= exact_origin;
                    if prefer_exact_origin || same_origin_quality {
                        classes[index].1 = source_site.clone();
                        class_meetings[index] = meeting;
                    }
                } else {
                    classes.push((identity.clone(), source_site.clone(), exact_origin));
                    class_meetings.push(meeting);
                }
            }
            ClassAtom::Unknown(reason) => {
                push_reason(&mut unknown, reason.clone());
                push_reason(&mut flow_unknown, reason.clone());
            }
        }
    }
    let mut ordered_classes = classes.into_iter().zip(class_meetings).collect::<Vec<_>>();
    ordered_classes
        .sort_unstable_by(|((left, _, _), _), ((right, _, _), _)| class_order(left, right));
    let (classes, class_meetings): (
        Vec<(ClassIdentity, SourceSite, bool)>,
        Vec<&ValueFlowMeeting>,
    ) = ordered_classes.into_iter().unzip();
    sort_unknown_reasons(&mut unknown);
    sort_unknown_reasons(&mut flow_unknown);
    let mut status = if !unknown.is_empty() {
        ClassSetStatus::Partial
    } else if classes.is_empty() {
        ClassSetStatus::NoInformation
    } else {
        ClassSetStatus::Known
    };
    if matches!(status, ClassSetStatus::Known | ClassSetStatus::Partial) {
        // Known atoms in a partial set may still contribute positive member
        // and dispatch evidence, but the open remainder prevents an Absent
        // result from authorizing a finding or an exhaustive dispatch hint.
        let complete_receiver_set = status == ClassSetStatus::Known;
        // Classes whose own lookup proves the member absent. A global Any
        // write may be carried as an explicit Conditional remainder; every
        // other write remains a blocker for that class.
        let mut absent: Vec<(
            usize,
            Vec<super::dynamic_stores::DynamicWriteEvidence>,
            bool,
        )> = Vec::new();
        let mut unbounded_dynamic_writes = Vec::new();
        let mut blocking_dynamic_write = false;
        let mut blocking_field_slot_incomplete = false;
        for (index, (identity, _, _)) in classes.iter().enumerate() {
            let lookup = if site.purpose == TypeFlowSitePurpose::PythonIteratorReturn {
                adapter.member_lookup(workspace, site.kind, identity, &site.member)
            } else if site.kind == MemberAccessKind::Call {
                let call_id = site
                    .call
                    .expect("a call-shaped member sink retains its call-site ID");
                let call = site
                    .procedure
                    .semantics()
                    .call_sites()
                    .iter()
                    .find(|call| call.id == call_id)
                    .expect("a member sink retains its call site");
                adapter.member_lookup_for_receiver(
                    workspace,
                    MemberReceiverQuery {
                        procedure: &site.procedure,
                        receiver: site.receiver,
                        call,
                        constructor: &constructor,
                        class: identity,
                        member: &site.member,
                    },
                )
            } else {
                adapter.member_lookup(workspace, site.kind, identity, &site.member)
            };
            let own_dynamic_writes = if matches!(lookup, MemberLookup::Present(_)) {
                Vec::new()
            } else {
                field_slots
                    .dynamic_write_evidence(workspace, adapter, identity, &site.member)
                    .cloned()
                    .collect::<Vec<_>>()
            };
            for evidence in &own_dynamic_writes {
                if !dynamic_writes.contains(evidence) {
                    dynamic_writes.push(evidence.clone());
                }
            }
            match lookup {
                MemberLookup::Present(hit) => {
                    member_declarations.push((identity.clone(), hit));
                }
                MemberLookup::DeclarationAbsent => {
                    match field_slots.member_store_evidence(
                        workspace,
                        adapter,
                        identity,
                        &site.member,
                    ) {
                        MemberStoreEvidence::NoStore if own_dynamic_writes.is_empty() => {
                            absent.push((index, Vec::new(), false));
                        }
                        MemberStoreEvidence::NoStore => {
                            if let Some(writes) = field_slots.unbounded_any_dynamic_write_evidence(
                                workspace,
                                adapter,
                                identity,
                                &site.member,
                            ) {
                                add_dynamic_write_evidence(&mut unbounded_dynamic_writes, &writes);
                                absent.push((index, writes, false));
                            } else {
                                blocking_dynamic_write = true;
                            }
                        }
                        MemberStoreEvidence::Stored if site.kind == MemberAccessKind::Load => {
                            blocking_dynamic_write |= !own_dynamic_writes.is_empty();
                        }
                        // A stored value is not a callable declaration. Keep the
                        // dispatch remainder open instead of inventing a target.
                        MemberStoreEvidence::Stored => {
                            blocking_dynamic_write |= !own_dynamic_writes.is_empty();
                        }
                        MemberStoreEvidence::Unknown => {
                            if let Some(writes) = field_slots
                                .member_store_unknown_only_from_unbounded_any_writes(
                                    workspace,
                                    adapter,
                                    identity,
                                    &site.member,
                                )
                            {
                                add_dynamic_write_evidence(&mut unbounded_dynamic_writes, &writes);
                                absent.push((index, writes, true));
                            } else {
                                blocking_field_slot_incomplete = true;
                                blocking_dynamic_write |= !own_dynamic_writes.is_empty();
                            }
                        }
                    }
                }
                MemberLookup::Absent if own_dynamic_writes.is_empty() => {
                    absent.push((index, Vec::new(), false));
                }
                MemberLookup::Absent => {
                    if let Some(writes) = field_slots.unbounded_any_dynamic_write_evidence(
                        workspace,
                        adapter,
                        identity,
                        &site.member,
                    ) {
                        add_dynamic_write_evidence(&mut unbounded_dynamic_writes, &writes);
                        absent.push((index, writes, false));
                    } else {
                        blocking_dynamic_write = true;
                    }
                }
                MemberLookup::Unknown(reason) => {
                    blocking_dynamic_write |= !own_dynamic_writes.is_empty();
                    push_reason(&mut unknown, reason);
                }
            }
        }
        if blocking_dynamic_write || !unbounded_dynamic_writes.is_empty() {
            push_reason(&mut unknown, UnknownReason::DynamicFieldWrite);
        }
        if blocking_field_slot_incomplete {
            push_reason(&mut unknown, UnknownReason::FieldSlotIncomplete);
        }
        if complete_receiver_set && unknown.is_empty() {
            if site.purpose == TypeFlowSitePurpose::MemberAccess {
                for (index, _, _) in absent {
                    let (identity, origin, has_exact_origin) = &classes[index];
                    if !has_exact_origin || origin.kind == SourceSiteKind::ConditionalNarrowingGuard
                    {
                        continue;
                    }
                    findings.push(AbsentMemberFinding {
                        root: root.clone(),
                        site: site.clone(),
                        class: identity.clone(),
                        origin: origin.clone(),
                        witness: best_witness(result, class_meetings[index]),
                        proof: AbsentMemberProof::Proven,
                        also_fails_at: Vec::new(),
                    });
                }
            }
        } else {
            debug_assert!(
                !unknown.is_empty(),
                "a set that is not complete names at least one remainder"
            );
            if complete_receiver_set {
                status = ClassSetStatus::Partial;
            }
            if unknown.iter().all(remainder_names_another_alternative) {
                let mut remainders = unknown.clone();
                sort_unknown_reasons(&mut remainders);
                if site.purpose == TypeFlowSitePurpose::MemberAccess {
                    for (index, unbounded_dynamic_writes, attributed_field_slot_incomplete) in
                        absent
                    {
                        let (identity, origin, has_exact_origin) = &classes[index];
                        // A guard-only origin does not admit the class as a value,
                        // and an uncertain meeting does not prove that it arrives.
                        let admitted_parameter_origin = origin.kind
                            == SourceSiteKind::DeclaredParameter
                            && adapter.declared_parameter_conditional_origin_is_closed(
                                workspace, identity, origin,
                            );
                        if !has_exact_origin
                            || (!conditional_origin_admits_class(origin.kind)
                                && !admitted_parameter_origin)
                            || class_meetings[index].is_uncertain()
                        {
                            continue;
                        }
                        let has_unattributed_surface_uncertainty = flow_unknown
                            .iter()
                            .filter(|reason| is_member_surface_uncertainty(reason))
                            .any(|reason| match reason {
                                UnknownReason::DynamicFieldWrite => {
                                    unbounded_dynamic_writes.is_empty()
                                }
                                // A value-flow atom does not retain enough provenance
                                // to tie its incomplete field slot to these writes.
                                UnknownReason::FieldSlotIncomplete => true,
                                _ => true,
                            });
                        if has_unattributed_surface_uncertainty {
                            continue;
                        }
                        let mut finding_remainders = remainders.clone();
                        if !unbounded_dynamic_writes.is_empty() {
                            if !blocking_dynamic_write {
                                finding_remainders
                                    .retain(|reason| *reason != UnknownReason::DynamicFieldWrite);
                            }
                            if attributed_field_slot_incomplete && !blocking_field_slot_incomplete {
                                finding_remainders
                                    .retain(|reason| *reason != UnknownReason::FieldSlotIncomplete);
                            }
                        }
                        sort_unknown_reasons(&mut finding_remainders);
                        findings.push(AbsentMemberFinding {
                            root: root.clone(),
                            site: site.clone(),
                            class: identity.clone(),
                            origin: origin.clone(),
                            witness: best_witness(result, class_meetings[index]),
                            proof: AbsentMemberProof::Conditional {
                                remainders: finding_remainders,
                                unbounded_dynamic_writes,
                            },
                            also_fails_at: Vec::new(),
                        });
                    }
                }
            }
        }
    }
    ReceiverClassSet {
        site,
        classes: classes
            .into_iter()
            .map(|(identity, origin, _)| (identity, origin))
            .collect(),
        constructor_origin,
        exact_result_receiver_proven,
        member_declarations,
        flow_unknown,
        unknown,
        dynamic_writes,
        status,
    }
}

fn add_dynamic_write_evidence(
    evidence: &mut Vec<super::dynamic_stores::DynamicWriteEvidence>,
    additions: &[super::dynamic_stores::DynamicWriteEvidence],
) {
    for addition in additions {
        if !evidence.contains(addition) {
            evidence.push(addition.clone());
        }
    }
    evidence.sort_unstable_by_key(super::dynamic_stores::DynamicWriteEvidence::origin);
}

/// Whether one reason in a partial receiver set still permits a Conditional
/// finding for a class whose own arrival, meeting, and member lookup are
/// clean. An allowed reason describes another value or class at the site, or
/// an explicitly attributed global dynamic write that may install the member.
/// A blocking reason can mean that this class should have been filtered out
/// on this path, or that the answer was cut short.
///
/// The member-lookup reasons (`UnresolvedBase`, `DynamicAttributes`,
/// `ClassCreation`, `FieldSlotIncomplete`, `DynamicFieldWrite`) are allowed
/// for another candidate class. A candidate's own write remains blocking
/// unless every matching effect is a global write with an Any name set and
/// every store-survey gap is attributable to those writes. When a member
/// uncertainty arrives as a value-flow atom, class attribution is unavailable
/// and the Conditional tier is suppressed for the whole set. `UncertainFlow`
/// is allowed because the caller separately requires the class's own
/// representative meeting to be certain.
fn remainder_names_another_alternative(reason: &UnknownReason) -> bool {
    match reason {
        UnknownReason::RootParameter
        | UnknownReason::VariadicParameter
        | UnknownReason::SelfReceiver
        | UnknownReason::UnresolvedCall
        | UnknownReason::AmbiguousCallee
        | UnknownReason::UnmodeledLoad
        | UnknownReason::Await
        | UnknownReason::Capture
        | UnknownReason::ExternalNotModeled
        | UnknownReason::PackIncomplete
        | UnknownReason::OpenTypeBound
        | UnknownReason::ScalarReceiver
        | UnknownReason::ClassObject
        | UnknownReason::UncertainFlow
        | UnknownReason::UnresolvedBase
        | UnknownReason::DynamicAttributes
        | UnknownReason::ClassCreation
        | UnknownReason::FieldSlotIncomplete
        | UnknownReason::DynamicFieldWrite => true,
        // The closure stopped at a size limit; paths past it are unexplored.
        UnknownReason::Truncated => false,
        // The solver stopped before a fixed point; the set is not final.
        UnknownReason::SolverBudget => false,
        // A semantic charge was refused; refinement or filtering may be missing.
        UnknownReason::SemanticBudget => false,
        // The root is incomplete for a reason its closure does not name.
        UnknownReason::IncompleteRoot => false,
        // An unmodeled guard may have filtered this class out on this path.
        UnknownReason::UnmodeledGuard { .. } => false,
        // An unmodeled predicate may have filtered this class out on this path.
        UnknownReason::UnmodeledPredicate => false,
    }
}

fn is_member_surface_uncertainty(reason: &UnknownReason) -> bool {
    matches!(
        reason,
        UnknownReason::UnresolvedBase
            | UnknownReason::DynamicAttributes
            | UnknownReason::ClassCreation
            | UnknownReason::FieldSlotIncomplete
            | UnknownReason::DynamicFieldWrite
    )
}

/// Whether this origin kind establishes that the class can be a runtime value.
fn conditional_origin_admits_class(kind: SourceSiteKind) -> bool {
    match kind {
        SourceSiteKind::ConstructorCall
        | SourceSiteKind::ExactCallResult
        | SourceSiteKind::ExactAccessResult
        | SourceSiteKind::Literal
        | SourceSiteKind::ContainerLiteral
        | SourceSiteKind::NarrowingGuard
        // Class-bearing Unknown origins are retained or computed runtime
        // values. Annotations and assumed receivers have explicit kinds.
        | SourceSiteKind::Unknown => true,
        SourceSiteKind::DeclaredParameter
        | SourceSiteKind::RootReceiver
        | SourceSiteKind::ConditionalNarrowingGuard => false,
    }
}

/// Orders a guard-proved origin after every origin that produced a value.
fn narrowing_guard_rank(site: &SourceSite) -> u8 {
    match site.kind {
        SourceSiteKind::ConditionalNarrowingGuard => 2,
        SourceSiteKind::NarrowingGuard => 1,
        _ => 0,
    }
}

/// The canonical order of a reason list: by family label, then by payload.
pub fn sort_unknown_reasons(reasons: &mut [UnknownReason]) {
    reasons.sort_unstable_by(|left, right| {
        left.label()
            .cmp(right.label())
            .then_with(|| left.cmp(right))
    });
}

fn push_reason(reasons: &mut Vec<UnknownReason>, reason: UnknownReason) {
    brokk_bifrost_core::util::push_if_absent(reasons, reason);
}

/// The witness at the best path quality the meeting retained.
fn best_witness(
    result: &ValueFlowSummaryResult,
    meeting: &ValueFlowMeeting,
) -> Result<SummaryWitness, SummaryWitnessError> {
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
    result.source_witness_for_meeting(meeting, quality, WitnessReconstructionLimits::default())
}

#[derive(Debug, Clone, Copy)]
struct ReceiverRead {
    binding: ValueId,
    point: ProgramPointId,
    event_index: usize,
}

fn is_binding_value(kind: &SemanticValueKind) -> bool {
    matches!(
        kind,
        SemanticValueKind::Local
            | SemanticValueKind::Parameter { .. }
            | SemanticValueKind::Receiver { .. }
    )
}

fn receiver_read(site: &MemberAccessSite) -> Option<ReceiverRead> {
    let semantics = site.procedure.semantics();
    let receiver = semantics.value(site.receiver)?;
    if is_binding_value(&receiver.kind) {
        return Some(ReceiverRead {
            binding: site.receiver,
            point: site.point.id(),
            event_index: usize::MAX,
        });
    }

    let mut read = None;
    for point in semantics.points() {
        for (event_index, event) in point.events.iter().enumerate() {
            let SemanticEffect::ValueFlow {
                kind,
                source,
                target,
            } = &event.effect
            else {
                continue;
            };
            if *target != site.receiver {
                continue;
            }
            if !matches!(
                kind,
                ValueFlowKind::Local | ValueFlowKind::Parameter | ValueFlowKind::Receiver
            ) {
                return None;
            }
            let source_value = semantics.value(*source)?;
            if !is_binding_value(&source_value.kind) {
                return None;
            }
            if read.is_some() {
                return None;
            }
            read = Some(ReceiverRead {
                binding: *source,
                point: point.id,
                event_index,
            });
        }
    }
    read
}

fn reaching_binding_definition(procedure: &ProcedureHandle, read: ReceiverRead) -> Option<usize> {
    let semantics = procedure.semantics();
    let binding = semantics.value(read.binding)?;
    let has_entry_definition = matches!(
        &binding.kind,
        SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
    );
    let mut event_definitions = HashMap::default();
    let initial_definition = has_entry_definition.then_some(0_usize);
    let mut next_definition = usize::from(has_entry_definition);
    for point in semantics.points() {
        for (event_index, event) in point.events.iter().enumerate() {
            if matches!(
                &event.effect,
                SemanticEffect::Assignment { target, .. } if *target == read.binding
            ) {
                event_definitions.insert((point.id, event_index), next_definition);
                next_definition += 1;
            }
        }
    }
    if next_definition == 0 {
        return None;
    }

    let mut facts = GenKillFacts::new(semantics.points().len(), next_definition);
    let all_definitions = 0..next_definition;
    for point in semantics.points() {
        let node_index = point.id.index();
        let mut last_definition = None;
        for (event_index, event) in point.events.iter().enumerate() {
            if matches!(
                &event.effect,
                SemanticEffect::Assignment { target, .. } if *target == read.binding
            ) {
                last_definition = event_definitions.get(&(point.id, event_index)).copied();
            }
        }
        if let Some(definition) = last_definition {
            for killed in all_definitions.clone() {
                facts.record_killed(node_index, killed);
            }
            facts.record_generated(node_index, definition);
        } else if point.id == semantics.entry_point()
            && let Some(definition) = initial_definition
        {
            facts.record_generated(node_index, definition);
        }
    }

    let cancellation = CancellationToken::default();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
    let reaching =
        reaching_definitions(semantics, semantics.entry_point(), &facts, &mut request).ok()?;
    let mut definitions = reaching.reaching_in(read.point.index()).collect::<Vec<_>>();
    if read.point == semantics.entry_point()
        && let Some(definition) = initial_definition
    {
        definitions.push(definition);
    }
    let point = semantics.point(read.point)?;
    if read.event_index == usize::MAX
        && point.events.iter().any(|event| {
            matches!(
                &event.effect,
                SemanticEffect::Assignment { target, .. } if *target == read.binding
            )
        })
    {
        return None;
    }
    for event_index in 0..read.event_index.min(point.events.len()) {
        if let Some(definition) = event_definitions.get(&(read.point, event_index)).copied() {
            definitions.clear();
            definitions.push(definition);
        }
    }
    (definitions.len() == 1).then(|| definitions[0])
}

fn reaches_any(
    procedure: &ProcedureHandle,
    starts: impl IntoIterator<Item = ProgramPointId>,
    target: ProgramPointId,
) -> bool {
    let semantics = procedure.semantics();
    let mut reached = vec![false; semantics.points().len()];
    let mut pending = VecDeque::new();
    for start in starts {
        if !reached[start.index()] {
            reached[start.index()] = true;
            pending.push_back(start);
        }
    }
    while let Some(point) = pending.pop_front() {
        if point == target {
            return true;
        }
        for (_, edge) in semantics.successor_edges(point) {
            if !reached[edge.target_point.index()] {
                reached[edge.target_point.index()] = true;
                pending.push_back(edge.target_point);
            }
        }
    }
    false
}

fn normal_completion_dominates(first: &MemberAccessSite, later: &MemberAccessSite) -> bool {
    if first.point.id() == later.point.id() {
        return false;
    }
    let semantics = first.procedure.semantics();
    let first_point = first.point.id();
    let later_point = later.point.id();
    let cancellation = CancellationToken::default();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
    let Ok(dominators) = dominators(semantics, semantics.entry_point(), &mut request) else {
        return false;
    };
    if !dominators.dominates(semantics, first_point, later_point) {
        return false;
    }

    let mut normal_successors = Vec::new();
    let mut exceptional_successors = Vec::new();
    for (_, edge) in semantics.successor_edges(first_point) {
        match edge.kind {
            ControlEdgeKind::Exceptional
            | ControlEdgeKind::AsyncExceptional
            | ControlEdgeKind::Cleanup => exceptional_successors.push(edge.target_point),
            _ => normal_successors.push(edge.target_point),
        }
    }
    !normal_successors.is_empty()
        && reaches_any(&first.procedure, normal_successors, later_point)
        && !reaches_any(&first.procedure, exceptional_successors, later_point)
}

fn findings_can_collapse(first: &AbsentMemberFinding, later: &AbsentMemberFinding) -> bool {
    if first.class != later.class
        || first.origin != later.origin
        || first.proof.is_proven() != later.proof.is_proven()
        || first.site.procedure.durable_key() != later.site.procedure.durable_key()
    {
        return false;
    }
    let Some(first_read) = receiver_read(&first.site) else {
        return false;
    };
    let Some(later_read) = receiver_read(&later.site) else {
        return false;
    };
    if first_read.binding != later_read.binding {
        return false;
    }
    let Some(first_definition) = reaching_binding_definition(&first.site.procedure, first_read)
    else {
        return false;
    };
    let Some(later_definition) = reaching_binding_definition(&later.site.procedure, later_read)
    else {
        return false;
    };
    first_definition == later_definition && normal_completion_dominates(&first.site, &later.site)
}

fn compare_finding_order(
    first: &AbsentMemberFinding,
    second: &AbsentMemberFinding,
) -> std::cmp::Ordering {
    first
        .site
        .file
        .cmp(&second.site.file)
        .then_with(|| first.site.span.cmp(&second.site.span))
        .then_with(|| first.site.member.cmp(&second.site.member))
        .then_with(|| {
            first
                .class
                .qualified_name()
                .cmp(second.class.qualified_name())
        })
        .then_with(|| match (&first.class, &second.class) {
            (ClassIdentity::Workspace(first), ClassIdentity::Workspace(second)) => {
                first.declaration_id().cmp(&second.declaration_id())
            }
            (
                ClassIdentity::External {
                    symbol_id: first, ..
                },
                ClassIdentity::External {
                    symbol_id: second, ..
                },
            ) => first.cmp(second),
            (
                ClassIdentity::Workspace(_),
                ClassIdentity::External { .. } | ClassIdentity::Intrinsic { .. },
            ) => std::cmp::Ordering::Less,
            (
                ClassIdentity::External { .. } | ClassIdentity::Intrinsic { .. },
                ClassIdentity::Workspace(_),
            ) => std::cmp::Ordering::Greater,
            (ClassIdentity::External { .. }, ClassIdentity::Intrinsic { .. }) => {
                std::cmp::Ordering::Less
            }
            (ClassIdentity::Intrinsic { .. }, ClassIdentity::External { .. }) => {
                std::cmp::Ordering::Greater
            }
            (
                ClassIdentity::Intrinsic {
                    qualified_name: first,
                },
                ClassIdentity::Intrinsic {
                    qualified_name: second,
                },
            ) => first.cmp(second),
        })
        .then_with(|| first.origin.file.cmp(&second.origin.file))
        .then_with(|| first.origin.span.cmp(&second.origin.span))
        .then_with(|| first.proof.is_proven().cmp(&second.proof.is_proven()))
}

fn sort_additional_sites(finding: &mut AbsentMemberFinding) {
    finding.also_fails_at.sort_unstable();
    finding.also_fails_at.dedup();
}

/// Fold later findings into the first finding only after proving the same
/// receiver definition and normal-completion dominance within one procedure.
pub(super) fn collapse_absent_member_findings(findings: &mut Vec<AbsentMemberFinding>) {
    findings.sort_by(compare_finding_order);
    let mut retained: Vec<AbsentMemberFinding> = Vec::with_capacity(findings.len());
    for mut candidate in findings.drain(..) {
        sort_additional_sites(&mut candidate);
        let duplicate = retained
            .iter()
            .position(|existing| findings_can_collapse(existing, &candidate));
        if let Some(index) = duplicate {
            let existing = &mut retained[index];
            existing
                .also_fails_at
                .push((candidate.site.file.clone(), candidate.site.span));
            existing.also_fails_at.append(&mut candidate.also_fails_at);
            sort_additional_sites(existing);
        } else {
            retained.push(candidate);
        }
    }
    *findings = retained;
}

/// Keep the stronger of two duplicate findings: a Proven finding replaces a
/// Conditional one, and within one tier the finding whose witness was
/// retained replaces one whose witness is unavailable.
pub(super) fn prefer_retained_finding(
    existing: &mut AbsentMemberFinding,
    candidate: AbsentMemberFinding,
) {
    let stronger = candidate.proof.is_proven() && !existing.proof.is_proven();
    let same_tier = candidate.proof.is_proven() == existing.proof.is_proven();
    let merged_conditional_proof = match (&existing.proof, &candidate.proof) {
        (
            AbsentMemberProof::Conditional {
                remainders,
                unbounded_dynamic_writes,
            },
            AbsentMemberProof::Conditional {
                remainders: candidate_remainders,
                unbounded_dynamic_writes: candidate_writes,
            },
        ) => {
            let mut merged_remainders = remainders.clone();
            for reason in candidate_remainders {
                if !merged_remainders.contains(reason) {
                    merged_remainders.push(reason.clone());
                }
            }
            sort_unknown_reasons(&mut merged_remainders);
            let mut merged_writes = unbounded_dynamic_writes.clone();
            add_dynamic_write_evidence(&mut merged_writes, candidate_writes);
            Some(AbsentMemberProof::Conditional {
                remainders: merged_remainders,
                unbounded_dynamic_writes: merged_writes,
            })
        }
        _ => None,
    };
    if stronger {
        *existing = candidate;
    } else if same_tier {
        existing
            .also_fails_at
            .extend(candidate.also_fails_at.iter().cloned());
        sort_additional_sites(existing);
        if existing.witness.is_err() && candidate.witness.is_ok() {
            let also_fails_at = std::mem::take(&mut existing.also_fails_at);
            *existing = candidate;
            existing.also_fails_at = also_fails_at;
        }
        if let Some(proof) = merged_conditional_proof {
            existing.proof = proof;
        }
    }
}

#[cfg(test)]
mod retry_tests {
    use super::{
        ClassSetStatus, TypeFlowRootPersistenceRejection, TypeFlowRootPersistenceStatus,
        TypeFlowRootPersistenceTracker, dispatch_hints_exhaustive,
    };
    use crate::analyzer::semantic::{
        CandidateCoverage, ClassIdentity, ExternalMemberDeclaration, MemberDeclaration,
        MemberLookupHit,
    };
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "dd9df356894c: The open-bound feedback fix in dd9df356894c pins that an exact class with open member evidence cannot close dispatch."
    )]
    fn exact_receiver_with_open_member_hit_cannot_claim_exhaustive_dispatch() {
        let class = ClassIdentity::External {
            qualified_name: "pkg.Widget".into(),
            symbol_id: "class-widget".into(),
        };
        let declaration =
            MemberDeclaration::External(ExternalMemberDeclaration::new([Box::from("method-run")]));
        let declarations = [(
            class,
            MemberLookupHit::new(declaration, CandidateCoverage::Open),
        )];

        assert!(!dispatch_hints_exhaustive(
            &declarations,
            1,
            ClassSetStatus::Known
        ));
    }

    #[test]
    #[hardwon(
        "#3134: fixed resolved dispatch with complete receiver feedback; every receiver class must have a declaration."
    )]
    fn every_receiver_class_needs_a_dispatch_declaration() {
        let declaration =
            MemberDeclaration::External(ExternalMemberDeclaration::new([Box::from("method-run")]));
        let declarations = [(
            ClassIdentity::External {
                qualified_name: "pkg.Widget".into(),
                symbol_id: "class-widget".into(),
            },
            MemberLookupHit::new(declaration, CandidateCoverage::Exhaustive),
        )];
        assert!(dispatch_hints_exhaustive(
            &declarations,
            1,
            ClassSetStatus::Known
        ));
        assert!(!dispatch_hints_exhaustive(
            &declarations,
            2,
            ClassSetStatus::Known
        ));
        assert!(!dispatch_hints_exhaustive(&[], 0, ClassSetStatus::Known));
    }

    #[test]
    #[hardwon(
        "9d635b5199ca: fixed partial class-set dispatch; a positive exhaustive hit cannot close incomplete receiver coverage."
    )]
    fn partial_receiver_with_exhaustive_positive_hit_cannot_close_dispatch() {
        let class = ClassIdentity::External {
            qualified_name: "pkg.Widget".into(),
            symbol_id: "class-widget".into(),
        };
        let declaration =
            MemberDeclaration::External(ExternalMemberDeclaration::new([Box::from("method-run")]));
        let declarations = [(
            class,
            MemberLookupHit::new(declaration, CandidateCoverage::Exhaustive),
        )];

        assert!(!dispatch_hints_exhaustive(
            &declarations,
            1,
            ClassSetStatus::Partial
        ));
    }

    #[test]
    fn provider_persistence_rejection_is_sticky_across_feedback_and_retries() {
        let mut persistence = TypeFlowRootPersistenceTracker::default();
        assert_eq!(
            persistence.status(true, false),
            TypeFlowRootPersistenceStatus::Eligible
        );

        persistence.observe_provider_failure(true);
        persistence.observe_provider_failure(false);

        assert_eq!(
            persistence.status(true, false),
            TypeFlowRootPersistenceStatus::Ineligible(
                TypeFlowRootPersistenceRejection::ProviderFailure
            ),
            "a later successful pass cannot erase an earlier transient provider failure"
        );
    }
}

#[test]
fn persistence_status_preserves_stable_opens_and_rejects_transient_work() {
    assert_eq!(
        TypeFlowRootPersistenceStatus::from_solve(true, false, false),
        TypeFlowRootPersistenceStatus::Eligible,
        "a fixed point may retain stable open boundaries in its rows"
    );
    assert_eq!(
        TypeFlowRootPersistenceStatus::from_solve(true, false, true),
        TypeFlowRootPersistenceStatus::Ineligible(
            TypeFlowRootPersistenceRejection::ProviderFailure
        )
    );
    assert_eq!(
        TypeFlowRootPersistenceStatus::from_solve(true, true, false),
        TypeFlowRootPersistenceStatus::Ineligible(TypeFlowRootPersistenceRejection::SemanticBudget)
    );
    assert_eq!(
        TypeFlowRootPersistenceStatus::from_solve(false, false, false),
        TypeFlowRootPersistenceStatus::Ineligible(
            TypeFlowRootPersistenceRejection::SolverIncomplete
        )
    );
    assert_eq!(
        TypeFlowRootResult::feedback_fallback_status(),
        TypeFlowRootPersistenceStatus::Ineligible(
            TypeFlowRootPersistenceRejection::FeedbackFallback
        )
    );
}
