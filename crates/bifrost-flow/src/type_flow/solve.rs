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

use crate::analyzer::semantic::{
    CandidateCoverage, ClassAtom, ClassIdentity, DispatchHint, DispatchHintCallSiteKey,
    DispatchHintSet, DispatchHints, IcfgProvider, MemberAccessKind, MemberLookup, MemberLookupHit,
    ProcedureHandle, SemanticBudget, SourceSite, TypeFlowAdapter, UnknownReason,
    WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{AnalyzerQueryScope, WorkspaceAnalyzer};
use crate::dataflow::{
    DataflowRequest, PathQuality, SolverTermination, SummaryWitness, SummaryWitnessError,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use crate::hash::HashSet;
use crate::value_flow::{
    ClosureLimits, DurableProcedureKey, ValueFlowCache, ValueFlowCarrier, ValueFlowMeeting,
    ValueFlowSinkId, ValueFlowSinkOutcome, ValueFlowSolveError, ValueFlowSummaryResult,
    WorkspaceValueFlowProvider, solve_value_flow_with_reusable_summaries,
    solve_value_flow_with_summaries, solve_value_flow_with_witnesses,
};

use super::FieldSlotIndex;
use super::field_slots::{MemberStoreEvidence, class_order};
use super::plan::{
    MemberAccessSite, ProcedureRefinements, TypeFlowPlan, TypeFlowPlanError, uncovered_reason,
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

/// The classes and Unknown reasons that reached one member access under one
/// root, plus the status a consumer may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverClassSet {
    pub site: MemberAccessSite,
    pub classes: Vec<(ClassIdentity, SourceSite)>,
    /// Exact declarations that proved a class in `classes` has this member.
    /// Retained so feedback consumes the same lookup verdict that authorized
    /// the Known set instead of repeating a language query.
    pub member_declarations: Vec<(ClassIdentity, MemberLookupHit)>,
    pub unknown: Vec<UnknownReason>,
    pub dynamic_writes: Vec<super::dynamic_stores::DynamicWriteEvidence>,
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
    /// The independently reconstructed evidence for this Proven finding.
    ///
    /// A retention-truncated marker is an `Ok` witness with an explicit
    /// truncation cause. An `Err` preserves why evidence could not be
    /// reconstructed without weakening the finding's class-set proof.
    pub witness: Result<SummaryWitness, SummaryWitnessError>,
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
    fn mark_feedback_fallback(&mut self) {
        self.persistence_status = Self::feedback_fallback_status();
    }

    const fn feedback_fallback_status() -> TypeFlowRootPersistenceStatus {
        TypeFlowRootPersistenceStatus::Ineligible(
            TypeFlowRootPersistenceRejection::FeedbackFallback,
        )
    }
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
    /// Engine-owned durable-publication gate. Stable typed open boundaries
    /// remain eligible; transient provider failures, resource exhaustion,
    /// incomplete solves, and feedback fallback do not.
    pub persistence_status: TypeFlowRootPersistenceStatus,
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
    let _semantic_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        active_semantic_model_snapshot.clone(),
    );
    let _cancellation_scope =
        AnalyzerQueryScope::with_cancellation(workspace.analyzer(), request.cancellation);
    let mut dispatch_hints = DispatchHints::empty();
    let mut previous: Option<TypeFlowRootResult> = None;
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
    // Every plan attempt in this solve rederives the same procedure-local
    // refinements. Hold them across attempts so the work is performed once.
    let mut refinements = ProcedureRefinements::default();
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
        let (plan, mut interpreted, iteration_budget, maintenance, publication_writes) = 'plan_attempt: loop {
            let solver_budget_before_attempt = request.budget.clone();
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
                    &mut refinements,
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
                    &mut refinements,
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
            if plan.needs_source_refinement() && !plan.refinement_budget_exhausted() {
                if plan.has_summary_cuts() {
                    *semantic_budget = iteration_budget;
                    require_full_plan = true;
                    continue 'plan_attempt;
                }
                loop {
                    // Collect complete may-source evidence before deriving any
                    // exclusions. This trial never publishes reusable summaries.
                    let preliminary = solve_value_flow_with_summaries(
                        root,
                        &provider,
                        plan.value_flow(),
                        &mut iteration_budget,
                        request,
                    )?;
                    let preliminary_status =
                        interpret(workspace, adapter, field_slots, root, &plan, &preliminary);
                    if !preliminary_status.complete || preliminary_status.semantic_budget_exhausted
                    {
                        if preliminary_status.semantic_budget_exhausted {
                            plan.mark_refinement_budget_exhausted();
                        }
                        let interpreted =
                            interpret(workspace, adapter, field_slots, root, &plan, &preliminary);
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
                        Ok(false) => break,
                        Ok(true) => {}
                        Err(TypeFlowPlanError::RefinementBudget(_)) => {
                            plan.mark_refinement_budget_exhausted();
                            break;
                        }
                        Err(error) => {
                            *semantic_budget = iteration_budget;
                            return Err(error.into());
                        }
                    }
                    if request.cancellation.is_cancelled() {
                        return Err(TypeFlowPlanError::Cancelled.into());
                    }
                }
            }
            if plan.refinement_budget_exhausted() {
                let result = solve_value_flow_with_summaries(
                    root,
                    &provider,
                    plan.value_flow(),
                    &mut iteration_budget,
                    request,
                )?;
                let interpreted = interpret(workspace, adapter, field_slots, root, &plan, &result);
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
            let mut maintenance_solver_budget = request.budget.clone();
            let mut maintenance_request =
                DataflowRequest::new(&mut maintenance_solver_budget, request.cancellation)
                    .with_query_plan_config(request.query_plan_config());
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
            *request.budget = maintenance_solver_budget;
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
            if summaries.has_reusable_rows() {
                // Reusable rows currently retain reachability and path quality,
                // not witness fragments. Run the cheap symbolic trial without a
                // witness sidecar. If it produces a finding, run the exact
                // witness-producing path and discard the trial's staged solver
                // budget unless it retained shared summary state. Keep its
                // semantic charge because that path observes the provider cache
                // it warmed. Otherwise no consumer can observe the missing
                // sidecar, so commit the trial.
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
                    )
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
                        if trial_publication_writes {
                            *request.budget = trial_solver_budget;
                        }
                        prepare_plan_retry(
                            summaries.retained_maintenance_writes() || trial_publication_writes,
                            &solver_budget_before_attempt,
                            request.budget,
                        );
                        summary_profile = summary_profile.saturating_add(summaries.profile());
                        root_summary_observation_rejections = root_summary_observation_rejections
                            .saturating_add(summaries.root_observation_rejections());
                        continue 'plan_attempt;
                    }
                    Err(error) => {
                        if trial_publication_writes {
                            *semantic_budget = trial_semantic_budget;
                            *request.budget = trial_solver_budget;
                        }
                        return Err(error.into());
                    }
                };
                if trial_publication_writes {
                    *semantic_budget = trial_semantic_budget.clone();
                    *request.budget = trial_request.budget.clone();
                }
                let metrics = trial_result.result().metrics();
                let trial_interpreted =
                    interpret(workspace, adapter, field_slots, root, &plan, &trial_result);
                if metrics.reusable_summary_hits > 0 && trial_interpreted.findings.is_empty() {
                    iteration_budget = trial_semantic_budget;
                    interpreted = trial_interpreted;
                    interpreted.reusable_summary_hits = metrics.reusable_summary_hits;
                    interpreted.reusable_summary_misses = metrics.reusable_summary_misses;
                    interpreted.reusable_root_summary_hits = metrics.reusable_root_summary_hits;
                    interpreted.reusable_root_summary_observation_rejections =
                        summaries.root_observation_rejections();
                    interpreted.published_summaries =
                        summaries.publish_complete(&trial_result, &mut trial_request);
                    *request.budget = trial_solver_budget;
                } else {
                    if plan.has_summary_cuts() {
                        // The witnessless trial can warm shared semantic cache
                        // entries before a finding requires a fresh full plan.
                        *semantic_budget = trial_semantic_budget;
                        prepare_plan_retry(
                            summaries.retained_maintenance_writes() || trial_publication_writes,
                            &solver_budget_before_attempt,
                            request.budget,
                        );
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
                    let result = {
                        let _scope = profiling::scope("type_flow.solve");
                        let result = solve_value_flow_with_witnesses(
                            root,
                            &provider,
                            plan.value_flow(),
                            WitnessRetentionLimits::new(1)
                                .expect("one alternative is a valid witness retention limit"),
                            &mut iteration_budget,
                            request,
                        );
                        result?
                    };
                    interpreted = interpret(workspace, adapter, field_slots, root, &plan, &result);
                    interpreted.reusable_summary_hits = metrics.reusable_summary_hits;
                    interpreted.reusable_summary_misses = metrics.reusable_summary_misses;
                    interpreted.reusable_root_summary_hits = metrics.reusable_root_summary_hits;
                    interpreted.reusable_root_summary_observation_rejections =
                        summaries.root_observation_rejections();
                    interpreted.published_summaries = summaries.publish_complete(&result, request);
                }
            } else {
                if plan.has_summary_cuts() {
                    // Planning an unusable cut can still publish complete
                    // semantic/value-flow cache entries consumed by retry.
                    *semantic_budget = iteration_budget;
                    prepare_plan_retry(
                        summaries.retained_maintenance_writes(),
                        &solver_budget_before_attempt,
                        request.budget,
                    );
                    require_full_plan = true;
                    summary_profile = summary_profile.saturating_add(summaries.profile());
                    root_summary_observation_rejections = root_summary_observation_rejections
                        .saturating_add(summaries.root_observation_rejections());
                    continue 'plan_attempt;
                }
                let result = {
                    let _scope = profiling::scope("type_flow.solve");
                    let result = solve_value_flow_with_witnesses(
                        root,
                        &provider,
                        plan.value_flow(),
                        WitnessRetentionLimits::new(1)
                            .expect("one alternative is a valid witness retention limit"),
                        &mut iteration_budget,
                        request,
                    );
                    result?
                };
                interpreted = interpret(workspace, adapter, field_slots, root, &plan, &result);
                interpreted.published_summaries = summaries.publish_complete(&result, request);
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
        if interpreted.semantic_budget_exhausted || !interpreted.complete {
            if let Some(mut previous) = previous {
                if publication_writes {
                    // The returned result comes from an earlier feedback pass,
                    // but this pass published cache state that later queries
                    // can observe. Retain the work that produced those writes.
                    *semantic_budget = iteration_budget;
                }
                previous.summary_profile = summary_profile;
                previous.reusable_root_summary_observation_rejections =
                    root_summary_observation_rejections;
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
        previous = Some(interpreted);
        dispatch_hints = next_hints;
    }
    unreachable!("FeedbackLimits requires at least one iteration")
}

fn prepare_plan_retry(
    retained_writes: bool,
    before_attempt: &crate::dataflow::SolverBudget,
    current: &mut crate::dataflow::SolverBudget,
) {
    if !retained_writes {
        *current = before_attempt.clone();
    }
}

fn dispatch_hint_updates(plan: &TypeFlowPlan, result: &TypeFlowRootResult) -> Vec<DispatchHintSet> {
    let mut updates = Vec::new();
    for set in &result.class_sets {
        if !matches!(set.status, ClassSetStatus::Known | ClassSetStatus::Partial)
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
        let (exhaustive, singleton) = dispatch_hint_flags(
            &set.member_declarations,
            set.classes.len(),
            set.status == ClassSetStatus::Known,
        );
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
            singleton,
        ));
    }
    updates
}

fn dispatch_hint_flags(
    declarations: &[(ClassIdentity, MemberLookupHit)],
    receiver_class_count: usize,
    receiver_set_complete: bool,
) -> (bool, bool) {
    let exhaustive = receiver_set_complete
        && receiver_class_count > 0
        && declarations.len() == receiver_class_count
        && declarations
            .iter()
            .all(|(_, hit)| hit.dispatch_coverage == CandidateCoverage::Exhaustive);
    (exhaustive, exhaustive && receiver_class_count == 1)
}

fn interpret(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    root: &ProcedureHandle,
    plan: &TypeFlowPlan,
    result: &ValueFlowSummaryResult,
) -> TypeFlowRootResult {
    let termination = result.result().termination();
    // A dynamic-write survey boundary is carried per slot: a write that
    // carries a reason affects every class, so `member_store_evidence` answers
    // `Unknown` wherever it could apply. It is not a property of this root and
    // must not decide completion.
    let complete = termination.is_fixed_point() && !plan.refinement_budget_exhausted();
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
                member_declarations: Vec::new(),
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
                ReceiverClassSet {
                    site,
                    classes: Vec::new(),
                    member_declarations: Vec::new(),
                    dynamic_writes: Vec::new(),
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
    TypeFlowRootResult {
        root: root.clone(),
        class_sets,
        findings: distinct_findings,
        complete,
        semantic_budget_exhausted,
        persistence_status: TypeFlowRootPersistenceStatus::from_solve(
            complete,
            semantic_budget_exhausted,
            plan.provider_failure_observed(),
        ),
        reusable_summary_hits: 0,
        reusable_summary_misses: 0,
        reusable_root_summary_hits: 0,
        reusable_root_summary_observation_rejections: 0,
        published_summaries: 0,
        summary_profile: TypeFlowSummaryProfile::default(),
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
    field_slots: &FieldSlotIndex,
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
    let mut dynamic_writes = Vec::new();
    for meeting in meetings {
        if meeting.is_uncertain() {
            push_reason(&mut unknown, UnknownReason::UncertainFlow);
        }
        match plan.atom(meeting.source()) {
            ClassAtom::Class(identity) => {
                let source_site = plan.source_site(meeting.source());
                if let Some(index) = classes
                    .iter()
                    .position(|(existing, _)| existing == identity)
                {
                    let existing_site = &classes[index].1;
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
                    // rows and finding witnesses remain exact.
                    if source_site
                        .file
                        .cmp(&existing_site.file)
                        .then_with(|| source_site.span.cmp(&existing_site.span))
                        .then_with(|| candidate_key.cmp(existing_key))
                        .is_lt()
                    {
                        classes[index].1 = source_site.clone();
                        class_meetings[index] = meeting;
                    }
                } else {
                    classes.push((identity.clone(), source_site.clone()));
                    class_meetings.push(meeting);
                }
            }
            ClassAtom::Unknown(reason) => push_reason(&mut unknown, reason.clone()),
        }
    }
    let mut ordered_classes = classes.into_iter().zip(class_meetings).collect::<Vec<_>>();
    ordered_classes.sort_unstable_by(|((left, _), _), ((right, _), _)| class_order(left, right));
    let (classes, class_meetings): (Vec<(ClassIdentity, SourceSite)>, Vec<&ValueFlowMeeting>) =
        ordered_classes.into_iter().unzip();
    unknown.sort_unstable_by(|left, right| {
        left.label()
            .cmp(right.label())
            .then_with(|| left.cmp(right))
    });
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
        let mut absent: Vec<usize> = Vec::new();
        for (index, (identity, _)) in classes.iter().enumerate() {
            let lookup = adapter.member_lookup(workspace, site.kind, identity, &site.member);
            if matches!(
                lookup,
                MemberLookup::Absent | MemberLookup::DeclarationAbsent
            ) {
                for evidence in field_slots.dynamic_write_evidence(identity) {
                    if !dynamic_writes.contains(evidence) {
                        dynamic_writes.push(evidence.clone());
                    }
                }
                if !dynamic_writes.is_empty() {
                    push_reason(&mut unknown, UnknownReason::DynamicFieldWrite);
                }
            }
            match lookup {
                MemberLookup::Present(hit) => {
                    member_declarations.push((identity.clone(), hit));
                }
                MemberLookup::DeclarationAbsent => match field_slots.member_store_evidence(
                    workspace,
                    adapter,
                    identity,
                    &site.member,
                ) {
                    MemberStoreEvidence::NoStore if complete_receiver_set => absent.push(index),
                    MemberStoreEvidence::NoStore => {}
                    MemberStoreEvidence::Stored if site.kind == MemberAccessKind::Load => {}
                    // A stored value is not a callable declaration. Keep the
                    // dispatch remainder open instead of inventing a target.
                    MemberStoreEvidence::Stored | MemberStoreEvidence::Unknown => {
                        push_reason(&mut unknown, UnknownReason::FieldSlotIncomplete)
                    }
                },
                MemberLookup::Absent if complete_receiver_set => absent.push(index),
                MemberLookup::Absent => {}
                MemberLookup::Unknown(reason) => push_reason(&mut unknown, reason),
            }
        }
        if complete_receiver_set && unknown.is_empty() {
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
        } else if complete_receiver_set {
            status = ClassSetStatus::Partial;
        }
    }
    ReceiverClassSet {
        site,
        classes,
        member_declarations,
        unknown,
        dynamic_writes,
        status,
    }
}

fn push_reason(reasons: &mut Vec<UnknownReason>, reason: UnknownReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
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

/// Keep the complete finding whose witness was retained when duplicate
/// interpretations disagree only about witness availability.
pub(super) fn prefer_retained_finding(
    existing: &mut AbsentMemberFinding,
    candidate: AbsentMemberFinding,
) {
    if existing.witness.is_err() && candidate.witness.is_ok() {
        *existing = candidate;
    }
}

#[cfg(test)]
mod retry_tests {
    use super::{
        TypeFlowRootPersistenceRejection, TypeFlowRootPersistenceStatus,
        TypeFlowRootPersistenceTracker, TypeFlowRootResult, dispatch_hint_flags,
        prepare_plan_retry,
    };
    use crate::analyzer::semantic::{
        CandidateCoverage, ClassIdentity, ExternalMemberDeclaration, MemberDeclaration,
        MemberLookupHit,
    };
    use crate::dataflow::{SolverBudget, SolverWork};

    #[test]
    fn retained_maintenance_work_stays_charged_across_a_plan_retry() {
        let before = SolverBudget::default();
        let mut charged = before.clone();
        charged
            .charge(SolverWork {
                summary_applications: 3,
                flow_evaluations: 5,
                ..SolverWork::default()
            })
            .expect("fixture maintenance work fits");
        let retained = charged.used();
        prepare_plan_retry(true, &before, &mut charged);
        assert_eq!(charged.used(), retained);

        prepare_plan_retry(false, &before, &mut charged);
        assert_eq!(charged, before);
    }

    #[test]
    fn exact_receiver_with_open_member_hit_cannot_claim_exhaustive_or_singleton_dispatch() {
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

        assert_eq!(dispatch_hint_flags(&declarations, 1, true), (false, false));
    }

    #[test]
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
        assert_eq!(dispatch_hint_flags(&declarations, 1, true), (true, true));
        assert_eq!(dispatch_hint_flags(&declarations, 2, true), (false, false));
        assert_eq!(dispatch_hint_flags(&[], 0, true), (false, false));
    }

    #[test]
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

        assert_eq!(dispatch_hint_flags(&declarations, 1, false), (false, false));
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
            TypeFlowRootPersistenceStatus::Ineligible(
                TypeFlowRootPersistenceRejection::SemanticBudget
            )
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
