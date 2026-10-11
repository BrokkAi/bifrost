//! One explicit flow or taint candidate through the production route (issue
//! 3686).
//!
//! A `why-not` question about a flow or taint policy names two positions: where
//! the tracked value should enter (a flow origin or a taint source) and where
//! it should be observed (a flow observation or a taint sink). No ordinary run
//! retains an answer to it, so [`solve_flow_candidate`] runs the production
//! pipeline itself, narrowed to that pair:
//!
//! 1. compile the policy with [`TaintPolicyCompiler`], exactly as
//!    [`ProductionTaintPolicyEvaluator::prepare`] does, under the caller's one
//!    pinned semantic-model snapshot;
//! 2. resolve each position to the innermost bound endpoint site of its role
//!    that covers it, under the same containment rule a `match` candidate
//!    uses; a [`CandidateProbe`] records the bound sites before the compile
//!    keeps only the regions that pair a source with a sink;
//! 3. solve only the compiled analysis regions that bind both sites, through
//!    [`solve_and_project_batch`], so a reached candidate projects into the
//!    same finding, with the same identity and witnesses, that an ordinary run
//!    reports for that region.
//!
//! There is no second solver and no search. The compiler, the batch planner,
//! the solver and the projection are the ordinary ones; the only
//! candidate-specific step is the choice of which compiled regions to solve.
//! A caller that wants to know which declared kill blocked a path calls this
//! again with the kills removed from `spec`: that pass is the same pipeline
//! over a smaller policy, and [`CandidateSolve::kills_on`] matches the kills
//! of the first pass to the paths of the second by program-point identity.
//!
//! Persistence-store crossings are seeded across every region before any
//! region solves, so solving the candidate's regions alone cannot replay them.
//! A policy that declares store ends is answered with a typed
//! [`CandidateBoundaryKind::UnsupportedFlow`] boundary instead.
//!
//! Ordinary evaluation never calls this module, and nothing it builds outlives
//! the question it answers.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
use std::cell::Cell;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::{
    ProgramPointHandle, SemanticLocator, WorkspaceIcfgProvider, WorkspaceRelativePath,
};
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_flow::dataflow::{SemanticInputStatus, SolverTermination, SummaryWitness};
use brokk_bifrost_flow::taint::{TaintAnalysisPlan, TaintFindingReport};
use brokk_bifrost_flow::value_flow::{
    ValueFlowEventKey, ValueFlowEventKind, ValueFlowIncompleteCause,
};
use brokk_bifrost_rql::structural::CodeQueryCompletion;

use super::{
    BatchMerge, BoundEndpoint, CompiledTaintEndpoint, CompiledTaintPolicyPlan, PreparedTaintPlan,
    ProductionTaintPolicyEvaluator, StoreWriteEvidenceByRead, TaintBatchError,
    TaintExecutionBudget, TaintPolicyCompilation, TaintPolicyCompileError, TaintPolicyCompiler,
    compiled_payload, prepared_failure_payload, record_exhausted_lane, solve_and_project_batch,
    taint_witness_step_kind,
};
use crate::budget::PolicyBudget;
use crate::explain::{
    ExplanationCandidate, FlowExplanationCandidate, absence_reasons, row_covers_candidate,
};
use crate::finding::{BoundedWitness, PolicyIncompleteReason, PolicySourceLocation};
use crate::finding_identity::WitnessId;
use crate::resolved::{LoadedPolicy, ResolvedEndpointIdentity, ResolvedTaintPolicySpec};
use crate::semantic_identity::{
    call_site_locator, policy_location, program_point_locator, stable_hex,
};
use crate::taint_compose_provider::CompositionMemo;

#[cfg(test)]
thread_local! {
    static CANDIDATE_PASSES: Cell<u64> = const { Cell::new(0) };
}

/// How many candidate passes this thread has run. Ordinary evaluation must
/// leave it untouched.
#[cfg(test)]
pub(super) fn candidate_passes_for_test() -> u64 {
    CANDIDATE_PASSES.with(Cell::get)
}

/// One compiled endpoint that binds the site at a candidate position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateSite {
    pub(crate) endpoint: ResolvedEndpointIdentity,
    pub(crate) location: PolicySourceLocation,
}

/// What the compile established about one candidate position.
#[derive(Debug)]
pub(crate) enum CandidateBinding {
    /// The innermost compiled site that covers the position, once for each
    /// endpoint that binds it. Never empty.
    Bound(Vec<CandidateSite>),
    /// No compiled endpoint of this role covers the position.
    Unbound,
    /// The compile stopped before this role's sites were known.
    Unevaluated,
}

/// Which analysis limit kept one stage of a candidate from being decided.
///
/// Each kind is a stable label a consumer switches on; the reasons a boundary
/// carries are the run's own [`PolicyIncompleteReason`] vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CandidateBoundaryKind {
    /// A selector or a semantic discovery query did not finish exhaustively.
    DiscoveryIncomplete,
    /// A selector row named no single call site or formal, so it bound nothing.
    RefusedSite,
    /// An analysis region outgrew its discovery budget and was skipped.
    RegionBudget,
    /// A call has neither a completely resolved target nor an applicable
    /// complete model: unknown dispatch, or a missing model.
    UnresolvedCall,
    /// A call's actual-to-formal binding is not completely covered.
    CallBinding,
    /// A procedure's semantics are incomplete, or the solve cannot enter it.
    SemanticGap,
    /// An endpoint or policy-local rule's evidence is not proven and complete.
    EndpointEvidence,
    /// The fixed point retained an open coverage boundary with no plan-time
    /// cause, for example a recursive call.
    OpenCoverage,
    /// An activated semantic model could not be compiled for this policy.
    ModelUnavailable,
    /// The policy declares semantics this route cannot execute or replay.
    UnsupportedFlow,
    /// The analyzer could not provide the semantic facts a binding needs.
    SemanticUnavailable,
    /// The question was cancelled.
    Cancelled,
    /// An analysis work budget ran out before a fixed point.
    AnalysisBudget,
    /// A findings, origin, or witness retention bound ran out.
    OutputBudget,
    /// The production pipeline rejected its own plan.
    InvalidPlan,
}

impl CandidateBoundaryKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DiscoveryIncomplete => "discovery_incomplete",
            Self::RefusedSite => "refused_site",
            Self::RegionBudget => "region_budget",
            Self::UnresolvedCall => "unresolved_call",
            Self::CallBinding => "call_binding",
            Self::SemanticGap => "semantic_gap",
            Self::EndpointEvidence => "endpoint_evidence",
            Self::OpenCoverage => "open_coverage",
            Self::ModelUnavailable => "model_unavailable",
            Self::UnsupportedFlow => "unsupported_flow",
            Self::SemanticUnavailable => "semantic_unavailable",
            Self::Cancelled => "cancelled",
            Self::AnalysisBudget => "analysis_budget",
            Self::OutputBudget => "output_budget",
            Self::InvalidPlan => "invalid_plan",
        }
    }
}

/// One typed reason a candidate stage could not be decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateBoundary {
    pub(crate) kind: CandidateBoundaryKind,
    pub(crate) reasons: Vec<PolicyIncompleteReason>,
    pub(crate) location: Option<PolicySourceLocation>,
    pub(crate) detail: String,
}

impl CandidateBoundary {
    fn new(
        kind: CandidateBoundaryKind,
        mut reasons: Vec<PolicyIncompleteReason>,
        location: Option<PolicySourceLocation>,
        detail: String,
    ) -> Self {
        assert!(
            !reasons.is_empty(),
            "a candidate boundary names at least one incomplete reason"
        );
        reasons.sort();
        reasons.dedup();
        Self {
            kind,
            reasons,
            location,
            detail,
        }
    }
}

/// Everything one production pass established about one candidate.
pub(crate) struct CandidatePass {
    pub(crate) origin: CandidateBinding,
    pub(crate) observation: CandidateBinding,
    /// What keeps an unbound position or an absent region from being a proven
    /// absence. Empty when the compile was exhaustive.
    pub(crate) selection_gaps: Vec<CandidateBoundary>,
    /// How many analysis regions the policy compiled to.
    pub(crate) compiled_regions: usize,
    /// How many of them bind both candidate sites; only those were solved.
    pub(crate) candidate_regions: usize,
    /// The solve of the candidate regions. `None` when the compile stopped or
    /// no region binds both sites.
    pub(crate) solve: Option<CandidateSolve>,
    /// The policy's payload over exactly the candidate regions, for projection
    /// into a run by the ordinary evaluator.
    pub(crate) evaluator: ProductionTaintPolicyEvaluator,
}

impl CandidatePass {
    fn stopped(boundary: CandidateBoundary) -> Self {
        Self {
            origin: CandidateBinding::Unevaluated,
            observation: CandidateBinding::Unevaluated,
            selection_gaps: vec![boundary],
            compiled_regions: 0,
            candidate_regions: 0,
            solve: None,
            evaluator: ProductionTaintPolicyEvaluator::default(),
        }
    }
}

/// What the solve of the candidate regions established.
pub(crate) struct CandidateSolve {
    /// Why the solve is not exhaustive for this candidate. Empty when it is.
    pub(crate) boundaries: Vec<CandidateBoundary>,
    /// A candidate region concluded only through authored-complete external
    /// summaries (#1916), which ranks below a proof from analyzed code.
    pub(crate) proven_by_summary: bool,
    /// The solver reached the observation from the origin.
    pub(crate) reached: bool,
    /// The witnesses the solver retained for that reach, in solver order.
    pub(crate) witnesses: Vec<Arc<SummaryWitness>>,
    /// The kills bound inside the candidate regions, in compile order.
    kills: Vec<CandidateKill>,
}

struct CandidateKill {
    site: CandidateSite,
    point: ProgramPointHandle,
}

impl CandidateSolve {
    pub(crate) fn kill_sites(&self) -> impl Iterator<Item = &CandidateSite> {
        self.kills.iter().map(|kill| &kill.site)
    }

    /// The kills of this solve whose cleared program point `witness` passes.
    ///
    /// Durable point identity survives a second compile of the same snapshot,
    /// so the kills of an authored pass match the paths of a kill-free pass
    /// without comparing locations.
    pub(crate) fn kills_on(&self, witness: &SummaryWitness) -> Vec<&CandidateSite> {
        let passed = witness
            .steps()
            .iter()
            .map(|step| step.source().durable_key())
            .collect::<Vec<_>>();
        self.kills
            .iter()
            .filter(|kill| passed.contains(&kill.point.durable_key()))
            .map(|kill| &kill.site)
            .collect()
    }
}

/// Project one solver witness into the report's bounded witness vocabulary,
/// with the policy's own witness bounds. `index` keeps identities distinct
/// within one explanation.
pub(crate) fn project_candidate_witness(
    workspace: &WorkspaceAnalyzer,
    witness: &SummaryWitness,
    index: usize,
    budget: &PolicyBudget,
) -> Result<Option<BoundedWitness>, String> {
    let id = WitnessId::try_new(
        "bifrost",
        stable_hex(format!("flow-candidate-counterfactual:{index}").as_bytes()),
    )
    .map_err(|error| error.to_string())?;
    crate::witness_projection::project_summary_witness(
        workspace,
        witness,
        id,
        budget.max_witness_steps(),
        budget.max_witness_bytes(),
        taint_witness_step_kind,
    )
}

/// The bound endpoint sites that cover a flow candidate's two positions.
///
/// The compile records them once every endpoint selector has bound, before it
/// keeps only the regions that pair a source with a sink: a site bound in no
/// such region is still bound, and its candidate then fails at the region
/// stage rather than at the binding stage.
pub(crate) struct CandidateProbe {
    source: ExplanationCandidate,
    observation: ExplanationCandidate,
    recorded: Option<ProbedSites>,
}

struct ProbedSites {
    sources: Vec<(ResolvedEndpointIdentity, SemanticLocator)>,
    sinks: Vec<(ResolvedEndpointIdentity, SemanticLocator)>,
}

impl CandidateProbe {
    fn new(candidate: &FlowExplanationCandidate) -> Self {
        Self {
            source: candidate.source().clone(),
            observation: candidate.observation().clone(),
            recorded: None,
        }
    }

    /// Record the bound sources and sinks whose event site covers the
    /// candidate's positions. The site is minted exactly as the compile mints
    /// an endpoint's event key, so it compares equal to the compiled event.
    pub(super) fn record(
        &mut self,
        sources: &[BoundEndpoint],
        sinks: &[BoundEndpoint],
    ) -> Result<(), TaintPolicyCompileError> {
        let covering = |endpoints: &[BoundEndpoint],
                        kind: ValueFlowEventKind,
                        position: &ExplanationCandidate| {
            let mut covering = Vec::new();
            for endpoint in endpoints {
                let key = ValueFlowEventKey::at_point(&endpoint.point, 0, kind)
                    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
                if SiteKey::of(key.site()).covers(position) {
                    covering.push((endpoint.endpoint.clone(), key.site().clone()));
                }
            }
            Ok::<_, TaintPolicyCompileError>(covering)
        };
        self.recorded = Some(ProbedSites {
            sources: covering(sources, ValueFlowEventKind::Source, &self.source)?,
            sinks: covering(sinks, ValueFlowEventKind::Sink, &self.observation)?,
        });
        Ok(())
    }
}

impl<'a> TaintPolicyCompiler<'a> {
    fn with_candidate_probe(mut self, probe: &'a mut CandidateProbe) -> Self {
        self.candidate_probe = Some(probe);
        self
    }
}

/// One candidate position after the compile: the innermost bound site and
/// every endpoint bound there, no bound site, or not yet known.
enum Resolution {
    Unevaluated,
    Unbound,
    Bound(SiteKey, Vec<CandidateSite>),
}

impl Resolution {
    fn binding(self) -> CandidateBinding {
        match self {
            Self::Unevaluated => CandidateBinding::Unevaluated,
            Self::Unbound => CandidateBinding::Unbound,
            Self::Bound(_, sites) => CandidateBinding::Bound(sites),
        }
    }
}

/// Run one production pass for one flow or taint candidate.
///
/// `spec` is the policy's resolved specification or a copy of it with fewer
/// kills; everything else, including the semantic-model snapshot, is the
/// caller's pinned configuration for the whole question.
pub(crate) fn solve_flow_candidate(
    policy: &LoadedPolicy,
    spec: &ResolvedTaintPolicySpec,
    workspace: &WorkspaceAnalyzer,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    cancellation: Option<&CancellationToken>,
    budget: &PolicyBudget,
    candidate: &FlowExplanationCandidate,
) -> CandidatePass {
    #[cfg(test)]
    CANDIDATE_PASSES.with(|count| count.set(count.get() + 1));
    if !spec.store_writes.is_empty() || !spec.store_reads.is_empty() {
        return CandidatePass::stopped(CandidateBoundary::new(
            CandidateBoundaryKind::UnsupportedFlow,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
            None,
            "the policy declares persistence-store ends, whose crossings are seeded across \
             every analysis region before any region solves; one candidate's regions do not \
             replay that seeding"
                .to_owned(),
        ));
    }
    let uncancelled = CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let mut probe = CandidateProbe::new(candidate);
    let compilation_started = Instant::now();
    let compilation = TaintPolicyCompiler::new(
        workspace,
        active_semantic_model_snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(snapshot.active_models())),
        budget.query_limits(),
        budget.max_selector_results(),
        cancellation,
    )
    .with_active_semantic_model_snapshot(active_semantic_model_snapshot.clone())
    .with_candidate_probe(&mut probe)
    .compile(policy, spec);
    let compilation_elapsed = compilation_started.elapsed();
    let resolved = probe.recorded.as_ref().map_or_else(
        || Ok((Resolution::Unevaluated, Resolution::Unevaluated)),
        |sites| {
            Ok::<_, String>((
                resolve_position(workspace, &sites.sources)?,
                resolve_position(workspace, &sites.sinks)?,
            ))
        },
    );
    let (origin, observation) = match resolved {
        Ok(resolved) => resolved,
        Err(message) => return CandidatePass::stopped(invalid_plan(message)),
    };
    let unsolved =
        |origin: Resolution, observation: Resolution, gaps, compiled_regions| CandidatePass {
            origin: origin.binding(),
            observation: observation.binding(),
            selection_gaps: gaps,
            compiled_regions,
            candidate_regions: 0,
            solve: None,
            evaluator: ProductionTaintPolicyEvaluator::default(),
        };
    match compilation {
        Err(failure) => unsolved(
            origin,
            observation,
            vec![compile_boundary(&failure.error)],
            0,
        ),
        Ok(TaintPolicyCompilation::Clean {
            refusals,
            incomplete_selectors,
            ..
        }) => unsolved(
            origin,
            observation,
            selection_gaps(&refusals, &incomplete_selectors, 0),
            0,
        ),
        Ok(TaintPolicyCompilation::Plans {
            roots,
            work,
            refusals,
            incomplete_selectors,
            authored_selector_summary,
            skipped_region_roots,
        }) => {
            let gaps = selection_gaps(&refusals, &incomplete_selectors, skipped_region_roots);
            let (origin_key, origin_sites, observation_key, observation_sites) =
                match (origin, observation) {
                    (
                        Resolution::Bound(origin_key, origin_sites),
                        Resolution::Bound(observation_key, observation_sites),
                    ) => (origin_key, origin_sites, observation_key, observation_sites),
                    (origin, observation) => {
                        return unsolved(origin, observation, gaps, roots.len());
                    }
                };
            let payload = compiled_payload(
                &policy.definition().metadata.id,
                work,
                refusals,
                None,
                authored_selector_summary,
                incomplete_selectors,
            );
            solve_candidate_regions(
                policy,
                workspace,
                active_semantic_model_snapshot,
                cancellation,
                budget,
                (origin_key, origin_sites),
                (observation_key, observation_sites),
                roots,
                payload,
                gaps,
                compilation_elapsed,
            )
            .unwrap_or_else(|message| CandidatePass::stopped(invalid_plan(message)))
        }
    }
}

fn invalid_plan(message: String) -> CandidateBoundary {
    CandidateBoundary::new(
        CandidateBoundaryKind::InvalidPlan,
        vec![PolicyIncompleteReason::CapabilityIncomplete],
        None,
        message,
    )
}

// Every input is one the ordinary `prepare` path also threads to its solve;
// grouping them would only move the list.
#[allow(clippy::too_many_arguments)]
fn solve_candidate_regions(
    policy: &LoadedPolicy,
    workspace: &WorkspaceAnalyzer,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    (origin_key, origin_sites): (SiteKey, Vec<CandidateSite>),
    (observation_key, observation_sites): (SiteKey, Vec<CandidateSite>),
    roots: Vec<CompiledTaintPolicyPlan>,
    payload: crate::projection::TaintProjectionPayload,
    selection_gaps: Vec<CandidateBoundary>,
    compilation_elapsed: std::time::Duration,
) -> Result<CandidatePass, String> {
    let compiled_regions = roots.len();
    let policy_id = policy.definition().metadata.id.clone();
    let icfg_provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
        workspace,
        active_semantic_model_snapshot.clone(),
    );
    let mut metadata = HashMap::new();
    let mut plans = Vec::new();
    let mut kills = Vec::new();
    for root in roots {
        let binds = |endpoints: &[CompiledTaintEndpoint], key: &SiteKey| {
            endpoints
                .iter()
                .any(|endpoint| SiteKey::of(endpoint.event.site()) == *key)
        };
        if !binds(&root.sources, &origin_key) || !binds(&root.sinks, &observation_key) {
            continue;
        }
        for kill in root.kills.iter() {
            kills.push(CandidateKill {
                site: CandidateSite {
                    endpoint: kill.endpoint.clone(),
                    location: policy_location(workspace, program_point_locator(&kill.point))?,
                },
                point: kill.point.clone(),
            });
        }
        metadata.insert(
            root.internal_policy_id,
            PreparedTaintPlan {
                policy_id: policy_id.clone(),
                sources: root.sources,
                sinks: root.sinks,
                store_writes: root.store_writes,
                store_reads: root.store_reads,
                call_resolution_evidence: root.call_resolution_evidence,
                external_models: root.external_models,
                compilation_elapsed,
                engine: root.engine.clone(),
            },
        );
        plans.push((root.engine, root.plan));
    }
    let candidate_regions = plans.len();
    if plans.is_empty() {
        return Ok(CandidatePass {
            origin: CandidateBinding::Bound(origin_sites),
            observation: CandidateBinding::Bound(observation_sites),
            selection_gaps,
            compiled_regions,
            candidate_regions,
            solve: None,
            evaluator: ProductionTaintPolicyEvaluator::default(),
        });
    }

    let mut payloads = HashMap::from([(policy_id.clone(), payload)]);
    let mut merge = BatchMerge::default();
    let mut boundaries = Vec::new();
    let mut public_findings = Vec::new();
    let mut retained_analyses = Vec::new();
    let mut execution_budget = TaintExecutionBudget::new(budget);
    let planning_started = Instant::now();
    let batches = super::partition_taint_batches(plans).map_err(|error| error.to_string())?;
    let batch_planning_elapsed = planning_started.elapsed();
    let no_store_evidence = StoreWriteEvidenceByRead::new();
    let composition_memo = CompositionMemo::default();
    for batch in &batches {
        let Err(failure) = solve_and_project_batch(
            batch,
            &[],
            &metadata,
            &[policy],
            &mut payloads,
            &mut merge,
            workspace,
            cancellation,
            budget,
            &mut execution_budget,
            &mut public_findings,
            &mut retained_analyses,
            batch_planning_elapsed,
            active_semantic_model_snapshot.clone(),
            &icfg_provider,
            &no_store_evidence,
            &composition_memo,
        ) else {
            continue;
        };
        let payload = payloads
            .get_mut(&policy_id)
            .expect("the candidate's own payload was seeded above");
        match failure {
            TaintBatchError::BudgetExhausted(lane) => {
                record_exhausted_lane(payload, lane);
                boundaries.push(CandidateBoundary::new(
                    CandidateBoundaryKind::OutputBudget,
                    vec![lane.incomplete_reason()],
                    None,
                    format!("the taint {} lane was exhausted", lane.label()),
                ));
            }
            TaintBatchError::Internal(message) => {
                merge.envelopes.remove(&policy_id);
                *payload = prepared_failure_payload(&message, payload.work.clone());
                boundaries.push(invalid_plan(message));
            }
        }
    }

    let mut proven_by_summary = false;
    let mut reached = false;
    let mut witnesses = Vec::<Arc<SummaryWitness>>::new();
    for analysis in &retained_analyses {
        let report = analysis.report();
        if !report.is_complete() {
            if report.is_proven_by_authored_summaries() {
                proven_by_summary = true;
            } else {
                boundaries.push(solve_boundary(workspace, analysis.plan(), report)?);
            }
        }
        for finding in report.findings() {
            if SiteKey::of(finding.key().sink().site()) != observation_key {
                continue;
            }
            let mut origin_retained = false;
            for origin in finding.origins().evidence() {
                if SiteKey::of(origin.origin().value_flow_key().site()) != origin_key {
                    continue;
                }
                origin_retained = true;
                for witness in origin.witnesses() {
                    if !witnesses.contains(witness) {
                        witnesses.push(Arc::clone(witness));
                    }
                }
            }
            reached |= origin_retained;
            if !origin_retained && finding.origins().origin_truncated() {
                boundaries.push(CandidateBoundary::new(
                    CandidateBoundaryKind::OutputBudget,
                    vec![PolicyIncompleteReason::ReportRetentionBudget],
                    Some(policy_location(workspace, finding.key().sink().site())?),
                    "the solver reached the observation, but its retained origins were \
                     truncated before the candidate's origin could be checked"
                        .to_owned(),
                ));
            }
        }
    }
    boundaries.sort_by(|left, right| {
        (left.kind, &left.detail, &left.reasons).cmp(&(right.kind, &right.detail, &right.reasons))
    });
    boundaries.dedup();
    Ok(CandidatePass {
        origin: CandidateBinding::Bound(origin_sites),
        observation: CandidateBinding::Bound(observation_sites),
        selection_gaps,
        compiled_regions,
        candidate_regions,
        solve: Some(CandidateSolve {
            boundaries,
            proven_by_summary,
            reached,
            witnesses,
            kills,
        }),
        evaluator: ProductionTaintPolicyEvaluator {
            prepared: std::sync::Mutex::new(payloads),
            public_findings: std::sync::Mutex::new(public_findings),
            retained_analyses: std::sync::Mutex::new(Vec::new()),
        },
    })
}

/// One site in the analyzed source: a workspace path and an anchor byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SiteKey {
    path: WorkspaceRelativePath,
    span: Range<u32>,
}

impl SiteKey {
    fn of(locator: &SemanticLocator) -> Self {
        let span = locator.anchor().span();
        Self {
            path: locator.path().clone(),
            span: span.start_byte()..span.end_byte(),
        }
    }

    fn covers(&self, position: &ExplanationCandidate) -> bool {
        self.path == *position.path()
            && row_covers_candidate(
                Some(&(self.span.start as usize..self.span.end as usize)),
                position,
            )
    }
}

/// The innermost probed site, with every endpoint bound there.
///
/// "Innermost" is the narrowest covering span, with the earlier start breaking
/// a tie, so a position inside a nested call names the inner call and a range
/// spelling the outer call names the outer one.
fn resolve_position(
    workspace: &WorkspaceAnalyzer,
    covering: &[(ResolvedEndpointIdentity, SemanticLocator)],
) -> Result<Resolution, String> {
    let Some(innermost) = covering
        .iter()
        .map(|(_, site)| SiteKey::of(site))
        .min_by_key(|key| (key.span.len(), key.span.start))
    else {
        return Ok(Resolution::Unbound);
    };
    let mut sites = Vec::new();
    for (endpoint, site) in covering {
        if SiteKey::of(site) != innermost {
            continue;
        }
        let site = CandidateSite {
            endpoint: endpoint.clone(),
            location: policy_location(workspace, site)?,
        };
        if !sites.contains(&site) {
            sites.push(site);
        }
    }
    sites.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
    Ok(Resolution::Bound(innermost, sites))
}

/// What keeps the compile's endpoint and region selection from being
/// exhaustive.
fn selection_gaps(
    refusals: &[String],
    incomplete_selectors: &[String],
    skipped_region_roots: usize,
) -> Vec<CandidateBoundary> {
    let mut gaps = Vec::new();
    if !incomplete_selectors.is_empty() {
        gaps.push(CandidateBoundary::new(
            CandidateBoundaryKind::DiscoveryIncomplete,
            vec![PolicyIncompleteReason::PartialDiscovery],
            None,
            format!("endpoint selectors did not finish: {incomplete_selectors:?}"),
        ));
    }
    if !refusals.is_empty() {
        gaps.push(CandidateBoundary::new(
            CandidateBoundaryKind::RefusedSite,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
            None,
            format!("selector rows bound no single site: {refusals:?}"),
        ));
    }
    if skipped_region_roots > 0 {
        gaps.push(CandidateBoundary::new(
            CandidateBoundaryKind::RegionBudget,
            vec![PolicyIncompleteReason::PartialDiscovery],
            None,
            format!(
                "{skipped_region_roots} analysis region(s) outgrew their discovery budget and \
                 were not compiled"
            ),
        ));
    }
    gaps
}

/// The typed boundary a failed compile stands for.
///
/// An ordinary run reports some of these as a failed run. A candidate answers
/// `unknown` instead: the compile did not establish anything about the
/// candidate, which is a different statement from a proven absence.
fn compile_boundary(error: &TaintPolicyCompileError) -> CandidateBoundary {
    let (kind, reasons) = match error {
        TaintPolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Cancelled,
            ..
        } => (
            CandidateBoundaryKind::Cancelled,
            vec![PolicyIncompleteReason::Cancelled],
        ),
        TaintPolicyCompileError::QueryIncomplete { completion, .. } => (
            CandidateBoundaryKind::DiscoveryIncomplete,
            absence_reasons(completion, false),
        ),
        TaintPolicyCompileError::SemanticProvider(_)
        | TaintPolicyCompileError::SemanticUnavailable(_)
        | TaintPolicyCompileError::AmbiguousSemanticSite(_) => (
            CandidateBoundaryKind::SemanticUnavailable,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
        ),
        TaintPolicyCompileError::UnknownFormalName { .. }
        | TaintPolicyCompileError::UnsupportedBinding(_)
        | TaintPolicyCompileError::UnsupportedAuxiliarySemantics(_) => (
            CandidateBoundaryKind::UnsupportedFlow,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
        ),
        TaintPolicyCompileError::Model(_) => (
            CandidateBoundaryKind::ModelUnavailable,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
        ),
        TaintPolicyCompileError::MissingSelector(_) | TaintPolicyCompileError::Plan(_) => (
            CandidateBoundaryKind::InvalidPlan,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
        ),
        TaintPolicyCompileError::EmptyCompiledEndpoints(_) => {
            unreachable!("an empty endpoint selection compiles as a clean compilation")
        }
    };
    CandidateBoundary::new(kind, reasons, None, error.to_string())
}

/// The typed boundary of one candidate region whose solve is not exhaustive.
///
/// The solver's own termination comes first, because it says why the solve
/// stopped; a fixed point that is still incomplete is attributed to the
/// plan's first retained cause (#1952), with the same reason mapping an
/// ordinary run publishes.
fn solve_boundary(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    report: &TaintFindingReport,
) -> Result<CandidateBoundary, String> {
    match report.result().termination() {
        SolverTermination::Cancelled => {
            return Ok(CandidateBoundary::new(
                CandidateBoundaryKind::Cancelled,
                vec![PolicyIncompleteReason::Cancelled],
                None,
                "the solve of a candidate region was cancelled".to_owned(),
            ));
        }
        SolverTermination::ExceededBudget(exceeded) => {
            return Ok(CandidateBoundary::new(
                CandidateBoundaryKind::AnalysisBudget,
                vec![PolicyIncompleteReason::PartialDiscovery],
                None,
                format!("the solve of a candidate region exceeded its solver budget: {exceeded:?}"),
            ));
        }
        SolverTermination::FixedPoint => {}
    }
    let Some(cause) = plan.value_flow().first_incomplete_cause() else {
        return Ok(CandidateBoundary::new(
            CandidateBoundaryKind::OpenCoverage,
            vec![PolicyIncompleteReason::PartialDiscovery],
            None,
            "the fixed point retains an open coverage boundary with no plan-time cause".to_owned(),
        ));
    };
    let status = cause.status();
    let kind = match (cause, status) {
        (_, Some(SemanticInputStatus::Cancelled)) => CandidateBoundaryKind::Cancelled,
        (_, Some(SemanticInputStatus::ExceededBudget { .. })) => {
            CandidateBoundaryKind::AnalysisBudget
        }
        (ValueFlowIncompleteCause::CallResolution { .. }, _) => {
            CandidateBoundaryKind::UnresolvedCall
        }
        (
            ValueFlowIncompleteCause::CallBinding { .. }
            | ValueFlowIncompleteCause::CallBindingCoverage { .. },
            _,
        ) => CandidateBoundaryKind::CallBinding,
        (
            ValueFlowIncompleteCause::Snapshot { .. }
            | ValueFlowIncompleteCause::SnapshotCoverage { .. }
            | ValueFlowIncompleteCause::SemanticGap { .. }
            | ValueFlowIncompleteCause::UnenteredProcedure { .. },
            _,
        ) => CandidateBoundaryKind::SemanticGap,
        (
            ValueFlowIncompleteCause::SourceEvidence { .. }
            | ValueFlowIncompleteCause::SinkEvidence { .. }
            | ValueFlowIncompleteCause::LocalRuleEvidence { .. },
            _,
        ) => CandidateBoundaryKind::EndpointEvidence,
    };
    let reason = match status {
        Some(SemanticInputStatus::Cancelled) => PolicyIncompleteReason::Cancelled,
        Some(SemanticInputStatus::Unsupported { .. }) => {
            PolicyIncompleteReason::CapabilityIncomplete
        }
        _ => PolicyIncompleteReason::PartialDiscovery,
    };
    let status_label = match status {
        Some(status @ SemanticInputStatus::Unsupported { capability }) => {
            format!("{} ({})", status.label(), capability.label())
        }
        Some(status) => status.label().to_owned(),
        None => "incomplete coverage".to_owned(),
    };
    // The obligations are the ordinary run's own diagnostic wording, so a
    // reader sees one statement of what is missing on either surface.
    let (locator, obligation) = match cause {
        ValueFlowIncompleteCause::CallResolution { call, .. } => (
            call_site_locator(call),
            "; this exact call has neither a completely resolved executable target nor an \
             applicable complete external model",
        ),
        ValueFlowIncompleteCause::CallBinding { call, .. }
        | ValueFlowIncompleteCause::CallBindingCoverage { call, .. } => (
            call_site_locator(call),
            "; this exact call binding is not completely covered by executable code or an \
             applicable complete external model",
        ),
        ValueFlowIncompleteCause::SourceEvidence { point }
        | ValueFlowIncompleteCause::SinkEvidence { point }
        | ValueFlowIncompleteCause::LocalRuleEvidence { point } => {
            (program_point_locator(point), "")
        }
        _ => (cause.procedure().semantics().locator(), ""),
    };
    Ok(CandidateBoundary::new(
        kind,
        vec![reason],
        Some(policy_location(workspace, locator)?),
        format!("{} is {status_label}{obligation}", cause.label()),
    ))
}
