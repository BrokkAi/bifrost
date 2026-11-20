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
//!    uses; a [`CandidateProbe`] records the bound sites before region selection;
//! 3. seed declared stores from every ICFG region, including remote writers,
//!    then solve through [`solve_and_project_batch`], so a reached candidate projects into the
//!    same finding, with the same identity and witnesses, that an ordinary run
//!    reports for that region.
//!
//! There is no second solver and no search. The compiler, the batch planner,
//! the solver and the projection are the ordinary ones; the only
//! candidate-specific step is the choice of which composed regions to solve;
//! ICFG needs every root for the ordinary store-channel fixpoint.
//! A caller that wants to know which declared kill blocked a path calls this
//! again with the kills removed from `spec`: that pass is the same pipeline
//! over a smaller policy, and [`CandidateSolve::kills_on`] matches the kills
//! of the first pass to the paths of the second by program-point identity.
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
use brokk_bifrost_analysis::analyzer::store::cache_budget::RetainedHeap;
use brokk_bifrost_flow::dataflow::{SemanticInputStatus, SolverTermination, SummaryWitness};
use brokk_bifrost_flow::taint::{
    ProductionTaintAnalysisResult, TaintAnalysisPlan, TaintBatch, TaintFindingReport,
};
use brokk_bifrost_flow::value_flow::{ValueFlowEventKind, ValueFlowIncompleteCause};
use brokk_bifrost_rql::structural::CodeQueryCompletion;

use super::{
    BatchMerge, BoundEndpoint, BoundStoreEnd, CompiledTaintEndpoint, CompiledTaintPolicyPlan,
    EffectiveWitnessLimits, PreparedTaintPlan, ProductionTaintPolicyEvaluator, RefusalNotice,
    StoreCrossingProvenance, StoreReadSeed, TaintBatchError, TaintExecutionBudget,
    TaintPolicyCompilation, TaintPolicyCompileError, TaintPolicyCompiler, compiled_payload,
    composed_crossing_evidence, composed_crossing_matches, policy_sink_files,
    prepared_failure_payload, project_composed_store_crossing_witness, record_exhausted_lane,
    selector_endpoint_label, solve_and_project_batch, taint_witness_step_kind,
};
use crate::budget::PolicyBudget;
use crate::explain::{
    ExplanationCandidate, FlowExplanationCandidate, absence_reasons, row_covers_candidate,
};
use crate::finding::{BoundedWitness, PolicyIncompleteReason, PolicySourceLocation};
use crate::finding_identity::WitnessId;
use crate::resolved::{LoadedPolicy, ResolvedEndpointIdentity, ResolvedTaintPolicySpec};
use crate::selector_compiler::IncompleteTaintSelector;
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
    /// Typed causes behind this boundary, each with its own family and owner
    /// location. Empty when the boundary has no stored cause records.
    pub(crate) causes: Vec<CandidateBoundaryCause>,
}

/// One composition cause record, rendered once from the batch's typed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateBoundaryCause {
    pub(crate) family: String,
    pub(crate) message: String,
    pub(crate) location: Option<PolicySourceLocation>,
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
            causes: Vec::new(),
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
    /// How many regions were solved. Without store channels, these bind both
    /// candidate sites; a store crossing also needs remote writer regions.
    pub(crate) candidate_regions: usize,
    /// Store channels require remote writer and read regions in the solve.
    pub(crate) store_channel_search: bool,
    /// The solve of the candidate regions. `None` when the compile stopped or
    /// no region binds both sites.
    pub(crate) solve: Option<CandidateSolve>,
    /// The policy's payload over exactly the candidate regions, for projection
    /// into a run by the ordinary evaluator.
    pub(crate) evaluator: ProductionTaintPolicyEvaluator,
}

impl CandidatePass {
    pub(crate) fn discard_projection(&mut self) {
        // A negative/counterfactual question has finished using the ordinary
        // finding projector. Do not keep its duplicate prepared/public rows
        // alive just to compare the actual solver inputs.
        self.evaluator = ProductionTaintPolicyEvaluator::default();
    }

    pub(crate) fn discard_negative_display(&mut self) {
        self.discard_projection();
        if let Some(solve) = &mut self.solve {
            assert!(
                !solve.reached,
                "only an unreached authored candidate discards its display evidence"
            );
            solve.witnesses = Vec::new();
            solve.store_crossings = Vec::new();
        }
    }
    pub(crate) fn collective_kill_dependence(&self, relaxed: &Self) -> Result<(), &'static str> {
        if !self.selection_gaps.is_empty() || !relaxed.selection_gaps.is_empty() {
            return Err("the authored or counterfactual selector coverage is incomplete");
        }
        if self.store_channel_search || relaxed.store_channel_search {
            return Err(
                "the actual store inventory and seed closure have no established correspondence",
            );
        }
        let (Some(strict), Some(loose)) = (&self.solve, &relaxed.solve) else {
            return Err("one candidate execution produced no solved relation");
        };
        if strict.kills.is_empty() {
            return Err("the authored candidate has no bound declared kill set");
        }
        strict.collective_kill_dependence(loose)
    }

    fn stopped(boundary: CandidateBoundary) -> Self {
        Self {
            origin: CandidateBinding::Unevaluated,
            observation: CandidateBinding::Unevaluated,
            selection_gaps: vec![boundary],
            compiled_regions: 0,
            candidate_regions: 0,
            store_channel_search: false,
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
    store_crossings: Vec<(Arc<SummaryWitness>, Option<usize>, StoreCrossingProvenance)>,
    /// The kills bound inside the candidate regions, in compile order.
    kills: Vec<CandidateKill>,
    inputs: CandidateInputs,
}

/// Owned products of this execution, never a portable admission certificate.
enum CandidateInputs {
    Native {
        analyses: Vec<Arc<ProductionTaintAnalysisResult>>,
        origin: SiteKey,
        observation: SiteKey,
    },
    Composed {
        batches: Vec<TaintBatch>,
        reports: Box<[Option<super::ComposedCandidateReport>]>,
        origin: SiteKey,
        observation: SiteKey,
    },
    Unavailable(&'static str),
    RetentionRefused,
}

struct CandidateKill {
    site: CandidateSite,
    point: ProgramPointHandle,
}

impl CandidateSolve {
    pub(crate) fn input_retention_refused(&self) -> bool {
        matches!(self.inputs, CandidateInputs::RetentionRefused)
    }

    /// Complete strict absence and a corresponding relaxed meeting establish
    /// dependence on the collective bound kill set, independently of display
    /// path retention. No result's IDs or admission are used in the other run.
    fn collective_kill_dependence(&self, relaxed: &Self) -> Result<(), &'static str> {
        if matches!(&self.inputs, CandidateInputs::Composed { .. }) {
            return self.composed_kill_dependence(relaxed);
        }
        let CandidateInputs::Native {
            analyses: strict,
            origin,
            observation,
            ..
        } = &self.inputs
        else {
            return Err(match &self.inputs {
                CandidateInputs::Unavailable(reason) => reason,
                CandidateInputs::RetentionRefused => {
                    "the report allowance refused retained input products"
                }
                CandidateInputs::Native { .. } => unreachable!(),
                CandidateInputs::Composed { .. } => "the two passes used different engines",
            });
        };
        let CandidateInputs::Native {
            analyses: loose,
            origin: loose_origin,
            observation: loose_observation,
            ..
        } = &relaxed.inputs
        else {
            return Err(match &relaxed.inputs {
                CandidateInputs::Unavailable(reason) => reason,
                CandidateInputs::RetentionRefused => {
                    "the report allowance refused retained input products"
                }
                CandidateInputs::Native { .. } => unreachable!(),
                CandidateInputs::Composed { .. } => "the two passes used different engines",
            });
        };
        if origin != loose_origin
            || observation != loose_observation
            || strict.is_empty()
            || strict.len() != loose.len()
        {
            return Err(
                "the actual source, observation or region inventory differs between passes",
            );
        }
        if !self.boundaries.is_empty() || !relaxed.boundaries.is_empty() {
            return Err("an actual candidate execution retains an open coverage boundary");
        }
        let mut positive = false;
        for (index, analysis) in strict.iter().enumerate() {
            if strict[..index].iter().any(|previous| {
                previous.plan().value_flow().root() == analysis.plan().value_flow().root()
            }) {
                return Err("the correspondence between solved regions is ambiguous");
            }
            let mut corresponding = loose.iter().filter(|candidate| {
                candidate.plan().value_flow().root() == analysis.plan().value_flow().root()
            });
            let Some(other) = corresponding.next() else {
                return Err("a solved region has no corresponding relaxed region");
            };
            if corresponding.next().is_some() {
                return Err("the correspondence between solved regions is ambiguous");
            }
            if !analysis.plan_report_match() || !other.plan_report_match() {
                return Err("a retained result does not belong to its own executed plan");
            }
            let complete = |report: &TaintFindingReport| {
                report.result().termination().is_fixed_point()
                    && (report.is_complete()
                        || (report.is_proven_by_authored_summaries()
                            && !report.authored_arm_closures().is_empty()))
            };
            if !complete(analysis.report()) || !complete(other.report()) {
                return Err("the actual source or accepted-meeting domain did not complete");
            }
            if analysis.report().authored_arm_closures() != other.report().authored_arm_closures() {
                return Err("the actual authored model closure differs between passes");
            }
            if !analysis
                .plan()
                .has_same_inputs_without_sanitizers(other.plan())
            {
                return Err(
                    "actual nonkill inputs, endpoint bindings or bound kill removal do not correspond",
                );
            }
            if [analysis, other].into_iter().any(|analysis| {
                analysis.report().findings().iter().any(|finding| {
                    observation.matches(finding.key().sink().site())
                        && (finding.origins().origin_truncated()
                            || finding.origins().evidence().is_empty())
                })
            }) {
                return Err("accepted meetings have incomplete source attribution");
            }
            // Native IDE values merge origins. Absence of the candidate in a
            // bounded origin reconstruction therefore cannot prove absence.
            // Require the stronger, source-independent fact: this complete
            // report has NO accepted meeting at the observation. A peer meeting
            // conservatively prevents attribution too.
            if analysis
                .report()
                .findings()
                .iter()
                .any(|finding| observation.matches(finding.key().sink().site()))
            {
                return Err("the complete strict observation domain contains an accepted meeting");
            }
            // Positive evidence can name an actual own-source contribution
            // without enumerating every alternative.
            let reaches = |analysis: &ProductionTaintAnalysisResult| {
                analysis.report().findings().iter().any(|finding| {
                    observation.matches(finding.key().sink().site())
                        && finding.origins().evidence().iter().any(|evidence| {
                            analysis.plan().sources().iter().any(|source| {
                                source.origin() == evidence.origin()
                                    && origin.matches(source.origin().value_flow_key().site())
                                    && source.classes().intersects(evidence.classes())
                                    && finding.classes().intersects(evidence.reached_classes())
                            })
                        })
                })
            };
            positive |= reaches(other);
        }
        if !positive {
            return Err("the relaxed executed relation contains no accepted own-source meeting");
        }
        Ok(())
    }

    fn composed_kill_dependence(&self, relaxed: &Self) -> Result<(), &'static str> {
        let (
            CandidateInputs::Composed {
                batches,
                reports,
                origin,
                observation,
            },
            CandidateInputs::Composed {
                batches: loose_batches,
                reports: loose_reports,
                origin: loose_origin,
                observation: loose_observation,
            },
        ) = (&self.inputs, &relaxed.inputs)
        else {
            return Err("the two passes do not retain corresponding composed input owners");
        };
        if origin != loose_origin
            || observation != loose_observation
            || batches.is_empty()
            || batches.len() != loose_batches.len()
            || reports.len() != batches.len()
            || loose_reports.len() != loose_batches.len()
        {
            return Err("the actual source, observation or composed region inventory differs");
        }
        if !self.boundaries.is_empty() || !relaxed.boundaries.is_empty() {
            return Err("an actual composed execution retains an open coverage boundary");
        }
        let mut positive = false;
        for (index, batch) in batches.iter().enumerate() {
            let root = batch.analysis().value_flow().root();
            if batches[..index]
                .iter()
                .any(|previous| previous.analysis().value_flow().root() == root)
            {
                return Err("the correspondence between composed regions is ambiguous");
            }
            let mut matching = loose_batches
                .iter()
                .enumerate()
                .filter(|(_, candidate)| candidate.analysis().value_flow().root() == root);
            let Some((other_index, other_batch)) = matching.next() else {
                return Err("a composed region has no corresponding relaxed region");
            };
            if matching.next().is_some() {
                return Err("the correspondence between composed regions is ambiguous");
            }
            let (Some(strict), Some(loose)) = (&reports[index], &loose_reports[other_index]) else {
                return Err("a composed region produced no owned execution result");
            };
            if strict.batch_index != index
                || loose.batch_index != other_index
                || !batch
                    .analysis()
                    .has_same_inputs_without_sanitizers(other_batch.analysis())
            {
                return Err("actual composed root bindings or nonkill plan inputs differ");
            }
            let (Some(inputs), Some(other_inputs)) = (&strict.inputs, &loose.inputs) else {
                return Err("an actual composed execution did not retain its input domain");
            };
            if !inputs.shared.has_same_nonkill_inputs(&other_inputs.shared)
                || !inputs
                    .provider
                    .has_same_nonkill_inputs(&other_inputs.provider)
                || !inputs
                    .discovery
                    .has_same_inputs(&other_inputs.discovery, root)
            {
                return Err(
                    "actual composed support, interpretation or nonkill inputs do not correspond",
                );
            }
            if !inputs.provider.all_sanitizers_match(|sanitizer| {
                self.kills
                    .iter()
                    .any(|kill| sanitizer.is_bound_to(&kill.site.endpoint, &kill.point))
            }) || !other_inputs.provider.all_sanitizers_match(|_| false)
            {
                return Err(
                    "an actual frontier sanitizer is outside the bound collective kill set",
                );
            }
            if !inputs.shared.all_sanitizers_match(|sanitizer| {
                sanitizer.proven
                    && sanitizer.resolved
                    && batch.analysis().sanitizers().iter().any(|binding| {
                        binding.is_proven()
                            && binding.is_resolved()
                            && binding.point() == &sanitizer.point
                            && batch.analysis().value_flow().carrier(binding.carrier())
                                == Some(&sanitizer.input)
                            && batch.analysis().value_flow().carrier(binding.output())
                                == Some(&sanitizer.output)
                            && sanitizer.function.is_kill_of(binding.removed())
                    })
            }) || !other_inputs.shared.all_sanitizers_match(|_| false)
            {
                return Err(
                    "an actual composed sanitizer recipe differs from the bound root kill set",
                );
            }
            let complete = |report: &TaintFindingReport| {
                report.result().termination().is_fixed_point()
                    && (report.is_complete()
                        || (report.is_proven_by_authored_summaries()
                            && !report.authored_arm_closures().is_empty()))
            };
            if !complete(&strict.report)
                || !complete(&loose.report)
                || strict.report.authored_arm_closures() != loose.report.authored_arm_closures()
            {
                return Err(
                    "the actual composed accepted-meeting domain or model closure is incomplete",
                );
            }
            // Any accepted strict origin refuses the stronger absence premise;
            // a bounded displayed origin inventory cannot prove a negative.
            if strict
                .report
                .findings()
                .iter()
                .any(|finding| observation.matches(finding.key().sink().site()))
            {
                return Err("the complete strict observation domain contains an accepted meeting");
            }
            let Some(sources) = other_inputs.shared.input_caches() else {
                return Err("the relaxed source inventory is unavailable");
            };
            positive |= loose.report.findings().iter().any(|finding| {
                observation.matches(finding.key().sink().site())
                    && finding.origins().evidence().iter().any(|evidence| {
                        sources.sources.iter().any(|source| {
                            source.origin == *evidence.origin()
                                && origin.matches(source.origin.value_flow_key().site())
                                && source.classes.intersects(evidence.classes())
                                && finding.classes().intersects(evidence.reached_classes())
                        })
                    })
            });
        }
        if !positive {
            return Err("the relaxed composed relation contains no accepted own-source meeting");
        }
        Ok(())
    }

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
    solve: &CandidateSolve,
    witness: &SummaryWitness,
    index: usize,
    budget: &PolicyBudget,
) -> Result<Option<BoundedWitness>, String> {
    let id = WitnessId::try_new(
        "bifrost",
        stable_hex(format!("flow-candidate-counterfactual:{index}").as_bytes()),
    )
    .map_err(|error| error.to_string())?;
    let projected = crate::witness_projection::project_summary_witness(
        workspace,
        witness,
        id,
        budget.max_witness_steps(),
        budget.max_witness_bytes(),
        taint_witness_step_kind,
    )?;
    let Some(projected) = projected else {
        return Ok(None);
    };
    let seeded = solve
        .store_crossings
        .iter()
        .find(|(retained, prefix, _)| retained.as_ref() == witness && prefix.is_none());
    if let Some((_, _, crossing)) = seeded {
        return super::project_store_crossing_witness(
            workspace,
            projected,
            crossing,
            EffectiveWitnessLimits {
                steps: budget.max_witness_steps(),
                bytes: budget.max_witness_bytes(),
            },
        )
        .map(Some);
    }
    let mut crossings = solve
        .store_crossings
        .iter()
        .filter(|(retained, _, _)| retained.as_ref() == witness)
        .filter_map(|(_, prefix, evidence)| prefix.map(|prefix| (prefix, evidence.clone())))
        .collect::<Vec<_>>();
    crossings.sort_by_key(|(prefix, _)| std::cmp::Reverse(*prefix));
    if crossings.is_empty() {
        Ok(Some(projected))
    } else {
        project_composed_store_crossing_witness(
            workspace,
            projected,
            &crossings,
            EffectiveWitnessLimits {
                steps: budget.max_witness_steps(),
                bytes: budget.max_witness_bytes(),
            },
        )
        .map(Some)
    }
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

    /// A declared store write can itself be the candidate's observation.
    /// The ordinary policy has no finding sink there, so bind that selected
    /// write as a candidate-only sink when no declared sink covers the site.
    pub(super) fn store_write_observation_sinks(
        &self,
        sources: &[BoundEndpoint],
        sinks: &[BoundEndpoint],
        writes: &[BoundStoreEnd],
    ) -> Vec<BoundEndpoint> {
        let covers = |endpoint: &BoundEndpoint| {
            SiteKey::of(program_point_locator(&endpoint.point)).covers(&self.observation)
        };
        if sinks.iter().any(covers) {
            return Vec::new();
        }
        let mut labels = Vec::new();
        for source in sources.iter().filter(|source| {
            super::endpoint_event_key(source, 0, ValueFlowEventKind::Source)
                .is_ok_and(|key| SiteKey::of(key.site()).covers(&self.source))
        }) {
            for label in &source.labels {
                if !labels.contains(label) {
                    labels.push(label.clone());
                }
            }
        }
        let labels = labels.into_boxed_slice();
        writes
            .iter()
            .filter(|write| covers(&write.endpoint))
            .map(|write| {
                let mut sink = write.endpoint.clone();
                sink.labels = labels.clone();
                sink
            })
            .collect()
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
                let key = super::endpoint_event_key(endpoint, 0, kind)?;
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn solve_flow_candidate(
    policy: &LoadedPolicy,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    spec: &ResolvedTaintPolicySpec,
    workspace: &WorkspaceAnalyzer,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    cancellation: Option<&CancellationToken>,
    budget: &PolicyBudget,
    candidate: &FlowExplanationCandidate,
    input_retention: Option<&mut RetainedHeap>,
) -> CandidatePass {
    let flow_state = flow_state.into();
    #[cfg(test)]
    CANDIDATE_PASSES.with(|count| count.set(count.get() + 1));
    let uncancelled = CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let mut probe = CandidateProbe::new(candidate);
    let compilation_started = Instant::now();
    let compilation = TaintPolicyCompiler::new(
        workspace,
        &flow_state,
        active_semantic_model_snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(snapshot.active_models())),
        budget.query_limits(),
        budget.max_selector_results(),
        cancellation,
    )
    .with_active_semantic_model_snapshot(active_semantic_model_snapshot.clone())
    .with_candidate_probe(&mut probe)
    .compile(policy, spec, None);
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
            store_channel_search: false,
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
        Ok(TaintPolicyCompilation::StaticGaps {
            gaps,
            incomplete_selectors,
            ..
        }) => unsolved(
            origin,
            observation,
            gaps.into_iter()
                .map(|gap| compile_boundary(&TaintPolicyCompileError::UnsupportedBinding(gap)))
                .chain(selection_gaps(&[], &incomplete_selectors, 0))
                .collect(),
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
            selection_answer,
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
                Vec::new(),
                |path| selector_endpoint_label(spec, path),
                budget.max_related_locations_per_finding(),
            );
            solve_candidate_regions(
                policy,
                spec,
                &flow_state,
                workspace,
                active_semantic_model_snapshot,
                cancellation,
                budget,
                (origin_key, origin_sites),
                (observation_key, observation_sites),
                roots,
                selection_answer,
                payload,
                gaps,
                compilation_elapsed,
                input_retention,
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
    spec: &ResolvedTaintPolicySpec,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    workspace: &WorkspaceAnalyzer,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    (origin_key, origin_sites): (SiteKey, Vec<CandidateSite>),
    (observation_key, observation_sites): (SiteKey, Vec<CandidateSite>),
    roots: Vec<CompiledTaintPolicyPlan>,
    selection_answer: super::StableDigest,
    payload: crate::projection::TaintProjectionPayload,
    selection_gaps: Vec<CandidateBoundary>,
    compilation_elapsed: std::time::Duration,
    mut input_retention: Option<&mut RetainedHeap>,
) -> Result<CandidatePass, String> {
    let flow_state = flow_state.into();
    let compiled_regions = roots.len();
    let store_channel_search = roots.iter().any(|root| {
        matches!(root.engine, super::TaintEngine::Icfg { .. }) && !root.store_writes.is_empty()
    }) && roots.iter().any(|root| {
        matches!(root.engine, super::TaintEngine::Icfg { .. }) && !root.store_reads.is_empty()
    });
    let policy_id = policy.definition().metadata.id.clone();
    let icfg_provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
        workspace,
        active_semantic_model_snapshot.clone(),
    );
    let mut metadata = HashMap::new();
    let mut plans = Vec::new();
    let mut kills = Vec::new();
    // Policy-wide, as an ordinary run states it, so a candidate pass reports
    // the same scope for the same gap.
    let sink_files = policy_sink_files(&roots);
    for root in roots {
        let binds = |endpoints: &[CompiledTaintEndpoint], key: &SiteKey| {
            endpoints
                .iter()
                .any(|endpoint| SiteKey::of(endpoint.event.site()) == *key)
        };
        let composed_store_root =
            matches!(root.engine, super::TaintEngine::Composition) && !root.store_reads.is_empty();
        if (!store_channel_search || matches!(root.engine, super::TaintEngine::Composition))
            && ((!binds(&root.sources, &origin_key) && !composed_store_root)
                || !binds(&root.sinks, &observation_key))
        {
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
                selected_entry_scope: root.selected_entry_scope,
                selection_answer,
                policy_id: policy_id.clone(),
                sources: root.sources,
                bound_source_inventory: root.bound_source_inventory,
                admitted_pattern_sites: root.admitted_pattern_sites,
                admission_stopped_sites: root.admission_stopped_sites,
                entry_points: root.entry_points,
                sinks: root.sinks,
                store_writes: root.store_writes,
                store_reads: root.store_reads,
                call_resolution_evidence: root.call_resolution_evidence,
                sanitizer_declines: root.sanitizer_declines,
                external_models: root.external_models,
                secondary: root.secondary,
                model_receipts: root.model_receipts,
                compilation_elapsed,
                engine: root.engine.clone(),
                sink_files: Arc::clone(&sink_files),
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
            store_channel_search,
            solve: None,
            evaluator: ProductionTaintPolicyEvaluator::default(),
        });
    }

    let mut payloads = HashMap::from([(policy_id.clone(), payload)]);
    let mut merge = BatchMerge::default();
    let mut boundaries = Vec::new();
    let mut public_findings = Vec::new();
    let mut retained_analyses = Vec::new();
    let mut retained_batch_indices = Vec::new();
    let mut retained_output_rows = Vec::new();
    let composed = metadata
        .values()
        .next()
        .is_some_and(|plan| matches!(&plan.engine, super::TaintEngine::Composition));
    let mut execution_budget = TaintExecutionBudget::new(budget);
    let planning_started = Instant::now();
    let batches = super::partition_taint_batches(plans).map_err(|error| error.to_string())?;
    let batch_planning_elapsed = planning_started.elapsed();
    let slot_count = if composed { batches.len() } else { 0 };
    let slot_bytes =
        slot_count.saturating_mul(std::mem::size_of::<Option<super::ComposedCandidateReport>>());
    if let Some(heap) = input_retention.as_deref_mut()
        && !heap.reserve_scratch(slot_bytes)
    {
        return Ok(CandidatePass::stopped(CandidateBoundary::new(
            CandidateBoundaryKind::OutputBudget,
            vec![PolicyIncompleteReason::ReportRetentionBudget],
            None,
            "the report allowance refused candidate input owner slots".to_owned(),
        )));
    }
    let mut slots = Box::<[Option<super::ComposedCandidateReport>]>::new_uninit_slice(slot_count);
    for slot in &mut slots {
        slot.write(None);
    }
    // SAFETY: every slot was initialized to None above.
    let slots = unsafe { slots.assume_init() };
    if let Some(heap) = input_retention.as_deref_mut()
        && slot_bytes != 0
        && !heap.adopt_allocation(slots.as_ptr() as usize, slot_bytes, slot_bytes)
    {
        drop(slots);
        heap.release_scratch(slot_bytes);
        return Ok(CandidatePass::stopped(CandidateBoundary::new(
            CandidateBoundaryKind::OutputBudget,
            vec![PolicyIncompleteReason::ReportRetentionBudget],
            None,
            "the report allowance refused candidate input owner census".to_owned(),
        )));
    }
    let mut composed_reports = super::CandidateComposition {
        spec,
        reports: slots,
        input_retention,
        batch_index: 0,
    };
    let seeding = super::seed_store_channels(
        &batches,
        &metadata,
        workspace,
        cancellation,
        budget,
        &mut execution_budget,
        &icfg_provider,
        &mut payloads,
        &mut merge,
    )?;
    super::narrow_store_source_metadata(&batches, &seeding, &mut metadata);
    let store_write_evidence = seeding.write_evidence_by_read(&batches);
    if seeding.uncertain
        && batches
            .iter()
            .any(|batch| !batch.analysis().store_reads().is_empty())
    {
        boundaries.push(CandidateBoundary::new(
            CandidateBoundaryKind::DiscoveryIncomplete,
            vec![PolicyIncompleteReason::PartialDiscovery],
            None,
            "a persistence-store observation solve stayed incomplete".to_owned(),
        ));
    }
    let composition_memo = CompositionMemo::default();
    for (batch_index, batch) in batches.iter().enumerate() {
        composed_reports.batch_index = batch_index;
        let seeds = &seeding.seeds[batch_index];
        let seed_classes = seeds
            .iter()
            .map(|seed| (seed.source, seed.classes.clone()))
            .collect::<Vec<_>>();
        let seeded_batch = if seed_classes.is_empty() {
            None
        } else {
            Some(
                batch
                    .with_seeded_store_reads(&seed_classes)
                    .map_err(|error| error.to_string())?,
            )
        };
        let batch = seeded_batch.as_ref().unwrap_or(batch);
        let retained_before = retained_analyses.len();
        let result = solve_and_project_batch(
            batch,
            &flow_state,
            seeds,
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
            &mut retained_output_rows,
            batch_planning_elapsed,
            active_semantic_model_snapshot.clone(),
            &icfg_provider,
            &store_write_evidence,
            &composition_memo,
            None,
            Some(&mut composed_reports),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        retained_batch_indices.extend(std::iter::repeat_n(
            batch_index,
            retained_analyses.len() - retained_before,
        ));
        let Err(failure) = result else {
            continue;
        };
        // A failed production/projection path may have dropped input owners
        // whose metadata was already admitted. Never reuse their pointer
        // records for a later batch or counterfactual allocation.
        if let Some(heap) = composed_reports.input_retention.as_deref_mut() {
            heap.refuse();
        }
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
            TaintBatchError::RefinementTerminated(termination) => {
                let reason = super::record_refinement_termination(payload, termination);
                let kind = if matches!(termination, SolverTermination::Cancelled) {
                    CandidateBoundaryKind::Cancelled
                } else {
                    CandidateBoundaryKind::AnalysisBudget
                };
                boundaries.push(CandidateBoundary::new(
                    kind,
                    vec![reason],
                    None,
                    format!("ICFG value-type barrier refinement stopped: {termination:?}"),
                ));
            }
            TaintBatchError::SourceCoverageIncomplete(cause) => {
                // Its sole constructor, icfg_batch_error, currently wraps a
                // retained-byte refusal; successful partial outcomes use their data path.
                super::record_source_coverage_incomplete(payload, &cause);
                boundaries.push(CandidateBoundary::new(
                    CandidateBoundaryKind::OutputBudget,
                    vec![PolicyIncompleteReason::ReportRetentionBudget],
                    None,
                    format!("ICFG source attribution coverage stopped: {cause:?}"),
                ));
            }
            TaintBatchError::Internal(message)
            | TaintBatchError::SemanticBudgetRefused(message) => {
                merge.envelopes.remove(&policy_id);
                *payload = prepared_failure_payload(&message, payload.work.clone());
                boundaries.push(invalid_plan(message));
            }
            TaintBatchError::UnitBudgetStop(_) => unreachable!(
                "only OutputUnitSlice::prefix passes selected sinks to compose_batch, \
                 and it turns the stop into the unit's product"
            ),
        }
    }

    let mut proven_by_summary = false;
    let mut reached = false;
    let mut witnesses = Vec::<Arc<SummaryWitness>>::new();
    let mut matched_store_crossings = Vec::new();
    let mut matched_seed_crossings = Vec::new();
    if composed {
        for composed in composed_reports.reports.iter().flatten() {
            let report = &composed.report;
            if !report.is_complete() {
                if report.is_proven_by_authored_summaries() {
                    proven_by_summary = true;
                } else {
                    boundaries.push(composed_boundary(
                        report,
                        composed.status.as_ref(),
                        &composed.causes,
                    ));
                }
            }
            reached |= read_candidate_reaches(
                workspace,
                report,
                &origin_key,
                &observation_key,
                &composed.store_crossings,
                None,
                &origin_sites,
                &mut boundaries,
                &mut witnesses,
                &mut matched_store_crossings,
                &mut matched_seed_crossings,
            )?;
        }
    } else {
        assert_eq!(retained_analyses.len(), retained_batch_indices.len());
        for (analysis, batch_index) in retained_analyses.iter().zip(retained_batch_indices) {
            let report = analysis.report();
            if !report.is_complete() {
                if report.is_proven_by_authored_summaries() {
                    proven_by_summary = true;
                } else {
                    boundaries.push(solve_boundary(workspace, analysis.plan(), report)?);
                }
            }
            reached |= read_candidate_reaches(
                workspace,
                report,
                &origin_key,
                &observation_key,
                &[],
                Some((&batches[batch_index], &seeding.seeds[batch_index])),
                &origin_sites,
                &mut boundaries,
                &mut witnesses,
                &mut matched_store_crossings,
                &mut matched_seed_crossings,
            )?;
        }
    }
    // A retained downstream path cannot certify the candidate when a store
    // observation solve left seed provenance incomplete.
    if seeding.uncertain {
        reached = false;
    }
    boundaries.sort_by(|left, right| {
        (left.kind, &left.detail, &left.reasons).cmp(&(right.kind, &right.detail, &right.reasons))
    });
    boundaries.dedup();
    let mut store_crossings = Vec::new();
    store_crossings.extend(matched_seed_crossings);
    for crossing in matched_store_crossings {
        let plan = metadata
            .values()
            .find(|plan| {
                plan.store_writes
                    .iter()
                    .any(|write| write.call.durable_key() == crossing.write_call)
                    && plan
                        .store_reads
                        .iter()
                        .any(|read| read.call.durable_key() == crossing.read_call)
            })
            .expect("a retained composed crossing has selected store ends");
        let (prefix, evidence) =
            composed_crossing_evidence(plan, &origin_sites[0].endpoint, &crossing);
        store_crossings.push((crossing.witness, Some(prefix), evidence));
    }
    let input_retention = composed_reports.input_retention.take();
    // Crossing metadata already served candidate projection above. It is not
    // an input to the collective theorem; do not extend a second copy's life.
    for result in composed_reports.reports.iter_mut().flatten() {
        result.store_crossings = Vec::new();
    }
    let inputs = if let Some(heap) = input_retention {
        // These are already computed production products, moved rather than
        // copied. One census stays live across BOTH passes: shared backing is
        // counted once, while its own index is admitted before allocation.
        if !composed && retained_analyses.capacity() != 0 {
            heap.allocation(
                retained_analyses.as_ptr() as usize,
                retained_analyses.capacity()
                    * std::mem::size_of::<Arc<ProductionTaintAnalysisResult>>(),
            );
        }
        for site in [&origin_key, &observation_key] {
            let path = site.path.as_str();
            if !path.is_empty() {
                heap.allocation(path.as_ptr() as usize, path.len());
            }
        }
        for sites in [&origin_sites, &observation_sites] {
            heap.vec(sites);
            for site in sites {
                heap.add(crate::retained::retained_extra(&site.endpoint));
                heap.add(crate::retained::retained_extra(&site.location));
            }
        }
        heap.vec(&kills);
        for kill in &kills {
            heap.add(crate::retained::retained_extra(&kill.site.endpoint));
            heap.add(crate::retained::retained_extra(&kill.site.location));
        }
        if composed {
            if batches.capacity() != 0 {
                heap.allocation(
                    batches.as_ptr() as usize,
                    batches.capacity() * std::mem::size_of::<TaintBatch>(),
                );
            }
            for batch in &batches {
                batch.retained_heap(heap);
            }
            for result in composed_reports.reports.iter().flatten() {
                result.report.retained_inputs_heap(heap);
                if let Some(inputs) = &result.inputs {
                    inputs.retained_heap(heap);
                }
            }
        } else {
            for analysis in &retained_analyses {
                ProductionTaintAnalysisResult::retained_heap(analysis, heap);
            }
        }
        if heap.is_refused() {
            CandidateInputs::RetentionRefused
        } else if composed {
            CandidateInputs::Composed {
                batches,
                reports: composed_reports.reports,
                origin: origin_key,
                observation: observation_key,
            }
        } else {
            CandidateInputs::Native {
                analyses: retained_analyses,
                origin: origin_key,
                observation: observation_key,
            }
        }
    } else {
        CandidateInputs::Unavailable("this question did not retain counterfactual input products")
    };
    Ok(CandidatePass {
        origin: CandidateBinding::Bound(origin_sites),
        observation: CandidateBinding::Bound(observation_sites),
        selection_gaps,
        compiled_regions,
        candidate_regions,
        store_channel_search,
        solve: Some(CandidateSolve {
            boundaries,
            proven_by_summary,
            reached,
            witnesses,
            store_crossings,
            kills,
            inputs,
        }),
        evaluator: ProductionTaintPolicyEvaluator {
            prepared: std::sync::Mutex::new(payloads),
            cpu_by_policy: Default::default(),
            cpu_unavailable_by_policy: Default::default(),
            preparation_reads: Default::default(),
            store_seeding_reads: None,
            public_findings: std::sync::Mutex::new(public_findings),
            retained_analyses: std::sync::Mutex::new(Vec::new()),
            retained_output_rows: std::sync::Mutex::new(Vec::new()),
        },
    })
}

/// The composition reports its own incomplete status. An ICFG plan's first
/// discovery cause is not an authority for this result.
fn composed_boundary(
    report: &TaintFindingReport,
    status: Option<&SemanticInputStatus>,
    causes: &[CandidateBoundaryCause],
) -> CandidateBoundary {
    let mut boundary = match report.result().termination() {
        SolverTermination::Cancelled => CandidateBoundary::new(
            CandidateBoundaryKind::Cancelled,
            vec![PolicyIncompleteReason::Cancelled],
            None,
            "the composed candidate search was cancelled".to_owned(),
        ),
        SolverTermination::ExceededBudget(exceeded) => CandidateBoundary::new(
            CandidateBoundaryKind::AnalysisBudget,
            vec![PolicyIncompleteReason::PartialDiscovery],
            None,
            format!("the composed candidate search exceeded its budget: {exceeded:?}"),
        ),
        SolverTermination::FixedPoint => {
            let (kind, reason) = match status {
                Some(SemanticInputStatus::Cancelled) => (
                    CandidateBoundaryKind::Cancelled,
                    PolicyIncompleteReason::Cancelled,
                ),
                Some(SemanticInputStatus::ExceededBudget { .. }) => (
                    CandidateBoundaryKind::AnalysisBudget,
                    PolicyIncompleteReason::PartialDiscovery,
                ),
                Some(SemanticInputStatus::Unsupported { .. }) => (
                    CandidateBoundaryKind::SemanticUnavailable,
                    PolicyIncompleteReason::CapabilityIncomplete,
                ),
                _ => (
                    CandidateBoundaryKind::OpenCoverage,
                    PolicyIncompleteReason::PartialDiscovery,
                ),
            };
            CandidateBoundary::new(
                kind,
                vec![reason],
                None,
                format!("the composed candidate retained an open boundary: {status:?}"),
            )
        }
    };
    // Kind and reasons above come only from the termination and status. The
    // records name where and why, so they cannot move a verdict; each cause is
    // rendered as its own child, and the boundary takes the first owner location.
    boundary.location = causes.iter().find_map(|cause| cause.location.clone());
    boundary.causes = causes.to_vec();
    boundary
}

/// Origin and witness evidence is the common report vocabulary. Each engine
/// supplies its own report and its own completeness boundary above.
#[allow(clippy::too_many_arguments)]
fn read_candidate_reaches(
    workspace: &WorkspaceAnalyzer,
    report: &TaintFindingReport,
    origin_key: &SiteKey,
    observation_key: &SiteKey,
    store_crossings: &[brokk_bifrost_flow::taint::compose::ComposedStoreCrossing],
    store_batch: Option<(&super::TaintBatch, &[StoreReadSeed])>,
    origin_sites: &[CandidateSite],
    boundaries: &mut Vec<CandidateBoundary>,
    witnesses: &mut Vec<Arc<SummaryWitness>>,
    matched_store_crossings: &mut Vec<brokk_bifrost_flow::taint::compose::ComposedStoreCrossing>,
    matched_seed_crossings: &mut Vec<(Arc<SummaryWitness>, Option<usize>, StoreCrossingProvenance)>,
) -> Result<bool, String> {
    let mut reached = false;
    for finding in report.findings() {
        if SiteKey::of(finding.key().sink().site()) != *observation_key {
            continue;
        }
        let mut origin_retained = false;
        for origin in finding.origins().evidence() {
            let direct = SiteKey::of(origin.origin().value_flow_key().site()) == *origin_key;
            let via_store = store_crossings.iter().any(|crossing| {
                super::composed_crossing_matches(crossing, origin.origin(), None)
                    && crossing.sink == *finding.key().sink()
                    && SiteKey::of(crossing.original_source.value_flow_key().site()) == *origin_key
            });
            let seeded = store_batch
                .map(|(batch, seeds)| {
                    seeds
                        .iter()
                        .filter(|seed| seed.event == *origin.origin().value_flow_key())
                        .flat_map(|seed| {
                            batch
                                .analysis()
                                .store_reads()
                                .iter()
                                .filter(move |read| read.source() == seed.source)
                                .flat_map(move |read| {
                                    seed.crossings.iter().filter(move |crossing| {
                                        crossing.read_channel == *read.channel()
                                            && origin_sites.iter().any(|site| {
                                                site.endpoint == crossing.source_endpoint
                                            })
                                            && SiteKey::of(crossing.source_event.site())
                                                == *origin_key
                                    })
                                })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !direct && !via_store && seeded.is_empty() {
                continue;
            }
            // A store crossing depends on the complete writer inventory and
            // every remote artifact visited by composition. A retained path
            // alone cannot discharge an open inventory.
            if (via_store || !seeded.is_empty()) && !report.is_complete() {
                continue;
            }
            origin_retained = true;
            for witness in origin.witnesses() {
                if !witnesses.contains(witness) {
                    witnesses.push(Arc::clone(witness));
                }
                matched_store_crossings.extend(
                    store_crossings
                        .iter()
                        .filter(|crossing| {
                            composed_crossing_matches(crossing, origin.origin(), Some(witness))
                                && crossing.sink == *finding.key().sink()
                                && SiteKey::of(crossing.original_source.value_flow_key().site())
                                    == *origin_key
                        })
                        .cloned(),
                );
                matched_seed_crossings.extend(
                    seeded
                        .iter()
                        .map(|crossing| (Arc::clone(witness), None, (*crossing).clone())),
                );
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
    Ok(reached)
}

/// One site in the analyzed source: a workspace path and an anchor byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SiteKey {
    path: WorkspaceRelativePath,
    span: Range<u32>,
}

impl SiteKey {
    fn matches(&self, locator: &SemanticLocator) -> bool {
        let span = locator.anchor().span();
        self.path == *locator.path()
            && self.span.start == span.start_byte()
            && self.span.end == span.end_byte()
    }

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
    refusals: &[RefusalNotice],
    incomplete_selectors: &[IncompleteTaintSelector],
    skipped_region_roots: usize,
) -> Vec<CandidateBoundary> {
    let mut gaps = Vec::new();
    if !incomplete_selectors.is_empty() {
        gaps.push(CandidateBoundary::new(
            CandidateBoundaryKind::DiscoveryIncomplete,
            vec![PolicyIncompleteReason::PartialDiscovery],
            None,
            format!(
                "endpoint selectors did not finish: {:?}",
                incomplete_selectors
                    .iter()
                    .map(|gap| gap.message.as_str())
                    .collect::<Vec<_>>()
            ),
        ));
    }
    let incomplete_refusals = refusals
        .iter()
        .filter(|refusal| refusal.impact == super::PolicyDiagnosticImpact::RunIncomplete)
        .collect::<Vec<_>>();
    if !incomplete_refusals.is_empty() {
        gaps.push(CandidateBoundary::new(
            CandidateBoundaryKind::RefusedSite,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
            None,
            brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                format_args!("selector rows bound no single site: {incomplete_refusals:?}"),
                format_args!("selector rows bound no single site"),
                incomplete_refusals.iter(),
            ),
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
            absence_reasons(completion),
        ),
        // Untranslated retained identities are a content limitation.
        TaintPolicyCompileError::CandidateLocatorRefusal(_)
        | TaintPolicyCompileError::ProcedureLocalLocatorRefusal(_)
        | TaintPolicyCompileError::SemanticProvider(_)
        | TaintPolicyCompileError::SemanticUnavailable(_)
        | TaintPolicyCompileError::AmbiguousSemanticSite(_) => (
            CandidateBoundaryKind::SemanticUnavailable,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
        ),
        TaintPolicyCompileError::UnknownFormalName { .. }
        | TaintPolicyCompileError::UnsupportedBinding(_)
        | TaintPolicyCompileError::UnsupportedBarrierEngine(_)
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
