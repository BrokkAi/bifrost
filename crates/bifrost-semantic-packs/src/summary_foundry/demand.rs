//! The demand sweep (#1871 milestone 4.5).
//!
//! Stage 0's demand ranking measures which unmodeled calls actually block real
//! taint verdicts. The harness runs the repository's `require-model` taint
//! policy over a fixed corpus slice, records each run's completion, and for
//! every `Inconclusive` conclusion attributes the blocking boundaries the taint
//! report emits, tagged by boundary kind.
//!
//! The load-bearing diagnostic is the boundary-kind split. A blocker a procedure
//! summary can close (an unmodeled external call-through, a bodyless callee) is
//! separated from a blocker only engine work can close (an unresolved or
//! truncated virtual dispatch, a native source/sink boundary #1917, an analysis
//! limit, a deferred continuation). The engine-blocked share of the blocked
//! verdicts is the ceiling on what any pilot of summary content can move, so a
//! large share redirects effort to the engine before more summaries are authored.
//!
//! This module owns two things and no I/O:
//!
//! * the boundary vocabulary mapping (`classify_summary_boundary`) and the
//!   blocker extraction from a live [`TaintFindingReport`], and
//! * the pure aggregation ([`summarize`]) that ranks blockers and computes the
//!   baseline, both deterministic so the same slice yields a byte-identical
//!   report.
//!
//! The fleet driver that builds a workspace per repo and runs the policy
//! evaluator lives in the facade, because only the facade sees both this crate's
//! IR and `brokk-bifrost-policy`'s evaluator; this module is what that driver
//! calls to classify a report and to aggregate the run outcomes it collects.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost_analysis::analyzer::dataflow::SummaryBoundaryKind;
use brokk_bifrost_analysis::analyzer::semantic::{
    DeclarationSegmentKind, DispatchBoundaryKind, SemanticLocator,
};
use brokk_bifrost_analysis::analyzer::taint::TaintFindingReport;
use serde::{Deserialize, Serialize};

/// The schema tag for a written demand-sweep report. Bump it only when a reader
/// must interpret the artifact differently, not when a field is added.
pub const DEMAND_SWEEP_REPORT_FORMAT: &str = "bifrost_summary_foundry_demand_sweep/v1";

/// Which kind of work can close a blocker.
///
/// This is the milestone's load-bearing split: only `SummaryClosable` blockers
/// are what the procedure-summary foundry produces content for. `EngineBlocked`
/// blockers are orthogonal engine gaps a summary cannot touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerBucket {
    /// A summary can close it: the callee's body is unavailable and a procedure
    /// summary is exactly the model that describes its value flow.
    SummaryClosable,
    /// Only engine work can close it: there is no single external procedure a
    /// summary could attach to (unresolved or truncated dispatch), or the gap is
    /// a native source/sink boundary, an analysis limit, or a deferred body.
    EngineBlocked,
}

impl BlockerBucket {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SummaryClosable => "summary_closable",
            Self::EngineBlocked => "engine_blocked",
        }
    }
}

/// The boundary kind that blocked a verdict, in the demand sweep's own
/// vocabulary. Each variant maps to exactly one emitted `SummaryBoundaryKind`
/// shape, and each carries a fixed bucket.
///
/// The mapping is recorded here, beside the variants, so the boundary-kind ->
/// bucket decision is one table a reviewer reads rather than logic spread across
/// call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerBoundaryKind {
    /// `Dispatch(External(_))`: an unmodeled external call-through. The canonical
    /// thing a procedure summary fixes.
    ExternalCallThrough,
    /// `Dispatch(Unmaterialized(_))`: a resolved callee whose body is not
    /// materialized in the workspace (a native, abstract, or interface method
    /// with no analyzed body). A summary describes it the same way it describes
    /// any bodyless callee, so it is summary-closable. The report cannot yet
    /// subdivide a native callee from an abstract one at this boundary (the
    /// native flag milestone 2 added is not consumed here), which is recorded as
    /// a known coarseness rather than guessed at.
    UnmaterializedCallee,
    /// `Dispatch(Unresolved)`: virtual dispatch that named no target at all. No
    /// procedure exists to attach a summary to, so only dispatch resolution can
    /// close it.
    UnresolvedDispatch,
    /// `Dispatch(Truncated)`: dispatch resolution abandoned after too many arms.
    /// A summary on one arm cannot make the residual arms decidable.
    TruncatedDispatch,
    /// `Dispatch(Deferred{..})`: an async, generator, or language-defined
    /// continuation whose body runs later. Engine work, not a summary.
    DeferredContinuation,
    /// `Semantic(_)`: the provider envelope at this point was itself incomplete.
    /// The gap is upstream of any summary.
    SemanticEnvelope,
    /// `Limit(_)`: an analysis budget (call depth, nodes, or edges) cut the walk
    /// short. Raising the budget, not a summary, closes it.
    AnalysisLimit,
    /// `Continuation{..}`: a control continuation the solver could not follow.
    /// Engine work, not a summary.
    ControlContinuation,
}

impl BlockerBoundaryKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExternalCallThrough => "external_call_through",
            Self::UnmaterializedCallee => "unmaterialized_callee",
            Self::UnresolvedDispatch => "unresolved_dispatch",
            Self::TruncatedDispatch => "truncated_dispatch",
            Self::DeferredContinuation => "deferred_continuation",
            Self::SemanticEnvelope => "semantic_envelope",
            Self::AnalysisLimit => "analysis_limit",
            Self::ControlContinuation => "control_continuation",
        }
    }

    /// The fixed bucket for this boundary kind. This is the recorded mapping.
    pub const fn bucket(self) -> BlockerBucket {
        match self {
            Self::ExternalCallThrough | Self::UnmaterializedCallee => {
                BlockerBucket::SummaryClosable
            }
            Self::UnresolvedDispatch
            | Self::TruncatedDispatch
            | Self::DeferredContinuation
            | Self::SemanticEnvelope
            | Self::AnalysisLimit
            | Self::ControlContinuation => BlockerBucket::EngineBlocked,
        }
    }
}

/// Map one emitted taint boundary kind to the demand sweep's vocabulary.
///
/// The mapping is total over the emitted `SummaryBoundaryKind` shape, so a new
/// boundary variant fails to compile here rather than being silently dropped
/// into the wrong bucket.
pub fn classify_summary_boundary(kind: &SummaryBoundaryKind) -> BlockerBoundaryKind {
    match kind {
        SummaryBoundaryKind::Dispatch(dispatch) => match dispatch {
            DispatchBoundaryKind::External(_) => BlockerBoundaryKind::ExternalCallThrough,
            DispatchBoundaryKind::Unmaterialized(_) => BlockerBoundaryKind::UnmaterializedCallee,
            DispatchBoundaryKind::Unresolved => BlockerBoundaryKind::UnresolvedDispatch,
            DispatchBoundaryKind::Truncated => BlockerBoundaryKind::TruncatedDispatch,
            DispatchBoundaryKind::Deferred { .. } => BlockerBoundaryKind::DeferredContinuation,
        },
        SummaryBoundaryKind::Semantic(_) => BlockerBoundaryKind::SemanticEnvelope,
        SummaryBoundaryKind::Limit(_) => BlockerBoundaryKind::AnalysisLimit,
        SummaryBoundaryKind::Continuation { .. } => BlockerBoundaryKind::ControlContinuation,
    }
}

/// The blocked callee's stable spelling, `path#Type.member`, from the structured
/// locator the boundary retained. Boundary shapes with no named target (an
/// unresolved or truncated dispatch, an external boundary that kept no locator)
/// have no callee.
fn boundary_callee(kind: &SummaryBoundaryKind) -> Option<String> {
    let SummaryBoundaryKind::Dispatch(dispatch) = kind else {
        return None;
    };
    dispatch.target_locator().map(callee_spelling)
}

/// Spell a callee locator as `path#Type.member`, reading the declaration segment
/// structure rather than any source text. Two overloads collapse to one spelling
/// here, which is the right granularity for demand: a summary author models the
/// member, and the arity split is a downstream concern.
pub fn callee_spelling(locator: &SemanticLocator) -> String {
    let member = locator
        .declaration()
        .segments()
        .iter()
        .filter_map(|segment| match segment.kind() {
            DeclarationSegmentKind::Type
            | DeclarationSegmentKind::Method
            | DeclarationSegmentKind::Constructor => segment.name().map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".");
    format!("{}#{member}", locator.path().as_str())
}

/// One boundary the taint report attributed to a blocked verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockerObservation {
    pub kind: BlockerBoundaryKind,
    /// The blocked callee, when the boundary named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee: Option<String>,
}

impl BlockerObservation {
    pub fn bucket(&self) -> BlockerBucket {
        self.kind.bucket()
    }
}

/// Extract every open-boundary blocker a taint report emitted.
///
/// This reads the report's own coverage boundaries -- the structured record of
/// where the value-flow walk could not continue -- and classifies each. It is
/// the live counterpart of the hermetic aggregation below: the driver calls it
/// on a real `Inconclusive` run, the aggregation ranks what it collected.
pub fn blockers_from_report(report: &TaintFindingReport) -> Vec<BlockerObservation> {
    report
        .result()
        .fact_result()
        .coverage()
        .boundaries()
        .iter()
        .map(|boundary| {
            let kind = boundary.kind();
            BlockerObservation {
                kind: classify_summary_boundary(kind),
                callee: boundary_callee(kind),
            }
        })
        .collect()
}

/// How one policy run concluded, projected onto the buckets the sweep records.
///
/// The facade maps `PolicyRunCompletion` onto this; the mapping stays in the
/// facade because `PolicyRunCompletion` lives above this crate. A run is a clean
/// conclusion when it is any variant except `Inconclusive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionBucket {
    Complete,
    ProvenBySummary,
    ProvenSubset,
    Inconclusive,
    Unsupported,
    Failed,
}

impl CompletionBucket {
    /// Whether this conclusion counts toward the clean-conclusion baseline. Every
    /// terminating conclusion counts; only `Inconclusive` does not.
    pub const fn is_clean_conclusion(self) -> bool {
        !matches!(self, Self::Inconclusive)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ProvenBySummary => "proven_by_summary",
            Self::ProvenSubset => "proven_subset",
            Self::Inconclusive => "inconclusive",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
        }
    }
}

/// What happened to one repo in the sweep.
///
/// A repo the policy could not run over is its own datum, never a dropped repo:
/// a workspace that would not build, an evaluation that errored, or a run that
/// exceeded its time budget each take a bucket so the denominator stays honest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RepoOutcome {
    /// The policy ran and the taint run concluded.
    Ran {
        completion: CompletionBucket,
        findings: usize,
    },
    /// The workspace analyzer could not be built for this repo.
    WorkspaceBuildFailed { detail: String },
    /// Policy evaluation returned an error rather than a report.
    EvaluationFailed { detail: String },
    /// The run exceeded the per-repo time budget and was cancelled.
    TimedOut,
}

/// One repo's run outcome and the blockers attributed to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRunOutcome {
    pub repo: String,
    pub java_files: usize,
    pub outcome: RepoOutcome,
    /// Empty unless the run concluded `Inconclusive` with attributable
    /// boundaries. Deduplicated within the run so one blocker counts once toward
    /// this verdict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<BlockerObservation>,
    /// The typed reasons an `Inconclusive` run gave for abstaining, as the policy
    /// layer's own snake_case labels (`capability_incomplete`,
    /// `partial_discovery`, ...). Empty for a clean conclusion. This is the
    /// coarse, run-level abstention cause; it is recorded because a real
    /// require-model run over these workspaces abstains here rather than at a
    /// per-callee value-flow boundary, so the reason is the only structured
    /// account of why the verdict is not clean.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inconclusive_reasons: Vec<String>,
}

impl RepoRunOutcome {
    /// The distinct blockers this verdict carries, in sorted order.
    fn distinct_blockers(&self) -> Vec<BlockerObservation> {
        let mut blockers = self.blockers.clone();
        blockers.sort();
        blockers.dedup();
        blockers
    }

    fn is_inconclusive(&self) -> bool {
        matches!(
            self.outcome,
            RepoOutcome::Ran {
                completion: CompletionBucket::Inconclusive,
                ..
            }
        )
    }
}

/// One repo in the fixed slice, recorded so the slice is reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceRepo {
    pub name: String,
    pub java_files: usize,
    /// The git HEAD commit when the clone is a git checkout, else absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// How the fixed slice was chosen, recorded beside the repos it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceMeta {
    /// The reproducible rule that selected the repos, in prose.
    pub selection_rule: String,
    pub repos: Vec<SliceRepo>,
}

/// One ranked blocker: a boundary kind and optional callee, and how many
/// verdicts it blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedBlocker {
    pub kind: BlockerBoundaryKind,
    pub bucket: BlockerBucket,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee: Option<String>,
    /// How many distinct blocked verdicts (repos) this blocker appeared in.
    pub blocked_verdicts: usize,
    /// The complete set of repos it blocked, sorted, so the ranking is auditable.
    pub repos: Vec<String>,
}

/// The per-bucket verdict split, and the headline engine-blocked share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictBucketSplit {
    /// Blocked verdicts with at least one attributed blocker.
    pub blocked_verdicts: usize,
    /// Blocked verdicts every one of whose blockers is summary-closable: the
    /// verdicts a summary pilot could, in principle, fully close.
    pub verdicts_all_summary_closable: usize,
    /// Blocked verdicts carrying at least one engine-blocked blocker: a summary
    /// alone cannot close these.
    pub verdicts_with_engine_blocker: usize,
    /// `verdicts_with_engine_blocker / blocked_verdicts`, in permille (integer,
    /// so the artifact is byte-stable). This is the ceiling headline.
    pub engine_blocked_verdict_permille: u32,
}

/// Per-bucket counts over the distinct ranked blockers, for context beside the
/// per-verdict split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerBucketTotals {
    pub summary_closable: usize,
    pub engine_blocked: usize,
}

/// How the slice's runs landed across the outcome buckets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeTallies {
    pub complete: usize,
    pub proven_by_summary: usize,
    pub proven_subset: usize,
    pub inconclusive: usize,
    pub unsupported: usize,
    pub failed: usize,
    pub workspace_build_failed: usize,
    pub evaluation_failed: usize,
    pub timed_out: usize,
}

/// The whole deterministic demand-sweep report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemandSweepReport {
    pub format: String,
    pub slice: SliceMeta,
    /// Repos in the slice.
    pub repo_count: usize,
    /// Repos whose policy actually ran (a taint run concluded), the baseline
    /// denominator.
    pub evaluated_runs: usize,
    /// Evaluated runs that concluded non-`Inconclusive`.
    pub clean_conclusion_runs: usize,
    /// `clean_conclusion_runs / evaluated_runs`, in permille (integer).
    pub clean_conclusion_permille: u32,
    pub outcomes: OutcomeTallies,
    pub verdict_split: VerdictBucketSplit,
    pub blocker_bucket_totals: BlockerBucketTotals,
    /// How many `Inconclusive` verdicts each abstention reason appeared in, keyed
    /// by the policy layer's snake_case reason label, sorted. When the ranked
    /// blocker list is empty but verdicts are inconclusive, this is where the
    /// abstention cause is visible: a run-level reason such as
    /// `capability_incomplete`, which no procedure summary closes.
    pub inconclusive_reason_verdicts: BTreeMap<String, usize>,
    /// Blockers ranked by how many verdicts each blocked, descending, then by a
    /// stable key so the order is total.
    pub ranked_blockers: Vec<RankedBlocker>,
    /// Every repo's outcome, in the slice's order, so the artifact is auditable
    /// and no repo is a silent drop.
    pub repo_outcomes: Vec<RepoRunOutcome>,
}

/// A blocker's identity for aggregation: its kind and optional callee.
type BlockerKey = (BlockerBoundaryKind, Option<String>);

/// Aggregate per-repo run outcomes into the deterministic demand-sweep report.
///
/// This is pure: it takes what the driver collected and returns the ranking, the
/// baseline, and the bucket split with no I/O and no clock, so the same slice
/// yields a byte-identical report.
pub fn summarize(slice: SliceMeta, outcomes: &[RepoRunOutcome]) -> DemandSweepReport {
    let mut tallies = OutcomeTallies::default();
    let mut evaluated_runs = 0usize;
    let mut clean_conclusion_runs = 0usize;

    for outcome in outcomes {
        match &outcome.outcome {
            RepoOutcome::Ran { completion, .. } => {
                evaluated_runs += 1;
                if completion.is_clean_conclusion() {
                    clean_conclusion_runs += 1;
                }
                match completion {
                    CompletionBucket::Complete => tallies.complete += 1,
                    CompletionBucket::ProvenBySummary => tallies.proven_by_summary += 1,
                    CompletionBucket::ProvenSubset => tallies.proven_subset += 1,
                    CompletionBucket::Inconclusive => tallies.inconclusive += 1,
                    CompletionBucket::Unsupported => tallies.unsupported += 1,
                    CompletionBucket::Failed => tallies.failed += 1,
                }
            }
            RepoOutcome::WorkspaceBuildFailed { .. } => tallies.workspace_build_failed += 1,
            RepoOutcome::EvaluationFailed { .. } => tallies.evaluation_failed += 1,
            RepoOutcome::TimedOut => tallies.timed_out += 1,
        }
    }

    // Aggregate blockers across the inconclusive runs. Each blocker records the
    // set of verdicts (repos) it blocked; a blocker seen twice in one run counts
    // once for that verdict.
    let mut blocker_repos: BTreeMap<BlockerKey, BTreeSet<String>> = BTreeMap::new();
    let mut blocked_verdicts = 0usize;
    let mut verdicts_all_summary_closable = 0usize;
    let mut verdicts_with_engine_blocker = 0usize;
    // How many inconclusive verdicts carried each abstention reason. A reason
    // seen twice in one run counts once for that verdict.
    let mut inconclusive_reason_verdicts: BTreeMap<String, usize> = BTreeMap::new();

    for outcome in outcomes {
        if !outcome.is_inconclusive() {
            continue;
        }
        let mut reasons = outcome.inconclusive_reasons.clone();
        reasons.sort();
        reasons.dedup();
        for reason in reasons {
            *inconclusive_reason_verdicts.entry(reason).or_default() += 1;
        }
        let blockers = outcome.distinct_blockers();
        if blockers.is_empty() {
            continue;
        }
        blocked_verdicts += 1;
        let has_engine = blockers
            .iter()
            .any(|blocker| blocker.bucket() == BlockerBucket::EngineBlocked);
        if has_engine {
            verdicts_with_engine_blocker += 1;
        } else {
            verdicts_all_summary_closable += 1;
        }
        for blocker in blockers {
            blocker_repos
                .entry((blocker.kind, blocker.callee))
                .or_default()
                .insert(outcome.repo.clone());
        }
    }

    let mut ranked_blockers = blocker_repos
        .into_iter()
        .map(|((kind, callee), repos)| RankedBlocker {
            kind,
            bucket: kind.bucket(),
            callee,
            blocked_verdicts: repos.len(),
            repos: repos.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    // Rank by verdicts blocked, descending, then by a total stable key so two
    // runs over the same slice order identically.
    ranked_blockers.sort_by(|left, right| {
        right
            .blocked_verdicts
            .cmp(&left.blocked_verdicts)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.callee.cmp(&right.callee))
    });

    let blocker_bucket_totals = BlockerBucketTotals {
        summary_closable: ranked_blockers
            .iter()
            .filter(|blocker| blocker.bucket == BlockerBucket::SummaryClosable)
            .count(),
        engine_blocked: ranked_blockers
            .iter()
            .filter(|blocker| blocker.bucket == BlockerBucket::EngineBlocked)
            .count(),
    };

    DemandSweepReport {
        format: DEMAND_SWEEP_REPORT_FORMAT.to_owned(),
        repo_count: slice.repos.len(),
        evaluated_runs,
        clean_conclusion_runs,
        clean_conclusion_permille: permille(clean_conclusion_runs, evaluated_runs),
        outcomes: tallies,
        verdict_split: VerdictBucketSplit {
            blocked_verdicts,
            verdicts_all_summary_closable,
            verdicts_with_engine_blocker,
            engine_blocked_verdict_permille: permille(
                verdicts_with_engine_blocker,
                blocked_verdicts,
            ),
        },
        blocker_bucket_totals,
        inconclusive_reason_verdicts,
        ranked_blockers,
        repo_outcomes: outcomes.to_vec(),
        slice,
    }
}

/// `numerator / denominator` in permille, rounded to nearest, saturating. A zero
/// denominator yields zero, which the report's own counts disambiguate from a
/// genuine zero rate.
fn permille(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    let scaled = numerator as u128 * 1000 + denominator as u128 / 2;
    u32::try_from(scaled / denominator as u128).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic::DispatchBoundaryKind;

    fn observation(kind: BlockerBoundaryKind, callee: Option<&str>) -> BlockerObservation {
        BlockerObservation {
            kind,
            callee: callee.map(ToOwned::to_owned),
        }
    }

    fn inconclusive(repo: &str, blockers: Vec<BlockerObservation>) -> RepoRunOutcome {
        RepoRunOutcome {
            repo: repo.to_owned(),
            java_files: 1,
            outcome: RepoOutcome::Ran {
                completion: CompletionBucket::Inconclusive,
                findings: 0,
            },
            blockers,
            inconclusive_reasons: Vec::new(),
        }
    }

    fn inconclusive_with_reasons(repo: &str, reasons: &[&str]) -> RepoRunOutcome {
        RepoRunOutcome {
            repo: repo.to_owned(),
            java_files: 1,
            outcome: RepoOutcome::Ran {
                completion: CompletionBucket::Inconclusive,
                findings: 0,
            },
            blockers: Vec::new(),
            inconclusive_reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
        }
    }

    fn concluded(repo: &str, completion: CompletionBucket) -> RepoRunOutcome {
        RepoRunOutcome {
            repo: repo.to_owned(),
            java_files: 1,
            outcome: RepoOutcome::Ran {
                completion,
                findings: 0,
            },
            blockers: Vec::new(),
            inconclusive_reasons: Vec::new(),
        }
    }

    fn slice(names: &[&str]) -> SliceMeta {
        SliceMeta {
            selection_rule: "test".to_owned(),
            repos: names
                .iter()
                .map(|name| SliceRepo {
                    name: (*name).to_owned(),
                    java_files: 1,
                    commit: None,
                })
                .collect(),
        }
    }

    #[test]
    fn the_boundary_mapping_buckets_every_dispatch_shape() {
        // The two summary-closable dispatch shapes.
        assert_eq!(
            classify_summary_boundary(&SummaryBoundaryKind::Dispatch(
                DispatchBoundaryKind::External(None)
            )),
            BlockerBoundaryKind::ExternalCallThrough
        );
        assert_eq!(
            BlockerBoundaryKind::ExternalCallThrough.bucket(),
            BlockerBucket::SummaryClosable
        );
        // The engine-blocked residual dispatch shapes.
        assert_eq!(
            classify_summary_boundary(&SummaryBoundaryKind::Dispatch(
                DispatchBoundaryKind::Unresolved
            )),
            BlockerBoundaryKind::UnresolvedDispatch
        );
        assert_eq!(
            classify_summary_boundary(&SummaryBoundaryKind::Dispatch(
                DispatchBoundaryKind::Truncated
            )),
            BlockerBoundaryKind::TruncatedDispatch
        );
        assert_eq!(
            BlockerBoundaryKind::UnresolvedDispatch.bucket(),
            BlockerBucket::EngineBlocked
        );
        assert_eq!(
            BlockerBoundaryKind::TruncatedDispatch.bucket(),
            BlockerBucket::EngineBlocked
        );
        // An external boundary that kept no locator has no callee.
        assert_eq!(
            boundary_callee(&SummaryBoundaryKind::Dispatch(
                DispatchBoundaryKind::External(None)
            )),
            None
        );
    }

    #[test]
    fn ranking_orders_by_verdicts_blocked_then_a_stable_key() {
        // `gizmo` blocks three verdicts, `widget` two, an unresolved dispatch
        // one. The ranking must be gizmo, widget, unresolved.
        let outcomes = vec![
            inconclusive(
                "a",
                vec![
                    observation(
                        BlockerBoundaryKind::ExternalCallThrough,
                        Some("p#Gizmo.run"),
                    ),
                    observation(
                        BlockerBoundaryKind::ExternalCallThrough,
                        Some("p#Widget.tick"),
                    ),
                ],
            ),
            inconclusive(
                "b",
                vec![
                    observation(
                        BlockerBoundaryKind::ExternalCallThrough,
                        Some("p#Gizmo.run"),
                    ),
                    observation(
                        BlockerBoundaryKind::ExternalCallThrough,
                        Some("p#Widget.tick"),
                    ),
                ],
            ),
            inconclusive(
                "c",
                vec![
                    observation(
                        BlockerBoundaryKind::ExternalCallThrough,
                        Some("p#Gizmo.run"),
                    ),
                    observation(BlockerBoundaryKind::UnresolvedDispatch, None),
                ],
            ),
        ];
        let report = summarize(slice(&["a", "b", "c"]), &outcomes);

        let ranked = &report.ranked_blockers;
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].callee.as_deref(), Some("p#Gizmo.run"));
        assert_eq!(ranked[0].blocked_verdicts, 3);
        assert_eq!(ranked[0].repos, vec!["a", "b", "c"]);
        assert_eq!(ranked[1].callee.as_deref(), Some("p#Widget.tick"));
        assert_eq!(ranked[1].blocked_verdicts, 2);
        assert_eq!(ranked[2].kind, BlockerBoundaryKind::UnresolvedDispatch);
        assert_eq!(ranked[2].blocked_verdicts, 1);
    }

    #[test]
    fn the_bucket_split_reports_the_engine_blocked_ceiling() {
        // Two verdicts a summary could fully close, one that also has an
        // engine-blocked boundary: the engine-blocked ceiling is 1 of 3.
        let outcomes = vec![
            inconclusive(
                "a",
                vec![observation(
                    BlockerBoundaryKind::ExternalCallThrough,
                    Some("p#A.m"),
                )],
            ),
            inconclusive(
                "b",
                vec![observation(
                    BlockerBoundaryKind::UnmaterializedCallee,
                    Some("p#B.m"),
                )],
            ),
            inconclusive(
                "c",
                vec![
                    observation(BlockerBoundaryKind::ExternalCallThrough, Some("p#C.m")),
                    observation(BlockerBoundaryKind::UnresolvedDispatch, None),
                ],
            ),
        ];
        let report = summarize(slice(&["a", "b", "c"]), &outcomes);

        assert_eq!(report.verdict_split.blocked_verdicts, 3);
        assert_eq!(report.verdict_split.verdicts_all_summary_closable, 2);
        assert_eq!(report.verdict_split.verdicts_with_engine_blocker, 1);
        // 1 of 3 is 333 permille (rounded).
        assert_eq!(report.verdict_split.engine_blocked_verdict_permille, 333);
        assert_eq!(report.blocker_bucket_totals.summary_closable, 3);
        assert_eq!(report.blocker_bucket_totals.engine_blocked, 1);
    }

    #[test]
    fn the_baseline_counts_every_non_inconclusive_conclusion_as_clean() {
        let outcomes = vec![
            concluded("a", CompletionBucket::Complete),
            concluded("b", CompletionBucket::ProvenBySummary),
            inconclusive(
                "c",
                vec![observation(BlockerBoundaryKind::UnresolvedDispatch, None)],
            ),
            RepoRunOutcome {
                repo: "d".to_owned(),
                java_files: 1,
                outcome: RepoOutcome::WorkspaceBuildFailed {
                    detail: "boom".to_owned(),
                },
                blockers: Vec::new(),
                inconclusive_reasons: Vec::new(),
            },
        ];
        let report = summarize(slice(&["a", "b", "c", "d"]), &outcomes);

        // Three runs evaluated (a, b, c); the build failure is not a run.
        assert_eq!(report.evaluated_runs, 3);
        assert_eq!(report.clean_conclusion_runs, 2);
        // 2 of 3 clean is 667 permille (rounded).
        assert_eq!(report.clean_conclusion_permille, 667);
        assert_eq!(report.outcomes.complete, 1);
        assert_eq!(report.outcomes.proven_by_summary, 1);
        assert_eq!(report.outcomes.inconclusive, 1);
        assert_eq!(report.outcomes.workspace_build_failed, 1);
        assert_eq!(report.repo_count, 4);
    }

    #[test]
    fn a_blocker_seen_twice_in_one_run_counts_once_for_that_verdict() {
        let outcomes = vec![inconclusive(
            "a",
            vec![
                observation(BlockerBoundaryKind::ExternalCallThrough, Some("p#A.m")),
                observation(BlockerBoundaryKind::ExternalCallThrough, Some("p#A.m")),
            ],
        )];
        let report = summarize(slice(&["a"]), &outcomes);
        assert_eq!(report.ranked_blockers.len(), 1);
        assert_eq!(report.ranked_blockers[0].blocked_verdicts, 1);
        assert_eq!(report.verdict_split.blocked_verdicts, 1);
    }

    #[test]
    fn inconclusive_reasons_tally_across_verdicts_even_with_no_blockers() {
        // The realistic-sweep shape: inconclusive verdicts that carry a run-level
        // abstention reason but no per-callee blocker. The reason tally is where
        // the abstention cause stays visible.
        let outcomes = vec![
            inconclusive_with_reasons("a", &["capability_incomplete"]),
            inconclusive_with_reasons("b", &["capability_incomplete", "partial_discovery"]),
            concluded("c", CompletionBucket::Complete),
        ];
        let report = summarize(slice(&["a", "b", "c"]), &outcomes);

        assert!(report.ranked_blockers.is_empty());
        assert_eq!(report.verdict_split.blocked_verdicts, 0);
        assert_eq!(
            report
                .inconclusive_reason_verdicts
                .get("capability_incomplete"),
            Some(&2)
        );
        assert_eq!(
            report.inconclusive_reason_verdicts.get("partial_discovery"),
            Some(&1)
        );
        assert_eq!(report.outcomes.inconclusive, 2);
    }

    #[test]
    fn the_report_round_trips_through_json_byte_identically() {
        let outcomes = vec![
            concluded("a", CompletionBucket::Complete),
            inconclusive(
                "b",
                vec![observation(
                    BlockerBoundaryKind::ExternalCallThrough,
                    Some("p#A.m"),
                )],
            ),
        ];
        let report = summarize(slice(&["a", "b"]), &outcomes);
        let first = serde_json::to_string_pretty(&report).expect("serializes");
        let decoded: DemandSweepReport = serde_json::from_str(&first).expect("round trips");
        let second = serde_json::to_string_pretty(&decoded).expect("re-serializes");
        assert_eq!(first, second);
    }
}
