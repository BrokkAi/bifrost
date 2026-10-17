//! Taint composition over per-procedure partial flows.
//!
//! A backward search from each bound sink over a port graph whose nodes are
//! `(procedure durable key, port)` finds the sources that can reach it
//! (stage 1). Labels are then evaluated forward along each retained path
//! (stage 2), and pairs whose reached classes meet the sink's accepted classes
//! become findings (stage 3). Every answer from outside the plan comes from a
//! [`CompositionProvider`].

mod graph;
mod labels;
mod provider;
mod report;
mod search;
#[cfg(test)]
mod tests;

use std::fmt;

pub use graph::{ComposedSourceId, Endpoint, Hop, HopQuality, PortNode};
pub use provider::{
    BlockedGap, BoundSanitizer, BoundSource, BoundTransform, CallModel, CallerLocation, Callers,
    Completeness, CompositionProvider, Dispatch, DispatchCandidate, EndpointEvidence,
    FallbackPorts, InteriorFlow, InteriorFlows, InteriorObservation, InteriorSeed, InteriorTarget,
    InteriorWitnessStep, ModelTransfer, Openness, ProcedureEndpoints, ValueTypeBarrierCheck,
    ValueTypeBarrierFindingNotes,
};
pub use search::{BudgetLane, Incompleteness, SearchStats, SourceSinkPair};

use crate::analyzer::semantic::SemanticRequest;
use crate::value_flow::DurableCallSiteKey;

use super::{TaintAnalysisPlan, TaintFindingError, TaintFindingReport};

/// Bounds on one composition. Exhausting a lane marks the batch incomplete
/// with the lane named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositionBudget {
    /// Distinct procedures whose flows the search reads.
    pub max_procedures: usize,
    /// Hops the search expands.
    pub max_hops: usize,
    /// Incoming calls enumerated for one procedure.
    pub max_callers_per_procedure: usize,
}

/// Why a composition produced no report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    /// The provider failed; its message is kept.
    Provider(Box<str>),
    /// The report could not be assembled.
    Report(TaintFindingError),
}

impl fmt::Display for ComposeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(message) => write!(formatter, "composition provider failed: {message}"),
            Self::Report(error) => write!(formatter, "composed taint report failed: {error}"),
        }
    }
}

impl std::error::Error for ComposeError {}

/// Evidence for one concrete source/sink pair, before public finding grouping.
/// A note-free lenient witness is also its strict witness without another run.
#[derive(Debug, Clone)]
pub struct ValueTypeBarrierPairEvidence {
    pub lenient: TaintFindingReport,
    /// None means that the concrete source/sink pair did not survive strict.
    pub strict: Option<TaintFindingReport>,
}

/// A composed report and every reason the composition may have missed a
/// flow, in the order they were found. The report is incomplete exactly when
/// `incompleteness` is non-empty or a sanitizer was unresolved.
///
/// `abstained` lists the calls at which a require-model policy declined to
/// carry a demand, in the order they were found. An abstention is not a
/// reason of its own: the ICFG engine's abstention changes neither the
/// completion nor the diagnostics of a run, which come from the call's
/// dispatch.
#[derive(Debug, Clone)]
pub struct ComposeOutcome {
    /// Lenient composition evidence; public barrier selection uses `barrier_pairs`.
    pub report: TaintFindingReport,
    pub incompleteness: Vec<Incompleteness>,
    /// Causes retained on partial findings, separate from run completion.
    pub finding_incompleteness: Vec<Incompleteness>,
    pub abstained: Vec<DurableCallSiteKey>,
    pub stats: SearchStats,
    pub barrier_notes: Vec<ValueTypeBarrierFindingNotes>,
    pub barrier_pairs: Vec<ValueTypeBarrierPairEvidence>,
}

/// Judge the evidence of every source with `Unknown` evidence that a reported
/// path starts at, once per source. The judgment
/// conjoins into the quality of each path from that source, and a source
/// whose evidence is not proven and complete leaves the run incomplete with
/// [`Incompleteness::SourceEvidence`], as the ICFG engine's plan does for a
/// bound source.
///
/// This is the one difference from the ICFG engine, which checks every
/// source of every region for completion: a source the search reached that
/// lies on no reported path keeps `Unknown` evidence, is not judged and
/// leaves the run's completion alone.
fn judge_reported_sources<Provider: CompositionProvider>(
    provider: &Provider,
    outcome: &mut search::SearchOutcome,
    labeled: &mut [labels::LabeledPath],
    request: &mut SemanticRequest<'_>,
) -> Result<(), ComposeError> {
    let mut judged: Vec<(ComposedSourceId, HopQuality)> = Vec::new();
    for path in labeled.iter_mut() {
        let source = &outcome.sources[path.source.index()];
        if source.evidence != EndpointEvidence::Unknown {
            continue;
        }
        let quality = match judged.iter().find(|(id, _)| *id == path.source) {
            Some((_, quality)) => *quality,
            None => {
                let quality = provider
                    .source_evidence(source, request)
                    .map_err(search::provider_error)?;
                judged.push((path.source, quality));
                quality
            }
        };
        path.quality = path.quality.conjoin(quality);
    }
    for (id, quality) in judged {
        let source = &mut outcome.sources[id.index()];
        source.evidence = EndpointEvidence::Known(quality);
        if !quality.is_certain() {
            let reason = Incompleteness::SourceEvidence {
                point: source.point.clone(),
            };
            if !outcome.incomplete.contains(&reason) {
                outcome.incomplete.push(reason);
            }
        }
    }
    Ok(())
}

/// Compose the plan's sinks with the plan's sources and the sources the
/// provider matches on the frontier, over the provider's port graph: stage 1
/// finds the source-sink pairs and their paths, stage 2 evaluates labels
/// along each path, and stage 3 reports the pairs that reach an accepted
/// class.
pub fn compose_taint_batch(
    plan: &TaintAnalysisPlan,
    provider: &impl CompositionProvider,
    budget: CompositionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<ComposeOutcome, ComposeError> {
    provider.reset_value_type_witnesses();
    let mut outcome = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.search");
        search::search_pairs(plan, provider, budget, request)?
    };
    let mut labeled = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.labels");
        labels::evaluate_pairs(plan, &outcome.sources, &outcome.pairs)
    };
    {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.source_evidence");
        judge_reported_sources(provider, &mut outcome, &mut labeled, request)?;
    }
    let (report, mut finding_incompleteness) = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.report");
        report::build_report(plan, provider, budget, &outcome, labeled, request)?
    };
    let mut barrier_pairs = Vec::new();
    if provider.has_value_type_barriers() {
        for pair in &outcome.pairs {
            let mut labeled =
                labels::evaluate_pairs(plan, &outcome.sources, std::slice::from_ref(pair));
            for path in &mut labeled {
                if let EndpointEvidence::Known(quality) =
                    outcome.sources[path.source.index()].evidence
                {
                    path.quality = path.quality.conjoin(quality);
                }
            }
            // Source judgments were already installed by the main report pass.
            let (lenient, _) =
                report::build_report(plan, provider, budget, &outcome, labeled, request)?;
            if lenient.findings().is_empty() {
                continue;
            }
            let strict = if let Some(strict) = outcome
                .strict_pairs
                .iter()
                .find(|strict| strict.source == pair.source && strict.sink == pair.sink)
            {
                let has_undecided = outcome.barrier_notes.iter().any(|notes| {
                    notes.source == outcome.sources[pair.source.index()].origin
                        && plan
                            .value_flow()
                            .sink(pair.sink)
                            .expect("a pair sink is live")
                            .key()
                            == &notes.sink
                });
                if !has_undecided {
                    // This witness already passed strict: do not recompute it.
                    Some(lenient.clone())
                } else {
                    provider.retain_strict_value_type_witness(
                        &outcome.sources[pair.source.index()],
                        pair.sink,
                    );
                    let mut labeled = labels::evaluate_pairs(
                        plan,
                        &outcome.sources,
                        std::slice::from_ref(strict),
                    );
                    for path in &mut labeled {
                        if let EndpointEvidence::Known(quality) =
                            outcome.sources[path.source.index()].evidence
                        {
                            path.quality = path.quality.conjoin(quality);
                        }
                    }
                    let (strict_report, reasons) =
                        report::build_report(plan, provider, budget, &outcome, labeled, request)?;
                    for reason in reasons {
                        if !finding_incompleteness.contains(&reason) {
                            finding_incompleteness.push(reason);
                        }
                    }
                    Some(strict_report)
                }
            } else {
                None
            };
            barrier_pairs.push(ValueTypeBarrierPairEvidence { lenient, strict });
        }
    }
    Ok(ComposeOutcome {
        report,
        finding_incompleteness,
        incompleteness: outcome.incomplete,
        abstained: outcome.abstained,
        stats: outcome.stats,
        barrier_notes: outcome.barrier_notes,
        barrier_pairs,
    })
}
