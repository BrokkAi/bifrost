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
    InteriorWitnessStep, ModelTransfer, Openness, ProcedureEndpoints,
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
    pub report: TaintFindingReport,
    pub incompleteness: Vec<Incompleteness>,
    /// Causes retained on partial findings, separate from run completion.
    pub finding_incompleteness: Vec<Incompleteness>,
    pub abstained: Vec<DurableCallSiteKey>,
    pub stats: SearchStats,
}

/// Judge the evidence of every source with `Unknown` evidence that a reported
/// path starts at, once per source (spec M4.2, stage 3). The judgment
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
    let (report, finding_incompleteness) = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.report");
        report::build_report(plan, provider, budget, &outcome, labeled, request)?
    };
    Ok(ComposeOutcome {
        report,
        finding_incompleteness,
        incompleteness: outcome.incomplete,
        abstained: outcome.abstained,
        stats: outcome.stats,
    })
}
