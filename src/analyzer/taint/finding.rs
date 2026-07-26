use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use crate::analyzer::dataflow::{
    PathQualityFrontier, SummaryEntry, SummaryWitnessError, WitnessReconstructionLimits,
};
use crate::analyzer::semantic::{SemanticArtifactKey, SemanticLocator};
use crate::analyzer::value_flow::{ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowSinkId};

use super::{
    SourceEventKey, TaintAnalysisPlan, TaintClassSet, TaintSummaryResult, TaintUniverseHash,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintFindingKey {
    universe: TaintUniverseHash,
    snapshot: SemanticArtifactKey,
    sink: ValueFlowEventKey,
    entry: SemanticLocator,
    entry_carrier: Option<ValueFlowCarrierKey>,
    entry_uncertain: bool,
    meeting_site: SemanticLocator,
    meeting_uncertain: bool,
}

impl TaintFindingKey {
    pub const fn universe(&self) -> TaintUniverseHash {
        self.universe
    }

    pub const fn sink(&self) -> &ValueFlowEventKey {
        &self.sink
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintOriginStatus {
    origins: Box<[SourceEventKey]>,
    origin_truncated: bool,
    witness_truncated: bool,
    witness_unavailable: bool,
}

impl TaintOriginStatus {
    pub const fn origins(&self) -> &[SourceEventKey] {
        &self.origins
    }

    pub const fn origin_truncated(&self) -> bool {
        self.origin_truncated
    }

    pub const fn witness_truncated(&self) -> bool {
        self.witness_truncated
    }

    pub const fn witness_unavailable(&self) -> bool {
        self.witness_unavailable
    }

    pub const fn is_complete(&self) -> bool {
        !self.origin_truncated && !self.witness_truncated && !self.witness_unavailable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFinding {
    key: TaintFindingKey,
    sink: ValueFlowSinkId,
    classes: TaintClassSet,
    entry: SummaryEntry,
    path_qualities: PathQualityFrontier,
    proven: bool,
    complete: bool,
    origins: TaintOriginStatus,
}

impl TaintFinding {
    pub const fn key(&self) -> &TaintFindingKey {
        &self.key
    }

    pub const fn sink(&self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn classes(&self) -> &TaintClassSet {
        &self.classes
    }

    pub const fn entry(&self) -> &SummaryEntry {
        &self.entry
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }

    pub const fn is_proven(&self) -> bool {
        self.proven
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub const fn origins(&self) -> &TaintOriginStatus {
        &self.origins
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFindingReport {
    result: TaintSummaryResult,
    findings: Box<[TaintFinding]>,
}

impl TaintFindingReport {
    pub const fn result(&self) -> &TaintSummaryResult {
        &self.result
    }

    pub fn findings(&self) -> &[TaintFinding] {
        &self.findings
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_complete()
    }
}

pub fn collect_taint_findings(
    plan: &TaintAnalysisPlan,
    result: TaintSummaryResult,
    max_origins_per_finding: usize,
    witness_limits: WitnessReconstructionLimits,
) -> Result<TaintFindingReport, TaintFindingError> {
    if max_origins_per_finding == 0 {
        return Err(TaintFindingError::InvalidOriginLimit);
    }
    if !Arc::ptr_eq(plan.owner(), result.owner()) {
        return Err(TaintFindingError::PlanMismatch);
    }
    let mut findings = Vec::new();
    for point_value in result.point_values() {
        let fact = *result
            .fact_result()
            .fact(point_value.fact())
            .ok_or(TaintFindingError::InvalidResult)?;
        let Some(sink) = fact.sink() else {
            continue;
        };
        let Some(binding) = plan.sink(sink) else {
            return Err(TaintFindingError::InvalidResult);
        };
        let value = result
            .value(point_value.value())
            .ok_or(TaintFindingError::InvalidResult)?;
        let classes = value.intersection(binding.accepted());
        if classes.is_empty() {
            continue;
        }
        let sink_spec = plan
            .value_flow()
            .sink(sink)
            .ok_or(TaintFindingError::InvalidResult)?;
        let entry = point_value.entry().clone();
        let entry_fact = *result
            .fact_result()
            .fact(entry.entry_fact())
            .ok_or(TaintFindingError::InvalidResult)?;
        let entry_carrier = entry_fact
            .carrier()
            .map(|carrier| {
                plan.value_flow()
                    .carrier_key(carrier)
                    .cloned()
                    .ok_or(TaintFindingError::InvalidResult)
            })
            .transpose()?;
        let key = TaintFindingKey {
            universe: plan.universe().hash(),
            snapshot: plan.value_flow().root().artifact().key().clone(),
            sink: sink_spec.key().clone(),
            entry: point_locator(entry.entry_point())?,
            entry_carrier,
            entry_uncertain: entry_fact.is_uncertain(),
            meeting_site: point_locator(point_value.point())?,
            meeting_uncertain: fact.is_uncertain(),
        };
        let origins = reconstruct_origins(
            plan,
            &result,
            point_value,
            &classes,
            max_origins_per_finding,
            witness_limits,
        )?;
        findings.push(TaintFinding {
            key,
            sink,
            classes,
            entry,
            path_qualities: point_value.path_qualities(),
            proven: !fact.is_uncertain()
                && result.termination().is_fixed_point()
                && result.coverage().unproven_edges().is_empty()
                && result.coverage().partial_edges().is_empty()
                && point_value.path_qualities().has_proven_path(),
            complete: result.is_complete() && point_value.path_qualities().has_complete_path(),
            origins,
        });
    }
    findings.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(TaintFindingReport {
        result,
        findings: findings.into_boxed_slice(),
    })
}

fn reconstruct_origins(
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    point_value: &crate::analyzer::dataflow::IdePointValue,
    classes: &TaintClassSet,
    limit: usize,
    witness_limits: WitnessReconstructionLimits,
) -> Result<TaintOriginStatus, TaintFindingError> {
    let reached = result
        .fact_result()
        .reached()
        .iter()
        .find(|reached| {
            reached.entry() == point_value.entry()
                && reached.point() == point_value.point()
                && reached.fact() == point_value.fact()
        })
        .ok_or(TaintFindingError::InvalidResult)?;
    let mut origins = BTreeSet::new();
    let mut origin_truncated = false;
    let mut witness_unavailable = false;
    let mut witness_truncated = false;
    let problem = super::TaintFlowProblem::new(plan);
    for quality in point_value.path_qualities().iter() {
        match result
            .fact_result()
            .witness_for_reached(reached, quality, witness_limits)
        {
            Ok(witness) => {
                witness_truncated |= witness.truncated()
                    || witness.alternatives_truncated()
                    || witness.retention_truncated();
                for step in witness.steps() {
                    let input = result
                        .fact_result()
                        .fact(step.input_fact())
                        .copied()
                        .ok_or(TaintFindingError::InvalidResult)?;
                    if !input.is_zero() {
                        continue;
                    }
                    let output = result
                        .fact_result()
                        .fact(step.output_fact())
                        .copied()
                        .ok_or(TaintFindingError::InvalidResult)?;
                    for source in plan.sources().iter().filter(|source| {
                        plan.value_flow()
                            .source(source.source())
                            .is_some_and(|spec| spec.point() == step.source())
                    }) {
                        if !problem
                            .source_contribution(source.source(), output, step)
                            .intersects(classes)
                        {
                            continue;
                        }
                        origins.insert(source.origin().clone());
                        if origins.len() > limit {
                            origins.pop_last();
                            origin_truncated = true;
                        }
                    }
                }
            }
            Err(SummaryWitnessError::RetentionDisabled) => witness_unavailable = true,
            Err(SummaryWitnessError::QualityNotRetained(_)) => witness_truncated = true,
            Err(error) => return Err(TaintFindingError::Witness(error)),
        }
    }
    Ok(TaintOriginStatus {
        origins: origins.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        origin_truncated,
        witness_truncated,
        witness_unavailable,
    })
}

fn point_locator(
    point: &crate::analyzer::semantic::ProgramPointHandle,
) -> Result<SemanticLocator, TaintFindingError> {
    let row = point
        .procedure()
        .semantics()
        .point(point.id())
        .ok_or(TaintFindingError::InvalidResult)?;
    point
        .procedure()
        .semantics()
        .source_mapping(row.source)
        .map(|mapping| mapping.locator.clone())
        .ok_or(TaintFindingError::InvalidResult)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintFindingError {
    InvalidOriginLimit,
    PlanMismatch,
    InvalidResult,
    Witness(SummaryWitnessError),
}

impl fmt::Display for TaintFindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOriginLimit => formatter.write_str("taint origin limit must be positive"),
            Self::PlanMismatch => formatter.write_str("taint result belongs to another plan"),
            Self::InvalidResult => formatter.write_str("taint result does not match its plan"),
            Self::Witness(error) => error.fmt(formatter),
        }
    }
}

impl Error for TaintFindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Witness(error) => Some(error),
            Self::InvalidOriginLimit | Self::PlanMismatch | Self::InvalidResult => None,
        }
    }
}
