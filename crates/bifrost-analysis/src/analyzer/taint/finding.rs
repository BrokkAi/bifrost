use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use crate::analyzer::dataflow::{
    PathQualityFrontier, SummaryWitness, SummaryWitnessError, WitnessReconstructionLimits,
};
use crate::analyzer::semantic::{
    ProcedureHandle, ProgramPointHandle, SemanticArtifactKey, SemanticLocator,
};
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
    evidence: Box<[TaintOriginFindingEvidence]>,
    origin_truncated: bool,
    witness_truncated: bool,
    witness_unavailable: bool,
}

/// Exact retained evidence for one source occurrence contributing to a finding.
///
/// The class set is computed at the source step by the taint problem rather
/// than reconstructed later from policy labels. Witnesses are the bounded
/// values already reconstructed while collecting the finding; consumers must
/// not invoke the solver again to project them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintOriginFindingEvidence {
    origin: SourceEventKey,
    classes: TaintClassSet,
    witnesses: Box<[Arc<SummaryWitness>]>,
}

impl TaintOriginFindingEvidence {
    pub const fn origin(&self) -> &SourceEventKey {
        &self.origin
    }

    pub const fn classes(&self) -> &TaintClassSet {
        &self.classes
    }

    pub const fn witnesses(&self) -> &[Arc<SummaryWitness>] {
        &self.witnesses
    }
}

/// Stable semantic entry attached to one finding.
///
/// This retains the sink-owning procedure and its live entry fact rather than
/// a query-local `FactId`, so cached transitive observations and uncached
/// callee observations compare identically after actual-to-formal remapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFindingEntry {
    procedure: ProcedureHandle,
    point: ProgramPointHandle,
    fact: super::TaintFact,
}

impl TaintFindingEntry {
    pub const fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn fact(&self) -> super::TaintFact {
        self.fact
    }
}

impl TaintOriginStatus {
    pub const fn origins(&self) -> &[SourceEventKey] {
        &self.origins
    }

    pub const fn evidence(&self) -> &[TaintOriginFindingEvidence] {
        &self.evidence
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
    entry: TaintFindingEntry,
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

    pub const fn entry(&self) -> &TaintFindingEntry {
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
    collection_truncated: bool,
    omitted_findings_lower_bound: usize,
    retained_witnesses: usize,
    retained_witness_steps: usize,
    witness_expansions: usize,
    retained_witness_bytes: usize,
}

impl TaintFindingReport {
    pub const fn result(&self) -> &TaintSummaryResult {
        &self.result
    }

    pub fn findings(&self) -> &[TaintFinding] {
        &self.findings
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_complete() && !self.collection_truncated
    }

    pub const fn omitted_findings_lower_bound(&self) -> usize {
        self.omitted_findings_lower_bound
    }

    pub const fn retained_witnesses(&self) -> usize {
        self.retained_witnesses
    }

    pub const fn retained_witness_steps(&self) -> usize {
        self.retained_witness_steps
    }

    pub const fn witness_expansions(&self) -> usize {
        self.witness_expansions
    }

    pub const fn retained_witness_bytes(&self) -> usize {
        self.retained_witness_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintFindingCollectionLimits {
    pub max_findings: usize,
    pub max_witnesses: usize,
    pub max_witness_steps: usize,
    pub max_witness_expansions: usize,
    pub max_retained_witness_bytes: usize,
}

impl TaintFindingCollectionLimits {
    pub fn new(
        max_findings: usize,
        max_witnesses: usize,
        max_witness_steps: usize,
        max_witness_expansions: usize,
        max_retained_witness_bytes: usize,
    ) -> Result<Self, TaintFindingError> {
        if [
            max_findings,
            max_witnesses,
            max_witness_steps,
            max_witness_expansions,
            max_retained_witness_bytes,
        ]
        .contains(&0)
        {
            return Err(TaintFindingError::InvalidCollectionLimits);
        }
        Ok(Self {
            max_findings,
            max_witnesses,
            max_witness_steps,
            max_witness_expansions,
            max_retained_witness_bytes,
        })
    }
}

#[derive(Debug)]
struct CollectionBudget {
    limits: TaintFindingCollectionLimits,
    witnesses: usize,
    witness_steps: usize,
    witness_expansions: usize,
    retained_witness_bytes: usize,
    truncated: bool,
}

pub fn collect_taint_findings(
    plan: &TaintAnalysisPlan,
    result: TaintSummaryResult,
    max_origins_per_finding: usize,
    witness_limits: WitnessReconstructionLimits,
) -> Result<TaintFindingReport, TaintFindingError> {
    collect_taint_findings_with_limits(
        plan,
        result,
        max_origins_per_finding,
        witness_limits,
        TaintFindingCollectionLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        )?,
    )
}

pub fn collect_taint_findings_with_limits(
    plan: &TaintAnalysisPlan,
    result: TaintSummaryResult,
    max_origins_per_finding: usize,
    witness_limits: WitnessReconstructionLimits,
    collection_limits: TaintFindingCollectionLimits,
) -> Result<TaintFindingReport, TaintFindingError> {
    if max_origins_per_finding == 0 {
        return Err(TaintFindingError::InvalidOriginLimit);
    }
    if !Arc::ptr_eq(plan.owner(), result.owner()) {
        return Err(TaintFindingError::PlanMismatch);
    }
    let mut findings = Vec::new();
    let mut budget = CollectionBudget {
        limits: collection_limits,
        witnesses: 0,
        witness_steps: 0,
        witness_expansions: 0,
        retained_witness_bytes: 0,
        truncated: false,
    };
    let mut omitted_findings_lower_bound = 0usize;
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
        if findings.len() == budget.limits.max_findings {
            omitted_findings_lower_bound = omitted_findings_lower_bound.saturating_add(1);
            budget.truncated = true;
            continue;
        }
        let sink_spec = plan
            .value_flow()
            .sink(sink)
            .ok_or(TaintFindingError::InvalidResult)?;
        let reached_entry = point_value.entry();
        let reached_entry_fact = *result
            .fact_result()
            .fact(reached_entry.entry_fact())
            .ok_or(TaintFindingError::InvalidResult)?;
        let entry_fact = fact.meeting_entry_fact().unwrap_or(reached_entry_fact);
        let entry_procedure = sink_spec.point().procedure().clone();
        let entry_point = entry_procedure
            .point_handle(entry_procedure.semantics().entry_point())
            .ok_or(TaintFindingError::InvalidResult)?;
        let entry = TaintFindingEntry {
            procedure: entry_procedure,
            point: entry_point,
            fact: entry_fact,
        };
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
            entry: point_locator(entry.point())?,
            entry_carrier,
            entry_uncertain: entry_fact.is_uncertain(),
            // A meeting fact is materialized on the edge leaving the sink
            // point, so its reached point is an implementation detail rather
            // than the semantic observation site.
            meeting_site: sink_spec.key().site().clone(),
            meeting_uncertain: fact.is_uncertain(),
        };
        let origins = reconstruct_origins(
            plan,
            &result,
            point_value,
            &classes,
            max_origins_per_finding,
            witness_limits,
            &mut budget,
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
        collection_truncated: budget.truncated,
        omitted_findings_lower_bound,
        retained_witnesses: budget.witnesses,
        retained_witness_steps: budget.witness_steps,
        witness_expansions: budget.witness_expansions,
        retained_witness_bytes: budget.retained_witness_bytes,
    })
}

fn reconstruct_origins(
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    point_value: &crate::analyzer::dataflow::IdePointValue,
    classes: &TaintClassSet,
    limit: usize,
    witness_limits: WitnessReconstructionLimits,
    budget: &mut CollectionBudget,
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
    let mut evidence = Vec::<(SourceEventKey, TaintClassSet, Vec<Arc<SummaryWitness>>)>::new();
    let mut origin_truncated = false;
    let mut witness_unavailable = false;
    let mut witness_truncated = false;
    let problem = super::TaintFlowProblem::new(plan);
    for quality in point_value.path_qualities().iter() {
        let remaining_steps = budget
            .limits
            .max_witness_steps
            .saturating_sub(budget.witness_steps);
        let remaining_expansions = budget
            .limits
            .max_witness_expansions
            .saturating_sub(budget.witness_expansions);
        if budget.witnesses == budget.limits.max_witnesses
            || remaining_steps == 0
            || remaining_expansions == 0
        {
            witness_truncated = true;
            budget.truncated = true;
            continue;
        }
        let bounded_limits = WitnessReconstructionLimits::new(
            witness_limits.max_steps().min(remaining_steps),
            witness_limits.max_expansions().min(remaining_expansions),
        )
        .expect("positive remaining witness limits were checked");
        match result
            .fact_result()
            .witness_for_reached(reached, quality, bounded_limits)
        {
            Ok(witness) => {
                let retained_bytes = witness.retained_bytes();
                if retained_bytes
                    > budget
                        .limits
                        .max_retained_witness_bytes
                        .saturating_sub(budget.retained_witness_bytes)
                {
                    witness_truncated = true;
                    budget.truncated = true;
                    continue;
                }
                budget.witnesses = budget.witnesses.saturating_add(1);
                budget.witness_steps = budget
                    .witness_steps
                    .saturating_add(witness.work().emitted_steps());
                budget.witness_expansions = budget
                    .witness_expansions
                    .saturating_add(witness.work().evidence_expansions());
                budget.retained_witness_bytes =
                    budget.retained_witness_bytes.saturating_add(retained_bytes);
                let witness = Arc::new(witness);
                witness_truncated |= witness.truncated()
                    || witness.alternatives_truncated()
                    || witness.retention_truncated();
                budget.truncated |= witness.truncated()
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
                        let contribution = problem
                            .source_contribution(source.source(), output, step)
                            .intersection(classes);
                        if contribution.is_empty() {
                            continue;
                        }
                        origins.insert(source.origin().clone());
                        match evidence
                            .iter_mut()
                            .find(|(origin, _, _)| origin == source.origin())
                        {
                            Some((_, retained_classes, retained_witnesses)) => {
                                *retained_classes = retained_classes.union(&contribution);
                                if !retained_witnesses.contains(&witness) {
                                    retained_witnesses.push(Arc::clone(&witness));
                                }
                            }
                            None => evidence.push((
                                source.origin().clone(),
                                contribution,
                                vec![Arc::clone(&witness)],
                            )),
                        }
                        if origins.len() > limit {
                            let removed = origins
                                .pop_last()
                                .expect("an over-limit origin set is nonempty");
                            evidence.retain(|(origin, _, _)| origin != &removed);
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
    evidence.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(TaintOriginStatus {
        origins: origins.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        evidence: evidence
            .into_iter()
            .map(|(origin, classes, witnesses)| TaintOriginFindingEvidence {
                origin,
                classes,
                witnesses: witnesses.into_boxed_slice(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
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
    InvalidCollectionLimits,
    PlanMismatch,
    InvalidResult,
    Witness(SummaryWitnessError),
}

impl fmt::Display for TaintFindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOriginLimit => formatter.write_str("taint origin limit must be positive"),
            Self::InvalidCollectionLimits => {
                formatter.write_str("taint finding collection limits must be positive")
            }
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
            Self::InvalidOriginLimit
            | Self::InvalidCollectionLimits
            | Self::PlanMismatch
            | Self::InvalidResult => None,
        }
    }
}
