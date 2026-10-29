use std::{collections::BTreeSet, error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::semantic::{
    OracleCallContext, ProcedureHandle, ProgramPointHandle, SemanticArtifactKey, SemanticLocator,
};
use crate::dataflow::{
    PathQualityFrontier, SummaryEntry, SummaryWitness, SummaryWitnessError, SummaryWitnessStep,
    WitnessReconstructionLimits, WitnessTruncationCause,
};
use crate::value_flow::{
    AuthoredArmClosure, ValueFlowCarrier, ValueFlowCarrierKey, ValueFlowEventKey,
    ValueFlowObservationPhase, ValueFlowSinkId, semantic_locator_heap_bytes,
};

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

/// Why retained witness evidence for one finding is incomplete.
///
/// The first cause encountered while collecting the finding is retained.
/// Unretained sibling alternatives are not a cause: the retained witness's own
/// steps are complete without them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintWitnessTruncationCause {
    /// The finding-collection witness, step, expansion, or byte budget refused
    /// a reconstruction or a reconstructed witness.
    CollectionBudget,
    /// The solver did not retain a witness for a reached path quality.
    QualityNotRetained,
    /// A retained witness's own reconstruction is incomplete.
    Reconstruction(WitnessTruncationCause),
}

impl TaintWitnessTruncationCause {
    /// Stable diagnostic label safe for public projection.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::CollectionBudget => "collection_budget",
            Self::QualityNotRetained => "quality_not_retained",
            Self::Reconstruction(cause) => cause.stable_label(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintOriginStatus {
    origins: Box<[SourceEventKey]>,
    evidence: Box<[TaintOriginFindingEvidence]>,
    origin_truncated: bool,
    witness_truncated: bool,
    witness_truncation_cause: Option<TaintWitnessTruncationCause>,
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
    /// Source-declared classes that contributed along this witness.
    classes: TaintClassSet,
    /// Classes observed at the sink after every intervening transform.
    reached_classes: TaintClassSet,
    witnesses: Box<[Arc<SummaryWitness>]>,
    certain_path: bool,
    authored_arm_closures: Box<[AuthoredArmClosure]>,
    /// The phase and carrier of a source that a composition matched on its
    /// frontier, which the plan does not hold. `None` for a source of the
    /// plan, whose specification the plan answers.
    frontier_source: Option<(ValueFlowObservationPhase, ValueFlowCarrier)>,
}

impl TaintOriginFindingEvidence {
    /// The phase and carrier of a source matched on a composition's frontier;
    /// `None` when the plan holds the source's specification.
    pub fn frontier_source(&self) -> Option<(ValueFlowObservationPhase, &ValueFlowCarrier)> {
        self.frontier_source
            .as_ref()
            .map(|(phase, carrier)| (*phase, carrier))
    }

    pub const fn origin(&self) -> &SourceEventKey {
        &self.origin
    }

    pub const fn classes(&self) -> &TaintClassSet {
        &self.classes
    }

    pub const fn reached_classes(&self) -> &TaintClassSet {
        &self.reached_classes
    }

    pub const fn witnesses(&self) -> &[Arc<SummaryWitness>] {
        &self.witnesses
    }

    /// A concrete retained path that is proven and complete at every hop,
    /// counting a complete, exactly bound authored summary from an active
    /// pack as closing its call (#5218). The authored dependencies it rests
    /// on are in `authored_arm_closures`.
    pub const fn has_certain_path(&self) -> bool {
        self.certain_path
    }

    /// Authored dependencies associated with this source occurrence's paths.
    pub fn authored_arm_closures(&self) -> &[AuthoredArmClosure] {
        &self.authored_arm_closures
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

    /// The exact first cause that made retained witness evidence incomplete.
    pub const fn witness_truncation_cause(&self) -> Option<TaintWitnessTruncationCause> {
        self.witness_truncation_cause
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

/// Query-local reconstruction work, including duplicate candidates and witnesses
/// refused by the evidence-retention budget.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TaintAttributionWork {
    pub attempts: usize,
    pub steps: usize,
    pub expansions: usize,
    pub candidate_exhaustions: usize,
    pub run_exhausted: bool,
}

impl TaintAttributionWork {
    /// Work charged since an earlier snapshot of the same query ledger.
    pub fn since(self, earlier: Self) -> Self {
        assert!(
            self.attempts >= earlier.attempts
                && self.steps >= earlier.steps
                && self.expansions >= earlier.expansions
                && self.candidate_exhaustions >= earlier.candidate_exhaustions,
            "attribution snapshots belong to one monotone query ledger"
        );
        Self {
            attempts: self.attempts - earlier.attempts,
            steps: self.steps - earlier.steps,
            expansions: self.expansions - earlier.expansions,
            candidate_exhaustions: self.candidate_exhaustions - earlier.candidate_exhaustions,
            run_exhausted: self.run_exhausted && !earlier.run_exhausted,
        }
    }
}

/// One query's attribution allowance, shared across collections and charged
/// at reconstruction, including when later projection or refinement fails.
#[derive(Debug)]
pub struct TaintAttributionBudget {
    limits: (usize, usize),
    work: TaintAttributionWork,
}

impl TaintAttributionBudget {
    pub fn new(max_steps: usize, max_expansions: usize) -> Self {
        Self {
            limits: (max_steps, max_expansions),
            work: TaintAttributionWork::default(),
        }
    }

    pub const fn work(&self) -> TaintAttributionWork {
        self.work
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
    attribution: TaintAttributionWork,
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

    /// Whether the run concludes precisely only because authored-complete
    /// external procedure summaries closed every open boundary (#1916). A
    /// truncated collection is a real gap, so it never earns this state.
    pub fn is_proven_by_authored_summaries(&self) -> bool {
        self.result.is_proven_by_authored_summaries() && !self.collection_truncated
    }

    /// Authored identities that closed a residual dispatch arm when this
    /// report is proven by summary (#2342). Empty otherwise.
    pub fn authored_arm_closures(&self) -> &[AuthoredArmClosure] {
        if self.collection_truncated {
            return &[];
        }
        self.result.authored_arm_closures()
    }

    pub const fn omitted_findings_lower_bound(&self) -> usize {
        self.omitted_findings_lower_bound
    }

    pub const fn attribution_work(&self) -> TaintAttributionWork {
        self.attribution
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

    pub(crate) fn belongs_to(&self, plan: &TaintAnalysisPlan) -> bool {
        Arc::ptr_eq(plan.owner(), self.result.owner())
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.result.retained_bytes())
            .saturating_add(size_of_val(&*self.findings))
            .saturating_add(
                self.findings
                    .iter()
                    .map(|finding| {
                        finding
                            .key
                            .sink
                            .retained_bytes()
                            .saturating_add(semantic_locator_heap_bytes(&finding.key.entry))
                            .saturating_add(
                                finding
                                    .key
                                    .entry_carrier
                                    .as_ref()
                                    .map_or(0, ValueFlowCarrierKey::retained_bytes),
                            )
                            .saturating_add(semantic_locator_heap_bytes(&finding.key.meeting_site))
                            .saturating_add(finding.classes.retained_heap_bytes())
                            .saturating_add(size_of_val(&*finding.origins.origins))
                            .saturating_add(size_of_val(&*finding.origins.evidence))
                            .saturating_add(
                                finding
                                    .origins
                                    .origins
                                    .iter()
                                    .map(|origin| origin.value_flow_key().retained_bytes())
                                    .fold(0usize, usize::saturating_add),
                            )
                            .saturating_add(
                                finding
                                    .origins
                                    .evidence
                                    .iter()
                                    .map(|evidence| {
                                        evidence
                                            .origin
                                            .value_flow_key()
                                            .retained_bytes()
                                            .saturating_add(evidence.classes.retained_heap_bytes())
                                            .saturating_add(
                                                evidence.reached_classes.retained_heap_bytes(),
                                            )
                                            .saturating_add(size_of_val(
                                                &*evidence.authored_arm_closures,
                                            ))
                                            .saturating_add(
                                                evidence
                                                    .authored_arm_closures
                                                    .iter()
                                                    .map(AuthoredArmClosure::retained_heap_bytes)
                                                    .fold(0usize, usize::saturating_add),
                                            )
                                            .saturating_add(size_of_val(&*evidence.witnesses))
                                            .saturating_add(
                                                evidence
                                                    .witnesses
                                                    .iter()
                                                    .map(|witness| witness.retained_bytes())
                                                    .fold(0usize, usize::saturating_add),
                                            )
                                    })
                                    .fold(0usize, usize::saturating_add),
                            )
                    })
                    .fold(0usize, usize::saturating_add),
            )
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
struct CollectionBudget<'a> {
    limits: TaintFindingCollectionLimits,
    witnesses: usize,
    witness_steps: usize,
    witness_expansions: usize,
    retained_witness_bytes: usize,
    truncated: bool,
    attribution: &'a mut TaintAttributionBudget,
    attribution_start: TaintAttributionWork,
}

impl CollectionBudget<'_> {
    fn attribution_limits(
        &self,
        candidate: &TaintAttributionWork,
        limits: WitnessReconstructionLimits,
    ) -> Option<WitnessReconstructionLimits> {
        let steps = limits.max_steps().saturating_sub(candidate.steps).min(
            self.attribution
                .limits
                .0
                .saturating_sub(self.attribution.work.steps),
        );
        let expansions = limits
            .max_expansions()
            .saturating_sub(candidate.expansions)
            .min(
                self.attribution
                    .limits
                    .1
                    .saturating_sub(self.attribution.work.expansions),
            );
        WitnessReconstructionLimits::new(steps, expansions).ok()
    }

    fn charge_attribution(
        &mut self,
        candidate: &mut TaintAttributionWork,
        reconstructed: &Result<SummaryWitness, SummaryWitnessError>,
        granted: WitnessReconstructionLimits,
    ) {
        let (steps, expansions) = match reconstructed {
            Ok(witness) => (
                witness.work().emitted_steps(),
                witness.work().evidence_expansions().max(1),
            ),
            // These lookups return before reconstruction starts. Charge the
            // attempt itself so disabled retention cannot evade the work bound.
            Err(
                SummaryWitnessError::RetentionDisabled | SummaryWitnessError::QualityNotRetained(_),
            ) => (0, 1),
            // Invalid evidence can fail after doing part of a walk. Its error
            // carries no work receipt, so charge its entire grant rather than
            // allow a failed batch to refund work before the next batch.
            Err(_) => {
                self.attribution.work.candidate_exhaustions += 1;
                (granted.max_steps(), granted.max_expansions())
            }
        };
        candidate.attempts += 1;
        candidate.steps += steps;
        candidate.expansions += expansions;
        self.attribution.work.attempts += 1;
        self.attribution.work.steps += steps;
        self.attribution.work.expansions += expansions;
        debug_assert!(
            self.attribution.work.steps <= self.attribution.limits.0
                && self.attribution.work.expansions <= self.attribution.limits.1
        );
        self.attribution.work.run_exhausted |= self.attribution.work.steps
            == self.attribution.limits.0
            || self.attribution.work.expansions == self.attribution.limits.1;
    }

    /// Attribution has already used the transient path. Only retained evidence
    /// spends the collection's witness, step, expansion and byte allowance.
    fn retain_witness(
        &mut self,
        witness: &SummaryWitness,
        steps: usize,
        expansions: usize,
    ) -> bool {
        if self.witnesses == self.limits.max_witnesses
            || steps
                > self
                    .limits
                    .max_witness_steps
                    .saturating_sub(self.witness_steps)
            || expansions
                > self
                    .limits
                    .max_witness_expansions
                    .saturating_sub(self.witness_expansions)
            || witness.retained_bytes()
                > self
                    .limits
                    .max_retained_witness_bytes
                    .saturating_sub(self.retained_witness_bytes)
        {
            self.truncated = true;
            return false;
        }
        self.witnesses += 1;
        self.witness_steps += steps;
        self.witness_expansions += expansions;
        self.retained_witness_bytes += witness.retained_bytes();
        true
    }
}

/// Constructors for a report composed over partial flows instead of solved
/// by the IDE kernel. The public shape of the report is unchanged.
impl TaintOriginFindingEvidence {
    pub(crate) fn composed(
        origin: SourceEventKey,
        classes: TaintClassSet,
        reached_classes: TaintClassSet,
        witnesses: Vec<Arc<SummaryWitness>>,
        certain_path: bool,
        authored_arm_closures: Vec<AuthoredArmClosure>,
        frontier_source: Option<(ValueFlowObservationPhase, ValueFlowCarrier)>,
    ) -> Self {
        Self {
            origin,
            classes,
            reached_classes,
            witnesses: witnesses.into_boxed_slice(),
            certain_path,
            authored_arm_closures: authored_arm_closures.into_boxed_slice(),
            frontier_source,
        }
    }
}

impl TaintOriginStatus {
    /// `evidence` holds one entry per distinct origin, sorted by origin.
    pub(crate) fn composed(
        evidence: Vec<TaintOriginFindingEvidence>,
        witness_unavailable: bool,
    ) -> Self {
        assert!(
            evidence
                .windows(2)
                .all(|pair| pair[0].origin < pair[1].origin),
            "composed origin evidence is sorted and distinct"
        );
        Self {
            origins: evidence
                .iter()
                .map(|evidence| evidence.origin.clone())
                .collect(),
            evidence: evidence.into_boxed_slice(),
            origin_truncated: false,
            witness_truncated: false,
            witness_truncation_cause: None,
            witness_unavailable,
        }
    }
}

impl TaintFinding {
    /// A finding at `sink` whose entry is the zero fact at the entry of the
    /// sink's procedure.
    pub(crate) fn composed(
        plan: &TaintAnalysisPlan,
        sink: ValueFlowSinkId,
        classes: TaintClassSet,
        path_qualities: PathQualityFrontier,
        proven: bool,
        complete: bool,
        origins: TaintOriginStatus,
    ) -> Result<Self, TaintFindingError> {
        let sink_spec = plan
            .value_flow()
            .sink(sink)
            .ok_or(TaintFindingError::InvalidResult)?;
        let procedure = sink_spec.point().procedure().clone();
        let point = procedure
            .point_handle(procedure.semantics().entry_point())
            .ok_or(TaintFindingError::InvalidResult)?;
        let fact = super::TaintFact::zero();
        let key = TaintFindingKey {
            universe: plan.universe().hash(),
            snapshot: plan.value_flow().root().artifact().key().clone(),
            sink: sink_spec.key().clone(),
            entry: point_locator(&point)?,
            entry_carrier: None,
            entry_uncertain: false,
            meeting_site: sink_spec.key().site().clone(),
            meeting_uncertain: !path_qualities.has_proven_complete_path(),
        };
        Ok(Self {
            key,
            sink,
            classes,
            entry: TaintFindingEntry {
                procedure,
                point,
                fact,
            },
            path_qualities,
            proven,
            complete,
            origins,
        })
    }
}

impl TaintFindingReport {
    /// Per-pair envelopes retain the first collection's incompleteness without
    /// copying its complete IDE graph for every source/sink pair.
    pub(crate) fn refined_pair(
        &self,
        result: TaintSummaryResult,
        findings: Vec<TaintFinding>,
        incomplete: bool,
    ) -> Self {
        let mut report = Self::composed(result, findings);
        report.collection_truncated = self.collection_truncated || incomplete;
        report.omitted_findings_lower_bound = self.omitted_findings_lower_bound;
        report.attribution = self.attribution;
        report
    }

    /// Move the first solve's coverage into the final report. Its original
    /// unfiltered values cannot be used to reconstruct removed origins.
    pub(crate) fn into_refined_findings(
        self,
        findings: Vec<TaintFinding>,
        incomplete: bool,
    ) -> Self {
        let mut report = Self::composed(self.result.without_observed_values(), findings);
        report.collection_truncated = self.collection_truncated || incomplete;
        report.omitted_findings_lower_bound = self.omitted_findings_lower_bound;
        report.attribution = self.attribution;
        report
    }

    pub(crate) fn composed(result: TaintSummaryResult, mut findings: Vec<TaintFinding>) -> Self {
        findings.sort_by(|left, right| left.key.cmp(&right.key));
        let witnesses = findings
            .iter()
            .flat_map(|finding| finding.origins.evidence.iter())
            .flat_map(|evidence| evidence.witnesses.iter())
            .collect::<Vec<_>>();
        Self {
            result,
            collection_truncated: false,
            omitted_findings_lower_bound: 0,
            retained_witnesses: witnesses.len(),
            retained_witness_steps: witnesses.iter().map(|witness| witness.steps().len()).sum(),
            witness_expansions: 0,
            attribution: TaintAttributionWork::default(),
            retained_witness_bytes: witnesses
                .iter()
                .map(|witness| witness.retained_bytes())
                .fold(0usize, usize::saturating_add),
            findings: findings.into_boxed_slice(),
        }
    }
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
    let mut attribution = TaintAttributionBudget::new(
        witness_limits
            .max_steps()
            .saturating_mul(collection_limits.max_findings),
        witness_limits
            .max_expansions()
            .saturating_mul(collection_limits.max_findings),
    );
    collect_taint_findings_with_attribution_budget(
        plan,
        result,
        max_origins_per_finding,
        witness_limits,
        collection_limits,
        &mut attribution,
    )
}

pub fn collect_taint_findings_with_attribution_budget(
    plan: &TaintAnalysisPlan,
    result: TaintSummaryResult,
    max_origins_per_finding: usize,
    witness_limits: WitnessReconstructionLimits,
    collection_limits: TaintFindingCollectionLimits,
    attribution: &mut TaintAttributionBudget,
) -> Result<TaintFindingReport, TaintFindingError> {
    if max_origins_per_finding == 0 {
        return Err(TaintFindingError::InvalidOriginLimit);
    }
    if !Arc::ptr_eq(plan.owner(), result.owner()) {
        return Err(TaintFindingError::PlanMismatch);
    }
    let mut findings = Vec::new();
    let attribution_start = attribution.work();
    let mut budget = CollectionBudget {
        limits: collection_limits,
        witnesses: 0,
        witness_steps: 0,
        witness_expansions: 0,
        retained_witness_bytes: 0,
        truncated: false,
        attribution,
        attribution_start,
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
        let certain_path = !fact.is_uncertain()
            && result.termination().is_fixed_point()
            && origins.is_complete()
            && !origins.evidence().is_empty()
            && origins
                .evidence()
                .iter()
                .all(|origin| origin.has_certain_path());
        let finding = TaintFinding {
            key,
            sink,
            classes,
            entry,
            path_qualities: point_value.path_qualities(),
            // A derived-complete run has discharged every unproven or partial
            // edge it retained -- an abort-only exceptional return carries no
            // value, and a fully modeled call's continuation is modeled -- so
            // none of them can weaken this finding's proven path. Counting
            // them raw left every Rust finding possible, because Rust lowers
            // its implicit aborts as exactly such edges.
            proven: !fact.is_uncertain()
                && result.termination().is_fixed_point()
                && (result.is_complete()
                    || (result.coverage().unproven_edges().is_empty()
                        && result.coverage().partial_edges().is_empty()))
                && point_value.path_qualities().has_proven_path()
                || certain_path,
            complete: (result.is_complete() && point_value.path_qualities().has_complete_path())
                || certain_path,
            origins,
        };
        // Distinct summary entries can reach one sink with identical facts --
        // the resolved-call continuation edges (#1952) make that routine --
        // and an identical finding carries no additional information.
        if findings.contains(&finding) {
            continue;
        }
        findings.push(finding);
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
        attribution: budget.attribution.work().since(budget.attribution_start),
    })
}

/// The most caller contexts one finding's origin reconstruction replays.
///
/// Attribution has aggregate candidate and request work bounds, independent
/// of evidence retention. This additional cap bounds caller-context search, so a value entering a helper
/// that thousands of procedures call cannot make one finding's origin walk
/// scale with the call graph. Reaching it truncates the origin set, which the
/// projected finding reports; it never invents an origin and never hides one
/// already found.
const MAX_ORIGIN_CALLER_EXPANSIONS: usize = 64;

/// One reconstructed path whose entry fact was produced by a call.
///
/// `witness` runs from `entry`'s own seed to the sink. Prepending a replayed
/// incoming call witness -- which ends at exactly that seed -- yields the
/// caller-relative path. `chain` records the entries the walk already crossed,
/// so a recursive call graph cannot replay one cycle forever.
struct PendingCallerContext {
    entry: SummaryEntry,
    witness: Arc<SummaryWitness>,
    chain: Vec<SummaryEntry>,
}

impl PendingCallerContext {
    fn new(entry: SummaryEntry, witness: &Arc<SummaryWitness>) -> Self {
        let chain = vec![entry.clone()];
        Self {
            entry,
            witness: Arc::clone(witness),
            chain,
        }
    }

    fn extended(previous: &Self, entry: SummaryEntry, witness: &Arc<SummaryWitness>) -> Self {
        let mut chain = previous.chain.clone();
        chain.push(entry.clone());
        Self {
            entry,
            witness: Arc::clone(witness),
            chain,
        }
    }
}

/// Whether `entry`'s fact is the distinguished zero fact the solve seeds with.
fn entry_fact_is_zero(
    result: &TaintSummaryResult,
    entry: &SummaryEntry,
) -> Result<bool, TaintFindingError> {
    result
        .fact_result()
        .fact(entry.entry_fact())
        .map(|fact| fact.is_zero())
        .ok_or(TaintFindingError::InvalidResult)
}

/// Attribute every source that generates taint along `steps` to `witness`.
///
/// `source_contribution` replays each selected source from the zero value at
/// its own observation point and checks the resulting output fact against the
/// witness step. This also attributes a source that regenerates a taint class
/// on a path whose input fact already carries taint. Nothing else is
/// consulted: the origin is the solver's own generation step, never a name or
/// a spelling.
#[allow(clippy::too_many_arguments)]
fn collect_step_origins(
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    problem: &super::TaintFlowProblem<'_>,
    classes: &TaintClassSet,
    limit: usize,
    call_context: &OracleCallContext,
    steps: &[SummaryWitnessStep],
    witness: &Arc<SummaryWitness>,
    origins: &mut BTreeSet<SourceEventKey>,
    evidence: &mut Vec<(
        SourceEventKey,
        TaintClassSet,
        TaintClassSet,
        Vec<Arc<SummaryWitness>>,
    )>,
    origin_truncated: &mut bool,
) -> Result<(), TaintFindingError> {
    let mut demanded = classes
        .iter_dense()
        .map(|class| {
            let mut singleton = plan.universe().empty_set();
            singleton.insert_dense(class);
            (class, singleton)
        })
        .collect::<Vec<_>>();
    for step in steps.iter().rev() {
        let input = result
            .fact_result()
            .fact(step.input_fact())
            .copied()
            .ok_or(TaintFindingError::InvalidResult)?;
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
            let immediate =
                problem.source_contribution(source.source(), output, call_context, step);
            let mut contribution = plan.universe().empty_set();
            let mut reached_classes = plan.universe().empty_set();
            for (reached, required_here) in &demanded {
                let contributing = immediate.intersection(required_here);
                if !contributing.is_empty() {
                    contribution.union_with(&contributing);
                    reached_classes.insert_dense(*reached);
                }
            }
            if contribution.is_empty() {
                continue;
            }
            origins.insert(source.origin().clone());
            match evidence
                .iter_mut()
                .find(|(origin, _, _, _)| origin == source.origin())
            {
                Some((_, retained_classes, retained_reached, retained_witnesses)) => {
                    *retained_classes = retained_classes.union(&contribution);
                    *retained_reached = retained_reached.union(&reached_classes);
                    if !retained_witnesses.contains(witness) {
                        retained_witnesses.push(Arc::clone(witness));
                    }
                }
                None => evidence.push((
                    source.origin().clone(),
                    contribution,
                    reached_classes,
                    vec![Arc::clone(witness)],
                )),
            }
            if origins.len() > limit {
                let removed = origins
                    .pop_last()
                    .expect("an over-limit origin set is nonempty");
                evidence.retain(|(origin, _, _, _)| origin != &removed);
                *origin_truncated = true;
            }
        }
        let preimages =
            problem.witness_step_preimages(input, output, call_context, step, &demanded);
        for ((_, classes), preimage) in demanded.iter_mut().zip(preimages) {
            *classes = preimage;
        }
    }
    Ok(())
}

fn reconstruct_origins(
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    point_value: &crate::dataflow::IdePointValue,
    classes: &TaintClassSet,
    limit: usize,
    witness_limits: WitnessReconstructionLimits,
    budget: &mut CollectionBudget<'_>,
) -> Result<TaintOriginStatus, TaintFindingError> {
    let sink = result
        .fact_result()
        .fact(point_value.fact())
        .and_then(|fact| fact.sink())
        .and_then(|sink| plan.value_flow().sink(sink))
        .ok_or(TaintFindingError::InvalidResult)?;
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
    let mut evidence = Vec::<(
        SourceEventKey,
        TaintClassSet,
        TaintClassSet,
        Vec<Arc<SummaryWitness>>,
    )>::new();
    let mut origin_truncated = false;
    let mut witness_unavailable = false;
    let mut witness_truncated = false;
    let mut witness_truncation_cause = None::<TaintWitnessTruncationCause>;
    let mut pending_callers = Vec::<PendingCallerContext>::new();
    let mut candidate = TaintAttributionWork::default();
    let problem = super::TaintFlowProblem::new(plan);
    for quality in point_value.path_qualities().iter() {
        // One reached fact is routinely derived along several paths, and two
        // paths can generate it from different sources, so the origin set is
        // the union over every retained derivation rather than a property of
        // whichever one the solver retained first (#2734). Asking for
        // derivation zero when none was retained is what reports whether
        // retention was disabled or the quality was dropped, so an empty
        // retention still runs exactly one pass.
        let derivations = reached.retained_derivations(quality).max(1);
        for derivation in 0..derivations {
            let Some(bounded_limits) = budget.attribution_limits(&candidate, witness_limits) else {
                origin_truncated = true;
                witness_truncated = true;
                witness_truncation_cause = witness_truncation_cause
                    .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                budget.truncated = true;
                budget.attribution.work.run_exhausted |= budget.attribution.work.steps
                    == budget.attribution.limits.0
                    || budget.attribution.work.expansions == budget.attribution.limits.1;
                break;
            };
            let reconstructed = result.fact_result().witness_for_reached_derivation(
                reached,
                quality,
                derivation,
                bounded_limits,
            );
            budget.charge_attribution(&mut candidate, &reconstructed, bounded_limits);
            match reconstructed {
                Ok(witness) => {
                    let witness = Arc::new(witness);
                    // Sibling derivations the retention limit dropped are still not
                    // marked truncated: this witness's own steps are complete
                    // without them, and the production retention limit of one
                    // alternative per quality would otherwise mark nearly every
                    // witness.
                    witness_truncated |= witness.truncated();
                    witness_truncation_cause = witness_truncation_cause.or(witness
                        .truncation_cause()
                        .map(TaintWitnessTruncationCause::Reconstruction));
                    budget.truncated |= witness.truncated();
                    collect_step_origins(
                        plan,
                        result,
                        &problem,
                        classes,
                        limit,
                        reached.entry().call_context(),
                        witness.steps(),
                        &witness,
                        &mut origins,
                        &mut evidence,
                        &mut origin_truncated,
                    )?;
                    if !budget.retain_witness(
                        &witness,
                        witness.work().emitted_steps(),
                        witness.work().evidence_expansions(),
                    ) {
                        for (_, _, _, witnesses) in &mut evidence {
                            witnesses.retain(|retained| !Arc::ptr_eq(retained, &witness));
                        }
                        witness_truncated = true;
                        witness_truncation_cause = witness_truncation_cause
                            .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                    }
                    // A path edge is relative to its entry, so a witness whose entry
                    // fact is not the distinguished zero fact begins mid-flow: the
                    // value was already tainted when the procedure was entered, and
                    // the step that generated it belongs to a caller (#2546).
                    if !entry_fact_is_zero(result, reached.entry())? {
                        pending_callers
                            .push(PendingCallerContext::new(reached.entry().clone(), &witness));
                    }
                }
                Err(SummaryWitnessError::RetentionDisabled) => witness_unavailable = true,
                Err(SummaryWitnessError::QualityNotRetained(_)) => {
                    witness_truncated = true;
                    witness_truncation_cause = witness_truncation_cause
                        .or(Some(TaintWitnessTruncationCause::QualityNotRetained));
                }
                Err(error) => return Err(TaintFindingError::Witness(error)),
            }
        }
    }
    // Walk back through the published incoming-call relations until the chain
    // reaches an entry the solve itself seeded. Each replayed call witness ends
    // at exactly the entry seed its suffix begins with, so concatenating them
    // yields one realizable caller-to-sink path -- real evidence, never an
    // origin inferred from the callee's own text or naming.
    let mut caller_expansions = 0usize;
    'callers: while let Some(context) = pending_callers.pop() {
        for incoming in result.fact_result().incoming_calls_for(&context.entry) {
            // A recursive chain would replay an entry the suffix already
            // crossed. A longer replay of the same cycle reaches the same
            // callers and can add no origin the first pass did not.
            if context.chain.contains(incoming.caller()) {
                continue;
            }
            for quality in incoming.path_qualities().iter() {
                // The same union-over-derivations rule as the reached walk
                // above: one call can be reached along several caller-relative
                // paths, each of which can carry its own sources (#2734).
                for derivation in 0..incoming.retained_derivations(quality).max(1) {
                    if caller_expansions == MAX_ORIGIN_CALLER_EXPANSIONS {
                        origin_truncated = true;
                        break 'callers;
                    }
                    let Some(bounded_limits) =
                        budget.attribution_limits(&candidate, witness_limits)
                    else {
                        origin_truncated = true;
                        witness_truncated = true;
                        witness_truncation_cause = witness_truncation_cause
                            .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                        budget.truncated = true;
                        budget.attribution.work.run_exhausted |= budget.attribution.work.steps
                            == budget.attribution.limits.0
                            || budget.attribution.work.expansions == budget.attribution.limits.1;
                        break 'callers;
                    };
                    let reconstructed = result.fact_result().witness_for_incoming_call_derivation(
                        incoming,
                        quality,
                        derivation,
                        bounded_limits,
                    );
                    budget.charge_attribution(&mut candidate, &reconstructed, bounded_limits);
                    let call_witness = match reconstructed {
                        Ok(call_witness) => call_witness,
                        Err(SummaryWitnessError::RetentionDisabled) => {
                            witness_unavailable = true;
                            continue;
                        }
                        Err(SummaryWitnessError::QualityNotRetained(_)) => {
                            witness_truncated = true;
                            witness_truncation_cause = witness_truncation_cause
                                .or(Some(TaintWitnessTruncationCause::QualityNotRetained));
                            continue;
                        }
                        Err(error) => return Err(TaintFindingError::Witness(error)),
                    };
                    caller_expansions = caller_expansions.saturating_add(1);
                    let retained_steps = call_witness.work().emitted_steps();
                    let retained_expansions = call_witness.work().evidence_expansions();
                    let call_steps = call_witness.steps().len();
                    let Some(composed) =
                        call_witness.joined_at_call(&context.witness, witness_limits.max_steps())
                    else {
                        // A retention marker carries no steps, so there is nothing
                        // to compose and nothing the caller could witness.
                        witness_truncated = true;
                        witness_truncation_cause = witness_truncation_cause
                            .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                        continue;
                    };
                    witness_truncated |= composed.truncated();
                    witness_truncation_cause = witness_truncation_cause.or(composed
                        .truncation_cause()
                        .map(TaintWitnessTruncationCause::Reconstruction));
                    budget.truncated |= composed.truncated();
                    let composed = Arc::new(composed);
                    // Only the replayed call's own steps are scanned: the suffix's
                    // generating steps were already attributed to the witness that
                    // contains them.
                    collect_step_origins(
                        plan,
                        result,
                        &problem,
                        classes,
                        limit,
                        incoming.caller().call_context(),
                        &composed.steps()[..call_steps.min(composed.steps().len())],
                        &composed,
                        &mut origins,
                        &mut evidence,
                        &mut origin_truncated,
                    )?;
                    if !budget.retain_witness(&composed, retained_steps, retained_expansions) {
                        for (_, _, _, witnesses) in &mut evidence {
                            witnesses.retain(|retained| !Arc::ptr_eq(retained, &composed));
                        }
                        witness_truncated = true;
                        witness_truncation_cause = witness_truncation_cause
                            .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                    }
                    if !entry_fact_is_zero(result, incoming.caller())? {
                        pending_callers.push(PendingCallerContext::extended(
                            &context,
                            incoming.caller().clone(),
                            &composed,
                        ));
                    }
                }
            }
        }
    }
    if witness_truncated
        && (candidate.steps == witness_limits.max_steps()
            || candidate.expansions == witness_limits.max_expansions())
    {
        budget.attribution.work.candidate_exhaustions += 1;
    }
    evidence.sort_by(|left, right| left.0.cmp(&right.0));
    let evidence = evidence
        .into_iter()
        .map(|(origin, classes, reached_classes, witnesses)| {
            let mut closures = Vec::new();
            let source = plan
                .sources()
                .iter()
                .find(|source| source.origin() == &origin)
                .and_then(|source| plan.value_flow().source(source.source()))
                .expect("reconstructed origin names a live source");
            let mut certain_path = !witnesses.is_empty();
            for witness in &witnesses {
                for closure in plan
                    .value_flow()
                    .witness_arm_closures(witness, source.point())
                {
                    if !closures.contains(&closure) {
                        closures.push(closure);
                    }
                }
                if let Some(certain) = plan.value_flow().certain_witness_closures(
                    result.fact_result(),
                    witness,
                    source,
                    sink,
                ) {
                    for closure in certain {
                        if !closures.contains(&closure) {
                            closures.push(closure);
                        }
                    }
                } else {
                    certain_path = false;
                }
            }
            let closure_bytes = size_of_val(closures.as_slice()).saturating_add(
                closures
                    .iter()
                    .map(AuthoredArmClosure::retained_heap_bytes)
                    .fold(0usize, usize::saturating_add),
            );
            if closure_bytes
                > budget
                    .limits
                    .max_retained_witness_bytes
                    .saturating_sub(budget.retained_witness_bytes)
            {
                closures.clear();
                certain_path = false;
                witness_truncated = true;
                witness_truncation_cause = witness_truncation_cause
                    .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                budget.truncated = true;
            } else {
                budget.retained_witness_bytes =
                    budget.retained_witness_bytes.saturating_add(closure_bytes);
            }
            TaintOriginFindingEvidence {
                origin,
                classes,
                reached_classes,
                witnesses: witnesses.into_boxed_slice(),
                certain_path,
                authored_arm_closures: closures.into_boxed_slice(),
                frontier_source: None,
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok(TaintOriginStatus {
        origins: origins.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        evidence,
        origin_truncated,
        witness_truncated,
        witness_truncation_cause,
        witness_unavailable,
    })
}

fn point_locator(
    point: &crate::analyzer::semantic::ProgramPointHandle,
) -> Result<SemanticLocator, TaintFindingError> {
    let _row = point
        .procedure()
        .semantics()
        .point(point.id())
        .ok_or(TaintFindingError::InvalidResult)?;
    point
        .locator()
        .cloned()
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
