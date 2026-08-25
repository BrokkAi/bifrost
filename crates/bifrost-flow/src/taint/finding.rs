use std::{collections::BTreeSet, error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::semantic::{
    ProcedureHandle, ProgramPointHandle, SemanticArtifactKey, SemanticLocator,
};
use crate::dataflow::{
    PathQualityFrontier, SummaryEntry, SummaryWitness, SummaryWitnessError, SummaryWitnessStep,
    WitnessReconstructionLimits, WitnessTruncationCause,
};
use crate::value_flow::{
    AuthoredArmClosure, ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowSinkId,
    semantic_locator_heap_bytes,
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
        let finding = TaintFinding {
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
    })
}

/// The most caller contexts one finding's origin reconstruction replays.
///
/// The collection budget already bounds witnesses, steps, expansions, and
/// bytes. This cap bounds the *search* itself, so a value entering a helper
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
/// A step whose input is the zero fact and whose source point carries a
/// selected source is the exact program point that introduced the value the
/// rest of the path carries. Nothing else is consulted: the origin is the
/// solver's own generation step, never a name or a spelling.
#[allow(clippy::too_many_arguments)]
fn collect_step_origins(
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    problem: &super::TaintFlowProblem<'_>,
    classes: &TaintClassSet,
    limit: usize,
    steps: &[SummaryWitnessStep],
    witness: &Arc<SummaryWitness>,
    origins: &mut BTreeSet<SourceEventKey>,
    evidence: &mut Vec<(SourceEventKey, TaintClassSet, Vec<Arc<SummaryWitness>>)>,
    origin_truncated: &mut bool,
) -> Result<(), TaintFindingError> {
    for step in steps {
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
                    if !retained_witnesses.contains(witness) {
                        retained_witnesses.push(Arc::clone(witness));
                    }
                }
                None => evidence.push((
                    source.origin().clone(),
                    contribution,
                    vec![Arc::clone(witness)],
                )),
            }
            if origins.len() > limit {
                let removed = origins
                    .pop_last()
                    .expect("an over-limit origin set is nonempty");
                evidence.retain(|(origin, _, _)| origin != &removed);
                *origin_truncated = true;
            }
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
    let mut witness_truncation_cause = None::<TaintWitnessTruncationCause>;
    let mut pending_callers = Vec::<PendingCallerContext>::new();
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
            witness_truncation_cause =
                witness_truncation_cause.or(Some(TaintWitnessTruncationCause::CollectionBudget));
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
                    witness_truncation_cause = witness_truncation_cause
                        .or(Some(TaintWitnessTruncationCause::CollectionBudget));
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
                // Unretained sibling alternatives are deliberately not folded
                // in: the retained witness's own steps are complete without
                // them, and the production retention limit of one alternative
                // per quality would otherwise mark nearly every witness.
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
                    witness.steps(),
                    &witness,
                    &mut origins,
                    &mut evidence,
                    &mut origin_truncated,
                )?;
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
                if caller_expansions == MAX_ORIGIN_CALLER_EXPANSIONS {
                    origin_truncated = true;
                    break 'callers;
                }
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
                    witness_truncation_cause = witness_truncation_cause
                        .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                    budget.truncated = true;
                    break 'callers;
                }
                let bounded_limits = WitnessReconstructionLimits::new(
                    witness_limits.max_steps().min(remaining_steps),
                    witness_limits.max_expansions().min(remaining_expansions),
                )
                .expect("positive remaining witness limits were checked");
                let call_witness = match result.fact_result().witness_for_incoming_call(
                    incoming,
                    quality,
                    bounded_limits,
                ) {
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
                if composed.retained_bytes()
                    > budget
                        .limits
                        .max_retained_witness_bytes
                        .saturating_sub(budget.retained_witness_bytes)
                {
                    witness_truncated = true;
                    witness_truncation_cause = witness_truncation_cause
                        .or(Some(TaintWitnessTruncationCause::CollectionBudget));
                    budget.truncated = true;
                    continue;
                }
                budget.witnesses = budget.witnesses.saturating_add(1);
                budget.witness_steps = budget
                    .witness_steps
                    .saturating_add(call_witness.work().emitted_steps());
                budget.witness_expansions = budget
                    .witness_expansions
                    .saturating_add(call_witness.work().evidence_expansions());
                budget.retained_witness_bytes = budget
                    .retained_witness_bytes
                    .saturating_add(composed.retained_bytes());
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
                    &composed.steps()[..call_steps.min(composed.steps().len())],
                    &composed,
                    &mut origins,
                    &mut evidence,
                    &mut origin_truncated,
                )?;
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
        witness_truncation_cause,
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
