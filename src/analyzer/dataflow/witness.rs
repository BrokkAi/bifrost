//! Policy-independent bounded witnesses for summary dataflow results.

use std::{error::Error, fmt, num::NonZeroUsize};
use std::{mem::size_of, sync::Arc};

use crate::analyzer::semantic::{
    CallSiteHandle, DispatchBoundaryKind, EvidenceCompleteness, IcfgEdgeKind, IcfgExitProfile,
    ProcedureIcfgEdge, ProgramPointHandle, ProofStatus, ReturnTransferKind,
};

use super::{FactId, PathQuality, PathQualityFrontier, SummaryEdge};

const DEFAULT_RECONSTRUCTION_STEPS: usize = 4_096;
const DEFAULT_RECONSTRUCTION_EXPANSIONS: usize = 16_384;

/// Maximum client-selectable alternatives retained for one exact path quality.
pub const MAX_WITNESS_ALTERNATIVES_PER_QUALITY: usize = 64;

/// Why witness-limit construction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessLimitError {
    field: &'static str,
    maximum: Option<usize>,
}

impl WitnessLimitError {
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for WitnessLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.maximum {
            Some(maximum) => write!(formatter, "{} must be at most {maximum}", self.field),
            None => write!(formatter, "{} must be greater than zero", self.field),
        }
    }
}

impl Error for WitnessLimitError {}

/// Query-local witness storage requested from the summary solver.
///
/// Disabled retention performs no predecessor allocation. Strict retention
/// preserves the historical behavior: exceeding the request's
/// [`super::SolverBudgetDimension::WitnessRelations`] limit terminates the
/// solve. Best-effort retention instead drops the entire witness sidecar when
/// either that request limit or its local relation/byte cap is reached, without
/// changing semantic reachability or termination. The byte cap covers arena
/// nodes and proof/completeness strings cloned into the sidecar; shared
/// semantic handles are excluded.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessRetentionLimits {
    max_alternatives_per_quality: Option<NonZeroUsize>,
    best_effort_max_relations: Option<NonZeroUsize>,
    best_effort_max_retained_bytes: Option<NonZeroUsize>,
}

impl WitnessRetentionLimits {
    pub const fn disabled() -> Self {
        Self {
            max_alternatives_per_quality: None,
            best_effort_max_relations: None,
            best_effort_max_retained_bytes: None,
        }
    }

    pub fn new(max_alternatives_per_quality: usize) -> Result<Self, WitnessLimitError> {
        Self::validate_alternatives(max_alternatives_per_quality).map(|limit| Self {
            max_alternatives_per_quality: Some(limit),
            best_effort_max_relations: None,
            best_effort_max_retained_bytes: None,
        })
    }

    pub fn best_effort(
        max_alternatives_per_quality: usize,
        max_retained_relations: usize,
        max_retained_bytes: usize,
    ) -> Result<Self, WitnessLimitError> {
        let max_alternatives_per_quality =
            Self::validate_alternatives(max_alternatives_per_quality)?;
        if max_alternatives_per_quality.get() != 1 {
            return Err(WitnessLimitError {
                field: "max_alternatives_per_quality",
                maximum: Some(1),
            });
        }
        let max_retained_relations =
            NonZeroUsize::new(max_retained_relations).ok_or(WitnessLimitError {
                field: "max_retained_relations",
                maximum: None,
            })?;
        if max_retained_relations.get() > u32::MAX as usize {
            return Err(WitnessLimitError {
                field: "max_retained_relations",
                maximum: Some(u32::MAX as usize),
            });
        }
        let max_retained_bytes =
            NonZeroUsize::new(max_retained_bytes).ok_or(WitnessLimitError {
                field: "max_retained_bytes",
                maximum: None,
            })?;
        Ok(Self {
            max_alternatives_per_quality: Some(max_alternatives_per_quality),
            best_effort_max_relations: Some(max_retained_relations),
            best_effort_max_retained_bytes: Some(max_retained_bytes),
        })
    }

    fn validate_alternatives(
        max_alternatives_per_quality: usize,
    ) -> Result<NonZeroUsize, WitnessLimitError> {
        let max_alternatives_per_quality =
            NonZeroUsize::new(max_alternatives_per_quality).ok_or(WitnessLimitError {
                field: "max_alternatives_per_quality",
                maximum: None,
            })?;
        if max_alternatives_per_quality.get() > MAX_WITNESS_ALTERNATIVES_PER_QUALITY {
            return Err(WitnessLimitError {
                field: "max_alternatives_per_quality",
                maximum: Some(MAX_WITNESS_ALTERNATIVES_PER_QUALITY),
            });
        }
        Ok(max_alternatives_per_quality)
    }

    pub const fn is_enabled(self) -> bool {
        self.max_alternatives_per_quality.is_some()
    }

    pub const fn max_alternatives_per_quality(self) -> usize {
        match self.max_alternatives_per_quality {
            Some(limit) => limit.get(),
            None => 0,
        }
    }

    pub const fn is_best_effort(self) -> bool {
        self.best_effort_max_relations.is_some() && self.best_effort_max_retained_bytes.is_some()
    }

    const fn best_effort_max_relations(self) -> Option<usize> {
        match self.best_effort_max_relations {
            Some(limit) => Some(limit.get()),
            None => None,
        }
    }

    const fn best_effort_max_retained_bytes(self) -> Option<usize> {
        match self.best_effort_max_retained_bytes {
            Some(limit) => Some(limit.get()),
            None => None,
        }
    }
}

/// Per-request bounds for expanding one retained witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessReconstructionLimits {
    max_steps: NonZeroUsize,
    max_expansions: NonZeroUsize,
}

impl WitnessReconstructionLimits {
    pub fn new(max_steps: usize, max_expansions: usize) -> Result<Self, WitnessLimitError> {
        let max_steps = NonZeroUsize::new(max_steps).ok_or(WitnessLimitError {
            field: "max_steps",
            maximum: None,
        })?;
        let max_expansions = NonZeroUsize::new(max_expansions).ok_or(WitnessLimitError {
            field: "max_expansions",
            maximum: None,
        })?;
        Ok(Self {
            max_steps,
            max_expansions,
        })
    }

    pub const fn max_steps(self) -> usize {
        self.max_steps.get()
    }

    pub const fn max_expansions(self) -> usize {
        self.max_expansions.get()
    }
}

impl Default for WitnessReconstructionLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_RECONSTRUCTION_STEPS,
            DEFAULT_RECONSTRUCTION_EXPANSIONS,
        )
        .expect("default witness reconstruction limits are positive")
    }
}

/// The semantic operation represented by one reconstructed witness step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SummaryWitnessStepKind {
    /// The distinguished or explicit fact at a procedure entry.
    Seed,
    /// One real semantic ICFG edge.
    Edge(IcfgEdgeKind),
    /// A source-backed return-affecting gap on a profiled callee exit.
    EndSummaryGap(ReturnTransferKind),
}

/// One source-backed step in a reconstructed summary-dataflow witness.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryWitnessStep {
    kind: SummaryWitnessStepKind,
    source: ProgramPointHandle,
    target: Option<ProgramPointHandle>,
    origin: Option<CallSiteHandle>,
    boundary: Option<DispatchBoundaryKind>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    input_fact: FactId,
    output_fact: FactId,
}

impl SummaryWitnessStep {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kind: SummaryWitnessStepKind,
        source: ProgramPointHandle,
        target: Option<ProgramPointHandle>,
        origin: Option<CallSiteHandle>,
        boundary: Option<DispatchBoundaryKind>,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        input_fact: FactId,
        output_fact: FactId,
    ) -> Self {
        Self {
            kind,
            source,
            target,
            origin,
            boundary,
            proof,
            completeness,
            input_fact,
            output_fact,
        }
    }

    pub const fn kind(&self) -> SummaryWitnessStepKind {
        self.kind
    }

    pub const fn source(&self) -> &ProgramPointHandle {
        &self.source
    }

    pub const fn target(&self) -> Option<&ProgramPointHandle> {
        self.target.as_ref()
    }

    pub const fn origin(&self) -> Option<&CallSiteHandle> {
        self.origin.as_ref()
    }

    pub const fn boundary(&self) -> Option<&DispatchBoundaryKind> {
        self.boundary.as_ref()
    }

    pub const fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub const fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }

    pub const fn input_fact(&self) -> FactId {
        self.input_fact
    }

    pub const fn output_fact(&self) -> FactId {
        self.output_fact
    }

    fn retained_owned_bytes(&self) -> usize {
        retained_evidence_bytes(&self.proof, &self.completeness)
    }

    #[allow(clippy::too_many_arguments)]
    fn matches_derivation(
        &self,
        kind: SummaryWitnessStepKind,
        source: &ProgramPointHandle,
        target: Option<&ProgramPointHandle>,
        origin: Option<&CallSiteHandle>,
        boundary: Option<&DispatchBoundaryKind>,
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
        input_fact: FactId,
        output_fact: FactId,
    ) -> bool {
        self.kind == kind
            && &self.source == source
            && self.target.as_ref() == target
            && self.origin.as_ref() == origin
            && self.boundary.as_ref() == boundary
            && &self.proof == proof
            && &self.completeness == completeness
            && self.input_fact == input_fact
            && self.output_fact == output_fact
    }
}

fn retained_evidence_bytes(proof: &ProofStatus, completeness: &EvidenceCompleteness) -> usize {
    let proof_bytes = match proof {
        ProofStatus::Proven => 0,
        ProofStatus::Unproven(reason) => reason.len(),
    };
    let completeness_bytes = match completeness {
        EvidenceCompleteness::Complete => 0,
        EvidenceCompleteness::Partial(reason) => reason.len(),
    };
    proof_bytes.saturating_add(completeness_bytes)
}

/// Work performed while reconstructing one retained witness.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessReconstructionWork {
    evidence_expansions: usize,
    emitted_steps: usize,
}

impl WitnessReconstructionWork {
    pub(crate) const fn new(evidence_expansions: usize, emitted_steps: usize) -> Self {
        Self {
            evidence_expansions,
            emitted_steps,
        }
    }

    pub const fn evidence_expansions(self) -> usize {
        self.evidence_expansions
    }

    pub const fn emitted_steps(self) -> usize {
        self.emitted_steps
    }
}

/// One deterministic bounded witness reconstructed from a completed solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryWitness {
    steps: Box<[SummaryWitnessStep]>,
    quality: PathQuality,
    truncated: bool,
    omitted_steps_lower_bound: usize,
    alternatives_truncated: bool,
    retention_truncated: bool,
    retained_bytes: usize,
    work: WitnessReconstructionWork,
}

impl SummaryWitness {
    pub(crate) fn from_parts(
        steps: Vec<SummaryWitnessStep>,
        quality: PathQuality,
        truncated: bool,
        omitted_steps_lower_bound: usize,
        alternatives_truncated: bool,
        retained_bytes: usize,
        work: WitnessReconstructionWork,
    ) -> Self {
        debug_assert_eq!(truncated, omitted_steps_lower_bound > 0);
        Self {
            steps: steps.into_boxed_slice(),
            quality,
            truncated,
            omitted_steps_lower_bound,
            alternatives_truncated,
            retention_truncated: false,
            retained_bytes,
            work,
        }
    }

    pub(crate) fn retention_truncated_marker(quality: PathQuality) -> Self {
        Self {
            steps: Box::new([]),
            quality,
            truncated: true,
            omitted_steps_lower_bound: 1,
            alternatives_truncated: true,
            retention_truncated: true,
            retained_bytes: size_of::<Self>(),
            work: WitnessReconstructionWork::default(),
        }
    }

    pub fn steps(&self) -> &[SummaryWitnessStep] {
        &self.steps
    }

    pub const fn quality(&self) -> PathQuality {
        self.quality
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub const fn omitted_steps_lower_bound(&self) -> usize {
        self.omitted_steps_lower_bound
    }

    pub const fn alternatives_truncated(&self) -> bool {
        self.alternatives_truncated
    }

    /// Whether best-effort retention exhausted its independent sidecar budget.
    ///
    /// In this state the zero-step witness is an explicit availability marker,
    /// not evidence that the target was reached without semantic steps.
    pub const fn retention_truncated(&self) -> bool {
        self.retention_truncated
    }

    /// Bytes exclusively retained by this value.
    ///
    /// This includes the witness object, its boxed step slice, and owned
    /// proof/completeness reason strings. Shared backing allocations referenced
    /// by semantic handles are intentionally excluded.
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub const fn work(&self) -> WitnessReconstructionWork {
        self.work
    }
}

/// Why a requested summary-dataflow witness could not be reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SummaryWitnessError {
    RetentionDisabled,
    TargetNotInResult,
    QualityNotRetained(PathQuality),
    InvalidEvidence(&'static str),
}

impl fmt::Display for SummaryWitnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetentionDisabled => {
                formatter.write_str("witness retention was not enabled for this solve")
            }
            Self::TargetNotInResult => {
                formatter.write_str("witness target does not belong to this result")
            }
            Self::QualityNotRetained(_) => {
                formatter.write_str("requested path quality is not retained for this target")
            }
            Self::InvalidEvidence(reason) => {
                write!(
                    formatter,
                    "retained witness evidence is inconsistent: {reason}"
                )
            }
        }
    }
}

impl Error for SummaryWitnessError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct WitnessEvidenceId(u32);

impl WitnessEvidenceId {
    const fn index(self) -> usize {
        self.0 as usize
    }

    fn try_from_index(index: usize) -> Option<Self> {
        u32::try_from(index).ok().map(Self)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct WitnessAlternatives {
    inner: Option<Box<WitnessAlternativeSets>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct WitnessAlternativeSets {
    by_quality: [Vec<WitnessEvidenceId>; 4],
    truncated: [bool; 4],
}

impl WitnessAlternatives {
    pub(crate) fn ids(&self, quality: PathQuality) -> &[WitnessEvidenceId] {
        self.inner
            .as_ref()
            .map_or(&[], |inner| &inner.by_quality[quality.ordinal()])
    }

    pub(crate) fn first(&self, quality: PathQuality) -> Option<WitnessEvidenceId> {
        self.ids(quality).first().copied()
    }

    pub(crate) fn contains(&self, quality: PathQuality, evidence: WitnessEvidenceId) -> bool {
        self.ids(quality).contains(&evidence)
    }

    pub(crate) fn is_truncated(&self, quality: PathQuality) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.truncated[quality.ordinal()])
    }

    pub(crate) fn push(&mut self, quality: PathQuality, evidence: WitnessEvidenceId) {
        self.inner.get_or_insert_with(Default::default).by_quality[quality.ordinal()]
            .push(evidence);
    }

    pub(crate) fn mark_truncated(&mut self, quality: PathQuality) {
        self.inner.get_or_insert_with(Default::default).truncated[quality.ordinal()] = true;
    }

    pub(crate) fn retain_frontier(&mut self, frontier: PathQualityFrontier) {
        let Some(inner) = self.inner.as_mut() else {
            return;
        };
        for quality in PathQuality::ALL {
            if !frontier.contains(quality) {
                inner.by_quality[quality.ordinal()].clear();
                inner.truncated[quality.ordinal()] = false;
            }
        }
        if inner.by_quality.iter().all(Vec::is_empty) && !inner.truncated.iter().any(|flag| *flag) {
            self.inner = None;
        }
    }

    pub(crate) fn remap(&mut self, remap: &[Option<WitnessEvidenceId>]) {
        let Some(inner) = self.inner.as_mut() else {
            return;
        };
        for alternatives in &mut inner.by_quality {
            for evidence in alternatives {
                *evidence = remap
                    .get(evidence.index())
                    .and_then(|mapped| *mapped)
                    .expect("active witness evidence remains reachable during compaction");
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessAdmission {
    Retained(WitnessEvidenceId),
    Duplicate,
    Truncated,
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessEvidenceNode {
    quality: PathQuality,
    alternatives_truncated: bool,
    kind: WitnessEvidenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WitnessEvidenceKind {
    Step {
        predecessor: Option<WitnessEvidenceId>,
        step: SummaryWitnessStep,
    },
    EndSummary {
        predecessor: WitnessEvidenceId,
        entry_point: ProgramPointHandle,
        entry_fact: FactId,
        exit: Arc<IcfgExitProfile>,
        exit_fact: FactId,
    },
    SummaryApplication {
        incoming: WitnessEvidenceId,
        summary: WitnessEvidenceId,
        return_step: SummaryWitnessStep,
    },
    ReusableSummaryApplication {
        incoming: WitnessEvidenceId,
        summary_quality: PathQuality,
        return_step: SummaryWitnessStep,
    },
}

impl WitnessEvidenceNode {
    pub(crate) const fn seed_retained_bytes() -> usize {
        size_of::<Self>()
    }

    pub(crate) fn seed(point: ProgramPointHandle, fact: FactId) -> Self {
        Self {
            quality: PathQuality::PROVEN_COMPLETE,
            alternatives_truncated: false,
            kind: WitnessEvidenceKind::Step {
                predecessor: None,
                step: SummaryWitnessStep::new(
                    SummaryWitnessStepKind::Seed,
                    point,
                    None,
                    None,
                    None,
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                    fact,
                    fact,
                ),
            },
        }
    }

    pub(crate) fn edge(
        predecessor: WitnessEvidenceId,
        predecessor_quality: PathQuality,
        edge: &ProcedureIcfgEdge,
        input_fact: FactId,
        output_fact: FactId,
    ) -> Self {
        Self {
            quality: predecessor_quality.through_evidence(&edge.proof, &edge.completeness),
            alternatives_truncated: false,
            kind: WitnessEvidenceKind::Step {
                predecessor: Some(predecessor),
                step: SummaryWitnessStep::new(
                    SummaryWitnessStepKind::Edge(edge.kind),
                    edge.source.clone(),
                    Some(edge.target.clone()),
                    edge.origin.clone(),
                    edge.boundary.clone(),
                    edge.proof.clone(),
                    edge.completeness.clone(),
                    input_fact,
                    output_fact,
                ),
            },
        }
    }

    pub(crate) fn edge_retained_bytes(edge: &ProcedureIcfgEdge) -> usize {
        size_of::<Self>().saturating_add(retained_evidence_bytes(&edge.proof, &edge.completeness))
    }

    pub(crate) fn end_summary(
        predecessor: WitnessEvidenceId,
        predecessor_quality: PathQuality,
        entry_point: ProgramPointHandle,
        entry_fact: FactId,
        exit: Arc<IcfgExitProfile>,
        exit_fact: FactId,
    ) -> Self {
        let quality = if exit.has_return_affecting_gaps() {
            predecessor_quality.conjoin(PathQuality::UNPROVEN_PARTIAL)
        } else {
            predecessor_quality
        };
        Self {
            quality,
            alternatives_truncated: false,
            kind: WitnessEvidenceKind::EndSummary {
                predecessor,
                entry_point,
                entry_fact,
                exit,
                exit_fact,
            },
        }
    }

    pub(crate) const fn end_summary_retained_bytes() -> usize {
        size_of::<Self>()
    }

    pub(crate) fn summary_application(
        incoming: WitnessEvidenceId,
        incoming_quality: PathQuality,
        summary: WitnessEvidenceId,
        summary_quality: PathQuality,
        return_edge: &SummaryEdge,
        input_fact: FactId,
        output_fact: FactId,
    ) -> Self {
        let quality = incoming_quality
            .conjoin(summary_quality)
            .through_evidence(return_edge.proof(), return_edge.completeness());
        Self {
            quality,
            alternatives_truncated: false,
            kind: WitnessEvidenceKind::SummaryApplication {
                incoming,
                summary,
                return_step: SummaryWitnessStep::new(
                    SummaryWitnessStepKind::Edge(return_edge.kind()),
                    return_edge.source().clone(),
                    Some(return_edge.target().clone()),
                    return_edge.origin().cloned(),
                    None,
                    return_edge.proof().clone(),
                    return_edge.completeness().clone(),
                    input_fact,
                    output_fact,
                ),
            },
        }
    }

    pub(crate) fn summary_application_retained_bytes(return_edge: &SummaryEdge) -> usize {
        size_of::<Self>().saturating_add(retained_evidence_bytes(
            return_edge.proof(),
            return_edge.completeness(),
        ))
    }

    pub(crate) fn reusable_summary_application(
        incoming: WitnessEvidenceId,
        incoming_quality: PathQuality,
        summary_quality: PathQuality,
        return_edge: &SummaryEdge,
        input_fact: FactId,
        output_fact: FactId,
    ) -> Self {
        let quality = incoming_quality
            .conjoin(summary_quality)
            .through_evidence(return_edge.proof(), return_edge.completeness());
        Self {
            quality,
            alternatives_truncated: false,
            kind: WitnessEvidenceKind::ReusableSummaryApplication {
                incoming,
                summary_quality,
                return_step: SummaryWitnessStep::new(
                    SummaryWitnessStepKind::Edge(return_edge.kind()),
                    return_edge.source().clone(),
                    Some(return_edge.target().clone()),
                    return_edge.origin().cloned(),
                    None,
                    return_edge.proof().clone(),
                    return_edge.completeness().clone(),
                    input_fact,
                    output_fact,
                ),
            },
        }
    }

    pub(crate) fn reusable_summary_application_retained_bytes(return_edge: &SummaryEdge) -> usize {
        size_of::<Self>().saturating_add(retained_evidence_bytes(
            return_edge.proof(),
            return_edge.completeness(),
        ))
    }

    pub(crate) fn matches_seed_derivation(&self, point: &ProgramPointHandle, fact: FactId) -> bool {
        self.quality == PathQuality::PROVEN_COMPLETE
            && matches!(
                &self.kind,
                WitnessEvidenceKind::Step {
                    predecessor: None,
                    step,
                } if step.matches_derivation(
                    SummaryWitnessStepKind::Seed,
                    point,
                    None,
                    None,
                    None,
                    &ProofStatus::Proven,
                    &EvidenceCompleteness::Complete,
                    fact,
                    fact,
                )
            )
    }

    pub(crate) fn matches_edge_derivation(
        &self,
        predecessor: WitnessEvidenceId,
        predecessor_quality: PathQuality,
        edge: &ProcedureIcfgEdge,
        input_fact: FactId,
        output_fact: FactId,
    ) -> bool {
        self.quality == predecessor_quality.through_evidence(&edge.proof, &edge.completeness)
            && matches!(
                &self.kind,
                WitnessEvidenceKind::Step {
                    predecessor: Some(retained_predecessor),
                    step,
                } if *retained_predecessor == predecessor
                    && step.matches_derivation(
                        SummaryWitnessStepKind::Edge(edge.kind),
                        &edge.source,
                        Some(&edge.target),
                        edge.origin.as_ref(),
                        edge.boundary.as_ref(),
                        &edge.proof,
                        &edge.completeness,
                        input_fact,
                        output_fact,
                    )
            )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches_summary_application_derivation(
        &self,
        incoming: WitnessEvidenceId,
        incoming_quality: PathQuality,
        summary: WitnessEvidenceId,
        summary_quality: PathQuality,
        return_edge: &SummaryEdge,
        input_fact: FactId,
        output_fact: FactId,
    ) -> bool {
        self.quality
            == incoming_quality
                .conjoin(summary_quality)
                .through_evidence(return_edge.proof(), return_edge.completeness())
            && matches!(
                &self.kind,
                WitnessEvidenceKind::SummaryApplication {
                    incoming: retained_incoming,
                    summary: retained_summary,
                    return_step,
                } if *retained_incoming == incoming
                    && *retained_summary == summary
                    && return_step.matches_derivation(
                        SummaryWitnessStepKind::Edge(return_edge.kind()),
                        return_edge.source(),
                        Some(return_edge.target()),
                        return_edge.origin(),
                        None,
                        return_edge.proof(),
                        return_edge.completeness(),
                        input_fact,
                        output_fact,
                    )
            )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches_reusable_summary_application_derivation(
        &self,
        incoming: WitnessEvidenceId,
        incoming_quality: PathQuality,
        summary_quality: PathQuality,
        return_edge: &SummaryEdge,
        input_fact: FactId,
        output_fact: FactId,
    ) -> bool {
        self.quality
            == incoming_quality
                .conjoin(summary_quality)
                .through_evidence(return_edge.proof(), return_edge.completeness())
            && matches!(
                &self.kind,
                WitnessEvidenceKind::ReusableSummaryApplication {
                    incoming: retained_incoming,
                    summary_quality: retained_summary_quality,
                    return_step,
                } if *retained_incoming == incoming
                    && *retained_summary_quality == summary_quality
                    && return_step.matches_derivation(
                        SummaryWitnessStepKind::Edge(return_edge.kind()),
                        return_edge.source(),
                        Some(return_edge.target()),
                        return_edge.origin(),
                        None,
                        return_edge.proof(),
                        return_edge.completeness(),
                        input_fact,
                        output_fact,
                    )
            )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches_end_summary_derivation(
        &self,
        predecessor: WitnessEvidenceId,
        predecessor_quality: PathQuality,
        entry_point: &ProgramPointHandle,
        entry_fact: FactId,
        exit: &Arc<IcfgExitProfile>,
        exit_fact: FactId,
    ) -> bool {
        let quality = if exit.has_return_affecting_gaps() {
            predecessor_quality.conjoin(PathQuality::UNPROVEN_PARTIAL)
        } else {
            predecessor_quality
        };
        self.quality == quality
            && matches!(
                &self.kind,
                WitnessEvidenceKind::EndSummary {
                    predecessor: retained_predecessor,
                    entry_point: retained_entry_point,
                    entry_fact: retained_entry_fact,
                    exit: retained_exit,
                    exit_fact: retained_exit_fact,
                } if *retained_predecessor == predecessor
                    && retained_entry_point == entry_point
                    && *retained_entry_fact == entry_fact
                    && retained_exit == exit
                    && *retained_exit_fact == exit_fact
            )
    }

    fn retained_bytes(&self) -> usize {
        size_of::<Self>().saturating_add(match &self.kind {
            WitnessEvidenceKind::Step { step, .. } => step.retained_owned_bytes(),
            WitnessEvidenceKind::EndSummary { .. } => 0,
            WitnessEvidenceKind::SummaryApplication { return_step, .. } => {
                return_step.retained_owned_bytes()
            }
            WitnessEvidenceKind::ReusableSummaryApplication { return_step, .. } => {
                return_step.retained_owned_bytes()
            }
        })
    }

    fn mark_alternatives_truncated(&mut self) {
        self.alternatives_truncated = true;
    }

    fn output_point(&self) -> &ProgramPointHandle {
        match &self.kind {
            WitnessEvidenceKind::Step { step, .. } => step.target().unwrap_or(step.source()),
            WitnessEvidenceKind::EndSummary { exit, .. } => exit.callee_exit(),
            WitnessEvidenceKind::SummaryApplication { return_step, .. } => return_step
                .target()
                .expect("summary application return step has a target"),
            WitnessEvidenceKind::ReusableSummaryApplication { return_step, .. } => return_step
                .target()
                .expect("reusable summary application return step has a target"),
        }
    }

    fn output_fact(&self) -> FactId {
        match &self.kind {
            WitnessEvidenceKind::Step { step, .. } => step.output_fact(),
            WitnessEvidenceKind::EndSummary { exit_fact, .. } => *exit_fact,
            WitnessEvidenceKind::SummaryApplication { return_step, .. } => {
                return_step.output_fact()
            }
            WitnessEvidenceKind::ReusableSummaryApplication { return_step, .. } => {
                return_step.output_fact()
            }
        }
    }

    fn predecessors(&self) -> [Option<WitnessEvidenceId>; 2] {
        match &self.kind {
            WitnessEvidenceKind::Step { predecessor, .. } => [*predecessor, None],
            WitnessEvidenceKind::EndSummary { predecessor, .. } => [Some(*predecessor), None],
            WitnessEvidenceKind::SummaryApplication {
                incoming, summary, ..
            } => [Some(*incoming), Some(*summary)],
            WitnessEvidenceKind::ReusableSummaryApplication { incoming, .. } => {
                [Some(*incoming), None]
            }
        }
    }

    fn end_summary_gap_step(&self) -> Option<SummaryWitnessStep> {
        let WitnessEvidenceKind::EndSummary {
            exit, exit_fact, ..
        } = &self.kind
        else {
            return None;
        };
        let reason = exit.return_affecting_gap_reason()?;
        Some(SummaryWitnessStep::new(
            SummaryWitnessStepKind::EndSummaryGap(exit.kind()),
            exit.callee_exit().clone(),
            None,
            None,
            None,
            ProofStatus::Unproven(
                format!(
                    "callee {:?} exit has a return-affecting semantic gap: {reason}",
                    exit.kind()
                )
                .into(),
            ),
            EvidenceCompleteness::Partial(
                format!("callee exit has return-affecting semantic gaps: {reason}").into(),
            ),
            *exit_fact,
            *exit_fact,
        ))
    }

    fn remap_predecessors(&mut self, remap: &[Option<WitnessEvidenceId>]) {
        let mapped = |evidence: WitnessEvidenceId| {
            remap
                .get(evidence.index())
                .and_then(|mapped| *mapped)
                .expect("reachable witness predecessors remain reachable during compaction")
        };
        match &mut self.kind {
            WitnessEvidenceKind::Step { predecessor, .. } => {
                *predecessor = predecessor.map(mapped);
            }
            WitnessEvidenceKind::EndSummary { predecessor, .. } => {
                *predecessor = mapped(*predecessor);
            }
            WitnessEvidenceKind::SummaryApplication {
                incoming, summary, ..
            } => {
                *incoming = mapped(*incoming);
                *summary = mapped(*summary);
            }
            WitnessEvidenceKind::ReusableSummaryApplication { incoming, .. } => {
                *incoming = mapped(*incoming);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct WitnessArena {
    limits: WitnessRetentionLimits,
    nodes: Vec<WitnessEvidenceNode>,
    retained_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WitnessCandidateBudget {
    retained_bytes: usize,
    request_remaining_relations: Option<usize>,
}

impl WitnessCandidateBudget {
    pub(crate) const fn new(
        retained_bytes: usize,
        request_remaining_relations: Option<usize>,
    ) -> Self {
        Self {
            retained_bytes,
            request_remaining_relations,
        }
    }
}

pub(crate) struct WitnessStaging<'staged> {
    nodes: &'staged mut Vec<(WitnessEvidenceId, WitnessEvidenceNode)>,
    retained_bytes: &'staged mut usize,
}

impl<'staged> WitnessStaging<'staged> {
    pub(crate) fn new(
        nodes: &'staged mut Vec<(WitnessEvidenceId, WitnessEvidenceNode)>,
        retained_bytes: &'staged mut usize,
    ) -> Self {
        Self {
            nodes,
            retained_bytes,
        }
    }
}

impl WitnessArena {
    pub(crate) fn new(limits: WitnessRetentionLimits) -> Self {
        Self {
            limits,
            nodes: Vec::new(),
            retained_bytes: 0,
        }
    }

    pub(crate) const fn is_enabled(&self) -> bool {
        self.limits.is_enabled()
    }

    pub(crate) fn max_alternatives_per_quality(&self) -> usize {
        self.limits.max_alternatives_per_quality()
    }

    fn staged_node<'staged>(
        &'staged self,
        id: WitnessEvidenceId,
        staged: &'staged [(WitnessEvidenceId, WitnessEvidenceNode)],
    ) -> Option<&'staged WitnessEvidenceNode> {
        if let Some(node) = self.nodes.get(id.index()) {
            return Some(node);
        }
        staged
            .get(id.index().checked_sub(self.nodes.len())?)
            .and_then(|(staged_id, node)| (*staged_id == id).then_some(node))
    }

    pub(crate) fn stage_candidate<Duplicate, Candidate>(
        &self,
        alternatives: &mut WitnessAlternatives,
        quality: PathQuality,
        candidate_budget: WitnessCandidateBudget,
        mut is_duplicate: Duplicate,
        candidate: Candidate,
        staging: WitnessStaging<'_>,
    ) -> Result<WitnessAdmission, usize>
    where
        Duplicate: FnMut(&WitnessEvidenceNode) -> bool,
        Candidate: FnOnce() -> WitnessEvidenceNode,
    {
        debug_assert!(self.is_enabled());
        if alternatives
            .ids(quality)
            .iter()
            .filter_map(|id| self.staged_node(*id, staging.nodes))
            .any(&mut is_duplicate)
        {
            return Ok(WitnessAdmission::Duplicate);
        }
        if self.limits.is_best_effort()
            && (candidate_budget
                .request_remaining_relations
                .is_some_and(|remaining| staging.nodes.len() >= remaining)
                || self
                    .limits
                    .best_effort_max_relations()
                    .is_some_and(|limit| {
                        self.nodes.len().saturating_add(staging.nodes.len()) >= limit
                    })
                || self
                    .limits
                    .best_effort_max_retained_bytes()
                    .is_some_and(|limit| {
                        self.retained_bytes
                            .saturating_add(*staging.retained_bytes)
                            .saturating_add(candidate_budget.retained_bytes)
                            > limit
                    }))
        {
            return Ok(WitnessAdmission::Exhausted);
        }
        if alternatives.ids(quality).len() >= self.max_alternatives_per_quality() {
            alternatives.mark_truncated(quality);
            return Ok(WitnessAdmission::Truncated);
        }
        let candidate = candidate();
        debug_assert_eq!(candidate.retained_bytes(), candidate_budget.retained_bytes);
        let id = self.staged_id(staging.nodes.len())?;
        alternatives.push(quality, id);
        staging.nodes.push((id, candidate));
        *staging.retained_bytes =
            (*staging.retained_bytes).saturating_add(candidate_budget.retained_bytes);
        Ok(WitnessAdmission::Retained(id))
    }

    fn staged_id(&self, additional_index: usize) -> Result<WitnessEvidenceId, usize> {
        let index = self.nodes.len().saturating_add(additional_index);
        WitnessEvidenceId::try_from_index(index).ok_or(index)
    }

    pub(crate) fn commit(&mut self, expected: WitnessEvidenceId, node: WitnessEvidenceNode) {
        debug_assert_eq!(expected.index(), self.nodes.len());
        self.retained_bytes = self.retained_bytes.saturating_add(node.retained_bytes());
        self.nodes.push(node);
    }

    pub(crate) fn mark_alternatives_truncated(&mut self, alternatives: &WitnessAlternatives) {
        for quality in PathQuality::ALL {
            if !alternatives.is_truncated(quality) {
                continue;
            }
            for evidence in alternatives.ids(quality) {
                self.nodes[evidence.index()].mark_alternatives_truncated();
            }
        }
    }

    pub(crate) fn into_compact_store(
        self,
        roots: impl IntoIterator<Item = WitnessEvidenceId>,
    ) -> (WitnessStore, Box<[Option<WitnessEvidenceId>]>) {
        let mut reachable = vec![false; self.nodes.len()];
        let mut stack = roots.into_iter().collect::<Vec<_>>();
        while let Some(evidence) = stack.pop() {
            let Some(reachable_slot) = reachable.get_mut(evidence.index()) else {
                debug_assert!(false, "active witness root is absent from its arena");
                continue;
            };
            if std::mem::replace(reachable_slot, true) {
                continue;
            }
            let node = self
                .nodes
                .get(evidence.index())
                .expect("validated witness root remains present");
            stack.extend(node.predecessors().into_iter().flatten());
        }

        let mut remap = vec![None; self.nodes.len()];
        let mut next = 0usize;
        for (index, is_reachable) in reachable.iter().copied().enumerate() {
            if !is_reachable {
                continue;
            }
            let evidence = WitnessEvidenceId::try_from_index(next)
                .expect("compacting a u32-bounded arena remains u32-bounded");
            remap[index] = Some(evidence);
            next = next.saturating_add(1);
        }

        let mut nodes = Vec::with_capacity(next);
        for (index, mut node) in self.nodes.into_iter().enumerate() {
            if !reachable[index] {
                continue;
            }
            node.remap_predecessors(&remap);
            nodes.push(node);
        }
        (
            WitnessStore {
                retention_enabled: self.limits.is_enabled(),
                nodes,
            },
            remap.into_boxed_slice(),
        )
    }

    pub(crate) fn into_store(self) -> WitnessStore {
        WitnessStore {
            retention_enabled: self.limits.is_enabled(),
            nodes: self.nodes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessStore {
    retention_enabled: bool,
    nodes: Vec<WitnessEvidenceNode>,
}

pub(crate) enum WitnessTarget<'target> {
    Reached {
        entry_point: &'target ProgramPointHandle,
        entry_fact: FactId,
        point: &'target ProgramPointHandle,
        fact: FactId,
    },
    EndSummary {
        entry_point: &'target ProgramPointHandle,
        entry_fact: FactId,
        exit: &'target IcfgExitProfile,
        exit_fact: FactId,
    },
}

impl WitnessTarget<'_> {
    fn entry_point(&self) -> &ProgramPointHandle {
        match self {
            Self::Reached { entry_point, .. } | Self::EndSummary { entry_point, .. } => entry_point,
        }
    }

    fn entry_fact(&self) -> FactId {
        match self {
            Self::Reached { entry_fact, .. } | Self::EndSummary { entry_fact, .. } => *entry_fact,
        }
    }
}

impl WitnessStore {
    pub(crate) fn reconstruct(
        &self,
        evidence: WitnessEvidenceId,
        quality: PathQuality,
        mut alternatives_truncated: bool,
        limits: WitnessReconstructionLimits,
        target: WitnessTarget<'_>,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        if !self.retention_enabled {
            return Err(SummaryWitnessError::RetentionDisabled);
        }
        let root = self
            .node(evidence)
            .ok_or(SummaryWitnessError::InvalidEvidence(
                "root evidence ID is absent",
            ))?;
        if root.quality != quality {
            return Err(SummaryWitnessError::InvalidEvidence(
                "root quality does not match its result slot",
            ));
        }
        self.validate_root(root, &target)?;

        #[derive(Debug)]
        enum Task {
            Expand(WitnessEvidenceId),
            Emit(Box<SummaryWitnessStep>),
            OmittedReusableSummary,
        }

        let mut stack = vec![Task::Expand(evidence)];
        let mut steps = Vec::new();
        let mut expansions = 0usize;
        let mut truncated = false;
        let mut omitted_steps_lower_bound = 0usize;

        while let Some(task) = stack.pop() {
            match task {
                Task::Expand(id) => {
                    if expansions >= limits.max_expansions() {
                        truncated = true;
                        omitted_steps_lower_bound = 1 + stack
                            .iter()
                            .filter(|task| matches!(task, Task::Emit(_)))
                            .count();
                        break;
                    }
                    expansions = expansions.saturating_add(1);
                    let node = self.node(id).ok_or(SummaryWitnessError::InvalidEvidence(
                        "predecessor evidence ID is absent",
                    ))?;
                    alternatives_truncated |= node.alternatives_truncated;
                    self.validate_node(node)?;
                    match &node.kind {
                        WitnessEvidenceKind::Step { predecessor, step } => {
                            stack.push(Task::Emit(Box::new(step.clone())));
                            if let Some(predecessor) = predecessor {
                                stack.push(Task::Expand(*predecessor));
                            }
                        }
                        WitnessEvidenceKind::EndSummary { predecessor, .. } => {
                            if let Some(gap_step) = node.end_summary_gap_step() {
                                stack.push(Task::Emit(Box::new(gap_step)));
                            }
                            stack.push(Task::Expand(*predecessor));
                        }
                        WitnessEvidenceKind::SummaryApplication {
                            incoming,
                            summary,
                            return_step,
                        } => {
                            stack.push(Task::Emit(Box::new(return_step.clone())));
                            stack.push(Task::Expand(*summary));
                            stack.push(Task::Expand(*incoming));
                        }
                        WitnessEvidenceKind::ReusableSummaryApplication {
                            incoming,
                            return_step,
                            ..
                        } => {
                            stack.push(Task::Emit(Box::new(return_step.clone())));
                            stack.push(Task::OmittedReusableSummary);
                            stack.push(Task::Expand(*incoming));
                        }
                    }
                }
                Task::Emit(step) => {
                    let step = *step;
                    if steps.len() >= limits.max_steps() {
                        truncated = true;
                        omitted_steps_lower_bound = 1 + stack
                            .iter()
                            .filter(|task| matches!(task, Task::Emit(_)))
                            .count();
                        break;
                    }
                    if steps.is_empty() {
                        let fact_is_stable = step.input_fact() == step.output_fact();
                        let root_entry_seed = step.source() == target.entry_point()
                            && step.input_fact() == target.entry_fact();
                        let explicit_point_seed = target.entry_fact().get() == 0
                            && step.source().procedure() == target.entry_point().procedure();
                        if !matches!(step.kind(), SummaryWitnessStepKind::Seed)
                            || !fact_is_stable
                            || (!root_entry_seed && !explicit_point_seed)
                        {
                            return Err(SummaryWitnessError::InvalidEvidence(
                                "witness does not begin at the requested entry relation",
                            ));
                        }
                    }
                    steps.push(step);
                }
                Task::OmittedReusableSummary => {
                    truncated = true;
                    omitted_steps_lower_bound = omitted_steps_lower_bound.saturating_add(1);
                }
            }
        }

        let retained_bytes = size_of::<SummaryWitness>()
            .saturating_add(steps.len().saturating_mul(size_of::<SummaryWitnessStep>()))
            .saturating_add(
                steps
                    .iter()
                    .map(SummaryWitnessStep::retained_owned_bytes)
                    .fold(0usize, usize::saturating_add),
            );
        let emitted_steps = steps.len();
        Ok(SummaryWitness::from_parts(
            steps,
            quality,
            truncated,
            omitted_steps_lower_bound,
            alternatives_truncated,
            retained_bytes,
            WitnessReconstructionWork::new(expansions, emitted_steps),
        ))
    }

    fn node(&self, id: WitnessEvidenceId) -> Option<&WitnessEvidenceNode> {
        self.nodes.get(id.index())
    }

    fn validate_root(
        &self,
        root: &WitnessEvidenceNode,
        target: &WitnessTarget<'_>,
    ) -> Result<(), SummaryWitnessError> {
        match target {
            WitnessTarget::Reached { point, fact, .. } => {
                if root.output_point() != *point || root.output_fact() != *fact {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "root evidence does not terminate at the requested reached fact",
                    ));
                }
            }
            WitnessTarget::EndSummary {
                entry_point,
                entry_fact,
                exit,
                exit_fact,
            } => {
                let WitnessEvidenceKind::EndSummary {
                    entry_point: root_entry_point,
                    entry_fact: root_entry_fact,
                    exit: root_exit,
                    exit_fact: root_exit_fact,
                    ..
                } = &root.kind
                else {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "end-summary target does not reference end-summary evidence",
                    ));
                };
                if root_entry_point != *entry_point
                    || *root_entry_fact != *entry_fact
                    || root_exit.as_ref() != *exit
                    || *root_exit_fact != *exit_fact
                {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "root evidence does not match the requested end summary",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_node(&self, node: &WitnessEvidenceNode) -> Result<(), SummaryWitnessError> {
        match &node.kind {
            WitnessEvidenceKind::Step { predecessor, step } => {
                if let Some(predecessor) = predecessor {
                    let predecessor =
                        self.node(*predecessor)
                            .ok_or(SummaryWitnessError::InvalidEvidence(
                                "edge predecessor is absent",
                            ))?;
                    if predecessor.output_point() != step.source() {
                        return Err(SummaryWitnessError::InvalidEvidence(
                            "edge predecessor point does not match its source",
                        ));
                    }
                    if predecessor.output_fact() != step.input_fact() {
                        return Err(SummaryWitnessError::InvalidEvidence(
                            "edge predecessor fact does not match its input",
                        ));
                    }
                    let expected = predecessor
                        .quality
                        .through_evidence(step.proof(), step.completeness());
                    if expected != node.quality {
                        return Err(SummaryWitnessError::InvalidEvidence(
                            "edge quality does not match its predecessor and evidence",
                        ));
                    }
                    if step.target().is_none() {
                        return Err(SummaryWitnessError::InvalidEvidence(
                            "edge witness step has no target",
                        ));
                    }
                } else if !matches!(step.kind(), SummaryWitnessStepKind::Seed)
                    || step.target().is_some()
                    || step.input_fact() != step.output_fact()
                    || node.quality != PathQuality::PROVEN_COMPLETE
                {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "seed evidence has an invalid shape",
                    ));
                }
            }
            WitnessEvidenceKind::EndSummary {
                predecessor,
                entry_point,
                exit,
                exit_fact,
                ..
            } => {
                let predecessor =
                    self.node(*predecessor)
                        .ok_or(SummaryWitnessError::InvalidEvidence(
                            "end-summary predecessor is absent",
                        ))?;
                if predecessor.output_point() != exit.callee_exit()
                    || predecessor.output_fact() != *exit_fact
                    || entry_point != exit.callee_entry()
                {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "end-summary topology does not match its predecessor",
                    ));
                }
                if predecessor.output_point().procedure() != entry_point.procedure() {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "end-summary entry and exit belong to different procedures",
                    ));
                }
                let expected = if exit.has_return_affecting_gaps() {
                    predecessor.quality.conjoin(PathQuality::UNPROVEN_PARTIAL)
                } else {
                    predecessor.quality
                };
                if expected != node.quality {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "end-summary quality is inconsistent",
                    ));
                }
            }
            WitnessEvidenceKind::SummaryApplication {
                incoming,
                summary,
                return_step,
            } => {
                let incoming = self
                    .node(*incoming)
                    .ok_or(SummaryWitnessError::InvalidEvidence(
                        "summary incoming evidence is absent",
                    ))?;
                let summary = self
                    .node(*summary)
                    .ok_or(SummaryWitnessError::InvalidEvidence(
                        "applied end-summary evidence is absent",
                    ))?;
                let WitnessEvidenceKind::EndSummary {
                    entry_point,
                    entry_fact,
                    exit,
                    ..
                } = &summary.kind
                else {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "summary application does not reference an end summary",
                    ));
                };
                let WitnessEvidenceKind::Step {
                    step: incoming_step,
                    ..
                } = &incoming.kind
                else {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "summary incoming evidence is not a call edge",
                    ));
                };
                let expected_return_kind = match exit.kind() {
                    ReturnTransferKind::Normal => IcfgEdgeKind::NormalReturn,
                    ReturnTransferKind::Exceptional => IcfgEdgeKind::ExceptionalReturn,
                };
                if incoming.output_point() != entry_point
                    || incoming.output_fact() != *entry_fact
                    || summary.output_point() != return_step.source()
                    || summary.output_fact() != return_step.input_fact()
                    || incoming_step.kind() != SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call)
                    || incoming_step.origin().is_none()
                    || incoming_step.origin() != return_step.origin()
                    || return_step.kind() != SummaryWitnessStepKind::Edge(expected_return_kind)
                    || return_step.target().is_none_or(|target| {
                        target.procedure() != incoming_step.source().procedure()
                    })
                {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "summary application call/return topology or facts do not match",
                    ));
                }
                let expected = incoming
                    .quality
                    .conjoin(summary.quality)
                    .through_evidence(return_step.proof(), return_step.completeness());
                if expected != node.quality || return_step.target().is_none() {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "summary application quality or return target is inconsistent",
                    ));
                }
            }
            WitnessEvidenceKind::ReusableSummaryApplication {
                incoming,
                summary_quality,
                return_step,
            } => {
                let incoming = self
                    .node(*incoming)
                    .ok_or(SummaryWitnessError::InvalidEvidence(
                        "reusable summary incoming evidence is absent",
                    ))?;
                let WitnessEvidenceKind::Step {
                    step: incoming_step,
                    ..
                } = &incoming.kind
                else {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "reusable summary incoming evidence is not a call edge",
                    ));
                };
                let expected_return_kind = match return_step.kind() {
                    SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn) => {
                        IcfgEdgeKind::NormalReturn
                    }
                    SummaryWitnessStepKind::Edge(IcfgEdgeKind::ExceptionalReturn) => {
                        IcfgEdgeKind::ExceptionalReturn
                    }
                    _ => {
                        return Err(SummaryWitnessError::InvalidEvidence(
                            "reusable summary application is not a return edge",
                        ));
                    }
                };
                if incoming_step.kind() != SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call)
                    || incoming_step.origin().is_none()
                    || incoming_step.origin() != return_step.origin()
                    || return_step.kind() != SummaryWitnessStepKind::Edge(expected_return_kind)
                    || incoming.output_point().procedure() != return_step.source().procedure()
                    || return_step.target().is_none_or(|target| {
                        target.procedure() != incoming_step.source().procedure()
                    })
                {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "reusable summary application call/return topology does not match",
                    ));
                }
                let expected = incoming
                    .quality
                    .conjoin(*summary_quality)
                    .through_evidence(return_step.proof(), return_step.completeness());
                if expected != node.quality || return_step.target().is_none() {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "reusable summary application quality or return target is inconsistent",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_retention_is_explicit_and_rejects_zero() {
        assert!(!WitnessRetentionLimits::default().is_enabled());
        assert_eq!(
            WitnessRetentionLimits::new(0).unwrap_err().field(),
            "max_alternatives_per_quality"
        );

        let enabled = WitnessRetentionLimits::new(3).unwrap();
        assert!(enabled.is_enabled());
        assert!(!enabled.is_best_effort());
        assert_eq!(enabled.max_alternatives_per_quality(), 3);
        let best_effort = WitnessRetentionLimits::best_effort(1, 64, 1024).unwrap();
        assert!(best_effort.is_enabled());
        assert!(best_effort.is_best_effort());
        assert_eq!(
            WitnessRetentionLimits::best_effort(1, 0, 1024)
                .unwrap_err()
                .field(),
            "max_retained_relations"
        );
        assert_eq!(
            WitnessRetentionLimits::best_effort(2, 64, 1024)
                .unwrap_err()
                .to_string(),
            "max_alternatives_per_quality must be at most 1"
        );
        assert_eq!(
            WitnessRetentionLimits::best_effort(1, 64, 0)
                .unwrap_err()
                .field(),
            "max_retained_bytes"
        );
        assert_eq!(
            WitnessRetentionLimits::new(MAX_WITNESS_ALTERNATIVES_PER_QUALITY + 1)
                .unwrap_err()
                .to_string(),
            format!(
                "max_alternatives_per_quality must be at most {MAX_WITNESS_ALTERNATIVES_PER_QUALITY}"
            ),
        );
        assert!(
            std::mem::size_of::<WitnessAlternatives>() <= std::mem::size_of::<usize>(),
            "disabled witness rows retain only one optional pointer",
        );
    }

    #[test]
    fn witness_reconstruction_limits_reject_zero_dimensions() {
        assert_eq!(
            WitnessReconstructionLimits::new(0, 1).unwrap_err().field(),
            "max_steps"
        );
        assert_eq!(
            WitnessReconstructionLimits::new(1, 0).unwrap_err().field(),
            "max_expansions"
        );

        let limits = WitnessReconstructionLimits::new(2, 5).unwrap();
        assert_eq!(limits.max_steps(), 2);
        assert_eq!(limits.max_expansions(), 5);
    }

    #[test]
    fn best_effort_byte_admission_is_checked_before_candidate_allocation() {
        let arena = WitnessArena::new(WitnessRetentionLimits::best_effort(1, 64, 1).unwrap());
        let mut alternatives = WitnessAlternatives::default();
        let mut staged = Vec::new();
        let mut staged_bytes = 0usize;

        let admission = arena
            .stage_candidate(
                &mut alternatives,
                PathQuality::PROVEN_COMPLETE,
                WitnessCandidateBudget::new(WitnessEvidenceNode::seed_retained_bytes(), None),
                |_| panic!("byte-exhausted candidates must not inspect duplicates"),
                || panic!("byte-exhausted candidates must remain lazy"),
                WitnessStaging::new(&mut staged, &mut staged_bytes),
            )
            .unwrap();

        assert_eq!(admission, WitnessAdmission::Exhausted);
        assert!(staged.is_empty());
        assert_eq!(staged_bytes, 0);
    }

    #[test]
    fn best_effort_request_admission_is_checked_before_candidate_allocation() {
        let arena = WitnessArena::new(WitnessRetentionLimits::best_effort(1, 64, 1024).unwrap());
        let mut alternatives = WitnessAlternatives::default();
        let mut staged = Vec::new();
        let mut staged_bytes = 0usize;

        let admission = arena
            .stage_candidate(
                &mut alternatives,
                PathQuality::PROVEN_COMPLETE,
                WitnessCandidateBudget::new(WitnessEvidenceNode::seed_retained_bytes(), Some(0)),
                |_| panic!("request-exhausted candidates must not inspect duplicates"),
                || panic!("request-exhausted candidates must remain lazy"),
                WitnessStaging::new(&mut staged, &mut staged_bytes),
            )
            .unwrap();

        assert_eq!(admission, WitnessAdmission::Exhausted);
        assert!(staged.is_empty());
        assert_eq!(staged_bytes, 0);
    }

    #[test]
    fn full_best_effort_alternative_slot_is_checked_before_candidate_allocation() {
        let arena = WitnessArena::new(WitnessRetentionLimits::best_effort(1, 64, 1024).unwrap());
        let mut alternatives = WitnessAlternatives::default();
        alternatives.push(
            PathQuality::PROVEN_COMPLETE,
            WitnessEvidenceId::try_from_index(0).unwrap(),
        );
        let mut staged = Vec::new();
        let mut staged_bytes = 0usize;

        let admission = arena
            .stage_candidate(
                &mut alternatives,
                PathQuality::PROVEN_COMPLETE,
                WitnessCandidateBudget::new(WitnessEvidenceNode::seed_retained_bytes(), None),
                |_| false,
                || panic!("full best-effort slots must not allocate candidates"),
                WitnessStaging::new(&mut staged, &mut staged_bytes),
            )
            .unwrap();

        assert_eq!(admission, WitnessAdmission::Truncated);
        assert!(alternatives.is_truncated(PathQuality::PROVEN_COMPLETE));
        assert!(staged.is_empty());
        assert_eq!(staged_bytes, 0);
    }
}
