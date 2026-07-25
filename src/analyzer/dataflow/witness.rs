//! Policy-independent bounded witnesses for summary dataflow results.

use std::{error::Error, fmt, num::NonZeroUsize};
use std::{mem::size_of, sync::Arc};

use crate::analyzer::semantic::{
    CallSiteHandle, EvidenceCompleteness, IcfgEdgeKind, IcfgExitProfile, ProcedureIcfgEdge,
    ProgramPointHandle, ProofStatus,
};

use super::{FactId, PathQuality, PathQualityFrontier, SummaryEdge};

const DEFAULT_RECONSTRUCTION_STEPS: usize = 4_096;
const DEFAULT_RECONSTRUCTION_EXPANSIONS: usize = 16_384;

/// Why witness-limit construction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessLimitError {
    field: &'static str,
}

impl WitnessLimitError {
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for WitnessLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} must be greater than zero", self.field)
    }
}

impl Error for WitnessLimitError {}

/// Query-local witness storage requested from the summary solver.
///
/// Disabled retention performs no predecessor allocation. When enabled, the
/// solver retains at most `max_alternatives_per_quality` derivations for one
/// concrete `(state, PathQuality)` pair. Total retained growth is independently
/// bounded by [`super::SolverBudgetDimension::WitnessRelations`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessRetentionLimits {
    max_alternatives_per_quality: Option<NonZeroUsize>,
}

impl WitnessRetentionLimits {
    pub const fn disabled() -> Self {
        Self {
            max_alternatives_per_quality: None,
        }
    }

    pub fn new(max_alternatives_per_quality: usize) -> Result<Self, WitnessLimitError> {
        let max_alternatives_per_quality =
            NonZeroUsize::new(max_alternatives_per_quality).ok_or(WitnessLimitError {
                field: "max_alternatives_per_quality",
            })?;
        Ok(Self {
            max_alternatives_per_quality: Some(max_alternatives_per_quality),
        })
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
}

/// Per-request bounds for expanding one retained witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessReconstructionLimits {
    max_steps: NonZeroUsize,
    max_expansions: NonZeroUsize,
}

impl WitnessReconstructionLimits {
    pub fn new(max_steps: usize, max_expansions: usize) -> Result<Self, WitnessLimitError> {
        let max_steps =
            NonZeroUsize::new(max_steps).ok_or(WitnessLimitError { field: "max_steps" })?;
        let max_expansions = NonZeroUsize::new(max_expansions).ok_or(WitnessLimitError {
            field: "max_expansions",
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
}

/// One source-backed step in a reconstructed summary-dataflow witness.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryWitnessStep {
    kind: SummaryWitnessStepKind,
    source: ProgramPointHandle,
    target: Option<ProgramPointHandle>,
    origin: Option<CallSiteHandle>,
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
            retained_bytes,
            work,
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
    by_quality: [Vec<WitnessEvidenceId>; 4],
    truncated: [bool; 4],
}

impl WitnessAlternatives {
    pub(crate) fn ids(&self, quality: PathQuality) -> &[WitnessEvidenceId] {
        &self.by_quality[quality.ordinal()]
    }

    pub(crate) fn first(&self, quality: PathQuality) -> Option<WitnessEvidenceId> {
        self.ids(quality).first().copied()
    }

    pub(crate) fn contains(&self, quality: PathQuality, evidence: WitnessEvidenceId) -> bool {
        self.ids(quality).contains(&evidence)
    }

    pub(crate) fn is_truncated(&self, quality: PathQuality) -> bool {
        self.truncated[quality.ordinal()]
    }

    pub(crate) fn push(&mut self, quality: PathQuality, evidence: WitnessEvidenceId) {
        self.by_quality[quality.ordinal()].push(evidence);
    }

    pub(crate) fn mark_truncated(&mut self, quality: PathQuality) {
        self.truncated[quality.ordinal()] = true;
    }

    pub(crate) fn retain_frontier(&mut self, frontier: PathQualityFrontier) {
        for quality in PathQuality::ALL {
            if !frontier.contains(quality) {
                self.by_quality[quality.ordinal()].clear();
                self.truncated[quality.ordinal()] = false;
            }
        }
    }

    pub(crate) fn all_ids(&self) -> impl Iterator<Item = WitnessEvidenceId> + '_ {
        self.by_quality
            .iter()
            .flat_map(|alternatives| alternatives.iter().copied())
    }

    pub(crate) fn remap(&mut self, remap: &[Option<WitnessEvidenceId>]) {
        for alternatives in &mut self.by_quality {
            for evidence in alternatives {
                *evidence = remap
                    .get(evidence.index())
                    .and_then(|mapped| *mapped)
                    .expect("active witness evidence remains reachable during compaction");
            }
        }
    }
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
}

impl WitnessEvidenceNode {
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
                    edge.proof.clone(),
                    edge.completeness.clone(),
                    input_fact,
                    output_fact,
                ),
            },
        }
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
                    return_edge.proof().clone(),
                    return_edge.completeness().clone(),
                    input_fact,
                    output_fact,
                ),
            },
        }
    }

    pub(crate) const fn quality(&self) -> PathQuality {
        self.quality
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
        }
    }

    fn output_fact(&self) -> FactId {
        match &self.kind {
            WitnessEvidenceKind::Step { step, .. } => step.output_fact(),
            WitnessEvidenceKind::EndSummary { exit_fact, .. } => *exit_fact,
            WitnessEvidenceKind::SummaryApplication { return_step, .. } => {
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
        }
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
        }
    }
}

#[derive(Debug)]
pub(crate) struct WitnessArena {
    limits: WitnessRetentionLimits,
    nodes: Vec<WitnessEvidenceNode>,
}

impl WitnessArena {
    pub(crate) fn new(limits: WitnessRetentionLimits) -> Self {
        Self {
            limits,
            nodes: Vec::new(),
        }
    }

    pub(crate) const fn is_enabled(&self) -> bool {
        self.limits.is_enabled()
    }

    pub(crate) fn max_alternatives_per_quality(&self) -> usize {
        self.limits.max_alternatives_per_quality()
    }

    pub(crate) fn node(&self, id: WitnessEvidenceId) -> Option<&WitnessEvidenceNode> {
        self.nodes.get(id.index())
    }

    pub(crate) fn should_retain(
        &self,
        alternatives: &WitnessAlternatives,
        quality: PathQuality,
        candidate: &WitnessEvidenceNode,
    ) -> bool {
        if !self.is_enabled()
            || alternatives.ids(quality).len() >= self.max_alternatives_per_quality()
        {
            return false;
        }
        alternatives
            .ids(quality)
            .iter()
            .filter_map(|id| self.node(*id))
            .all(|existing| existing != candidate)
    }

    pub(crate) fn staged_id(&self, additional_index: usize) -> Result<WitnessEvidenceId, usize> {
        let index = self.nodes.len().saturating_add(additional_index);
        WitnessEvidenceId::try_from_index(index).ok_or(index)
    }

    pub(crate) fn commit(&mut self, expected: WitnessEvidenceId, node: WitnessEvidenceNode) {
        debug_assert_eq!(expected.index(), self.nodes.len());
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
                nodes: nodes.into_boxed_slice(),
            },
            remap.into_boxed_slice(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessStore {
    retention_enabled: bool,
    nodes: Box<[WitnessEvidenceNode]>,
}

impl WitnessStore {
    pub(crate) fn reconstruct(
        &self,
        evidence: WitnessEvidenceId,
        quality: PathQuality,
        mut alternatives_truncated: bool,
        limits: WitnessReconstructionLimits,
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

        #[derive(Debug)]
        enum Task {
            Expand(WitnessEvidenceId),
            Emit(SummaryWitnessStep),
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
                            stack.push(Task::Emit(step.clone()));
                            if let Some(predecessor) = predecessor {
                                stack.push(Task::Expand(*predecessor));
                            }
                        }
                        WitnessEvidenceKind::EndSummary { predecessor, .. } => {
                            stack.push(Task::Expand(*predecessor));
                        }
                        WitnessEvidenceKind::SummaryApplication {
                            incoming,
                            summary,
                            return_step,
                        } => {
                            stack.push(Task::Emit(return_step.clone()));
                            stack.push(Task::Expand(*summary));
                            stack.push(Task::Expand(*incoming));
                        }
                    }
                }
                Task::Emit(step) => {
                    if steps.len() >= limits.max_steps() {
                        truncated = true;
                        omitted_steps_lower_bound = 1 + stack
                            .iter()
                            .filter(|task| matches!(task, Task::Emit(_)))
                            .count();
                        break;
                    }
                    steps.push(step);
                }
            }
        }

        let retained_bytes = size_of::<SummaryWitness>()
            .saturating_add(steps.len().saturating_mul(size_of::<SummaryWitnessStep>()));
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
                    ..
                } = &summary.kind
                else {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "summary application does not reference an end summary",
                    ));
                };
                if incoming.output_point() != entry_point
                    || incoming.output_fact() != *entry_fact
                    || summary.output_point() != return_step.source()
                    || summary.output_fact() != return_step.input_fact()
                {
                    return Err(SummaryWitnessError::InvalidEvidence(
                        "summary application topology or facts do not match",
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
        assert_eq!(enabled.max_alternatives_per_quality(), 3);
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
}
