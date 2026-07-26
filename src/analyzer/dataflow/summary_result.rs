//! Deterministic public results for in-memory summary tabulation.

use std::{
    cmp::Ordering,
    error::Error,
    fmt,
    hash::{Hash, Hasher},
    sync::Arc,
};

use crate::analyzer::semantic::{
    CallContinuationKind, CallSiteHandle, ControlContinuation, ControlEdgeKind, DispatchBoundary,
    DispatchBoundaryKind, EvidenceCompleteness, IcfgBoundaryKind, IcfgEdgeKind, IcfgExitProfile,
    IcfgLimitKind, OracleRelationHandle, ProcedureHandle, ProcedureIcfgBoundary, ProcedureIcfgEdge,
    ProgramPointHandle, ProofStatus, ReturnTransferKind, SemanticProviderError, SemanticWork,
    compare_relation_provenance,
};

use super::{FactId, PathQualityFrontier, SemanticInputStatus, SolverTermination, SolverWork};
use super::{
    PathQuality, SummaryWitness, SummaryWitnessError, WitnessReconstructionLimits,
    witness::{WitnessAlternatives, WitnessStore, WitnessTarget},
};

/// One procedure entry and fact whose relative path edges share an end-summary
/// relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryEntry {
    procedure: ProcedureHandle,
    entry_point: ProgramPointHandle,
    entry_fact: FactId,
}

impl SummaryEntry {
    pub(crate) fn new(
        procedure: ProcedureHandle,
        entry_point: ProgramPointHandle,
        entry_fact: FactId,
    ) -> Self {
        debug_assert_eq!(
            &procedure,
            entry_point.procedure(),
            "summary entry point must belong to its procedure"
        );
        Self {
            procedure,
            entry_point,
            entry_fact,
        }
    }

    pub const fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub const fn entry_point(&self) -> &ProgramPointHandle {
        &self.entry_point
    }

    pub const fn entry_fact(&self) -> FactId {
        self.entry_fact
    }
}

/// One deterministically ordered relative `(entry, point, fact)` path edge.
#[derive(Debug, Clone)]
pub struct SummaryReachedFact {
    entry: SummaryEntry,
    point: ProgramPointHandle,
    fact: FactId,
    path_qualities: PathQualityFrontier,
    witnesses: WitnessAlternatives,
    witness_owner: Option<Arc<()>>,
}

impl PartialEq for SummaryReachedFact {
    fn eq(&self, other: &Self) -> bool {
        self.entry == other.entry
            && self.point == other.point
            && self.fact == other.fact
            && self.path_qualities == other.path_qualities
    }
}

impl Eq for SummaryReachedFact {}

impl Hash for SummaryReachedFact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entry.hash(state);
        self.point.hash(state);
        self.fact.hash(state);
        self.path_qualities.hash(state);
    }
}

impl SummaryReachedFact {
    pub(crate) fn new(
        entry: SummaryEntry,
        point: ProgramPointHandle,
        fact: FactId,
        path_qualities: PathQualityFrontier,
        witnesses: WitnessAlternatives,
        witness_owner: Option<Arc<()>>,
    ) -> Self {
        debug_assert_eq!(
            entry.procedure(),
            point.procedure(),
            "summary path point must belong to its entry procedure"
        );
        Self {
            entry,
            point,
            fact,
            path_qualities,
            witnesses,
            witness_owner,
        }
    }

    pub const fn entry(&self) -> &SummaryEntry {
        &self.entry
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn fact(&self) -> FactId {
        self.fact
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }
}

/// One query-local entry-to-exit summary used for matched-return replay.
///
/// This is correctness-critical tabulation state, not a persisted semantic,
/// taint, typestate, or protocol summary.
#[derive(Debug, Clone)]
pub struct TabulationEndSummary {
    entry: SummaryEntry,
    exit: Arc<IcfgExitProfile>,
    exit_fact: FactId,
    path_qualities: PathQualityFrontier,
    witnesses: WitnessAlternatives,
    witness_owner: Option<Arc<()>>,
}

impl PartialEq for TabulationEndSummary {
    fn eq(&self, other: &Self) -> bool {
        self.entry == other.entry
            && self.exit == other.exit
            && self.exit_fact == other.exit_fact
            && self.path_qualities == other.path_qualities
    }
}

impl Eq for TabulationEndSummary {}

impl TabulationEndSummary {
    pub(crate) fn new(
        entry: SummaryEntry,
        exit: Arc<IcfgExitProfile>,
        exit_fact: FactId,
        path_qualities: PathQualityFrontier,
        witnesses: WitnessAlternatives,
        witness_owner: Option<Arc<()>>,
    ) -> Self {
        debug_assert_eq!(
            entry.procedure(),
            exit.callee_exit().procedure(),
            "summary exit must belong to its entry procedure"
        );
        debug_assert_eq!(
            entry.entry_point(),
            exit.callee_entry(),
            "summary exit evidence must start at its exact entry"
        );
        Self {
            entry,
            exit,
            exit_fact,
            path_qualities,
            witnesses,
            witness_owner,
        }
    }

    pub const fn entry(&self) -> &SummaryEntry {
        &self.entry
    }

    pub fn exit(&self) -> &IcfgExitProfile {
        self.exit.as_ref()
    }

    pub fn exit_point(&self) -> &ProgramPointHandle {
        self.exit.callee_exit()
    }

    pub fn exit_kind(&self) -> ReturnTransferKind {
        self.exit.kind()
    }

    pub const fn exit_fact(&self) -> FactId {
        self.exit_fact
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }
}

/// One reachable semantic transfer whose evidence is unproven or incomplete.
///
/// Unlike bounded tabulation, a summary result has no backing `IcfgSnapshot`
/// from which a client could recover the evidence. The owned row therefore
/// retains exact proof and completeness details as well as topology.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryEdge {
    kind: IcfgEdgeKind,
    origin: Option<CallSiteHandle>,
    source: ProgramPointHandle,
    target: ProgramPointHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

impl SummaryEdge {
    pub(crate) fn from_procedure_edge(edge: &ProcedureIcfgEdge) -> Self {
        Self {
            kind: edge.kind,
            origin: edge.origin.clone(),
            source: edge.source.clone(),
            target: edge.target.clone(),
            proof: edge.proof.clone(),
            completeness: edge.completeness.clone(),
        }
    }

    pub(crate) fn from_owned_procedure_edge(edge: ProcedureIcfgEdge) -> Self {
        Self {
            kind: edge.kind,
            origin: edge.origin,
            source: edge.source,
            target: edge.target,
            proof: edge.proof,
            completeness: edge.completeness,
        }
    }

    pub const fn kind(&self) -> IcfgEdgeKind {
        self.kind
    }

    pub const fn origin(&self) -> Option<&CallSiteHandle> {
        self.origin.as_ref()
    }

    pub const fn source(&self) -> &ProgramPointHandle {
        &self.source
    }

    pub const fn target(&self) -> &ProgramPointHandle {
        &self.target
    }

    pub const fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub const fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }
}

/// Summary-solve terminology for the shared semantic input status.
pub type SummarySemanticStatus = SemanticInputStatus;

/// Why a reachable summary point does not have complete ICFG coverage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SummaryBoundaryKind {
    /// A non-complete provider envelope at this query point.
    Semantic(SummarySemanticStatus),
    Dispatch(DispatchBoundaryKind),
    Limit(IcfgLimitKind),
    Continuation {
        kind: CallContinuationKind,
        state: ControlContinuation,
    },
}

impl From<IcfgBoundaryKind> for SummaryBoundaryKind {
    fn from(kind: IcfgBoundaryKind) -> Self {
        match kind {
            IcfgBoundaryKind::Dispatch(kind) => Self::Dispatch(kind),
            IcfgBoundaryKind::Limit(kind) => Self::Limit(kind),
            IcfgBoundaryKind::Continuation { kind, state } => Self::Continuation { kind, state },
        }
    }
}

/// One incomplete boundary keyed by a semantic program point rather than a
/// bounded-snapshot node ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryBoundary {
    at: ProgramPointHandle,
    origin: Option<CallSiteHandle>,
    kind: SummaryBoundaryKind,
    proof: Option<ProofStatus>,
    completeness: Option<EvidenceCompleteness>,
    provenance: Box<[OracleRelationHandle]>,
}

impl SummaryBoundary {
    pub(crate) fn new(
        at: ProgramPointHandle,
        origin: Option<CallSiteHandle>,
        kind: SummaryBoundaryKind,
    ) -> Self {
        Self {
            at,
            origin,
            kind,
            proof: None,
            completeness: None,
            provenance: Box::new([]),
        }
    }

    pub(crate) fn from_dispatch(
        at: ProgramPointHandle,
        origin: CallSiteHandle,
        dispatch: &DispatchBoundary,
    ) -> Self {
        Self {
            at,
            origin: Some(origin),
            kind: SummaryBoundaryKind::Dispatch(dispatch.kind.clone()),
            proof: Some(dispatch.proof.clone()),
            completeness: Some(dispatch.completeness.clone()),
            provenance: dispatch.provenance.clone(),
        }
    }

    pub(crate) fn from_procedure_boundary(boundary: ProcedureIcfgBoundary) -> Self {
        Self::new(boundary.at, boundary.origin, boundary.kind.into())
    }

    pub const fn at(&self) -> &ProgramPointHandle {
        &self.at
    }

    pub const fn origin(&self) -> Option<&CallSiteHandle> {
        self.origin.as_ref()
    }

    pub const fn kind(&self) -> &SummaryBoundaryKind {
        &self.kind
    }

    /// Exact boundary proof when the originating semantic relation supplied
    /// one. Continuation and request-status boundaries have no edge proof.
    pub const fn proof(&self) -> Option<&ProofStatus> {
        self.proof.as_ref()
    }

    /// Exact boundary completeness when supplied by dispatch.
    pub const fn completeness(&self) -> Option<&EvidenceCompleteness> {
        self.completeness.as_ref()
    }

    /// Structured dispatch provenance retained by the semantic oracle.
    pub fn provenance(&self) -> &[OracleRelationHandle] {
        &self.provenance
    }
}

/// Global semantic and reachable-edge coverage observed by a summary solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryCoverage {
    semantic_status: SummarySemanticStatus,
    unproven_edges: Box<[SummaryEdge]>,
    partial_edges: Box<[SummaryEdge]>,
    boundaries: Box<[SummaryBoundary]>,
}

impl SummaryCoverage {
    pub(crate) fn from_parts(
        mut unproven_edges: Vec<SummaryEdge>,
        mut partial_edges: Vec<SummaryEdge>,
        mut boundaries: Vec<SummaryBoundary>,
    ) -> Self {
        // Complete provider envelopes are not boundaries and retaining them
        // would make an otherwise complete result appear incomplete.
        boundaries.retain(|boundary| {
            !matches!(
                boundary.kind(),
                SummaryBoundaryKind::Semantic(SummarySemanticStatus::Complete)
            )
        });
        let semantic_status = boundaries
            .iter()
            .filter_map(|boundary| match boundary.kind() {
                SummaryBoundaryKind::Semantic(status) => Some(*status),
                SummaryBoundaryKind::Dispatch(_)
                | SummaryBoundaryKind::Limit(_)
                | SummaryBoundaryKind::Continuation { .. } => None,
            })
            .fold(SummarySemanticStatus::Complete, |current, incoming| {
                current.merge(incoming)
            });

        unproven_edges.sort_by(compare_summary_edges);
        unproven_edges.dedup();
        partial_edges.sort_by(compare_summary_edges);
        partial_edges.dedup();
        boundaries.sort_by(compare_summary_boundaries);
        boundaries.dedup();

        Self {
            semantic_status,
            unproven_edges: unproven_edges.into_boxed_slice(),
            partial_edges: partial_edges.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
        }
    }

    pub const fn semantic_status(&self) -> SummarySemanticStatus {
        self.semantic_status
    }

    pub fn unproven_edges(&self) -> &[SummaryEdge] {
        &self.unproven_edges
    }

    pub fn partial_edges(&self) -> &[SummaryEdge] {
        &self.partial_edges
    }

    pub fn boundaries(&self) -> &[SummaryBoundary] {
        &self.boundaries
    }

    pub fn is_complete(&self) -> bool {
        self.semantic_status.is_complete()
            && self.unproven_edges.is_empty()
            && self.partial_edges.is_empty()
            && self.boundaries.is_empty()
    }
}

/// Deterministic cache and reuse counters for one summary solve.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SummaryMetrics {
    /// Call-transfer and exit-profile provider cache misses.
    pub provider_materializations: usize,
    pub provider_cache_hits: usize,
    /// Incoming qualities that found at least one already available summary.
    pub summary_hits: usize,
    /// Incoming qualities that had to wait for a later end summary.
    pub summary_misses: usize,
    /// Matched-return projections whose no-op/boundary handling or transfer
    /// callback completed without cancellation or a work-budget failure.
    pub summary_applications: usize,
    /// Incoming relations that reused an existing callee entry context.
    pub reused_entry_contexts: usize,
    /// Exact callee entry contexts served by a cross-query reusable artifact.
    pub reusable_summary_hits: usize,
    /// Callee entry contexts for which the cross-query oracle had no artifact.
    pub reusable_summary_misses: usize,
    /// Query-visible internal observations restored from reusable artifacts.
    pub reusable_observations: usize,
}

/// Deterministic typed result of one query-local summary solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryDataflowResult<Fact> {
    facts: Box<[Fact]>,
    reached: Box<[SummaryReachedFact]>,
    end_summaries: Box<[TabulationEndSummary]>,
    coverage: SummaryCoverage,
    termination: SolverTermination,
    work: SolverWork,
    semantic_work: SemanticWork,
    metrics: SummaryMetrics,
    witness_store: WitnessStore,
    witness_retention_truncated: bool,
}

impl<Fact> SummaryDataflowResult<Fact> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        facts: Vec<Fact>,
        mut reached: Vec<SummaryReachedFact>,
        mut end_summaries: Vec<TabulationEndSummary>,
        coverage: SummaryCoverage,
        termination: SolverTermination,
        work: SolverWork,
        semantic_work: SemanticWork,
        metrics: SummaryMetrics,
        witness_store: WitnessStore,
        witness_retention_truncated: bool,
    ) -> Self {
        reached.sort_by(compare_reached_facts);
        reached.dedup();
        end_summaries.sort_by(compare_end_summaries);
        end_summaries.dedup();

        Self {
            facts: facts.into_boxed_slice(),
            reached: reached.into_boxed_slice(),
            end_summaries: end_summaries.into_boxed_slice(),
            coverage,
            termination,
            work,
            semantic_work,
            metrics,
            witness_store,
            witness_retention_truncated,
        }
    }

    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    pub fn fact(&self, id: FactId) -> Option<&Fact> {
        self.facts.get(id.index())
    }

    pub fn reached(&self) -> &[SummaryReachedFact] {
        &self.reached
    }

    pub fn end_summaries(&self) -> &[TabulationEndSummary] {
        &self.end_summaries
    }

    pub const fn coverage(&self) -> &SummaryCoverage {
        &self.coverage
    }

    pub const fn termination(&self) -> SolverTermination {
        self.termination
    }

    pub const fn work(&self) -> SolverWork {
        self.work
    }

    pub const fn semantic_work(&self) -> SemanticWork {
        self.semantic_work
    }

    pub const fn metrics(&self) -> SummaryMetrics {
        self.metrics
    }

    pub const fn witness_retention_truncated(&self) -> bool {
        self.witness_retention_truncated
    }

    pub fn is_complete(&self) -> bool {
        self.termination.is_fixed_point() && self.coverage.is_complete()
    }

    pub fn reached_at<'result>(
        &'result self,
        point: &'result ProgramPointHandle,
    ) -> impl Iterator<Item = &'result SummaryReachedFact> + 'result {
        self.reached
            .iter()
            .filter(move |reached| reached.point() == point)
    }

    pub fn summaries_for<'result>(
        &'result self,
        entry: &'result SummaryEntry,
    ) -> impl Iterator<Item = &'result TabulationEndSummary> + 'result {
        self.end_summaries
            .iter()
            .filter(move |summary| summary.entry() == entry)
    }

    pub fn witness_for_reached(
        &self,
        reached: &SummaryReachedFact,
        quality: PathQuality,
        limits: WitnessReconstructionLimits,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        let reached_index = self
            .reached
            .iter()
            .position(|candidate| {
                candidate == reached
                    && witness_owners_match(
                        candidate.witness_owner.as_ref(),
                        reached.witness_owner.as_ref(),
                    )
            })
            .ok_or(SummaryWitnessError::TargetNotInResult)?;
        self.witness_for_reached_index(reached_index, quality, limits)
    }

    pub(crate) fn witness_for_reached_index(
        &self,
        reached_index: usize,
        quality: PathQuality,
        limits: WitnessReconstructionLimits,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        let reached = self
            .reached
            .get(reached_index)
            .ok_or(SummaryWitnessError::TargetNotInResult)?;
        if !reached.path_qualities.contains(quality) {
            return Err(SummaryWitnessError::QualityNotRetained(quality));
        }
        let Some(evidence) = reached.witnesses.first(quality) else {
            return if self.witness_retention_truncated {
                Ok(SummaryWitness::retention_truncated_marker(quality))
            } else {
                Err(SummaryWitnessError::RetentionDisabled)
            };
        };
        self.witness_store.reconstruct(
            evidence,
            quality,
            reached.witnesses.is_truncated(quality),
            limits,
            WitnessTarget::Reached {
                entry_point: reached.entry.entry_point(),
                entry_fact: reached.entry.entry_fact(),
                point: reached.point(),
                fact: reached.fact(),
            },
        )
    }

    pub fn witness_for_end_summary(
        &self,
        summary: &TabulationEndSummary,
        quality: PathQuality,
        limits: WitnessReconstructionLimits,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        let summary = self
            .end_summaries
            .iter()
            .find(|candidate| {
                *candidate == summary
                    && witness_owners_match(
                        candidate.witness_owner.as_ref(),
                        summary.witness_owner.as_ref(),
                    )
            })
            .ok_or(SummaryWitnessError::TargetNotInResult)?;
        if !summary.path_qualities.contains(quality) {
            return Err(SummaryWitnessError::QualityNotRetained(quality));
        }
        let Some(evidence) = summary.witnesses.first(quality) else {
            return if self.witness_retention_truncated {
                Ok(SummaryWitness::retention_truncated_marker(quality))
            } else {
                Err(SummaryWitnessError::RetentionDisabled)
            };
        };
        self.witness_store.reconstruct(
            evidence,
            quality,
            summary.witnesses.is_truncated(quality),
            limits,
            WitnessTarget::EndSummary {
                entry_point: summary.entry.entry_point(),
                entry_fact: summary.entry.entry_fact(),
                exit: summary.exit(),
                exit_fact: summary.exit_fact(),
            },
        )
    }
}

fn witness_owners_match(left: Option<&Arc<()>>, right: Option<&Arc<()>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

/// Stable malformed-input/provider errors for summary tabulation.
///
/// Cancellation and both solver and semantic budget exhaustion remain normal
/// typed results rather than operational errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryDataflowError {
    FactIdOverflow { index: usize },
    WitnessEvidenceIdOverflow { index: usize },
    WitnessInvariant(&'static str),
    SemanticProvider(SemanticProviderError),
}

impl fmt::Display for SummaryDataflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FactIdOverflow { index } => {
                write!(formatter, "data-flow fact index {index} exceeds u32")
            }
            Self::WitnessEvidenceIdOverflow { index } => {
                write!(formatter, "witness evidence index {index} exceeds u32")
            }
            Self::WitnessInvariant(reason) => {
                write!(formatter, "summary witness invariant failed: {reason}")
            }
            Self::SemanticProvider(error) => error.fmt(formatter),
        }
    }
}

impl Error for SummaryDataflowError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FactIdOverflow { .. }
            | Self::WitnessEvidenceIdOverflow { .. }
            | Self::WitnessInvariant(_) => None,
            Self::SemanticProvider(error) => Some(error),
        }
    }
}

impl From<SemanticProviderError> for SummaryDataflowError {
    fn from(error: SemanticProviderError) -> Self {
        Self::SemanticProvider(error)
    }
}

fn compare_procedures(left: &ProcedureHandle, right: &ProcedureHandle) -> Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
        .then_with(|| left.id().cmp(&right.id()))
        .then_with(|| {
            std::sync::Arc::as_ptr(left.artifact())
                .cast::<()>()
                .cmp(&std::sync::Arc::as_ptr(right.artifact()).cast::<()>())
        })
}

fn compare_points(left: &ProgramPointHandle, right: &ProgramPointHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_call_sites(left: &CallSiteHandle, right: &CallSiteHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_optional_call_sites(
    left: Option<&CallSiteHandle>,
    right: Option<&CallSiteHandle>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_call_sites(left, right),
    }
}

fn compare_entries(left: &SummaryEntry, right: &SummaryEntry) -> Ordering {
    compare_procedures(left.procedure(), right.procedure())
        .then_with(|| left.entry_point().id().cmp(&right.entry_point().id()))
        .then_with(|| left.entry_fact().cmp(&right.entry_fact()))
}

fn compare_reached_facts(left: &SummaryReachedFact, right: &SummaryReachedFact) -> Ordering {
    compare_entries(left.entry(), right.entry())
        .then_with(|| left.point().id().cmp(&right.point().id()))
        .then_with(|| left.fact().cmp(&right.fact()))
}

fn compare_end_summaries(left: &TabulationEndSummary, right: &TabulationEndSummary) -> Ordering {
    compare_entries(left.entry(), right.entry())
        .then_with(|| return_kind_rank(left.exit_kind()).cmp(&return_kind_rank(right.exit_kind())))
        .then_with(|| left.exit_point().id().cmp(&right.exit_point().id()))
        .then_with(|| left.exit_fact().cmp(&right.exit_fact()))
}

fn compare_summary_edges(left: &SummaryEdge, right: &SummaryEdge) -> Ordering {
    compare_points(left.source(), right.source())
        .then_with(|| compare_points(left.target(), right.target()))
        .then_with(|| edge_kind_key(left.kind()).cmp(&edge_kind_key(right.kind())))
        .then_with(|| compare_optional_call_sites(left.origin(), right.origin()))
        .then_with(|| compare_proof(left.proof(), right.proof()))
        .then_with(|| compare_completeness(left.completeness(), right.completeness()))
}

fn compare_proof(left: &ProofStatus, right: &ProofStatus) -> Ordering {
    match (left, right) {
        (ProofStatus::Proven, ProofStatus::Proven) => Ordering::Equal,
        (ProofStatus::Proven, ProofStatus::Unproven(_)) => Ordering::Less,
        (ProofStatus::Unproven(_), ProofStatus::Proven) => Ordering::Greater,
        (ProofStatus::Unproven(left), ProofStatus::Unproven(right)) => left.cmp(right),
    }
}

fn compare_completeness(left: &EvidenceCompleteness, right: &EvidenceCompleteness) -> Ordering {
    match (left, right) {
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Complete) => Ordering::Equal,
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Partial(_)) => Ordering::Less,
        (EvidenceCompleteness::Partial(_), EvidenceCompleteness::Complete) => Ordering::Greater,
        (EvidenceCompleteness::Partial(left), EvidenceCompleteness::Partial(right)) => {
            left.cmp(right)
        }
    }
}

fn compare_summary_boundaries(left: &SummaryBoundary, right: &SummaryBoundary) -> Ordering {
    compare_points(left.at(), right.at())
        .then_with(|| compare_optional_call_sites(left.origin(), right.origin()))
        .then_with(|| compare_boundary_kinds(left.kind(), right.kind()))
        .then_with(|| compare_optional_proof(left.proof(), right.proof()))
        .then_with(|| compare_optional_completeness(left.completeness(), right.completeness()))
        .then_with(|| compare_relation_provenance(left.provenance(), right.provenance()))
}

fn compare_optional_proof(left: Option<&ProofStatus>, right: Option<&ProofStatus>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_proof(left, right),
    }
}

fn compare_optional_completeness(
    left: Option<&EvidenceCompleteness>,
    right: Option<&EvidenceCompleteness>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_completeness(left, right),
    }
}

fn edge_kind_key(kind: IcfgEdgeKind) -> (u8, u8) {
    match kind {
        IcfgEdgeKind::Intraprocedural(kind) => (0, control_edge_kind_rank(kind)),
        IcfgEdgeKind::Call => (1, 0),
        IcfgEdgeKind::NormalReturn => (2, 0),
        IcfgEdgeKind::ExceptionalReturn => (3, 0),
        IcfgEdgeKind::CallToNormalContinuation => (4, 0),
        IcfgEdgeKind::CallToExceptionalContinuation => (5, 0),
    }
}

fn control_edge_kind_rank(kind: ControlEdgeKind) -> u8 {
    match kind {
        ControlEdgeKind::Normal => 0,
        ControlEdgeKind::ConditionalTrue => 1,
        ControlEdgeKind::ConditionalFalse => 2,
        ControlEdgeKind::SwitchCase => 3,
        ControlEdgeKind::LoopBack => 4,
        ControlEdgeKind::Exceptional => 5,
        ControlEdgeKind::Cleanup => 6,
        ControlEdgeKind::AsyncNormal => 7,
        ControlEdgeKind::AsyncExceptional => 8,
    }
}

fn return_kind_rank(kind: ReturnTransferKind) -> u8 {
    match kind {
        ReturnTransferKind::Normal => 0,
        ReturnTransferKind::Exceptional => 1,
    }
}

fn compare_boundary_kinds(left: &SummaryBoundaryKind, right: &SummaryBoundaryKind) -> Ordering {
    let rank = |kind: &SummaryBoundaryKind| match kind {
        SummaryBoundaryKind::Semantic(_) => 0,
        SummaryBoundaryKind::Dispatch(_) => 1,
        SummaryBoundaryKind::Limit(_) => 2,
        SummaryBoundaryKind::Continuation { .. } => 3,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (SummaryBoundaryKind::Semantic(left), SummaryBoundaryKind::Semantic(right)) => {
                compare_semantic_status(*left, *right)
            }
            (SummaryBoundaryKind::Dispatch(left), SummaryBoundaryKind::Dispatch(right)) => {
                compare_dispatch_boundaries(left, right)
            }
            (SummaryBoundaryKind::Limit(left), SummaryBoundaryKind::Limit(right)) => {
                limit_kind_rank(*left).cmp(&limit_kind_rank(*right))
            }
            (
                SummaryBoundaryKind::Continuation {
                    kind: left_kind,
                    state: left_state,
                },
                SummaryBoundaryKind::Continuation {
                    kind: right_kind,
                    state: right_state,
                },
            ) => continuation_kind_rank(*left_kind)
                .cmp(&continuation_kind_rank(*right_kind))
                .then_with(|| compare_continuations(*left_state, *right_state)),
            _ => Ordering::Equal,
        })
}

fn compare_semantic_status(left: SummarySemanticStatus, right: SummarySemanticStatus) -> Ordering {
    left.cmp(&right)
}

fn compare_dispatch_boundaries(
    left: &DispatchBoundaryKind,
    right: &DispatchBoundaryKind,
) -> Ordering {
    let rank = |kind: &DispatchBoundaryKind| match kind {
        DispatchBoundaryKind::External(_) => 0,
        DispatchBoundaryKind::Unmaterialized(_) => 1,
        DispatchBoundaryKind::Deferred { .. } => 2,
        DispatchBoundaryKind::Unresolved => 3,
        DispatchBoundaryKind::Truncated => 4,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (DispatchBoundaryKind::External(left), DispatchBoundaryKind::External(right)) => {
                left.cmp(right)
            }
            (
                DispatchBoundaryKind::Unmaterialized(left),
                DispatchBoundaryKind::Unmaterialized(right),
            ) => left.cmp(right),
            (
                DispatchBoundaryKind::Deferred {
                    target: left_target,
                    kind: left_kind,
                },
                DispatchBoundaryKind::Deferred {
                    target: right_target,
                    kind: right_kind,
                },
            ) => left_target
                .cmp(right_target)
                .then_with(|| left_kind.label().cmp(right_kind.label())),
            _ => Ordering::Equal,
        })
}

fn limit_kind_rank(kind: IcfgLimitKind) -> u8 {
    match kind {
        IcfgLimitKind::CallDepth => 0,
        IcfgLimitKind::Nodes => 1,
        IcfgLimitKind::Edges => 2,
    }
}

fn continuation_kind_rank(kind: CallContinuationKind) -> u8 {
    match kind {
        CallContinuationKind::Normal => 0,
        CallContinuationKind::Exceptional => 1,
    }
}

fn compare_continuations(left: ControlContinuation, right: ControlContinuation) -> Ordering {
    let rank = |state: ControlContinuation| match state {
        ControlContinuation::Target(_) => 0,
        ControlContinuation::Absent => 1,
        ControlContinuation::Unknown => 2,
        ControlContinuation::Unsupported => 3,
        ControlContinuation::Unproven => 4,
        ControlContinuation::ExceededBudget => 5,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (ControlContinuation::Target(left), ControlContinuation::Target(right)) => {
                left.cmp(&right)
            }
            _ => Ordering::Equal,
        })
}
