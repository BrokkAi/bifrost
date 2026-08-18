//! Stable symbolic taint transfers projected from complete IDE solves.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::mem::{size_of, size_of_val};
use std::sync::Arc;

use crate::analyzer::dataflow::{
    DataflowRequest, PathQuality, PathQualityFrontier, ProcedureSummaryIdentity,
    ProcedureSummaryKey, ReusableIdeEndSummary, ReusableIdeProcedureSummary,
    ReusableIdeReachedFact, ReusableIdeSummaryProvider, SemanticProcedureSummary,
    SemanticSummarySetValidationError, SolverTermination, SolverWork, SummaryCallCycle,
    SummaryCalledProcedures, SummaryDependencyKey, SummaryEntry, SummaryExitKind,
    SummaryRecursiveGroupKey, canonicalize_semantic_summary_items,
    validate_recursive_summary_batch,
};
use crate::analyzer::semantic::{
    DeclarationLocator, IcfgProvider, ProcedureHandle, ProgramPointId, ReturnTransferKind,
    SemanticArtifactKey, SemanticBudget,
};
use crate::analyzer::value_flow::{
    ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowObservationPhase,
};

use super::client::solve_taint_with_reusable_provider;
use super::{
    SourceClassId, TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction, TaintFact, TaintSolveError,
    TaintSummaryResult, TaintUniverse, TaintUniverseHash,
};

pub const TAINT_TRANSFER_SUMMARY_SCHEMA_VERSION: u32 = 2;
pub const MAX_TAINT_TRANSFER_SUMMARY_ROWS: usize = 65_536;
pub const MAX_TAINT_TRANSFER_OBSERVATIONS: usize = 262_144;
pub const MAX_TAINT_LIVE_OBSERVER_ROWS: usize = 262_144;
pub const DEFAULT_TAINT_SUMMARY_REPOSITORY_ENTRIES: usize = 4_096;
pub const DEFAULT_TAINT_SUMMARY_REPOSITORY_BYTES: usize = 64 * 1024 * 1024;

/// Version of the finite source-set algebra and taint propagation callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintPropagationSemanticsVersion(u32);

impl TaintPropagationSemanticsVersion {
    pub const CURRENT: Self = Self(1);

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Exact procedure and value-flow contract behind one symbolic carrier relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CarrierSummaryKey {
    procedure: ProcedureSummaryKey,
    carrier_contract: crate::analyzer::value_flow::ValueFlowCarrierSummaryIdentity,
    schema_version: u32,
}

impl CarrierSummaryKey {
    fn try_new(
        procedure: &ProcedureHandle,
        semantic: &SemanticProcedureSummary,
        carrier_contract: crate::analyzer::value_flow::ValueFlowCarrierSummaryIdentity,
    ) -> Result<Self, TaintTransferSummaryError> {
        if !semantic.completeness().is_complete() {
            return Err(TaintTransferSummaryError::IncompleteSemanticSummary);
        }
        if !procedure_matches(procedure, semantic.key()) {
            return Err(TaintTransferSummaryError::ProcedureMismatch);
        }
        Ok(Self {
            procedure: semantic.key().clone(),
            carrier_contract,
            schema_version: TAINT_TRANSFER_SUMMARY_SCHEMA_VERSION,
        })
    }

    pub const fn procedure(&self) -> &ProcedureSummaryKey {
        &self.procedure
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    fn retained_bytes(&self) -> usize {
        self.procedure
            .retained_bytes()
            .saturating_add(self.carrier_contract.retained_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableTaintClassSet(Box<[SourceClassId]>);

impl StableTaintClassSet {
    pub fn classes(&self) -> &[SourceClassId] {
        &self.0
    }

    fn from_live(
        classes: &TaintClassSet,
        universe: &TaintUniverse,
    ) -> Result<Self, TaintTransferSummaryError> {
        let classes = universe
            .stable_classes(classes)
            .map_err(|_| TaintTransferSummaryError::UniverseMismatch)?
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self(classes))
    }

    fn to_live(
        &self,
        universe: &TaintUniverse,
    ) -> Result<TaintClassSet, TaintTransferSummaryError> {
        universe
            .class_set(self.0.iter())
            .map_err(|_| TaintTransferSummaryError::UniverseMismatch)
    }

    fn retained_bytes(&self) -> usize {
        size_of_val(self.0.as_ref()).saturating_add(
            self.0
                .iter()
                .map(|class| class.as_str().len())
                .sum::<usize>(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableTaintEdgeFunction {
    generated: StableTaintClassSet,
    default_identity: bool,
    overrides: Box<[(SourceClassId, StableTaintClassSet)]>,
}

impl StableTaintEdgeFunction {
    pub fn generated(&self) -> &StableTaintClassSet {
        &self.generated
    }

    pub const fn default_identity(&self) -> bool {
        self.default_identity
    }

    pub fn overrides(
        &self,
    ) -> impl ExactSizeIterator<Item = (&SourceClassId, &StableTaintClassSet)> {
        self.overrides
            .iter()
            .map(|(source, targets)| (source, targets))
    }

    fn from_live(
        function: &TaintEdgeFunction,
        universe: &TaintUniverse,
    ) -> Result<Self, TaintTransferSummaryError> {
        if function.universe() != universe.hash()
            || function.class_count() != universe.classes().len()
        {
            return Err(TaintTransferSummaryError::UniverseMismatch);
        }
        let mut overrides = Vec::with_capacity(function.overrides().len());
        for (source, targets) in function.overrides() {
            let source = universe
                .stable_id(*source)
                .ok_or(TaintTransferSummaryError::UniverseMismatch)?
                .clone();
            overrides.push((source, StableTaintClassSet::from_live(targets, universe)?));
        }
        Ok(Self {
            generated: StableTaintClassSet::from_live(function.generated(), universe)?,
            default_identity: function.default_identity(),
            overrides: overrides.into_boxed_slice(),
        })
    }

    fn to_live(
        &self,
        universe: &TaintUniverse,
    ) -> Result<TaintEdgeFunction, TaintTransferSummaryError> {
        let mut overrides = Vec::with_capacity(self.overrides.len());
        for (source, targets) in &self.overrides {
            overrides.push((
                universe
                    .class_id(source)
                    .ok_or(TaintTransferSummaryError::UniverseMismatch)?,
                targets.to_live(universe)?,
            ));
        }
        TaintEdgeFunction::from_canonical_parts(
            universe,
            self.generated.to_live(universe)?,
            self.default_identity,
            overrides,
        )
        .map_err(|_| TaintTransferSummaryError::InvalidEdgeFunction)
    }

    fn retained_bytes(&self) -> usize {
        self.generated
            .retained_bytes()
            .saturating_add(size_of_val(self.overrides.as_ref()))
            .saturating_add(self.overrides.iter().fold(0, |total, (source, targets)| {
                total
                    .saturating_add(source.as_str().len())
                    .saturating_add(targets.retained_bytes())
            }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableSourceGenerator {
    point: ProgramPointId,
    event: ValueFlowEventKey,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrierKey,
    classes: StableTaintClassSet,
    proven: bool,
    complete: bool,
}

impl StableSourceGenerator {
    pub const fn point(&self) -> ProgramPointId {
        self.point
    }

    pub const fn event(&self) -> &ValueFlowEventKey {
        &self.event
    }

    pub const fn phase(&self) -> ValueFlowObservationPhase {
        self.phase
    }

    pub const fn carrier(&self) -> &ValueFlowCarrierKey {
        &self.carrier
    }

    pub const fn classes(&self) -> &StableTaintClassSet {
        &self.classes
    }

    pub const fn is_proven(&self) -> bool {
        self.proven
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum StablePropagationTransfer {
    Sanitizer {
        point: ProgramPointId,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierKey,
        removed: StableTaintClassSet,
        resolved: bool,
    },
    Transform {
        point: ProgramPointId,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierKey,
        function: StableTaintEdgeFunction,
    },
}

/// Source-generator and sanitizer/transform matching that changes propagation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintPropagationEventMatchKey {
    sources: Box<[StableSourceGenerator]>,
    transfers: Box<[StablePropagationTransfer]>,
}

impl TaintPropagationEventMatchKey {
    pub fn source_generators(&self) -> &[StableSourceGenerator] {
        &self.sources
    }

    fn retained_bytes(&self) -> usize {
        size_of_val(self.sources.as_ref())
            .saturating_add(self.sources.iter().fold(0usize, |total, source| {
                total
                    .saturating_add(source.event.retained_bytes())
                    .saturating_add(source.carrier.retained_bytes())
                    .saturating_add(source.classes.retained_bytes())
            }))
            .saturating_add(size_of_val(self.transfers.as_ref()))
            .saturating_add(self.transfers.iter().fold(0usize, |total, transfer| {
                total.saturating_add(match transfer {
                    StablePropagationTransfer::Sanitizer {
                        carrier, removed, ..
                    } => carrier
                        .retained_bytes()
                        .saturating_add(removed.retained_bytes()),
                    StablePropagationTransfer::Transform {
                        carrier, function, ..
                    } => carrier
                        .retained_bytes()
                        .saturating_add(function.retained_bytes()),
                })
            }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableSinkObserver {
    point: ProgramPointId,
    event: ValueFlowEventKey,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrierKey,
    proven: bool,
    complete: bool,
}

impl StableSinkObserver {
    pub const fn point(&self) -> ProgramPointId {
        self.point
    }

    pub const fn event(&self) -> &ValueFlowEventKey {
        &self.event
    }

    pub const fn phase(&self) -> ValueFlowObservationPhase {
        self.phase
    }

    pub const fn carrier(&self) -> &ValueFlowCarrierKey {
        &self.carrier
    }

    pub const fn is_proven(&self) -> bool {
        self.proven
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Selector/dangerous-operand identity for current sink observation.
///
/// Accepted classes and all presentation metadata are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintSinkObserverMatchKey(Box<[StableSinkObserver]>);

impl TaintSinkObserverMatchKey {
    pub fn observers(&self) -> &[StableSinkObserver] {
        &self.0
    }

    fn observers_at(&self, point: ProgramPointId) -> &[StableSinkObserver] {
        let start = self.0.partition_point(|observer| observer.point < point);
        let end = start + self.0[start..].partition_point(|observer| observer.point == point);
        &self.0[start..end]
    }
}

/// Full transfer validity. Sink observation is deliberately a separate overlay key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintTransferSummaryKey {
    carrier: CarrierSummaryKey,
    universe: TaintUniverseHash,
    propagation_semantics: TaintPropagationSemanticsVersion,
    propagation: TaintPropagationEventMatchKey,
    dependency_contract: TaintDependencyContractKey,
    entry_facts: Box<[StableTaintFact]>,
    schema_version: u32,
}

impl TaintTransferSummaryKey {
    pub const fn carrier(&self) -> &CarrierSummaryKey {
        &self.carrier
    }

    pub const fn universe(&self) -> TaintUniverseHash {
        self.universe
    }

    pub const fn propagation(&self) -> &TaintPropagationEventMatchKey {
        &self.propagation
    }

    pub const fn propagation_semantics(&self) -> TaintPropagationSemanticsVersion {
        self.propagation_semantics
    }

    pub const fn dependency_contract(&self) -> &TaintDependencyContractKey {
        &self.dependency_contract
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.carrier.retained_bytes())
            .saturating_add(self.propagation.retained_bytes())
            .saturating_add(self.dependency_contract.retained_bytes())
            .saturating_add(size_of_val(self.entry_facts.as_ref()))
            .saturating_add(self.entry_facts.iter().fold(0usize, |total, fact| {
                total.saturating_add(fact.retained_bytes())
            }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaintLocalClientContract {
    procedure: ProcedureSummaryKey,
    carrier: CarrierSummaryKey,
    propagation: TaintPropagationEventMatchKey,
}

impl TaintLocalClientContract {
    fn retained_bytes(&self) -> usize {
        self.procedure
            .retained_bytes()
            .saturating_add(self.carrier.retained_bytes())
            .saturating_add(self.propagation.retained_bytes())
    }
}

/// Exact transitive taint client contract for a procedure dependency closure.
///
/// Recursive members share the same canonical closure, so one member cannot be
/// reused from an older SCC generation after another member changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintDependencyContractKey(Arc<[Arc<TaintLocalClientContract>]>);

impl TaintDependencyContractKey {
    fn retained_bytes(&self) -> usize {
        size_of_val(self.0.as_ref()).saturating_add(self.0.iter().fold(0usize, |total, row| {
            total.saturating_add(row.retained_bytes())
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StableTaintFact {
    Zero,
    Carrier {
        carrier: ValueFlowCarrierKey,
        uncertain: bool,
    },
    SinkObservation {
        sink: ValueFlowEventKey,
        uncertain: bool,
    },
}

impl StableTaintFact {
    fn from_live(
        fact: TaintFact,
        plan: &TaintAnalysisPlan,
    ) -> Result<Self, TaintTransferSummaryError> {
        if fact.is_zero() {
            return Ok(Self::Zero);
        }
        if let Some(carrier) = fact.carrier() {
            return Ok(Self::Carrier {
                carrier: plan
                    .value_flow()
                    .carrier_key(carrier)
                    .ok_or(TaintTransferSummaryError::InvalidFact)?
                    .clone(),
                uncertain: fact.is_uncertain(),
            });
        }
        if let Some(sink) = fact.sink() {
            return Ok(Self::SinkObservation {
                sink: plan
                    .value_flow()
                    .sink(sink)
                    .ok_or(TaintTransferSummaryError::InvalidFact)?
                    .key()
                    .clone(),
                uncertain: fact.is_uncertain(),
            });
        }
        Err(TaintTransferSummaryError::InvalidFact)
    }

    fn to_live(&self, plan: &TaintAnalysisPlan) -> Result<TaintFact, TaintTransferSummaryError> {
        match self {
            Self::Zero => Ok(TaintFact::zero()),
            Self::Carrier { carrier, uncertain } => plan
                .value_flow()
                .carrier_id_for_key(carrier)
                .map(|carrier| TaintFact::for_carrier(carrier, *uncertain))
                .ok_or(TaintTransferSummaryError::InvalidFact),
            Self::SinkObservation { sink, uncertain } => plan
                .value_flow()
                .sink_id_for_key(sink)
                .map(|sink| TaintFact::for_sink(sink, *uncertain))
                .ok_or(TaintTransferSummaryError::SinkObserverMismatch),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::Zero => 0,
            Self::Carrier { carrier, .. } => carrier.retained_bytes(),
            Self::SinkObservation { sink, .. } => sink.retained_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintPathEvidence(u8);

impl TaintPathEvidence {
    pub const fn has_proven_path(self) -> bool {
        self.0 & 0b1100 != 0
    }

    pub const fn has_complete_path(self) -> bool {
        self.0 & 0b1010 != 0
    }

    pub const fn has_proven_complete_path(self) -> bool {
        self.0 & 0b1000 != 0
    }

    fn from_frontier(frontier: PathQualityFrontier) -> Self {
        let mut bits = 0;
        for quality in frontier.iter() {
            bits |= match (quality.is_proven(), quality.is_complete()) {
                (false, false) => 0b0001,
                (false, true) => 0b0010,
                (true, false) => 0b0100,
                (true, true) => 0b1000,
            };
        }
        Self(bits)
    }

    fn qualities(self) -> Box<[PathQuality]> {
        [
            (0b0001, PathQuality::UNPROVEN_PARTIAL),
            (0b0010, PathQuality::UNPROVEN_COMPLETE),
            (0b0100, PathQuality::PROVEN_PARTIAL),
            (0b1000, PathQuality::PROVEN_COMPLETE),
        ]
        .into_iter()
        .filter_map(|(bit, quality)| (self.0 & bit != 0).then_some(quality))
        .collect::<Vec<_>>()
        .into_boxed_slice()
    }

    fn frontier(self) -> PathQualityFrontier {
        let mut frontier = PathQualityFrontier::default();
        for quality in self.qualities() {
            frontier.insert(quality);
        }
        frontier
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintTransferRow {
    input: StableTaintFact,
    exit_kind: SummaryExitKind,
    output: StableTaintFact,
    evidence: TaintPathEvidence,
    function: StableTaintEdgeFunction,
}

impl TaintTransferRow {
    pub const fn input(&self) -> &StableTaintFact {
        &self.input
    }

    pub const fn exit_kind(&self) -> SummaryExitKind {
        self.exit_kind
    }

    pub const fn output(&self) -> &StableTaintFact {
        &self.output
    }

    pub const fn evidence(&self) -> TaintPathEvidence {
        self.evidence
    }

    pub const fn function(&self) -> &StableTaintEdgeFunction {
        &self.function
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintObservedPort {
    input: StableTaintFact,
    semantic_entry: StableTaintFact,
    procedure: ProcedureSummaryKey,
    point: ProgramPointId,
    observation: StableTaintFact,
    evidence: TaintPathEvidence,
    function: StableTaintEdgeFunction,
}

impl TaintObservedPort {
    pub const fn input(&self) -> &StableTaintFact {
        &self.input
    }

    pub const fn procedure(&self) -> &ProcedureSummaryKey {
        &self.procedure
    }

    pub const fn semantic_entry(&self) -> &StableTaintFact {
        &self.semantic_entry
    }

    pub const fn point(&self) -> ProgramPointId {
        self.point
    }

    pub const fn observation(&self) -> &StableTaintFact {
        &self.observation
    }

    pub const fn evidence(&self) -> TaintPathEvidence {
        self.evidence
    }

    pub const fn function(&self) -> &StableTaintEdgeFunction {
        &self.function
    }
}

/// Complete symbolic entry-to-exit transfer plus sink-independent internal ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTransferSummary {
    key: TaintTransferSummaryKey,
    rows: Box<[TaintTransferRow]>,
    observations: Box<[TaintObservedPort]>,
}

impl TaintTransferSummary {
    pub const fn key(&self) -> &TaintTransferSummaryKey {
        &self.key
    }

    pub fn rows(&self) -> &[TaintTransferRow] {
        &self.rows
    }

    pub fn observations(&self) -> &[TaintObservedPort] {
        &self.observations
    }

    fn row_range(&self, input: &StableTaintFact) -> std::ops::Range<usize> {
        let start = self.rows.partition_point(|row| row.input < *input);
        let end = start + self.rows[start..].partition_point(|row| row.input == *input);
        start..end
    }

    fn observation_range(&self, input: &StableTaintFact) -> std::ops::Range<usize> {
        let start = self
            .observations
            .partition_point(|observation| observation.input < *input);
        let end = start
            + self.observations[start..].partition_point(|observation| observation.input == *input);
        start..end
    }

    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.key.retained_bytes())
            .saturating_add(size_of_val(self.rows()))
            .saturating_add(size_of_val(self.observations()))
            .saturating_add(self.rows.iter().fold(0, |total, row| {
                total
                    .saturating_add(row.input.retained_bytes())
                    .saturating_add(row.output.retained_bytes())
                    .saturating_add(row.function.retained_bytes())
            }))
            .saturating_add(self.observations.iter().fold(0, |total, observation| {
                total
                    .saturating_add(observation.input.retained_bytes())
                    .saturating_add(observation.semantic_entry.retained_bytes())
                    .saturating_add(observation.procedure.retained_bytes())
                    .saturating_add(observation.observation.retained_bytes())
                    .saturating_add(observation.function.retained_bytes())
            }))
    }
}

/// Query-scoped complete semantic summaries that authorize taint keys.
#[derive(Debug)]
pub struct TaintSemanticSummarySet<'summary> {
    summaries: Box<[&'summary SemanticProcedureSummary]>,
    by_artifact: HashMap<SemanticArtifactKey, HashMap<DeclarationLocator, usize>>,
    by_identity: HashMap<ProcedureSummaryIdentity, usize>,
    eligible: HashSet<ProcedureSummaryKey>,
}

impl<'summary> TaintSemanticSummarySet<'summary> {
    pub fn try_new(
        summaries: Vec<&'summary SemanticProcedureSummary>,
    ) -> Result<Self, TaintTransferSummaryError> {
        let summaries = canonicalize_semantic_summary_items(summaries, |summary| *summary, true)
            .map_err(|error| match error {
                SemanticSummarySetValidationError::Incomplete => {
                    TaintTransferSummaryError::IncompleteSemanticSummary
                }
                SemanticSummarySetValidationError::AmbiguousKey => {
                    TaintTransferSummaryError::AmbiguousSemanticSummary
                }
            })?;
        let mut by_artifact =
            HashMap::<SemanticArtifactKey, HashMap<DeclarationLocator, usize>>::new();
        let mut by_identity = HashMap::new();
        for (index, summary) in summaries.iter().enumerate() {
            if by_artifact
                .entry(summary.key().artifact().clone())
                .or_default()
                .insert(summary.key().declaration().clone(), index)
                .is_some()
            {
                return Err(TaintTransferSummaryError::AmbiguousSemanticSummary);
            }
            if by_identity
                .insert(summary.key().identity().clone(), index)
                .is_some()
            {
                return Err(TaintTransferSummaryError::AmbiguousSemanticSummary);
            }
        }
        let mut eligible = HashSet::new();
        let mut recursive =
            HashMap::<SummaryRecursiveGroupKey, Vec<&SemanticProcedureSummary>>::new();
        for summary in &summaries {
            if let Some(group) = summary.key().recursive_group() {
                recursive.entry(group).or_default().push(summary);
            } else {
                eligible.insert(summary.key().clone());
            }
        }
        for members in recursive.into_values() {
            if validate_recursive_summary_batch(&members).is_ok() {
                eligible.extend(members.into_iter().map(|member| member.key().clone()));
            }
        }
        Ok(Self {
            summaries,
            by_artifact,
            by_identity,
            eligible,
        })
    }

    fn unique_summary_for(&self, procedure: &ProcedureHandle) -> Option<&SemanticProcedureSummary> {
        let index = self
            .by_artifact
            .get(procedure.artifact().key())?
            .get(procedure.semantics().locator().declaration())?;
        self.summaries.get(*index).copied()
    }

    fn eligible(&self, summary: &SemanticProcedureSummary) -> bool {
        self.eligible.contains(summary.key())
    }

    fn summary_for_key(&self, key: &ProcedureSummaryKey) -> Option<&SemanticProcedureSummary> {
        self.summaries
            .binary_search_by(|summary| summary.key().cmp(key))
            .ok()
            .and_then(|index| self.summaries.get(index).copied())
    }

    fn summary_for_identity(
        &self,
        identity: &ProcedureSummaryIdentity,
    ) -> Option<&SemanticProcedureSummary> {
        self.by_identity
            .get(identity)
            .and_then(|index| self.summaries.get(*index).copied())
    }
}

#[derive(Debug, Clone)]
struct PreparedTaintProcedureContract {
    carrier: CarrierSummaryKey,
    propagation: TaintPropagationEventMatchKey,
    sink_observers: TaintSinkObserverMatchKey,
    dependency_contract: TaintDependencyContractKey,
}

#[derive(Default)]
struct PreparedTaintContractBuilder {
    carrier: Option<CarrierSummaryKey>,
    sources: Vec<StableSourceGenerator>,
    transfers: Vec<StablePropagationTransfer>,
    observers: Vec<StableSinkObserver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TaintContractNodeKey {
    Procedure(Box<ProcedureSummaryKey>),
    Recursive(SummaryRecursiveGroupKey),
}

#[derive(Debug)]
struct TaintContractNode {
    members: Vec<ProcedureSummaryKey>,
    dependencies: Vec<usize>,
    valid: bool,
}

fn taint_contract_node_key(key: &ProcedureSummaryKey) -> TaintContractNodeKey {
    match key.recursive_group() {
        Some(group) => TaintContractNodeKey::Recursive(group),
        None => TaintContractNodeKey::Procedure(Box::new(key.clone())),
    }
}

#[derive(Debug)]
struct TaintContractSet {
    by_procedure: HashMap<ProcedureHandle, PreparedTaintProcedureContract>,
    by_key: HashMap<ProcedureSummaryKey, ProcedureHandle>,
}

impl TaintContractSet {
    fn empty() -> Self {
        Self {
            by_procedure: HashMap::new(),
            by_key: HashMap::new(),
        }
    }

    fn try_new(
        plan: &TaintAnalysisPlan,
        semantics: &TaintSemanticSummarySet<'_>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Self, TaintTransferSummaryError> {
        let mut builders = HashMap::<ProcedureHandle, PreparedTaintContractBuilder>::new();
        for (procedure, identity) in plan.value_flow().carrier_summary_identities() {
            if request.cancellation.is_cancelled() {
                return Ok(Self {
                    by_procedure: HashMap::new(),
                    by_key: HashMap::new(),
                });
            }
            let Some(semantic) = semantics.unique_summary_for(&procedure) else {
                continue;
            };
            if !semantics.eligible(semantic) {
                continue;
            }
            builders.entry(procedure.clone()).or_default().carrier =
                Some(CarrierSummaryKey::try_new(&procedure, semantic, identity)?);
        }

        for binding in plan.sources() {
            if request.cancellation.is_cancelled() {
                return Ok(Self {
                    by_procedure: HashMap::new(),
                    by_key: HashMap::new(),
                });
            }
            let spec = plan
                .value_flow()
                .source(binding.source())
                .ok_or(TaintTransferSummaryError::InvalidPlan)?;
            let Some(builder) = builders.get_mut(spec.point().procedure()) else {
                continue;
            };
            builder.sources.push(StableSourceGenerator {
                point: spec.point().id(),
                event: spec.key().clone(),
                phase: spec.phase(),
                carrier: spec
                    .carrier()
                    .stable_key()
                    .map_err(|_| TaintTransferSummaryError::InvalidPlan)?,
                classes: StableTaintClassSet::from_live(binding.classes(), plan.universe())?,
                proven: matches!(spec.proof(), crate::analyzer::semantic::ProofStatus::Proven),
                complete: matches!(
                    spec.completeness(),
                    crate::analyzer::semantic::EvidenceCompleteness::Complete
                ),
            });
        }
        for binding in plan.sanitizers() {
            if request.cancellation.is_cancelled() {
                return Ok(Self::empty());
            }
            let Some(builder) = builders.get_mut(binding.point().procedure()) else {
                continue;
            };
            builder
                .transfers
                .push(StablePropagationTransfer::Sanitizer {
                    point: binding.point().id(),
                    phase: binding.phase(),
                    event_index: binding.event_index(),
                    carrier: plan
                        .value_flow()
                        .carrier_key(binding.carrier())
                        .ok_or(TaintTransferSummaryError::InvalidPlan)?
                        .clone(),
                    removed: StableTaintClassSet::from_live(binding.removed(), plan.universe())?,
                    resolved: binding.is_resolved(),
                });
        }
        for binding in plan.transforms() {
            if request.cancellation.is_cancelled() {
                return Ok(Self::empty());
            }
            let Some(builder) = builders.get_mut(binding.point().procedure()) else {
                continue;
            };
            builder
                .transfers
                .push(StablePropagationTransfer::Transform {
                    point: binding.point().id(),
                    phase: binding.phase(),
                    event_index: binding.event_index(),
                    carrier: plan
                        .value_flow()
                        .carrier_key(binding.carrier())
                        .ok_or(TaintTransferSummaryError::InvalidPlan)?
                        .clone(),
                    function: StableTaintEdgeFunction::from_live(
                        binding.function(),
                        plan.universe(),
                    )?,
                });
        }
        for binding in plan.sinks() {
            if request.cancellation.is_cancelled() {
                return Ok(Self {
                    by_procedure: HashMap::new(),
                    by_key: HashMap::new(),
                });
            }
            let spec = plan
                .value_flow()
                .sink(binding.sink())
                .ok_or(TaintTransferSummaryError::InvalidPlan)?;
            let Some(builder) = builders.get_mut(spec.point().procedure()) else {
                continue;
            };
            builder.observers.push(StableSinkObserver {
                point: spec.point().id(),
                event: spec.key().clone(),
                phase: spec.phase(),
                carrier: spec
                    .carrier()
                    .stable_key()
                    .map_err(|_| TaintTransferSummaryError::InvalidPlan)?,
                proven: matches!(spec.proof(), crate::analyzer::semantic::ProofStatus::Proven),
                complete: matches!(
                    spec.completeness(),
                    crate::analyzer::semantic::EvidenceCompleteness::Complete
                ),
            });
        }

        let mut local = HashMap::<
            ProcedureSummaryKey,
            (
                ProcedureHandle,
                Arc<TaintLocalClientContract>,
                TaintSinkObserverMatchKey,
            ),
        >::new();
        for (procedure, mut builder) in builders {
            let Some(carrier) = builder.carrier.take() else {
                continue;
            };
            builder
                .sources
                .sort_unstable_by(|left, right| left.event.cmp(&right.event));
            builder.transfers.sort_unstable();
            builder.observers.sort_unstable();
            let propagation = TaintPropagationEventMatchKey {
                sources: builder.sources.into_boxed_slice(),
                transfers: builder.transfers.into_boxed_slice(),
            };
            let procedure_key = carrier.procedure().clone();
            local.insert(
                procedure_key.clone(),
                (
                    procedure,
                    Arc::new(TaintLocalClientContract {
                        procedure: procedure_key,
                        carrier,
                        propagation,
                    }),
                    TaintSinkObserverMatchKey(builder.observers.into_boxed_slice()),
                ),
            );
        }

        let mut grouped = HashMap::<TaintContractNodeKey, Vec<ProcedureSummaryKey>>::new();
        for key in local.keys() {
            grouped
                .entry(taint_contract_node_key(key))
                .or_default()
                .push(key.clone());
        }
        let mut nodes = grouped
            .into_values()
            .map(|mut members| {
                members.sort_unstable();
                TaintContractNode {
                    members,
                    dependencies: Vec::new(),
                    valid: true,
                }
            })
            .collect::<Vec<_>>();
        nodes.sort_unstable_by(|left, right| left.members[0].cmp(&right.members[0]));
        let mut node_by_member = HashMap::new();
        for (node_id, node) in nodes.iter().enumerate() {
            for member in &node.members {
                node_by_member.insert(member.clone(), node_id);
            }
        }
        for (node_id, node) in nodes.iter_mut().enumerate() {
            let members = node.members.clone();
            let mut dependencies = HashSet::new();
            let mut valid = true;
            for member in members {
                let Some(summary) = semantics.summary_for_key(&member) else {
                    valid = false;
                    break;
                };
                for dependency in summary.dependencies() {
                    let dependency = match dependency {
                        SummaryDependencyKey::Complete(key) => semantics.summary_for_key(key),
                        SummaryDependencyKey::Recursive(identity) => {
                            semantics.summary_for_identity(identity)
                        }
                    };
                    let Some(dependency) = dependency else {
                        valid = false;
                        break;
                    };
                    let Some(dependency_node) = node_by_member.get(dependency.key()).copied()
                    else {
                        valid = false;
                        break;
                    };
                    if dependency_node != node_id {
                        dependencies.insert(dependency_node);
                    }
                }
                if !valid {
                    break;
                }
            }
            let mut dependencies = dependencies.into_iter().collect::<Vec<_>>();
            dependencies.sort_unstable();
            if request.cancellation.is_cancelled()
                || request
                    .reserve(SolverWork {
                        callback_rows: dependencies.len(),
                        ..SolverWork::default()
                    })
                    .is_some()
            {
                return Ok(Self::empty());
            }
            node.dependencies = dependencies;
            node.valid = valid;
        }

        let mut closures = vec![None::<Arc<[Arc<TaintLocalClientContract>]>>; nodes.len()];
        let mut visit_state = vec![0_u8; nodes.len()];
        for start in 0..nodes.len() {
            if visit_state[start] == 2 {
                continue;
            }
            let mut stack = vec![(start, false)];
            while let Some((node_id, expanded)) = stack.pop() {
                if expanded {
                    if !nodes[node_id].valid
                        || nodes[node_id]
                            .dependencies
                            .iter()
                            .any(|dependency| closures[*dependency].is_none())
                    {
                        visit_state[node_id] = 2;
                        continue;
                    }
                    let retained_rows = nodes[node_id].members.len().saturating_add(
                        nodes[node_id]
                            .dependencies
                            .iter()
                            .fold(0usize, |total, dependency| {
                                total.saturating_add(
                                    closures[*dependency]
                                        .as_ref()
                                        .expect("validated dependency closure exists")
                                        .len(),
                                )
                            }),
                    );
                    if request.cancellation.is_cancelled()
                        || request
                            .reserve(SolverWork {
                                callback_rows: retained_rows,
                                ..SolverWork::default()
                            })
                            .is_some()
                    {
                        return Ok(Self::empty());
                    }
                    let mut rows = Vec::with_capacity(retained_rows);
                    rows.extend(
                        nodes[node_id]
                            .members
                            .iter()
                            .filter_map(|member| local.get(member).map(|(_, contract, _)| contract))
                            .cloned(),
                    );
                    for dependency in &nodes[node_id].dependencies {
                        rows.extend(
                            closures[*dependency]
                                .as_ref()
                                .expect("validated dependency closure exists")
                                .iter()
                                .cloned(),
                        );
                    }
                    rows.sort_unstable_by(|left, right| left.procedure.cmp(&right.procedure));
                    rows.dedup_by(|left, right| left.procedure == right.procedure);
                    closures[node_id] = Some(Arc::from(rows));
                    visit_state[node_id] = 2;
                    continue;
                }
                match visit_state[node_id] {
                    2 => continue,
                    1 => return Ok(Self::empty()),
                    _ => {}
                }
                visit_state[node_id] = 1;
                stack.push((node_id, true));
                for dependency in nodes[node_id].dependencies.iter().rev().copied() {
                    match visit_state[dependency] {
                        0 => stack.push((dependency, false)),
                        1 => return Ok(Self::empty()),
                        _ => {}
                    }
                }
            }
        }

        let mut by_procedure = HashMap::new();
        for (root_key, (root_procedure, root_local, observers)) in &local {
            if request.cancellation.is_cancelled() {
                return Ok(Self {
                    by_procedure: HashMap::new(),
                    by_key: HashMap::new(),
                });
            }
            let Some(node_id) = node_by_member.get(root_key).copied() else {
                continue;
            };
            let Some(dependency_contract) = closures[node_id].clone() else {
                continue;
            };
            by_procedure.insert(
                root_procedure.clone(),
                PreparedTaintProcedureContract {
                    carrier: root_local.carrier.clone(),
                    propagation: root_local.propagation.clone(),
                    sink_observers: observers.clone(),
                    dependency_contract: TaintDependencyContractKey(dependency_contract),
                },
            );
        }
        let by_key = by_procedure
            .keys()
            .filter_map(|procedure| {
                semantics
                    .unique_summary_for(procedure)
                    .map(|summary| (summary.key().clone(), procedure.clone()))
            })
            .collect();
        Ok(Self {
            by_procedure,
            by_key,
        })
    }

    fn get(&self, procedure: &ProcedureHandle) -> Option<&PreparedTaintProcedureContract> {
        self.by_procedure.get(procedure)
    }

    fn get_by_key(
        &self,
        key: &ProcedureSummaryKey,
    ) -> Option<(&ProcedureHandle, &PreparedTaintProcedureContract)> {
        let procedure = self.by_key.get(key)?;
        self.get(procedure).map(|contract| (procedure, contract))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintTransferSummaryRepositoryLimits {
    pub max_entries: usize,
    pub max_retained_bytes: usize,
}

impl Default for TaintTransferSummaryRepositoryLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_TAINT_SUMMARY_REPOSITORY_ENTRIES,
            max_retained_bytes: DEFAULT_TAINT_SUMMARY_REPOSITORY_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaintSummaryLookupKey {
    carrier: CarrierSummaryKey,
    universe: TaintUniverseHash,
    propagation_semantics: TaintPropagationSemanticsVersion,
    propagation: TaintPropagationEventMatchKey,
    dependency_contract: TaintDependencyContractKey,
    entry: StableTaintFact,
}

/// Bounded complete-only in-memory taint transfer repository.
#[derive(Debug)]
pub struct CompleteTaintTransferSummaryRepository {
    entries: HashMap<TaintTransferSummaryKey, TaintTransferSummary>,
    by_entry: HashMap<TaintSummaryLookupKey, TaintTransferSummaryKey>,
    retained_bytes: usize,
    limits: TaintTransferSummaryRepositoryLimits,
}

impl Default for CompleteTaintTransferSummaryRepository {
    fn default() -> Self {
        Self::with_limits(TaintTransferSummaryRepositoryLimits::default())
    }
}

impl CompleteTaintTransferSummaryRepository {
    pub fn with_limits(limits: TaintTransferSummaryRepositoryLimits) -> Self {
        Self {
            entries: HashMap::new(),
            by_entry: HashMap::new(),
            retained_bytes: 0,
            limits,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub fn get(&self, key: &TaintTransferSummaryKey) -> Option<&TaintTransferSummary> {
        self.entries.get(key)
    }

    pub fn keys(&self) -> impl ExactSizeIterator<Item = &TaintTransferSummaryKey> {
        self.entries.keys()
    }

    fn matching_summary_for_entry(
        &self,
        carrier: CarrierSummaryKey,
        universe: TaintUniverseHash,
        propagation: TaintPropagationEventMatchKey,
        dependency_contract: TaintDependencyContractKey,
        entry: &StableTaintFact,
    ) -> Option<&TaintTransferSummary> {
        let lookup = TaintSummaryLookupKey {
            carrier,
            universe,
            propagation_semantics: TaintPropagationSemanticsVersion::CURRENT,
            propagation,
            dependency_contract,
            entry: entry.clone(),
        };
        let key = self.by_entry.get(&lookup)?;
        self.entries.get(key)
    }

    fn publish(
        &mut self,
        summary: TaintTransferSummary,
    ) -> Result<TaintSummaryPublicationOutcome, TaintSummaryPublicationError> {
        if summary.key.carrier.procedure.recursive_group().is_some() {
            return Err(TaintSummaryPublicationError::RecursiveSummaryRequiresBatch);
        }
        self.publish_batch(vec![summary])
    }

    fn publish_scc(
        &mut self,
        summaries: Vec<TaintTransferSummary>,
        semantics: &TaintSemanticSummarySet<'_>,
    ) -> Result<TaintSummaryPublicationOutcome, TaintSummaryPublicationError> {
        let first = summaries
            .first()
            .ok_or(TaintSummaryPublicationError::EmptyRecursiveBatch)?;
        let group = first
            .key
            .carrier
            .procedure
            .recursive_group()
            .ok_or(TaintSummaryPublicationError::NonRecursiveSummaryInBatch)?;
        if summaries.iter().any(|summary| {
            summary.key.carrier.procedure.recursive_group() != Some(group)
                || summary.key.dependency_contract != first.key.dependency_contract
        }) {
            return Err(TaintSummaryPublicationError::MismatchedRecursiveGroup);
        }
        let semantic_members = semantics
            .summaries
            .iter()
            .copied()
            .filter(|summary| summary.key().recursive_group() == Some(group))
            .collect::<Vec<_>>();
        let validated = validate_recursive_summary_batch(&semantic_members)
            .map_err(|_| TaintSummaryPublicationError::InvalidRecursiveManifest)?;
        if validated.group != group
            || summaries.len() != semantic_members.len()
            || semantic_members.iter().any(|semantic| {
                !summaries
                    .iter()
                    .any(|summary| summary.key.carrier.procedure == *semantic.key())
            })
        {
            return Err(TaintSummaryPublicationError::IncompleteRecursiveBatch);
        }
        self.publish_batch(summaries)
    }

    fn publish_batch(
        &mut self,
        summaries: Vec<TaintTransferSummary>,
    ) -> Result<TaintSummaryPublicationOutcome, TaintSummaryPublicationError> {
        let mut additions = Vec::new();
        let mut staged_entries = HashSet::new();
        let mut staged_lookups = HashMap::<TaintSummaryLookupKey, &TaintTransferSummary>::new();
        for summary in &summaries {
            if let Some(existing) = self.entries.get(summary.key()) {
                if existing == summary {
                    continue;
                }
                return Err(TaintSummaryPublicationError::ConflictingEntry);
            } else if !staged_entries.insert(summary.key().clone()) {
                return Err(TaintSummaryPublicationError::DuplicateKey);
            }
            for entry in summary.key.entry_facts.iter() {
                let lookup = TaintSummaryLookupKey {
                    carrier: summary.key.carrier.clone(),
                    universe: summary.key.universe,
                    propagation_semantics: summary.key.propagation_semantics,
                    propagation: summary.key.propagation.clone(),
                    dependency_contract: summary.key.dependency_contract.clone(),
                    entry: entry.clone(),
                };
                if let Some(existing_key) = self.by_entry.get(&lookup)
                    && existing_key != summary.key()
                {
                    return Err(TaintSummaryPublicationError::OverlappingEntryManifest);
                }
                if let Some(existing) = staged_lookups.insert(lookup, summary)
                    && existing.key() != summary.key()
                {
                    return Err(TaintSummaryPublicationError::OverlappingEntryManifest);
                }
            }
            additions.push(summary);
        }
        if additions.is_empty() {
            return Ok(TaintSummaryPublicationOutcome::AlreadyPresent);
        }
        let mut new_keys = HashSet::new();
        let retained = additions.iter().fold(0usize, |total, summary| {
            let new_key =
                !self.entries.contains_key(summary.key()) && new_keys.insert(summary.key().clone());
            let index_bytes = if new_key {
                repository_index_bytes(summary.key())
            } else {
                0
            };
            total
                .saturating_add(summary.retained_bytes())
                .saturating_add(index_bytes)
        });
        if self.entries.len().saturating_add(new_keys.len()) > self.limits.max_entries {
            return Err(TaintSummaryPublicationError::EntryLimitExceeded);
        }
        if self.retained_bytes.saturating_add(retained) > self.limits.max_retained_bytes {
            return Err(TaintSummaryPublicationError::ByteLimitExceeded);
        }
        for summary in summaries {
            if self.entries.get(summary.key()) == Some(&summary) {
                continue;
            }
            let key = summary.key().clone();
            if !self.entries.contains_key(&key) {
                for entry in key.entry_facts.iter() {
                    self.by_entry.insert(
                        TaintSummaryLookupKey {
                            carrier: key.carrier.clone(),
                            universe: key.universe,
                            propagation_semantics: key.propagation_semantics,
                            propagation: key.propagation.clone(),
                            dependency_contract: key.dependency_contract.clone(),
                            entry: entry.clone(),
                        },
                        key.clone(),
                    );
                }
            }
            let index_bytes = if self.entries.contains_key(&key) {
                0
            } else {
                repository_index_bytes(&key)
            };
            let added_bytes = summary.retained_bytes().saturating_add(index_bytes);
            self.retained_bytes = self.retained_bytes.saturating_add(added_bytes);
            self.entries.insert(key, summary);
        }
        Ok(TaintSummaryPublicationOutcome::Inserted)
    }
}

fn repository_index_bytes(key: &TaintTransferSummaryKey) -> usize {
    key.retained_bytes()
        .saturating_add(key.entry_facts.iter().fold(0usize, |total, entry| {
            total
                .saturating_add(size_of::<TaintSummaryLookupKey>())
                .saturating_add(key.carrier.retained_bytes())
                .saturating_add(key.propagation.retained_bytes())
                .saturating_add(key.dependency_contract.retained_bytes())
                .saturating_add(entry.retained_bytes())
                .saturating_add(key.retained_bytes())
        }))
}

struct TaintSummaryOracle<'query> {
    repository: &'query CompleteTaintTransferSummaryRepository,
    plan: &'query TaintAnalysisPlan,
    contracts: &'query TaintContractSet,
}

impl TaintSummaryOracle<'_> {
    /// Whether the summary's validity contract names every analyzed procedure
    /// this plan binds a call to, from the summarized body or from anything
    /// already inside that contract (#2296).
    ///
    /// A taint summary is looked up under a dependency contract: the exact
    /// transitive closure of client contracts of the summarized procedure's
    /// declared dependencies (`TaintContractSet::try_new`). That closure is
    /// what makes reuse safe for the completeness verdict. Replaying a summary
    /// skips the summarized body and every call it makes, so the subtree
    /// contributes no reached row and no coverage row to this solve (#2291).
    /// The verdict survives because the summary was published only from a solve
    /// that walked that subtree and reported itself complete
    /// (`solve_taint_with_reusable_summaries` returns `Incomplete` and publishes
    /// nothing otherwise), and because the closure pins each of those
    /// procedures' value-flow identity -- curated models, external summary
    /// fingerprints, snapshot presence, local and call rules, unmodeled call
    /// behavior (`ValueFlowPlan::carrier_summary_identities`) -- so the
    /// publishing plan discharged that subtree exactly the way this plan would.
    ///
    /// A declared dependency list that omits a call the plan binds breaks both
    /// halves at once: the omitted procedure's identity is absent from the key,
    /// so a summary published under a plan that modeled that subtree can be
    /// replayed into a plan that does not, and the run then reports a
    /// completeness the fresh solve refuses. Detect that here from the plan's
    /// own call bindings, which cost no semantic work to read, and let the
    /// solver refuse.
    ///
    /// Only bound calls need this. An unbound call is one
    /// `ValueFlowPlan::execution_discovery_modeled` accepts only through a
    /// fully modeled dispatch boundary, and the plan inputs that model it --
    /// curated call models and external summary fingerprints -- are already
    /// part of the calling procedure's own carrier identity, which the key
    /// pins. An unbound call that the solver nonetheless resolves into an
    /// analyzed body leaves that quantifier unsatisfied, so the publishing
    /// solve was not complete and no summary exists to replay.
    fn called_procedures(
        &self,
        procedure: &ProcedureHandle,
        contract: &PreparedTaintProcedureContract,
    ) -> SummaryCalledProcedures {
        let covered = contract
            .dependency_contract
            .0
            .iter()
            .filter_map(|row| self.contracts.get_by_key(&row.procedure))
            .map(|(handle, _)| handle)
            .collect::<Vec<_>>();
        for member in std::iter::once(procedure).chain(covered.iter().copied()) {
            for callee in self.plan.value_flow().bound_callees_of(member) {
                if callee != procedure && !covered.contains(&callee) {
                    return SummaryCalledProcedures::MayEscapeContract;
                }
            }
        }
        SummaryCalledProcedures::CoveredByContract
    }
}

impl ReusableIdeSummaryProvider<TaintFact, TaintEdgeFunction> for TaintSummaryOracle<'_> {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        root: &ProcedureHandle,
        entry_fact: TaintFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableIdeProcedureSummary<TaintFact, TaintEdgeFunction>>, SolverTermination>
    {
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        let Some(contract) = self.contracts.get(procedure) else {
            return Ok(None);
        };
        // #2285. Taint summaries are published for whole call cycles at once,
        // so the repository really can answer for a callee that calls back into
        // the procedure this solve is rooted at. Report that and let the solver
        // refuse the summary and solve the body. Without the root's own
        // contract there is nothing to compare, so report the cycle: refusing
        // reuse costs recomputation, and a wrong answer here costs a fact.
        let call_cycle = match self.contracts.get(root) {
            Some(root_contract) => contract
                .carrier
                .procedure
                .call_cycle_with_root(&root_contract.carrier.procedure),
            None if contract.carrier.procedure.recursive_group().is_some() => {
                SummaryCallCycle::IncludesRoot
            }
            None => SummaryCallCycle::ExcludesRoot,
        };
        let Ok(entry) = StableTaintFact::from_live(entry_fact, self.plan) else {
            return Ok(None);
        };
        let Some(summary) = self.repository.matching_summary_for_entry(
            contract.carrier.clone(),
            self.plan.universe().hash(),
            contract.propagation.clone(),
            contract.dependency_contract.clone(),
            &entry,
        ) else {
            return Ok(None);
        };
        let called_procedures = self.called_procedures(procedure, contract);
        let row_range = summary.row_range(&entry);
        let observation_range = summary.observation_range(&entry);
        let rows = row_range.len();
        let observations = observation_range.len();
        if let Some(termination) = request.reserve(SolverWork {
            callback_rows: rows.saturating_add(observations),
            propagated_outputs: rows,
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        let mut exits = Vec::with_capacity(row_range.len());
        for row in &summary.rows[row_range] {
            let (Ok(exit_fact), Ok(edge_function)) = (
                row.output.to_live(self.plan),
                row.function.to_live(self.plan.universe()),
            ) else {
                return Ok(None);
            };
            exits.push(ReusableIdeEndSummary {
                exit_kind: match row.exit_kind {
                    SummaryExitKind::Normal => ReturnTransferKind::Normal,
                    SummaryExitKind::Exceptional => ReturnTransferKind::Exceptional,
                },
                exit_fact,
                qualities: row.evidence.qualities(),
                edge_function,
            });
        }
        let mut reached = Vec::new();
        let problem = super::client::TaintFlowProblem::new(self.plan);
        for observation in &summary.observations[observation_range] {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled);
            }
            let Some((semantic_procedure, semantic_contract)) =
                self.contracts.get_by_key(observation.procedure())
            else {
                return Ok(None);
            };
            let (
                Some(point),
                Some(injection_point),
                Ok(fact),
                Ok(semantic_entry),
                Ok(edge_function),
            ) = (
                semantic_procedure.point_handle(observation.point),
                procedure.point_handle(procedure.semantics().entry_point()),
                observation.observation.to_live(self.plan),
                observation.semantic_entry.to_live(self.plan),
                observation.function.to_live(self.plan.universe()),
            )
            else {
                return Ok(None);
            };
            if fact.sink().is_some() {
                continue;
            }
            let observers = semantic_contract
                .sink_observers
                .observers_at(observation.point);
            for phase in [
                ValueFlowObservationPhase::BeforeEffects,
                ValueFlowObservationPhase::AfterEffects,
            ] {
                if !observers.iter().any(|observer| observer.phase() == phase) {
                    continue;
                }
                let remaining = MAX_TAINT_LIVE_OBSERVER_ROWS.saturating_sub(reached.len());
                let Some(candidates) =
                    problem.observer_candidates(&point, fact, phase, remaining, request)?
                else {
                    return Ok(None);
                };
                if let Some(termination) = request.reserve(SolverWork {
                    callback_rows: candidates.len(),
                    ..SolverWork::default()
                }) {
                    return Err(termination);
                }
                for observer in observers
                    .iter()
                    .filter(|observer| observer.phase() == phase)
                {
                    let Some(sink) = self.plan.value_flow().sink_id_for_key(observer.event())
                    else {
                        return Ok(None);
                    };
                    for (candidate, local_function) in &candidates {
                        if request.cancellation.is_cancelled() {
                            return Err(SolverTermination::Cancelled);
                        }
                        if let Some(termination) = request.reserve(SolverWork {
                            ide_propagations: 1,
                            ..SolverWork::default()
                        }) {
                            return Err(termination);
                        }
                        let Some(carrier) = candidate.carrier() else {
                            continue;
                        };
                        if self.plan.value_flow().carrier_key(carrier) != Some(observer.carrier()) {
                            continue;
                        }
                        if reached.len() == MAX_TAINT_LIVE_OBSERVER_ROWS {
                            return Ok(None);
                        }
                        if let Some(termination) = request.reserve(SolverWork {
                            callback_rows: 1,
                            propagated_outputs: 1,
                            edge_function_operations: 1,
                            ..SolverWork::default()
                        }) {
                            return Err(termination);
                        }
                        let Some(meeting) = TaintFact::for_sink_with_entry(
                            sink,
                            candidate.is_uncertain()
                                || !observer.is_proven()
                                || !observer.is_complete(),
                            semantic_entry,
                        ) else {
                            return Ok(None);
                        };
                        reached.push(ReusableIdeReachedFact {
                            point: injection_point.clone(),
                            fact: meeting,
                            qualities: observation.evidence.qualities(),
                            edge_function: edge_function.compose(local_function),
                        });
                    }
                }
            }
        }
        Ok(Some(ReusableIdeProcedureSummary {
            exits: exits.into_boxed_slice(),
            reached: reached.into_boxed_slice(),
            call_cycle,
            called_procedures,
        }))
    }
}

#[derive(Debug)]
pub struct TaintTransferSummarySolveResult {
    result: Box<TaintSummaryResult>,
    cache_status: TaintTransferSummaryCacheStatus,
    published_summaries: usize,
}

impl TaintTransferSummarySolveResult {
    pub fn was_reused(&self) -> bool {
        self.result.fact_result().metrics().reusable_summary_hits > 0
    }

    pub fn computed_result(&self) -> &TaintSummaryResult {
        self.result.as_ref()
    }

    pub fn into_computed_result(self) -> TaintSummaryResult {
        *self.result
    }

    pub const fn cache_status(&self) -> TaintTransferSummaryCacheStatus {
        self.cache_status
    }

    pub const fn published_summaries(&self) -> usize {
        self.published_summaries
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintTransferSummaryCacheStatus {
    Published,
    AlreadyPresent,
    Incomplete,
    RecursiveBatchRequired,
    CapacityExceeded,
    Conflict,
    ProjectionSkipped,
}

#[allow(clippy::too_many_arguments)]
pub fn solve_taint_with_reusable_summaries<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &TaintAnalysisPlan,
    semantic_summaries: &TaintSemanticSummarySet<'_>,
    repository: &mut CompleteTaintTransferSummaryRepository,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintTransferSummarySolveResult, TaintTransferSummarySolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    let root_semantic = semantic_summaries
        .unique_summary_for(root)
        .ok_or(TaintTransferSummaryError::ProcedureMismatch)?;
    if !procedure_matches(root, root_semantic.key()) {
        return Err(TaintTransferSummaryError::ProcedureMismatch.into());
    }
    let contracts = if request.cancellation.is_cancelled()
        || request
            .reserve(SolverWork {
                callback_rows: plan
                    .summary_key_rows()
                    .saturating_add(semantic_summaries.summaries.len()),
                ..SolverWork::default()
            })
            .is_some()
    {
        TaintContractSet::empty()
    } else {
        TaintContractSet::try_new(plan, semantic_summaries, request)?
    };
    let result = {
        let mut reusable = TaintSummaryOracle {
            repository,
            plan,
            contracts: &contracts,
        };
        solve_taint_with_reusable_provider(
            root,
            provider,
            &mut reusable,
            plan,
            crate::analyzer::dataflow::WitnessRetentionLimits::disabled(),
            semantic_budget,
            request,
        )?
    };
    if !result.is_complete() {
        return Ok(TaintTransferSummarySolveResult {
            result: Box::new(result),
            cache_status: TaintTransferSummaryCacheStatus::Incomplete,
            published_summaries: 0,
        });
    }
    let projection_rows = result
        .result()
        .end_summary_jump_functions()
        .count()
        .saturating_add(result.result().reached_jump_functions().count())
        .saturating_add(result.result().entry_transfers().count())
        .saturating_add(plan.summary_key_rows());
    if request.cancellation.is_cancelled()
        || request
            .reserve(SolverWork {
                callback_rows: projection_rows,
                ..SolverWork::default()
            })
            .is_some()
    {
        return Ok(TaintTransferSummarySolveResult {
            result: Box::new(result),
            cache_status: TaintTransferSummaryCacheStatus::ProjectionSkipped,
            published_summaries: 0,
        });
    }
    let projection = project_complete_taint_summaries(
        semantic_summaries,
        &contracts,
        repository,
        plan,
        &result,
        request,
    )?;
    let (cache_status, published_summaries) = publish_projected_summaries(
        repository,
        semantic_summaries,
        projection.summaries,
        projection.skipped,
    );
    Ok(TaintTransferSummarySolveResult {
        result: Box::new(result),
        cache_status,
        published_summaries,
    })
}

#[derive(Default)]
struct ProcedureProjection {
    entries: HashSet<StableTaintFact>,
    rows: Vec<TaintTransferRow>,
    observations: Vec<TaintObservedPort>,
    oversized: bool,
}

struct ProjectionBatch {
    summaries: Vec<TaintTransferSummary>,
    skipped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlattenedObservationKey {
    entry: SummaryEntry,
    semantic_entry: StableTaintFact,
    procedure: ProcedureSummaryKey,
    point: ProgramPointId,
    observation: StableTaintFact,
}

#[derive(Debug, Clone)]
struct FlattenedObservationValue {
    evidence: PathQualityFrontier,
    function: TaintEdgeFunction,
}

#[derive(Debug, Clone)]
struct FlattenedEntryTransfer {
    source: SummaryEntry,
    evidence: PathQualityFrontier,
    function: TaintEdgeFunction,
}

fn conjoin_taint_evidence(
    prefix: PathQualityFrontier,
    suffix: PathQualityFrontier,
) -> PathQualityFrontier {
    let mut combined = PathQualityFrontier::default();
    for prefix_quality in prefix.iter() {
        for suffix_quality in suffix.iter() {
            combined.insert(prefix_quality.conjoin(suffix_quality));
        }
    }
    combined
}

fn merge_flattened_observation(
    states: &mut HashMap<FlattenedObservationKey, FlattenedObservationValue>,
    key: FlattenedObservationKey,
    candidate: FlattenedObservationValue,
    request: &mut DataflowRequest<'_>,
) -> Option<bool> {
    if request.cancellation.is_cancelled() {
        return None;
    }
    if let Some(existing) = states.get_mut(&key) {
        if request
            .reserve(SolverWork {
                callback_rows: 1,
                edge_function_operations: 1,
                ..SolverWork::default()
            })
            .is_some()
        {
            return None;
        }
        let function = existing.function.meet(&candidate.function);
        let mut changed = function != existing.function;
        existing.function = function;
        for quality in candidate.evidence.iter() {
            changed |= existing.evidence.insert(quality);
        }
        return Some(changed);
    }
    if states.len() == MAX_TAINT_TRANSFER_OBSERVATIONS
        || request
            .reserve(SolverWork {
                callback_rows: 1,
                propagated_outputs: 1,
                ..SolverWork::default()
            })
            .is_some()
    {
        return None;
    }
    states.insert(key, candidate);
    Some(true)
}

fn flatten_taint_observations(
    semantic_summaries: &TaintSemanticSummarySet<'_>,
    contracts: &TaintContractSet,
    repository: &CompleteTaintTransferSummaryRepository,
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    request: &mut DataflowRequest<'_>,
) -> Result<
    Option<HashMap<FlattenedObservationKey, FlattenedObservationValue>>,
    TaintTransferSummaryError,
> {
    let mut incoming = HashMap::<SummaryEntry, Vec<FlattenedEntryTransfer>>::new();
    let mut entries = HashSet::<SummaryEntry>::new();
    for (transfer, function) in result.result().entry_transfers() {
        entries.insert(transfer.source().clone());
        entries.insert(transfer.target().clone());
        incoming
            .entry(transfer.target().clone())
            .or_default()
            .push(FlattenedEntryTransfer {
                source: transfer.source().clone(),
                evidence: transfer.path_qualities(),
                function: function.clone(),
            });
    }
    let mut states = HashMap::<FlattenedObservationKey, FlattenedObservationValue>::new();
    let mut worklist = VecDeque::<FlattenedObservationKey>::new();
    for (reached, function) in result.result().reached_jump_functions() {
        entries.insert(reached.entry().clone());
        let observation = StableTaintFact::from_live(
            *result
                .fact_result()
                .fact(reached.fact())
                .ok_or(TaintTransferSummaryError::InvalidFact)?,
            plan,
        )?;
        if matches!(observation, StableTaintFact::SinkObservation { .. }) {
            continue;
        }
        let Some(semantic) = semantic_summaries.unique_summary_for(reached.point().procedure())
        else {
            continue;
        };
        let key = FlattenedObservationKey {
            entry: reached.entry().clone(),
            semantic_entry: StableTaintFact::from_live(
                *result
                    .fact_result()
                    .fact(reached.entry().entry_fact())
                    .ok_or(TaintTransferSummaryError::InvalidFact)?,
                plan,
            )?,
            procedure: semantic.key().clone(),
            point: reached.point().id(),
            observation,
        };
        let changed = merge_flattened_observation(
            &mut states,
            key.clone(),
            FlattenedObservationValue {
                evidence: reached.path_qualities(),
                function: function.clone(),
            },
            request,
        );
        match changed {
            Some(true) => worklist.push_back(key),
            Some(false) => {}
            None => return Ok(None),
        }
    }
    for entry in entries {
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(contract) = contracts.get(entry.procedure()) else {
            continue;
        };
        let input = StableTaintFact::from_live(
            *result
                .fact_result()
                .fact(entry.entry_fact())
                .ok_or(TaintTransferSummaryError::InvalidFact)?,
            plan,
        )?;
        let Some(summary) = repository.matching_summary_for_entry(
            contract.carrier.clone(),
            plan.universe().hash(),
            contract.propagation.clone(),
            contract.dependency_contract.clone(),
            &input,
        ) else {
            continue;
        };
        for observation in &summary.observations[summary.observation_range(&input)] {
            let key = FlattenedObservationKey {
                entry: entry.clone(),
                semantic_entry: observation.semantic_entry.clone(),
                procedure: observation.procedure.clone(),
                point: observation.point,
                observation: observation.observation.clone(),
            };
            let changed = merge_flattened_observation(
                &mut states,
                key.clone(),
                FlattenedObservationValue {
                    evidence: observation.evidence.frontier(),
                    function: observation.function.to_live(plan.universe())?,
                },
                request,
            );
            match changed {
                Some(true) => worklist.push_back(key),
                Some(false) => {}
                None => return Ok(None),
            }
        }
    }
    while let Some(key) = worklist.pop_front() {
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(value) = states.get(&key).cloned() else {
            continue;
        };
        let Some(transfers) = incoming.get(&key.entry) else {
            continue;
        };
        for transfer in transfers {
            if request
                .reserve(SolverWork {
                    edge_function_operations: 1,
                    ..SolverWork::default()
                })
                .is_some()
            {
                return Ok(None);
            }
            let next_key = FlattenedObservationKey {
                entry: transfer.source.clone(),
                semantic_entry: key.semantic_entry.clone(),
                procedure: key.procedure.clone(),
                point: key.point,
                observation: key.observation.clone(),
            };
            let changed = merge_flattened_observation(
                &mut states,
                next_key.clone(),
                FlattenedObservationValue {
                    evidence: conjoin_taint_evidence(transfer.evidence, value.evidence),
                    function: transfer.function.compose(&value.function),
                },
                request,
            );
            match changed {
                Some(true) => worklist.push_back(next_key),
                Some(false) => {}
                None => return Ok(None),
            }
        }
    }
    Ok(Some(states))
}

fn project_complete_taint_summaries(
    semantic_summaries: &TaintSemanticSummarySet<'_>,
    contracts: &TaintContractSet,
    repository: &CompleteTaintTransferSummaryRepository,
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    request: &mut DataflowRequest<'_>,
) -> Result<ProjectionBatch, TaintTransferSummaryError> {
    if !result.is_complete() || !std::sync::Arc::ptr_eq(result.owner(), plan.owner()) {
        return Err(TaintTransferSummaryError::IncompleteResult);
    }
    let mut projections = HashMap::<ProcedureHandle, ProcedureProjection>::new();
    let mut skipped = false;
    for (summary, function) in result.result().end_summary_jump_functions() {
        if request.cancellation.is_cancelled() {
            return Ok(ProjectionBatch {
                summaries: Vec::new(),
                skipped: true,
            });
        }
        let procedure = summary.entry().procedure();
        let Some(semantic) = semantic_summaries.unique_summary_for(procedure) else {
            continue;
        };
        if !semantic_summaries.eligible(semantic) {
            skipped = true;
            continue;
        }
        if contracts.get(procedure).is_none() {
            skipped = true;
            continue;
        }
        let projection = projections.entry(procedure.clone()).or_default();
        let input = StableTaintFact::from_live(
            *result
                .fact_result()
                .fact(summary.entry().entry_fact())
                .ok_or(TaintTransferSummaryError::InvalidFact)?,
            plan,
        )?;
        projection.entries.insert(input.clone());
        if projection.rows.len() == MAX_TAINT_TRANSFER_SUMMARY_ROWS {
            projection.oversized = true;
            continue;
        }
        let output = StableTaintFact::from_live(
            *result
                .fact_result()
                .fact(summary.exit_fact())
                .ok_or(TaintTransferSummaryError::InvalidFact)?,
            plan,
        )?;
        projection.rows.push(TaintTransferRow {
            input,
            exit_kind: match summary.exit_kind() {
                ReturnTransferKind::Normal => SummaryExitKind::Normal,
                ReturnTransferKind::Exceptional => SummaryExitKind::Exceptional,
            },
            output,
            evidence: TaintPathEvidence::from_frontier(summary.path_qualities()),
            function: StableTaintEdgeFunction::from_live(function, plan.universe())?,
        });
    }
    let Some(flattened) = flatten_taint_observations(
        semantic_summaries,
        contracts,
        repository,
        plan,
        result,
        request,
    )?
    else {
        return Ok(ProjectionBatch {
            summaries: Vec::new(),
            skipped: true,
        });
    };
    for (key, value) in flattened {
        let procedure = key.entry.procedure();
        let Some(semantic) = semantic_summaries.unique_summary_for(procedure) else {
            continue;
        };
        if !semantic_summaries.eligible(semantic) || contracts.get(procedure).is_none() {
            skipped = true;
            continue;
        }
        let input = StableTaintFact::from_live(
            *result
                .fact_result()
                .fact(key.entry.entry_fact())
                .ok_or(TaintTransferSummaryError::InvalidFact)?,
            plan,
        )?;
        let projection = projections.entry(procedure.clone()).or_default();
        projection.entries.insert(input.clone());
        if projection.observations.len() == MAX_TAINT_TRANSFER_OBSERVATIONS {
            projection.oversized = true;
            continue;
        }
        projection.observations.push(TaintObservedPort {
            input,
            semantic_entry: key.semantic_entry,
            procedure: key.procedure,
            point: key.point,
            observation: key.observation,
            evidence: TaintPathEvidence::from_frontier(value.evidence),
            function: StableTaintEdgeFunction::from_live(&value.function, plan.universe())?,
        });
    }
    let mut summaries = Vec::new();
    for (procedure, mut projection) in projections {
        if projection.oversized {
            skipped = true;
            continue;
        }
        let Some(contract) = contracts.get(&procedure) else {
            skipped = true;
            continue;
        };
        let mut entries = projection.entries.into_iter().collect::<Vec<_>>();
        entries.sort_unstable();
        entries.dedup();
        projection.rows.sort_unstable();
        projection.rows.dedup();
        projection.observations.sort_unstable();
        projection.observations.dedup();
        let key = TaintTransferSummaryKey {
            carrier: contract.carrier.clone(),
            universe: plan.universe().hash(),
            propagation_semantics: TaintPropagationSemanticsVersion::CURRENT,
            propagation: contract.propagation.clone(),
            dependency_contract: contract.dependency_contract.clone(),
            entry_facts: entries.into_boxed_slice(),
            schema_version: TAINT_TRANSFER_SUMMARY_SCHEMA_VERSION,
        };
        if projection
            .rows
            .iter()
            .any(|row| key.entry_facts.binary_search(&row.input).is_err())
            || projection
                .observations
                .iter()
                .any(|row| key.entry_facts.binary_search(&row.input).is_err())
        {
            return Err(TaintTransferSummaryError::EntryFactCoverageMismatch);
        }
        summaries.push(TaintTransferSummary {
            key,
            rows: projection.rows.into_boxed_slice(),
            observations: projection.observations.into_boxed_slice(),
        });
    }
    summaries.sort_unstable_by(|left, right| {
        left.key.carrier.procedure.cmp(&right.key.carrier.procedure)
    });
    Ok(ProjectionBatch { summaries, skipped })
}

fn publish_projected_summaries(
    repository: &mut CompleteTaintTransferSummaryRepository,
    semantic_summaries: &TaintSemanticSummarySet<'_>,
    summaries: Vec<TaintTransferSummary>,
    projection_skipped: bool,
) -> (TaintTransferSummaryCacheStatus, usize) {
    let mut ordinary = Vec::new();
    let mut recursive = HashMap::<SummaryRecursiveGroupKey, Vec<TaintTransferSummary>>::new();
    for summary in summaries {
        if let Some(group) = summary.key.carrier.procedure.recursive_group() {
            recursive.entry(group).or_default().push(summary);
        } else {
            ordinary.push(summary);
        }
    }
    let mut published = 0usize;
    let mut inserted = false;
    let mut recursive_required = false;
    let mut capacity = false;
    let mut conflict = false;
    for summary in ordinary {
        match repository.publish(summary) {
            Ok(TaintSummaryPublicationOutcome::Inserted) => {
                inserted = true;
                published = published.saturating_add(1);
            }
            Ok(TaintSummaryPublicationOutcome::AlreadyPresent) => {}
            Err(
                TaintSummaryPublicationError::EntryLimitExceeded
                | TaintSummaryPublicationError::ByteLimitExceeded,
            ) => capacity = true,
            Err(_) => conflict = true,
        }
    }
    for summaries in recursive.into_values() {
        let count = summaries.len();
        match repository.publish_scc(summaries, semantic_summaries) {
            Ok(TaintSummaryPublicationOutcome::Inserted) => {
                inserted = true;
                published = published.saturating_add(count);
            }
            Ok(TaintSummaryPublicationOutcome::AlreadyPresent) => {}
            Err(TaintSummaryPublicationError::IncompleteRecursiveBatch) => {
                recursive_required = true
            }
            Err(
                TaintSummaryPublicationError::EntryLimitExceeded
                | TaintSummaryPublicationError::ByteLimitExceeded,
            ) => capacity = true,
            Err(_) => conflict = true,
        }
    }
    let status = if conflict {
        TaintTransferSummaryCacheStatus::Conflict
    } else if capacity {
        TaintTransferSummaryCacheStatus::CapacityExceeded
    } else if recursive_required {
        TaintTransferSummaryCacheStatus::RecursiveBatchRequired
    } else if inserted {
        TaintTransferSummaryCacheStatus::Published
    } else if projection_skipped {
        TaintTransferSummaryCacheStatus::ProjectionSkipped
    } else {
        TaintTransferSummaryCacheStatus::AlreadyPresent
    };
    (status, published)
}

fn procedure_matches(procedure: &ProcedureHandle, key: &ProcedureSummaryKey) -> bool {
    procedure.artifact().key() == key.artifact()
        && procedure.semantics().locator().declaration() == key.declaration()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintSummaryPublicationOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintSummaryPublicationError {
    RecursiveSummaryRequiresBatch,
    EmptyRecursiveBatch,
    NonRecursiveSummaryInBatch,
    MismatchedRecursiveGroup,
    InvalidRecursiveManifest,
    IncompleteRecursiveBatch,
    DuplicateKey,
    ConflictingEntry,
    OverlappingEntryManifest,
    EntryLimitExceeded,
    ByteLimitExceeded,
}

impl fmt::Display for TaintSummaryPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecursiveSummaryRequiresBatch => {
                "recursive taint summaries require atomic SCC publication"
            }
            Self::EmptyRecursiveBatch => "recursive taint summary batch is empty",
            Self::NonRecursiveSummaryInBatch => {
                "recursive taint summary batch contains a non-recursive member"
            }
            Self::MismatchedRecursiveGroup => {
                "recursive taint summary batch mixes recursive groups"
            }
            Self::InvalidRecursiveManifest => "recursive taint summary manifest is invalid",
            Self::IncompleteRecursiveBatch => "recursive taint summary batch is incomplete",
            Self::DuplicateKey => "taint summary batch repeats a key",
            Self::ConflictingEntry => "taint summary repository contains a conflicting entry",
            Self::OverlappingEntryManifest => "taint summary entry manifests overlap",
            Self::EntryLimitExceeded => "taint summary repository entry limit exceeded",
            Self::ByteLimitExceeded => "taint summary repository byte limit exceeded",
        })
    }
}

impl std::error::Error for TaintSummaryPublicationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintTransferSummaryError {
    IncompleteSemanticSummary,
    AmbiguousSemanticSummary,
    ProcedureMismatch,
    InvalidPlan,
    UniverseMismatch,
    InvalidFact,
    InvalidEdgeFunction,
    SinkObserverMismatch,
    EntryFactCoverageMismatch,
    IncompleteResult,
}

impl fmt::Display for TaintTransferSummaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IncompleteSemanticSummary => "taint summary requires a complete semantic summary",
            Self::AmbiguousSemanticSummary => "taint summary semantic set is ambiguous",
            Self::ProcedureMismatch => "taint summary procedure does not match its semantic key",
            Self::InvalidPlan => "taint summary plan contains a stale stable binding",
            Self::UniverseMismatch => "taint summary class universe does not match",
            Self::InvalidFact => "taint summary fact cannot be remapped",
            Self::InvalidEdgeFunction => "taint summary edge function is not canonical",
            Self::SinkObserverMismatch => "taint summary sink observer cannot be remapped",
            Self::EntryFactCoverageMismatch => "taint summary rows exceed the entry manifest",
            Self::IncompleteResult => {
                "taint summary projection requires a complete matching result"
            }
        })
    }
}

impl std::error::Error for TaintTransferSummaryError {}

#[derive(Debug)]
pub enum TaintTransferSummarySolveError {
    Taint(TaintSolveError),
    Summary(TaintTransferSummaryError),
}

impl fmt::Display for TaintTransferSummarySolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Taint(error) => error.fmt(formatter),
            Self::Summary(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TaintTransferSummarySolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Taint(error) => Some(error),
            Self::Summary(error) => Some(error),
        }
    }
}

impl From<TaintSolveError> for TaintTransferSummarySolveError {
    fn from(error: TaintSolveError) -> Self {
        Self::Taint(error)
    }
}

impl From<TaintTransferSummaryError> for TaintTransferSummarySolveError {
    fn from(error: TaintTransferSummaryError) -> Self {
        Self::Summary(error)
    }
}
