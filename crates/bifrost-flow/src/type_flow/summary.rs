//! Reusable symbolic value-flow relations for class-set analysis.
//!
//! Replaying a generic summary skips the callee body and therefore its
//! transitive observations. This dimension folds descendant observations to
//! caller call points before publishing an acyclic, fully closed procedure.
//! Entry-carried sources are stored as a symbolic placeholder instead of a
//! root-local source ID, so the same relation can be remapped for callers that
//! pass different class-producing values.

use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::analyzer::read_ledger::read_set_digest;
#[cfg(test)]
use crate::analyzer::semantic::MemberAccessKind;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, DispatchBoundaryKind, IcfgProvider,
    IcfgProviderBehaviorIdentity, LengthDelimitedDigest, OracleCallContext, ProcedureHandle,
    ProcedureId, ProgramPointId, ReturnTransferKind, SemanticArtifactKey,
    SemanticArtifactMaterializationId, SemanticBudget, SemanticRequest, SemanticWork, StableDigest,
    ValueFlowSnapshot, one_call_dispatch_answer_digest,
};
use crate::analyzer::store::class_set_procedure_surfaces::{
    ClassSetProcedureIdentityRow, ClassSetProcedureSurfaceCallRow,
    ClassSetProcedureSurfaceDispatchRow, ClassSetProcedureSurfaceHeaderRow,
    ClassSetProcedureSurfaceKey, ClassSetProcedureSurfaceRow, ClassSetProcedureSurfaceStatusRow,
};
use crate::analyzer::store::class_set_summaries::{
    ClassSetSummaryAttachment, ClassSetSummaryChargeRow, ClassSetSummaryDependencyEntryRow,
    ClassSetSummaryDependencyRow, ClassSetSummaryDependentRow, ClassSetSummaryExitKindRow,
    ClassSetSummaryExitRow, ClassSetSummaryFactRow, ClassSetSummaryFactShapeRow,
    ClassSetSummaryFactSourceRow, ClassSetSummaryFamilyKey, ClassSetSummaryHeaderRow,
    ClassSetSummaryOutputDigest, ClassSetSummaryReachedRow, ClassSetSummaryReadRow,
    ClassSetSummaryRow, ClassSetSummaryRowKey, class_set_summary_output_digest,
};
use crate::analyzer::store::{AnalyzerStore, StoreError};
use crate::analyzer::{ProjectFile, ReadKey, WorkspaceAnalyzer, procedure_dispatch_read_call};
use crate::dataflow::{
    DataflowRequest, FactId, PathQuality, PathQualityFrontier, ProcedureSummaryIdentity,
    ProcedureSummaryKey, ProductionSemanticSummaryRepository, ReusableEndSummary,
    ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryError, ReusableSummaryProvider,
    SemanticInputStatus, SemanticProcedureSummary, SolverTermination, SolverWork,
    SummaryBehaviorKey, SummaryCallCycle, SummaryCalledProcedures, SummaryCompleteness,
    SummaryContextKey, SummaryDataflowResult, SummaryDependencyKey, SummaryEffect,
    SummaryEffectKey, SummaryEntry, SummaryEventKey, SummaryOrigin, SummaryProcedureSemanticsKey,
    SummaryPublicationOutcome, SummarySchemaVersion, SummarySemanticsVersion,
};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    BindingCoverage, CallSiteCoverage, ClosureCutDecider, DispatchStatus, DurableProcedureKey,
    HydratedProcedureSurface, ValueFlowCarrierKey, ValueFlowCarrierSummaryIdentity,
    ValueFlowEventKey, ValueFlowFact, ValueFlowInput, ValueFlowPlan, ValueFlowPlanError,
    ValueFlowProvider, ValueFlowSourceBehaviorIdentity, ValueFlowUncertainty,
    solve_value_flow_entry_with_reusable_summaries,
};

use super::field_slots::FieldSlotIndexCache;
use super::plan::ProcedureDispatchReadContract;
use super::{FieldSlotIndex, TypeFlowPlan};

// Formal assignments now overwrite the port read by guards and later uses.
// Persisted surfaces from before #3124 must not replay the old value target.
const CLASS_SET_SUMMARY_SEMANTICS: &[u8] = b"bifrost-class-set-summary-semantics-v9";
const CLASS_SET_SUMMARY_CONTEXT: &[u8] = b"bifrost-class-set-summary-context-v1";
const CLASS_SET_SUMMARY_BEHAVIOR: &[u8] = b"bifrost-class-set-summary-behavior-v3";
const CLASS_SET_SUMMARY_ATOM: &[u8] = b"bifrost-class-set-summary-atom-v1";
const CLASS_SET_SUMMARY_ENTRY: &[u8] = b"bifrost-class-set-summary-entry-v3";
const CLASS_SET_SUMMARY_LOOKUP: &[u8] = b"bifrost-class-set-summary-lookup-v3";
const CLASS_SET_SUMMARY_CALL_CONTRACT: &[u8] = b"bifrost-class-set-summary-call-contract-v3";
const CLASS_SET_SUMMARY_BINDING_CONTRACT: &[u8] = b"bifrost-class-set-summary-binding-contract-v1";
const CLASS_SET_SUMMARY_SOURCE_BEHAVIOR: &[u8] = b"bifrost-class-set-source-behavior-v1";
const MAX_CLASS_SET_SUMMARIES: usize = 16_384;
const MAX_CLASS_SET_ENTRY_SELECTOR_PROBES: usize = 16_384;
const MAX_CLASS_SET_SUMMARY_ROWS: usize = 262_144;
const MAX_CLASS_SET_SURFACE_CANDIDATES: usize = 64;

/// Diagnostic attribution for reusable class-set summary work.
///
/// These counters describe why a reusable relation could not be prepared,
/// consumed, or published. They are deliberately separate from the solver's
/// hit/miss totals: one preparation rejection can explain many later entry
/// misses, while one publication attempt can reject several projected rows.
/// Counts are attempt events accumulated across feedback and selective-retry
/// plans, not a unique-procedure inventory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TypeFlowSummaryProfile {
    pub preparation_call_contract: u64,
    pub preparation_dependency: u64,
    pub preparation_source_limit: u64,
    pub preparation_recursive_dependency: u64,
    pub preparation_repository_failure: u64,
    pub preparation_surface: u64,
    pub lookup_procedure: u64,
    pub lookup_source_behavior: u64,
    pub lookup_source_partition: u64,
    pub lookup_entry: u64,
    pub lookup_relation: u64,
    pub lookup_live_remap: u64,
    pub publication_incomplete_result: u64,
    pub publication_projection: u64,
    pub publication_entry: u64,
    pub publication_relation_shape: u64,
    pub publication_dispatch_reads: u64,
    pub publication_reused_conflict: u64,
    pub publication_transfer: u64,
    pub publication_dependency: u64,
}

impl TypeFlowSummaryProfile {
    pub const fn is_empty(&self) -> bool {
        self.preparation_call_contract == 0
            && self.preparation_dependency == 0
            && self.preparation_source_limit == 0
            && self.preparation_recursive_dependency == 0
            && self.preparation_repository_failure == 0
            && self.preparation_surface == 0
            && self.lookup_procedure == 0
            && self.lookup_source_behavior == 0
            && self.lookup_source_partition == 0
            && self.lookup_entry == 0
            && self.lookup_relation == 0
            && self.lookup_live_remap == 0
            && self.publication_incomplete_result == 0
            && self.publication_projection == 0
            && self.publication_entry == 0
            && self.publication_relation_shape == 0
            && self.publication_dispatch_reads == 0
            && self.publication_reused_conflict == 0
            && self.publication_transfer == 0
            && self.publication_dependency == 0
    }

    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            preparation_call_contract: self
                .preparation_call_contract
                .saturating_add(other.preparation_call_contract),
            preparation_dependency: self
                .preparation_dependency
                .saturating_add(other.preparation_dependency),
            preparation_source_limit: self
                .preparation_source_limit
                .saturating_add(other.preparation_source_limit),
            preparation_recursive_dependency: self
                .preparation_recursive_dependency
                .saturating_add(other.preparation_recursive_dependency),
            preparation_repository_failure: self
                .preparation_repository_failure
                .saturating_add(other.preparation_repository_failure),
            preparation_surface: self
                .preparation_surface
                .saturating_add(other.preparation_surface),
            lookup_procedure: self.lookup_procedure.saturating_add(other.lookup_procedure),
            lookup_source_behavior: self
                .lookup_source_behavior
                .saturating_add(other.lookup_source_behavior),
            lookup_source_partition: self
                .lookup_source_partition
                .saturating_add(other.lookup_source_partition),
            lookup_entry: self.lookup_entry.saturating_add(other.lookup_entry),
            lookup_relation: self.lookup_relation.saturating_add(other.lookup_relation),
            lookup_live_remap: self
                .lookup_live_remap
                .saturating_add(other.lookup_live_remap),
            publication_incomplete_result: self
                .publication_incomplete_result
                .saturating_add(other.publication_incomplete_result),
            publication_projection: self
                .publication_projection
                .saturating_add(other.publication_projection),
            publication_entry: self
                .publication_entry
                .saturating_add(other.publication_entry),
            publication_relation_shape: self
                .publication_relation_shape
                .saturating_add(other.publication_relation_shape),
            publication_dispatch_reads: self
                .publication_dispatch_reads
                .saturating_add(other.publication_dispatch_reads),
            publication_reused_conflict: self
                .publication_reused_conflict
                .saturating_add(other.publication_reused_conflict),
            publication_transfer: self
                .publication_transfer
                .saturating_add(other.publication_transfer),
            publication_dependency: self
                .publication_dependency
                .saturating_add(other.publication_dependency),
        }
    }

    pub const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            preparation_call_contract: self
                .preparation_call_contract
                .saturating_sub(earlier.preparation_call_contract),
            preparation_dependency: self
                .preparation_dependency
                .saturating_sub(earlier.preparation_dependency),
            preparation_source_limit: self
                .preparation_source_limit
                .saturating_sub(earlier.preparation_source_limit),
            preparation_recursive_dependency: self
                .preparation_recursive_dependency
                .saturating_sub(earlier.preparation_recursive_dependency),
            preparation_repository_failure: self
                .preparation_repository_failure
                .saturating_sub(earlier.preparation_repository_failure),
            preparation_surface: self
                .preparation_surface
                .saturating_sub(earlier.preparation_surface),
            lookup_procedure: self
                .lookup_procedure
                .saturating_sub(earlier.lookup_procedure),
            lookup_source_behavior: self
                .lookup_source_behavior
                .saturating_sub(earlier.lookup_source_behavior),
            lookup_source_partition: self
                .lookup_source_partition
                .saturating_sub(earlier.lookup_source_partition),
            lookup_entry: self.lookup_entry.saturating_sub(earlier.lookup_entry),
            lookup_relation: self.lookup_relation.saturating_sub(earlier.lookup_relation),
            lookup_live_remap: self
                .lookup_live_remap
                .saturating_sub(earlier.lookup_live_remap),
            publication_incomplete_result: self
                .publication_incomplete_result
                .saturating_sub(earlier.publication_incomplete_result),
            publication_projection: self
                .publication_projection
                .saturating_sub(earlier.publication_projection),
            publication_entry: self
                .publication_entry
                .saturating_sub(earlier.publication_entry),
            publication_relation_shape: self
                .publication_relation_shape
                .saturating_sub(earlier.publication_relation_shape),
            publication_dispatch_reads: self
                .publication_dispatch_reads
                .saturating_sub(earlier.publication_dispatch_reads),
            publication_reused_conflict: self
                .publication_reused_conflict
                .saturating_sub(earlier.publication_reused_conflict),
            publication_transfer: self
                .publication_transfer
                .saturating_sub(earlier.publication_transfer),
            publication_dependency: self
                .publication_dependency
                .saturating_sub(earlier.publication_dependency),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SummaryProfileReason {
    PreparationCallContract,
    PreparationDependency,
    PreparationSourceLimit,
    PreparationRecursiveDependency,
    PreparationRepositoryFailure,
    PreparationSurface,
    LookupProcedure,
    LookupSourceBehavior,
    LookupSourcePartition,
    LookupEntry,
    LookupRelation,
    LookupLiveRemap,
    PublicationIncompleteResult,
    PublicationProjection,
    PublicationEntry,
    PublicationRelationShape,
    PublicationDispatchReads,
    PublicationReusedConflict,
    PublicationTransfer,
    PublicationDependency,
}

impl TypeFlowSummaryProfile {
    fn record(&mut self, reason: SummaryProfileReason) {
        let counter = match reason {
            SummaryProfileReason::PreparationCallContract => &mut self.preparation_call_contract,
            SummaryProfileReason::PreparationDependency => &mut self.preparation_dependency,
            SummaryProfileReason::PreparationSourceLimit => &mut self.preparation_source_limit,
            SummaryProfileReason::PreparationRecursiveDependency => {
                &mut self.preparation_recursive_dependency
            }
            SummaryProfileReason::PreparationRepositoryFailure => {
                &mut self.preparation_repository_failure
            }
            SummaryProfileReason::PreparationSurface => &mut self.preparation_surface,
            SummaryProfileReason::LookupProcedure => &mut self.lookup_procedure,
            SummaryProfileReason::LookupSourceBehavior => &mut self.lookup_source_behavior,
            SummaryProfileReason::LookupSourcePartition => &mut self.lookup_source_partition,
            SummaryProfileReason::LookupEntry => &mut self.lookup_entry,
            SummaryProfileReason::LookupRelation => &mut self.lookup_relation,
            SummaryProfileReason::LookupLiveRemap => &mut self.lookup_live_remap,
            SummaryProfileReason::PublicationIncompleteResult => {
                &mut self.publication_incomplete_result
            }
            SummaryProfileReason::PublicationProjection => &mut self.publication_projection,
            SummaryProfileReason::PublicationEntry => &mut self.publication_entry,
            SummaryProfileReason::PublicationRelationShape => &mut self.publication_relation_shape,
            SummaryProfileReason::PublicationDispatchReads => &mut self.publication_dispatch_reads,
            SummaryProfileReason::PublicationReusedConflict => {
                &mut self.publication_reused_conflict
            }
            SummaryProfileReason::PublicationTransfer => &mut self.publication_transfer,
            SummaryProfileReason::PublicationDependency => &mut self.publication_dependency,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Workspace-owned in-memory state for the class-set summary dimension.
#[derive(Debug, Clone)]
pub struct TypeFlowSummaryState {
    semantic: Arc<ProductionSemanticSummaryRepository>,
    class_set: Arc<ClassSetSummaryRepository>,
    field_slots: FieldSlotIndexCache,
}

impl Default for TypeFlowSummaryState {
    fn default() -> Self {
        Self::with_semantic(Arc::new(ProductionSemanticSummaryRepository::new()))
    }
}

impl TypeFlowSummaryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_semantic(semantic: Arc<ProductionSemanticSummaryRepository>) -> Self {
        Self {
            semantic,
            class_set: Arc::new(ClassSetSummaryRepository::default()),
            field_slots: FieldSlotIndexCache::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn semantic(&self) -> &Arc<ProductionSemanticSummaryRepository> {
        &self.semantic
    }

    pub fn field_slot_indexes(&self) -> FieldSlotIndexCache {
        self.field_slots.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClassSetProcedureContract {
    carrier_semantics: StableDigest,
    direct_calls: StableDigest,
    field_slots: StableDigest,
    sources: Box<[(ValueFlowEventKey, ClassAtom)]>,
    sinks: Box<[ValueFlowEventKey]>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum StableEntryFact {
    Zero,
    Carrier {
        carrier: Box<ValueFlowCarrierKey>,
        uncertain: bool,
        source_partition: Option<StableDigest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum StableSource {
    Entry,
    Event(ValueFlowEventKey),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum StableValueFlowFact {
    Zero,
    Carrier {
        source: StableSource,
        carrier: ValueFlowCarrierKey,
        uncertain: bool,
    },
    Meeting {
        source: StableSource,
        sink: ValueFlowEventKey,
        uncertain: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClassSetSummaryLookupKey {
    procedure: ProcedureSummaryKey,
    procedure_locator: crate::analyzer::semantic::SemanticLocator,
    procedure_semantics: SummaryProcedureSemanticsKey,
    contract: ClassSetProcedureContract,
    entry: StableEntryFact,
    dispatch_reads: StableDigest,
    root_surface: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableEndSummary {
    exit_kind: ReturnTransferKind,
    exit_fact: StableValueFlowFact,
    qualities: Box<[PathQuality]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableReachedFact {
    point: ProgramPointId,
    fact: StableValueFlowFact,
    qualities: Box<[PathQuality]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FlattenedClassSetEntry {
    entry: SummaryEntry,
    reached: Box<[StableReachedFact]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassSetObservationProjectionError {
    MissingFact(FactId),
    MissingEntryPoint(ProgramPointId),
    MissingReachedPoint(ProgramPointId),
    MissingCallPoint(ProgramPointId),
    MissingCallSite,
    InvalidMeetingFact(FactId),
    EmptyQualityFrontier,
    EntryCycle,
}

/// Flatten every descendant meeting observation into each caller entry.
///
/// The summary solver keeps reached rows relative to the entry that owns their
/// procedure. Replaying a non-leaf summary skips those descendant rows, so a
/// reusable caller relation must carry each meeting as a caller-owned
/// observation. Entry transfers form the exact bridge: this processes their
/// DAG from callees to callers and rehomes an observation at each call point
/// while preserving its stable sink fact and conjoining the two realizable
/// path-quality frontiers.
///
fn project_flattened_class_set_observations(
    plan: &ValueFlowPlan,
    result: &SummaryDataflowResult<ValueFlowFact>,
) -> Result<Box<[FlattenedClassSetEntry]>, ClassSetObservationProjectionError> {
    let mut entries = result
        .reached()
        .iter()
        .map(|row| row.entry().clone())
        .chain(result.end_summaries().iter().map(|row| row.entry().clone()))
        .chain(
            result
                .entry_transfers()
                .iter()
                .flat_map(|transfer| [transfer.source().clone(), transfer.target().clone()]),
        )
        .collect::<Vec<_>>();
    entries.sort_unstable_by(compare_summary_entries);
    entries.dedup();

    let mut entry_ids = HashMap::default();
    for (index, entry) in entries.iter().enumerate() {
        validate_projection_entry(result, entry)?;
        entry_ids.insert(entry.clone(), index);
    }

    let mut observations =
        vec![HashMap::<(ProgramPointId, FactId), PathQualityFrontier>::default(); entries.len()];
    for row in result.reached() {
        validate_projection_point(
            row.entry(),
            row.point(),
            ClassSetObservationProjectionError::MissingReachedPoint,
        )?;
        let fact = projection_fact(result, row.fact())?;
        if fact.sink().is_none() {
            continue;
        }
        if row.path_qualities().is_empty() {
            return Err(ClassSetObservationProjectionError::EmptyQualityFrontier);
        }
        let entry = entry_ids[row.entry()];
        merge_projection_frontier(
            observations[entry]
                .entry((row.point().id(), row.fact()))
                .or_default(),
            row.path_qualities(),
        );
    }

    let mut children = vec![Vec::<usize>::new(); entries.len()];
    let mut transfers_by_target = vec![Vec::<usize>::new(); entries.len()];
    for (index, transfer) in result.entry_transfers().iter().enumerate() {
        validate_projection_entry(result, transfer.source())?;
        validate_projection_entry(result, transfer.target())?;
        projection_fact(result, transfer.call_fact())?;
        validate_projection_point(
            transfer.source(),
            transfer.call_point(),
            ClassSetObservationProjectionError::MissingCallPoint,
        )?;
        if transfer
            .source()
            .procedure()
            .call_site_handle(transfer.origin().id())
            .as_ref()
            != Some(transfer.origin())
        {
            return Err(ClassSetObservationProjectionError::MissingCallSite);
        }
        if transfer.path_qualities().is_empty() {
            return Err(ClassSetObservationProjectionError::EmptyQualityFrontier);
        }
        let source = entry_ids[transfer.source()];
        let target = entry_ids[transfer.target()];
        children[source].push(target);
        transfers_by_target[target].push(index);
    }
    for targets in &mut children {
        targets.sort_unstable();
        targets.dedup();
    }
    let mut parents = vec![Vec::<usize>::new(); entries.len()];
    for (source, targets) in children.iter().enumerate() {
        for &target in targets {
            parents[target].push(source);
        }
    }
    for sources in &mut parents {
        sources.sort_unstable();
        sources.dedup();
    }

    let mut remaining_children = children.iter().map(Vec::len).collect::<Vec<_>>();
    let mut ready = remaining_children
        .iter()
        .enumerate()
        .filter_map(|(entry, &remaining)| (remaining == 0).then_some(Reverse(entry)))
        .collect::<BinaryHeap<_>>();
    let mut processed = 0usize;
    while let Some(Reverse(target)) = ready.pop() {
        processed = processed.saturating_add(1);
        let mut target_observations = observations[target]
            .iter()
            .map(|(&(point, fact), &qualities)| (point, fact, qualities))
            .collect::<Vec<_>>();
        target_observations.sort_unstable_by_key(|(point, fact, _)| (*point, *fact));
        for &transfer_index in &transfers_by_target[target] {
            let transfer = &result.entry_transfers()[transfer_index];
            let source = entry_ids[transfer.source()];
            for &(_, fact, qualities) in &target_observations {
                let combined = transfer.path_qualities().conjoin(qualities);
                if combined.is_empty() {
                    continue;
                }
                merge_projection_frontier(
                    observations[source]
                        .entry((transfer.call_point().id(), fact))
                        .or_default(),
                    combined,
                );
            }
        }
        for &source in &parents[target] {
            remaining_children[source] = remaining_children[source]
                .checked_sub(1)
                .expect("a projection parent is released once per unique child");
            if remaining_children[source] == 0 {
                ready.push(Reverse(source));
            }
        }
    }
    if processed != entries.len() {
        return Err(ClassSetObservationProjectionError::EntryCycle);
    }

    let mut flattened = Vec::with_capacity(entries.len());
    for (entry, live_rows) in entries.into_iter().zip(observations) {
        let entry_source = projection_fact(result, entry.entry_fact())?.source();
        let mut stable_rows =
            HashMap::<(ProgramPointId, StableValueFlowFact), PathQualityFrontier>::default();
        for ((point, fact_id), qualities) in live_rows {
            let fact = projection_fact(result, fact_id)?;
            let Some(stable) = stable_fact(plan, fact, entry_source) else {
                return Err(ClassSetObservationProjectionError::InvalidMeetingFact(
                    fact_id,
                ));
            };
            merge_projection_frontier(stable_rows.entry((point, stable)).or_default(), qualities);
        }
        let mut reached = stable_rows
            .into_iter()
            .map(|((point, fact), qualities)| StableReachedFact {
                point,
                fact,
                qualities: qualities.iter().collect(),
            })
            .collect::<Vec<_>>();
        reached.sort_unstable_by(|left, right| {
            left.point
                .cmp(&right.point)
                .then_with(|| left.fact.cmp(&right.fact))
                .then_with(|| compare_qualities(&left.qualities, &right.qualities))
        });
        flattened.push(FlattenedClassSetEntry {
            entry,
            reached: reached.into_boxed_slice(),
        });
    }
    Ok(flattened.into_boxed_slice())
}

fn validate_projection_entry(
    result: &SummaryDataflowResult<ValueFlowFact>,
    entry: &SummaryEntry,
) -> Result<(), ClassSetObservationProjectionError> {
    projection_fact(result, entry.entry_fact())?;
    if entry
        .procedure()
        .point_handle(entry.entry_point().id())
        .as_ref()
        != Some(entry.entry_point())
    {
        return Err(ClassSetObservationProjectionError::MissingEntryPoint(
            entry.entry_point().id(),
        ));
    }
    Ok(())
}

fn validate_projection_point(
    entry: &SummaryEntry,
    point: &crate::analyzer::semantic::ProgramPointHandle,
    missing: fn(ProgramPointId) -> ClassSetObservationProjectionError,
) -> Result<(), ClassSetObservationProjectionError> {
    if entry.procedure().point_handle(point.id()).as_ref() != Some(point) {
        return Err(missing(point.id()));
    }
    Ok(())
}

fn projection_fact(
    result: &SummaryDataflowResult<ValueFlowFact>,
    fact: FactId,
) -> Result<ValueFlowFact, ClassSetObservationProjectionError> {
    result
        .fact(fact)
        .copied()
        .ok_or(ClassSetObservationProjectionError::MissingFact(fact))
}

fn merge_projection_frontier(retained: &mut PathQualityFrontier, incoming: PathQualityFrontier) {
    for quality in incoming.iter() {
        retained.insert(quality);
    }
}

fn compare_summary_entries(left: &SummaryEntry, right: &SummaryEntry) -> Ordering {
    left.procedure()
        .artifact()
        .key()
        .cmp(right.procedure().artifact().key())
        .then_with(|| {
            left.procedure()
                .semantics()
                .locator()
                .cmp(right.procedure().semantics().locator())
        })
        .then_with(|| left.procedure().id().cmp(&right.procedure().id()))
        .then_with(|| {
            Arc::as_ptr(left.procedure().artifact())
                .cast::<()>()
                .cmp(&Arc::as_ptr(right.procedure().artifact()).cast::<()>())
        })
        .then_with(|| left.entry_point().id().cmp(&right.entry_point().id()))
        .then_with(|| left.entry_fact().cmp(&right.entry_fact()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassSetProcedureSummary {
    key: ClassSetSummaryLookupKey,
    exits: Box<[StableEndSummary]>,
    reached: Box<[StableReachedFact]>,
    dependencies: Box<[ClassSetRelationDependency]>,
    reads: Box<[ReadKey]>,
    output_digest: ClassSetSummaryOutputDigest,
}

struct ValidatedClassSetSummary {
    summary: Arc<ClassSetProcedureSummary>,
    publications: Vec<ValidatedClassSetPublication>,
}

enum ValidatedClassSetPublication {
    Runtime(Arc<ClassSetProcedureSummary>),
    Persisted(Arc<ClassSetProcedureSummary>),
}

struct PendingRootSummary {
    source_behaviors:
        HashMap<(ProcedureHandle, crate::value_flow::ValueFlowSourceId), StableDigest>,
    admission: Option<PendingRootSummaryAdmission>,
}

struct PendingRootSummaryAdmission {
    runtime_key: ClassSetRuntimeLookupKey,
    used_summary: Arc<ClassSetProcedureSummary>,
    publications: Vec<ValidatedClassSetPublication>,
}

/// Runtime dependency on the answer of one exact child entry relation.
///
/// The stable lineage and normalized entry selector locate the child's current
/// local relation. The output digest, rather than the child's semantic key,
/// lets an equal child answer remain usable after that child's key moves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ClassSetRelationDependency {
    procedure_lineage: StableDigest,
    entry_selector: StableDigest,
    entry: StableDependencyEntry,
    source_witnesses: Box<[StableDigest]>,
    output: ClassSetSummaryOutputDigest,
    consumed_lookup: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum StableDependencyEntry {
    Zero,
    Carrier {
        carrier: StableDigest,
        uncertain: bool,
        source_partition: Option<StableDigest>,
    },
}

fn compare_relation_dependencies(
    left: &ClassSetRelationDependency,
    right: &ClassSetRelationDependency,
) -> Ordering {
    left.procedure_lineage
        .cmp(&right.procedure_lineage)
        .then_with(|| left.entry_selector.cmp(&right.entry_selector))
        .then_with(|| left.entry.cmp(&right.entry))
        .then_with(|| left.output.cmp(&right.output))
        .then_with(|| left.consumed_lookup.cmp(&right.consumed_lookup))
}

fn relation_dependency_without_witnesses(
    left: &ClassSetRelationDependency,
    right: &ClassSetRelationDependency,
) -> bool {
    compare_relation_dependencies(left, right) == Ordering::Equal
}

fn has_same_runtime_semantic_publication(
    left: &ClassSetProcedureSummary,
    right: &ClassSetProcedureSummary,
) -> bool {
    class_set_runtime_lookup_key(&left.key) == class_set_runtime_lookup_key(&right.key)
        && left.exits == right.exits
        && left.reached == right.reached
        && left.reads == right.reads
        && left.dependencies.len() == right.dependencies.len()
        && left
            .dependencies
            .iter()
            .zip(&right.dependencies)
            .all(|(left, right)| {
                left.procedure_lineage == right.procedure_lineage
                    && left.entry_selector == right.entry_selector
                    && left.entry == right.entry
                    && left.output == right.output
            })
}

/// Runtime lookup independent of the common envelope's dependency keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClassSetRuntimeLookupKey {
    procedure: StableDigest,
    entry_selector: StableDigest,
    root_surface: StableDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassSetSummaryPersistence {
    Unavailable,
    Stored {
        published: bool,
        retained_write: bool,
    },
}

impl ClassSetSummaryPersistence {
    const fn retained_write(self) -> bool {
        matches!(
            self,
            Self::Stored {
                retained_write: true,
                ..
            }
        )
    }
}

#[derive(Debug, Default)]
struct ClassSetSummaryRepository {
    runtime: Mutex<HashMap<ClassSetRuntimeLookupKey, Arc<ClassSetProcedureSummary>>>,
    surfaces: Mutex<HashMap<StableDigest, Arc<ClassSetProcedureSurfaceRow>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeSummaryPublication {
    published: bool,
    retained_write: bool,
}

impl ClassSetSummaryRepository {
    fn get_runtime(&self, key: ClassSetRuntimeLookupKey) -> Option<Arc<ClassSetProcedureSummary>> {
        self.runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned()
    }

    fn contains_runtime_procedure(&self, procedure: StableDigest) -> bool {
        self.runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .any(|key| key.procedure == procedure)
    }

    fn runtime_snapshot(&self) -> Vec<Arc<ClassSetProcedureSummary>> {
        self.runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    fn publish_surface(&self, surface: ClassSetProcedureSurfaceRow) -> bool {
        let digest = StableDigest::from_array(*surface.surface_digest());
        let surface = Arc::new(surface);
        let mut surfaces = self
            .surfaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !surfaces.contains_key(&digest) && surfaces.len() >= MAX_CLASS_SET_SUMMARIES {
            return false;
        }
        let inserted = surfaces
            .get(&digest)
            .is_none_or(|existing| existing.as_ref() != surface.as_ref());
        surfaces.insert(digest, surface);
        inserted
    }

    fn runtime_surface_candidates(
        &self,
        key: &ClassSetProcedureSurfaceKey,
    ) -> Option<Vec<Arc<ClassSetProcedureSurfaceRow>>> {
        let surfaces = self
            .surfaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rows = surfaces
            .values()
            .filter(|surface| surface.header.key == *key)
            .cloned()
            .collect::<Vec<_>>();
        (rows.len() <= MAX_CLASS_SET_SURFACE_CANDIDATES).then_some(rows)
    }

    #[cfg(test)]
    fn publish(&self, summary: ClassSetProcedureSummary) -> bool {
        self.publish_tracked(summary).published
    }

    fn publish_tracked(&self, summary: ClassSetProcedureSummary) -> RuntimeSummaryPublication {
        assert_eq!(
            summary.key.dispatch_reads,
            read_set_digest(&summary.reads).digest(),
            "class-set summary reads match its exact in-memory key"
        );
        let summary = Arc::new(summary);
        let runtime_key = class_set_runtime_lookup_key(&summary.key);
        let mut runtime = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !runtime.contains_key(&runtime_key) && runtime.len() >= MAX_CLASS_SET_SUMMARIES {
            return RuntimeSummaryPublication {
                published: false,
                retained_write: false,
            };
        }
        let published = runtime
            .get(&runtime_key)
            .is_none_or(|existing| !has_same_runtime_semantic_publication(existing, &summary));
        let retained_write = runtime
            .get(&runtime_key)
            .is_none_or(|existing| existing.as_ref() != summary.as_ref());
        // Entry lookup is an owner-local mutable head. Exact dependency and
        // witness evidence validates the current relation before it replaces
        // an older answer under the same local key.
        runtime.insert(runtime_key, summary);
        RuntimeSummaryPublication {
            published,
            retained_write,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ClassSetCutManifest {
    expected_surfaces: HashMap<DurableProcedureKey, StableDigest>,
}

#[derive(Clone)]
enum ReplayedLexicalDescendants {
    /// Impact-sliced replay already materialized these children while proving
    /// that the current local surface still matches the stored digest.
    Ready(Vec<(ProcedureHandle, ValueFlowInput<ValueFlowSnapshot>)>),
    /// Exact-workspace provenance already binds these identities. Keep them
    /// lazy because the immediate lexical children of a cut root are acquired
    /// by ordinary discovery rather than mounted as mandatory descendants.
    ExactIdentities(Box<[ClassSetProcedureIdentityRow]>),
}

#[derive(Clone)]
struct ReplayedClassSetSurface {
    hydrated: HydratedProcedureSurface,
    call_descendants: Vec<(ProcedureHandle, ValueFlowInput<ValueFlowSnapshot>)>,
    lexical_descendants: ReplayedLexicalDescendants,
    surface_digest: StableDigest,
}

type ValidatedClassSetSurfaceClosure = (
    HydratedProcedureSurface,
    Vec<HydratedProcedureSurface>,
    HashMap<DurableProcedureKey, StableDigest>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZeroSummaryAvailability {
    Present,
    Absent,
    Indeterminate,
}

/// One bounded, indexed acquisition session for the selective plan attempts
/// within one type-flow feedback iteration.
pub(crate) struct ClassSetAcquisitionCuts<'workspace, 'provider> {
    workspace: &'workspace WorkspaceAnalyzer,
    provider: &'provider crate::value_flow::WorkspaceValueFlowProvider<'workspace>,
    repository: Arc<ClassSetSummaryRepository>,
    store: Option<Arc<AnalyzerStore>>,
    behavior: SummaryBehaviorKey,
    field_slots: StableDigest,
    validation_work: usize,
    replay_aborted: bool,
    disabled_cuts: HashSet<DurableProcedureKey>,
    pre_dispatch_attempted: HashSet<DurableProcedureKey>,
    manifest: ClassSetCutManifest,
    staged_expected_surfaces: Option<HashMap<DurableProcedureKey, StableDigest>>,
    hydrated_surfaces: Vec<HydratedProcedureSurface>,
    exact_identity_snapshots:
        HashMap<ClassSetProcedureIdentityRow, (ProcedureHandle, ValueFlowInput<ValueFlowSnapshot>)>,
    // One artifact key can have several partial materializations. Procedure
    // IDs are meaningful only with the exact row set that assigned them.
    exact_identity_lineage_indexes: HashMap<
        (SemanticArtifactKey, SemanticArtifactMaterializationId),
        HashMap<StableDigest, Option<ProcedureId>>,
    >,
    runtime_zero_surfaces: Option<HashSet<StableDigest>>,
    replayed_surfaces: HashMap<(DurableProcedureKey, StableDigest), Arc<ReplayedClassSetSurface>>,
}

impl<'workspace, 'provider> ClassSetAcquisitionCuts<'workspace, 'provider> {
    pub(crate) fn new(
        state: TypeFlowSummaryState,
        workspace: &'workspace WorkspaceAnalyzer,
        provider: &'provider crate::value_flow::WorkspaceValueFlowProvider<'workspace>,
        provider_behavior: IcfgProviderBehaviorIdentity,
        field_slots: &FieldSlotIndex,
        disabled_cuts: HashSet<DurableProcedureKey>,
    ) -> Self {
        let behavior = class_set_behavior(provider_behavior, field_slots.digest());
        Self {
            workspace,
            provider,
            repository: state.class_set,
            store: workspace.store().cloned(),
            behavior,
            field_slots: field_slots.digest(),
            validation_work: 0,
            replay_aborted: false,
            disabled_cuts,
            pre_dispatch_attempted: HashSet::default(),
            manifest: ClassSetCutManifest::default(),
            staged_expected_surfaces: None,
            hydrated_surfaces: Vec::new(),
            exact_identity_snapshots: HashMap::default(),
            exact_identity_lineage_indexes: HashMap::default(),
            runtime_zero_surfaces: None,
            replayed_surfaces: HashMap::default(),
        }
    }

    pub(crate) fn take_manifest(&mut self) -> ClassSetCutManifest {
        assert!(
            self.hydrated_surfaces.is_empty(),
            "discovery drains every accepted cut's hydrated surfaces"
        );
        assert!(
            self.staged_expected_surfaces.is_none(),
            "discovery accepts or discards every staged cut"
        );
        std::mem::take(&mut self.manifest)
    }

    pub(crate) fn disable_cut(&mut self, procedure: &ProcedureHandle) -> bool {
        self.disabled_cuts.insert(procedure.durable_key())
    }

    fn spend_validation_work(&mut self, request: &mut SemanticRequest<'_>, amount: usize) -> bool {
        self.validation_work = self.validation_work.saturating_add(amount);
        self.validation_work <= MAX_CLASS_SET_SUMMARY_ROWS
            && request
                .budget
                .charge(SemanticWork {
                    nested_entries: amount,
                    ..SemanticWork::uniform(0)
                })
                .is_ok()
    }

    fn surface_family_key(
        &self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
    ) -> Option<ClassSetProcedureSurfaceKey> {
        let identity = ProcedureSummaryIdentity::new(
            procedure.artifact().key().clone(),
            procedure.semantics().locator().declaration().clone(),
            SummarySchemaVersion::CURRENT,
            SummarySemanticsVersion::hash_bytes(CLASS_SET_SUMMARY_SEMANTICS),
            SummaryContextKey::hash_bytes(CLASS_SET_SUMMARY_CONTEXT),
            self.behavior,
            SummaryOrigin::Inferred,
        );
        Some(ClassSetProcedureSurfaceKey {
            procedure_lineage: *identity.read_lineage_fingerprint().as_bytes(),
            owner_rel_path: procedure.artifact().key().path().as_str().to_owned(),
            language: procedure.artifact().key().language().language(),
            schema_version: identity.schema().get(),
            local_structure_digest: *class_set_local_structure_digest(snapshot).ok()?.as_bytes(),
            behavior_read_digest: *self.behavior.read_bytes(),
        })
    }

    fn surface_candidates(
        &mut self,
        key: &ClassSetProcedureSurfaceKey,
        request: &mut SemanticRequest<'_>,
    ) -> Option<Vec<Arc<ClassSetProcedureSurfaceRow>>> {
        let mut rows = self.repository.runtime_surface_candidates(key)?;
        let runtime_rows_to_charge = rows.iter().try_fold(0usize, |total, surface| {
            total
                .checked_add(1)?
                .checked_add(surface.calls.len())?
                .checked_add(surface.calls.iter().try_fold(0usize, |count, call| {
                    count.checked_add(call.binding_statuses.len())
                })?)?
                .checked_add(
                    surface
                        .calls
                        .iter()
                        .try_fold(0usize, |count, call| count.checked_add(call.entered.len()))?,
                )?
                .checked_add(surface.lexical_children.len())?
                .checked_add(surface.reads.len())
        })?;
        if !self.spend_validation_work(request, runtime_rows_to_charge) {
            return None;
        }
        if let Some(store) = self.store.clone() {
            let candidates = match store
                .class_set_procedure_surface_candidates(key, MAX_CLASS_SET_SURFACE_CANDIDATES)
            {
                Ok(Some(candidates)) => candidates,
                Ok(None) => return None,
                Err(error) => {
                    self.workspace
                        .analyzer()
                        .record_query_failure(store_error_context(
                            error,
                            "loading class-set procedure surface candidates",
                        ));
                    return None;
                }
            };
            let rows_to_charge = candidates.iter().try_fold(0usize, |total, candidate| {
                total
                    .checked_add(1)?
                    .checked_add(candidate.call_count)?
                    .checked_add(candidate.binding_count)?
                    .checked_add(candidate.entered_count)?
                    .checked_add(candidate.lexical_child_count)?
                    .checked_add(candidate.read_count)
            })?;
            if !self.spend_validation_work(request, rows_to_charge) {
                return None;
            }
            for candidate in candidates {
                let row =
                    match store.class_set_procedure_surface_for_digest(candidate.surface_digest) {
                        Ok(Some(row)) => row,
                        Ok(None) => return None,
                        Err(error) => {
                            self.workspace
                                .analyzer()
                                .record_query_failure(store_error_context(
                                    error,
                                    "loading a class-set procedure surface",
                                ));
                            return None;
                        }
                    };
                if row.header != candidate.header
                    || row.calls.len() != candidate.call_count
                    || row.lexical_children.len() != candidate.lexical_child_count
                    || row.reads.len() != candidate.read_count
                    || row
                        .calls
                        .iter()
                        .map(|call| call.binding_statuses.len())
                        .sum::<usize>()
                        != candidate.binding_count
                    || row
                        .calls
                        .iter()
                        .map(|call| call.entered.len())
                        .sum::<usize>()
                        != candidate.entered_count
                {
                    return None;
                }
                rows.push(Arc::new(row));
            }
        }
        rows.sort_unstable_by_key(|surface| *surface.surface_digest());
        rows.dedup_by_key(|surface| *surface.surface_digest());
        (rows.len() <= MAX_CLASS_SET_SURFACE_CANDIDATES).then_some(rows)
    }

    fn acquire_snapshot(
        &mut self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Option<(ProcedureHandle, ValueFlowInput<ValueFlowSnapshot>)> {
        let procedure = self.provider.canonical_procedure(procedure);
        let outcome =
            match self
                .provider
                .procedure_snapshot(&procedure, &OracleCallContext::empty(), request)
            {
                Ok(outcome) => outcome,
                Err(_) => {
                    self.replay_aborted = true;
                    return None;
                }
            };
        let status = SemanticInputStatus::from_outcome(&outcome);
        if matches!(
            status,
            SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
        ) {
            self.replay_aborted = true;
            return None;
        }
        let Some(snapshot) = outcome.available_value().cloned() else {
            self.replay_aborted = true;
            return None;
        };
        Some((procedure, ValueFlowInput::new(snapshot, status)))
    }

    /// Rematerialize one exact stored procedure identity without asking the
    /// dispatch resolver to rediscover it. This route is used only when the
    /// surface's full provider behavior provenance equals the current
    /// workspace behavior, so the stored entered-target topology is already
    /// pinned to this exact analyzed file set, model set, hierarchy mode, and
    /// receiver-hint overlay.
    fn acquire_exact_identity(
        &mut self,
        identity: &ClassSetProcedureIdentityRow,
        request: &mut SemanticRequest<'_>,
    ) -> Option<(ProcedureHandle, ValueFlowInput<ValueFlowSnapshot>)> {
        if request.cancellation.is_cancelled() {
            self.replay_aborted = true;
            return None;
        }
        if let Some(retained) = self.exact_identity_snapshots.get(identity) {
            return Some(retained.clone());
        }
        let analyzer = self.workspace.analyzer();
        let file = ProjectFile::new(
            analyzer.project().root().to_path_buf(),
            Path::new(&identity.rel_path),
        );
        if file.language() != identity.language || !analyzer.is_analyzed(&file) {
            return None;
        }
        let outcome = match self.workspace.materialize_program_semantics(&file, request) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.replay_aborted = true;
                return None;
            }
        };
        let status = SemanticInputStatus::from_outcome(&outcome);
        if matches!(
            status,
            SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
        ) {
            self.replay_aborted = true;
            return None;
        }
        let artifact = outcome.available_value()?;
        if artifact.key().language().language() != identity.language
            || artifact.key().path().as_str() != identity.rel_path
            || artifact.key().public_fingerprint().as_bytes() != &identity.artifact_public_identity
            || artifact.key().revision().content().as_bytes() != &identity.artifact_content_identity
        {
            return None;
        }
        let index_key = (artifact.key().clone(), artifact.materialization_id());
        if !self.exact_identity_lineage_indexes.contains_key(&index_key) {
            // Publish only a complete scan. A cancelled or exhausted attempt
            // must rescan instead of observing a partial lineage index.
            let mut lineage_index = HashMap::default();
            for procedure in artifact.procedures() {
                if request.cancellation.is_cancelled()
                    || request
                        .budget
                        .charge(SemanticWork {
                            procedures: 1,
                            ..SemanticWork::uniform(0)
                        })
                        .is_err()
                {
                    self.replay_aborted = true;
                    return None;
                }
                let lineage = artifact
                    .key()
                    .procedure_lineage_fingerprint(procedure.locator().declaration());
                if let Some(existing) = lineage_index.get_mut(&lineage) {
                    *existing = None;
                } else {
                    lineage_index.insert(lineage, Some(procedure.id()));
                }
            }
            self.exact_identity_lineage_indexes
                .insert(index_key.clone(), lineage_index);
        }
        let procedure_id = self
            .exact_identity_lineage_indexes
            .get(&index_key)?
            .get(&StableDigest::from_array(identity.procedure_lineage))?
            .as_ref()
            .copied()?;
        let procedure = artifact.procedure_handle(procedure_id)?;
        let retained = self.acquire_snapshot(&procedure, request)?;
        if class_set_surface_identity_from_snapshot(&retained.0, &retained.1).as_ref()
            != Some(identity)
        {
            return None;
        }
        self.exact_identity_snapshots
            .insert(identity.clone(), retained.clone());
        Some(retained)
    }

    /// Reconstruct an identity-only descendant surface without replaying its
    /// dispatch and binding oracle calls. The exact behavior digest is
    /// provenance rather than semantic identity: a mismatching workspace uses
    /// `replay_surface` below and retains impact-sliced reuse.
    fn replay_exact_workspace_surface(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        candidate: &ClassSetProcedureSurfaceRow,
        request: &mut SemanticRequest<'_>,
    ) -> Option<ReplayedClassSetSurface> {
        if candidate.header.exact_behavior_digest != *self.behavior.as_bytes()
            || candidate.header.key != self.surface_family_key(procedure, snapshot)?
            || candidate.header.artifact_public_identity
                != *procedure.artifact().key().public_fingerprint().as_bytes()
            || candidate.header.artifact_content_identity
                != *procedure.artifact().key().revision().content().as_bytes()
            || candidate.calls.len() != procedure.semantics().call_sites().len()
        {
            return None;
        }
        let mut read_calls = HashSet::default();
        for read in &candidate.reads {
            let call = match procedure_dispatch_read_call(procedure, read, request) {
                Ok(Some((call, _))) => call,
                Ok(None) => return None,
                Err(_) => {
                    self.replay_aborted = true;
                    return None;
                }
            };
            if !read_calls.insert(call.id()) {
                return None;
            }
        }
        if read_calls.len() != candidate.calls.len() {
            return None;
        }
        let mut coverage_rows = Vec::with_capacity(candidate.calls.len());
        let mut call_descendants = Vec::new();
        for call in &candidate.calls {
            let call_id = crate::analyzer::semantic::CallSiteId::new(call.call_ordinal);
            if !read_calls.contains(&call_id) {
                return None;
            }
            let entered = call
                .entered
                .iter()
                .map(|identity| self.acquire_exact_identity(identity, request))
                .collect::<Option<Vec<_>>>()?;
            let dispatch = match call.dispatch {
                ClassSetProcedureSurfaceDispatchRow::Resolved { status, coverage } => {
                    DispatchStatus::Resolved {
                        status: class_set_surface_input_status(status),
                        coverage,
                    }
                }
                ClassSetProcedureSurfaceDispatchRow::Unavailable { status } => {
                    DispatchStatus::Unavailable {
                        status: class_set_surface_input_status(status),
                    }
                }
            };
            coverage_rows.push((
                call_id,
                CallSiteCoverage {
                    entered: entered
                        .iter()
                        .map(|(procedure, _)| procedure.clone())
                        .collect(),
                    has_uncovered_boundary: call.has_uncovered_boundary,
                    truncated: call.truncated,
                    complete_receiver_hint_refinable: call.complete_receiver_hint_refinable,
                    dispatch,
                    bindings: call
                        .binding_statuses
                        .iter()
                        .map(|status| BindingCoverage::Answered {
                            status: class_set_surface_input_status(*status),
                        })
                        .collect(),
                },
            ));
            call_descendants.extend(entered);
        }
        Some(ReplayedClassSetSurface {
            hydrated: HydratedProcedureSurface {
                procedure: procedure.clone(),
                snapshot: snapshot.clone(),
                coverage: coverage_rows,
                dispatch_reads: candidate.reads.clone().into_boxed_slice(),
                // Descendant bodies are mandatory summary cuts. Their stored
                // coverage already carries completeness; executable external
                // summary bindings are needed only for bodies that run.
                boundaries: Vec::new(),
            },
            call_descendants,
            lexical_descendants: ReplayedLexicalDescendants::ExactIdentities(
                candidate.lexical_children.clone().into_boxed_slice(),
            ),
            surface_digest: StableDigest::from_array(*candidate.surface_digest()),
        })
    }

    fn replay_surface(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        candidate: &ClassSetProcedureSurfaceRow,
        request: &mut SemanticRequest<'_>,
    ) -> Option<ReplayedClassSetSurface> {
        let current_key = self.surface_family_key(procedure, snapshot)?;
        if candidate.header.key != current_key
            || candidate.calls.len() != procedure.semantics().call_sites().len()
        {
            return None;
        }
        let mut coverage_rows = Vec::with_capacity(candidate.calls.len());
        let mut boundaries = Vec::new();
        let mut call_descendants = Vec::new();
        let mut calls_seen = HashSet::default();
        for read in &candidate.reads {
            let (call, expected_digest) =
                match procedure_dispatch_read_call(procedure, read, request) {
                    Ok(Some(addressed)) => addressed,
                    Ok(None) => return None,
                    Err(_) => {
                        self.replay_aborted = true;
                        return None;
                    }
                };
            if !calls_seen.insert(call.id()) {
                return None;
            }
            let outcome = match self.provider.resolve_call(&call, request) {
                Ok(outcome) => outcome,
                Err(_) => {
                    self.replay_aborted = true;
                    return None;
                }
            };
            if matches!(
                SemanticInputStatus::from_outcome(&outcome),
                SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
            ) {
                self.replay_aborted = true;
                return None;
            }
            if one_call_dispatch_answer_digest(&call, &outcome) != expected_digest {
                return None;
            }
            let dispatch_status = SemanticInputStatus::from_outcome(&outcome);
            let mut live = CallSiteCoverage {
                entered: Vec::new(),
                has_uncovered_boundary: false,
                truncated: false,
                complete_receiver_hint_refinable: false,
                dispatch: DispatchStatus::Unavailable {
                    status: dispatch_status,
                },
                bindings: Vec::new(),
            };
            if let Some(dispatch) = outcome.available_value() {
                live.has_uncovered_boundary = dispatch.boundaries().iter().any(|boundary| {
                    !matches!(
                        (&boundary.kind, &boundary.completeness),
                        (
                            DispatchBoundaryKind::External(Some(_)),
                            crate::analyzer::semantic::EvidenceCompleteness::Complete
                        )
                    )
                });
                live.truncated = dispatch
                    .boundaries()
                    .iter()
                    .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Truncated));
                live.complete_receiver_hint_refinable = dispatch.complete_receiver_hint_refinable();
                live.dispatch = DispatchStatus::Resolved {
                    status: dispatch_status,
                    coverage: dispatch.coverage(),
                };
                boundaries.extend(dispatch.boundaries().iter().cloned());
                let mut seen_targets = HashSet::default();
                for dispatch_candidate in dispatch.candidates() {
                    let target = dispatch_candidate.target();
                    if target.artifact().key().mount() != procedure.artifact().key().mount()
                        || !seen_targets.insert(target.durable_key())
                    {
                        continue;
                    }
                    let binding = match self.provider.call_bindings(
                        &call,
                        dispatch_candidate,
                        &OracleCallContext::empty(),
                        request,
                    ) {
                        Ok(binding) => binding,
                        Err(_) => {
                            self.replay_aborted = true;
                            return None;
                        }
                    };
                    let status = dispatch_status.merge(SemanticInputStatus::from_outcome(&binding));
                    if matches!(
                        status,
                        SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
                    ) {
                        self.replay_aborted = true;
                        return None;
                    }
                    live.bindings.push(BindingCoverage::Answered { status });
                    if binding.available_value().is_some() {
                        let (target, target_snapshot) = self.acquire_snapshot(target, request)?;
                        live.entered.push(target.clone());
                        call_descendants.push((target, target_snapshot));
                    }
                }
            }
            coverage_rows.push((call.id(), live));
        }
        if calls_seen.len() != procedure.semantics().call_sites().len() {
            return None;
        }
        coverage_rows.sort_unstable_by_key(|(call, _)| *call);
        let live_calls = coverage_rows
            .iter()
            .map(|(call, coverage)| {
                let binding_statuses = coverage
                    .bindings
                    .iter()
                    .map(|binding| match binding {
                        BindingCoverage::Answered { status } => class_set_surface_status(*status),
                        BindingCoverage::ProviderError { .. } => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                let entered = coverage
                    .entered
                    .iter()
                    .map(|target| {
                        call_descendants
                            .iter()
                            .find(|(descendant, _)| descendant == target)
                            .and_then(|(_, snapshot)| {
                                class_set_surface_identity_from_snapshot(target, snapshot)
                            })
                    })
                    .collect::<Option<Vec<_>>>()?;
                let dispatch = match coverage.dispatch {
                    DispatchStatus::Resolved { status, coverage } => {
                        ClassSetProcedureSurfaceDispatchRow::Resolved {
                            status: class_set_surface_status(status)?,
                            coverage,
                        }
                    }
                    DispatchStatus::Unavailable { status } => {
                        ClassSetProcedureSurfaceDispatchRow::Unavailable {
                            status: class_set_surface_status(status)?,
                        }
                    }
                    DispatchStatus::ProviderError { .. } => return None,
                };
                Some(ClassSetProcedureSurfaceCallRow {
                    call_ordinal: call.get(),
                    has_uncovered_boundary: coverage.has_uncovered_boundary,
                    truncated: coverage.truncated,
                    complete_receiver_hint_refinable: coverage.complete_receiver_hint_refinable,
                    dispatch,
                    binding_statuses,
                    entered,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let mut lexical_children = Vec::new();
        let mut lexical_descendants = Vec::new();
        for &id in procedure.artifact().lexical_children(procedure.id()) {
            let child = procedure.artifact().procedure_handle(id)?;
            let (child, child_snapshot) = self.acquire_snapshot(&child, request)?;
            lexical_children.push(class_set_surface_identity_from_snapshot(
                &child,
                &child_snapshot,
            )?);
            lexical_descendants.push((child, child_snapshot));
        }
        let replayed = match ClassSetProcedureSurfaceRow::try_new(
            candidate.header.clone(),
            live_calls,
            lexical_children,
            candidate.reads.clone(),
        ) {
            Ok(replayed) => replayed,
            Err(_) => {
                self.replay_aborted = true;
                return None;
            }
        };
        if replayed.surface_digest() != candidate.surface_digest() {
            return None;
        }
        Some(ReplayedClassSetSurface {
            hydrated: HydratedProcedureSurface {
                procedure: procedure.clone(),
                snapshot: snapshot.clone(),
                coverage: coverage_rows,
                dispatch_reads: candidate.reads.clone().into_boxed_slice(),
                boundaries,
            },
            call_descendants,
            lexical_descendants: ReplayedLexicalDescendants::Ready(lexical_descendants),
            surface_digest: StableDigest::from_array(*candidate.surface_digest()),
        })
    }

    fn replayed_surface(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        request: &mut SemanticRequest<'_>,
    ) -> Option<Arc<ReplayedClassSetSurface>> {
        let local_structure = class_set_local_structure_digest(snapshot).ok()?;
        let memo_key = (procedure.durable_key(), local_structure);
        if let Some(replayed) = self.replayed_surfaces.get(&memo_key) {
            return Some(Arc::clone(replayed));
        }
        if !self.spend_validation_work(request, 1) {
            return None;
        }
        let key = self.surface_family_key(procedure, snapshot)?;
        debug_assert_eq!(
            key.local_structure_digest,
            *local_structure.as_bytes(),
            "the acquisition memo and surface family use one local structure identity"
        );
        let candidates = self.surface_candidates(&key, request)?;
        self.replay_aborted = false;
        let mut selected = None;
        for candidate in &candidates {
            let surface = StableDigest::from_array(*candidate.surface_digest());
            // Every replayed descendant becomes a mandatory cut in this
            // attempt. Filter by executable Zero families before replay, so
            // surface-only history cannot either enter the closure or make
            // its one executable candidate appear ambiguous.
            match self.has_zero_summary_for_surface(surface, &candidate.header, request) {
                ZeroSummaryAvailability::Present => {}
                ZeroSummaryAvailability::Absent => continue,
                ZeroSummaryAvailability::Indeterminate => return None,
            }
            let replayed = if candidate.has_valid_exact_provenance()
                && candidate.header.exact_behavior_digest == *self.behavior.as_bytes()
            {
                self.replay_exact_workspace_surface(procedure, snapshot, candidate, request)
            } else {
                self.replay_surface(procedure, snapshot, candidate, request)
            };
            if let Some(replayed) = replayed
                && selected.replace(replayed).is_some()
            {
                return None;
            }
            if self.replay_aborted {
                return None;
            }
        }
        let selected = Arc::new(selected?);
        let previous = self.replayed_surfaces.insert(memo_key, selected.clone());
        assert!(
            previous.is_none(),
            "one local surface validation populates one acquisition memo entry"
        );
        Some(selected)
    }

    fn lexical_descendants(
        &mut self,
        replayed: &ReplayedClassSetSurface,
        request: &mut SemanticRequest<'_>,
    ) -> Option<Vec<(ProcedureHandle, ValueFlowInput<ValueFlowSnapshot>)>> {
        match &replayed.lexical_descendants {
            ReplayedLexicalDescendants::Ready(descendants) => Some(descendants.clone()),
            ReplayedLexicalDescendants::ExactIdentities(identities) => identities
                .iter()
                .map(|identity| self.acquire_exact_identity(identity, request))
                .collect(),
        }
    }

    fn validated_surface_closure(
        &mut self,
        root: &ProcedureHandle,
        root_snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        request: &mut SemanticRequest<'_>,
    ) -> Option<ValidatedClassSetSurfaceClosure> {
        let root_key = root.durable_key();
        let mut pending = vec![(root.clone(), root_snapshot.clone())];
        let mut seen = HashSet::default();
        let mut root_hydrated = None;
        let mut hydrated = Vec::new();
        let mut expected_surfaces = HashMap::default();
        while let Some((procedure, snapshot)) = pending.pop() {
            if self.disabled_cuts.contains(&procedure.durable_key()) {
                return None;
            }
            if request.cancellation.is_cancelled() || !seen.insert(procedure.durable_key()) {
                if request.cancellation.is_cancelled() {
                    return None;
                }
                continue;
            }
            let selected = self.replayed_surface(&procedure, &snapshot, request)?;
            if procedure.durable_key() == root_key {
                let previous = root_hydrated.replace(selected.hydrated.clone());
                assert!(previous.is_none(), "one closure has one root surface");
            } else {
                hydrated.push(selected.hydrated.clone());
            }
            let previous =
                expected_surfaces.insert(procedure.durable_key(), selected.surface_digest);
            assert!(
                previous.is_none(),
                "one closure traversal retains one expected surface per procedure"
            );
            pending.extend(selected.call_descendants.iter().cloned());
            if procedure.durable_key() != root_key {
                pending.extend(self.lexical_descendants(&selected, request)?);
            }
        }
        Some((root_hydrated?, hydrated, expected_surfaces))
    }

    fn stage_validated_cut(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        request: &mut SemanticRequest<'_>,
    ) -> Option<HydratedProcedureSurface> {
        assert!(
            self.staged_expected_surfaces.is_none() && self.hydrated_surfaces.is_empty(),
            "discovery resolves one staged cut before requesting another"
        );
        let (root, descendants, expected_surfaces) =
            self.validated_surface_closure(procedure, snapshot, request)?;
        self.staged_expected_surfaces = Some(expected_surfaces);
        self.hydrated_surfaces = descendants;
        Some(root)
    }

    fn has_zero_summary_for_surface(
        &mut self,
        surface: StableDigest,
        surface_header: &ClassSetProcedureSurfaceHeaderRow,
        request: &mut SemanticRequest<'_>,
    ) -> ZeroSummaryAvailability {
        if request.cancellation.is_cancelled() {
            return ZeroSummaryAvailability::Indeterminate;
        }
        if self.runtime_zero_surfaces.is_none() {
            let runtime = self.repository.runtime_snapshot();
            if !self.spend_validation_work(request, runtime.len()) {
                return ZeroSummaryAvailability::Indeterminate;
            }
            if request.cancellation.is_cancelled() {
                return ZeroSummaryAvailability::Indeterminate;
            }
            self.runtime_zero_surfaces = Some(
                runtime
                    .iter()
                    .filter(|summary| matches!(summary.key.entry, StableEntryFact::Zero))
                    .map(|summary| summary.key.root_surface)
                    .collect(),
            );
        }
        if self
            .runtime_zero_surfaces
            .as_ref()
            .expect("the runtime Zero index was initialized")
            .contains(&surface)
        {
            return ZeroSummaryAvailability::Present;
        }
        let Some(store) = self.store.clone() else {
            return ZeroSummaryAvailability::Absent;
        };
        if !self.spend_validation_work(request, 1) {
            return ZeroSummaryAvailability::Indeterminate;
        }
        let key = ClassSetSummaryFamilyKey {
            procedure_lineage: surface_header.key.procedure_lineage,
            owner_rel_path: surface_header.key.owner_rel_path.clone(),
            language: surface_header.key.language,
            schema_version: surface_header.key.schema_version,
            semantics_digest: *SummarySemanticsVersion::hash_bytes(CLASS_SET_SUMMARY_SEMANTICS)
                .as_bytes(),
            context_digest: *SummaryContextKey::hash_bytes(CLASS_SET_SUMMARY_CONTEXT).as_bytes(),
            behavior_read_digest: surface_header.key.behavior_read_digest,
            carrier_digest: surface_header.carrier_semantics_digest,
            field_slots_digest: *self.field_slots.as_bytes(),
            root_surface_digest: *surface.as_bytes(),
        };
        match store.class_set_summary_family_lookups(&key, MAX_CLASS_SET_SUMMARIES) {
            Ok(Some(rows)) => {
                if !self.spend_validation_work(request, rows.len())
                    || request.cancellation.is_cancelled()
                {
                    return ZeroSummaryAvailability::Indeterminate;
                }
                if rows.iter().any(|row| row.zero_entry) {
                    ZeroSummaryAvailability::Present
                } else {
                    ZeroSummaryAvailability::Absent
                }
            }
            Ok(None) => ZeroSummaryAvailability::Indeterminate,
            Err(error) => {
                self.workspace
                    .analyzer()
                    .record_query_failure(store_error_context(
                        error,
                        "loading a class-set summary family for a surface",
                    ));
                ZeroSummaryAvailability::Indeterminate
            }
        }
    }
}

impl ClosureCutDecider for ClassSetAcquisitionCuts<'_, '_> {
    fn pre_dispatch_cut(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        request: &mut SemanticRequest<'_>,
    ) -> Option<HydratedProcedureSurface> {
        if self.disabled_cuts.contains(&procedure.durable_key()) {
            return None;
        }
        self.pre_dispatch_attempted.insert(procedure.durable_key());
        self.stage_validated_cut(procedure, snapshot, request)
    }

    fn should_cut(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        _coverage: &HashMap<
            (DurableProcedureKey, crate::analyzer::semantic::CallSiteId),
            CallSiteCoverage,
        >,
        request: &mut SemanticRequest<'_>,
    ) -> bool {
        if self.disabled_cuts.contains(&procedure.durable_key())
            || self
                .pre_dispatch_attempted
                .contains(&procedure.durable_key())
        {
            return false;
        }
        self.stage_validated_cut(procedure, snapshot, request)
            .is_some()
    }

    fn take_hydrated_surfaces(&mut self) -> Vec<HydratedProcedureSurface> {
        std::mem::take(&mut self.hydrated_surfaces)
    }

    fn accept_staged_cut(&mut self) {
        let expected_surfaces = self
            .staged_expected_surfaces
            .take()
            .expect("an accepted cut has a staged surface manifest");
        self.manifest.expected_surfaces.extend(expected_surfaces);
    }

    fn discard_staged_cut(&mut self) {
        assert!(
            self.staged_expected_surfaces.take().is_some(),
            "a discarded cut has a staged surface manifest"
        );
        self.hydrated_surfaces.clear();
    }
}

#[derive(Debug, Clone)]
struct PreparedProcedureSummary {
    semantic: SemanticProcedureSummary,
    procedure_semantics: SummaryProcedureSemanticsKey,
    contract: ClassSetProcedureContract,
    publication_rank: usize,
    source_sensitive: bool,
    source_behavior: ValueFlowSourceBehaviorIdentity,
    source_behavior_dependencies: Box<[(StableDigest, ProcedureHandle)]>,
    entry_carriers: HashMap<[u8; 32], Option<ValueFlowCarrierKey>>,
}

fn push_semantic_input_status(digest: &mut LengthDelimitedDigest, status: SemanticInputStatus) {
    digest.push(status.label().as_bytes());
    match status {
        SemanticInputStatus::Unsupported { capability } => {
            digest.push(capability.label().as_bytes());
        }
        SemanticInputStatus::ExceededBudget { exceeded } => {
            digest.push(exceeded.dimension().label().as_bytes());
            digest.push(
                &u64::try_from(exceeded.limit())
                    .expect("semantic budget limit fits in u64")
                    .to_le_bytes(),
            );
            digest.push(
                &u64::try_from(exceeded.attempted())
                    .expect("semantic budget attempt fits in u64")
                    .to_le_bytes(),
            );
        }
        SemanticInputStatus::Complete
        | SemanticInputStatus::Ambiguous
        | SemanticInputStatus::Unknown
        | SemanticInputStatus::Unproven
        | SemanticInputStatus::Cancelled => {}
    }
}

fn push_call_coverage_contract(digest: &mut LengthDelimitedDigest, coverage: &CallSiteCoverage) {
    digest.push(&[u8::from(coverage.has_uncovered_boundary)]);
    digest.push(&[u8::from(coverage.truncated)]);
    digest.push(&[u8::from(coverage.complete_receiver_hint_refinable)]);
    match &coverage.dispatch {
        DispatchStatus::Resolved { status, coverage } => {
            digest.push(b"resolved");
            push_semantic_input_status(digest, *status);
            digest.push(coverage.label().as_bytes());
        }
        DispatchStatus::Unavailable { status } => {
            digest.push(b"unavailable");
            push_semantic_input_status(digest, *status);
        }
        DispatchStatus::ProviderError { detail } => {
            digest.push(b"provider-error");
            digest.push(detail.as_bytes());
        }
    }
}

fn call_coverage_is_summary_eligible(coverage: Option<&CallSiteCoverage>) -> bool {
    let Some(coverage) = coverage else {
        return false;
    };
    if coverage.truncated || coverage.bindings.len() < coverage.entered.len() {
        return false;
    }
    let dispatch_status = match coverage.dispatch {
        DispatchStatus::Resolved {
            coverage: crate::analyzer::semantic::CandidateCoverage::Truncated,
            ..
        } => return false,
        DispatchStatus::Resolved { status, .. } | DispatchStatus::Unavailable { status } => status,
        DispatchStatus::ProviderError { .. } => return false,
    };
    if matches!(
        dispatch_status,
        SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
    ) {
        return false;
    }
    coverage.bindings.iter().all(|binding| {
        matches!(
            binding,
            BindingCoverage::Answered { status }
                if !matches!(
                    status,
                    SemanticInputStatus::ExceededBudget { .. }
                        | SemanticInputStatus::Cancelled
                )
        )
    })
}

fn class_set_surface_status(
    status: SemanticInputStatus,
) -> Option<ClassSetProcedureSurfaceStatusRow> {
    match status {
        SemanticInputStatus::Complete => Some(ClassSetProcedureSurfaceStatusRow::Complete),
        SemanticInputStatus::Ambiguous => Some(ClassSetProcedureSurfaceStatusRow::Ambiguous),
        SemanticInputStatus::Unknown => Some(ClassSetProcedureSurfaceStatusRow::Unknown),
        SemanticInputStatus::Unsupported { capability } => {
            Some(ClassSetProcedureSurfaceStatusRow::Unsupported { capability })
        }
        SemanticInputStatus::Unproven => Some(ClassSetProcedureSurfaceStatusRow::Unproven),
        SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled => None,
    }
}

fn class_set_surface_input_status(
    status: ClassSetProcedureSurfaceStatusRow,
) -> SemanticInputStatus {
    match status {
        ClassSetProcedureSurfaceStatusRow::Complete => SemanticInputStatus::Complete,
        ClassSetProcedureSurfaceStatusRow::Ambiguous => SemanticInputStatus::Ambiguous,
        ClassSetProcedureSurfaceStatusRow::Unknown => SemanticInputStatus::Unknown,
        ClassSetProcedureSurfaceStatusRow::Unsupported { capability } => {
            SemanticInputStatus::Unsupported { capability }
        }
        ClassSetProcedureSurfaceStatusRow::Unproven => SemanticInputStatus::Unproven,
    }
}

fn class_set_surface_identity(
    plan: &TypeFlowPlan,
    procedure: &ProcedureHandle,
) -> Option<ClassSetProcedureIdentityRow> {
    let key = procedure.artifact().key();
    Some(ClassSetProcedureIdentityRow {
        procedure_lineage: *key
            .procedure_lineage_fingerprint(procedure.semantics().locator().declaration())
            .as_bytes(),
        rel_path: key.path().as_str().to_owned(),
        language: key.language().language(),
        artifact_public_identity: *key.public_fingerprint().as_bytes(),
        artifact_content_identity: *key.revision().content().as_bytes(),
        local_structure_digest: *plan.local_structure_digest(procedure)?.as_bytes(),
    })
}

fn class_set_surface_identity_from_snapshot(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowInput<ValueFlowSnapshot>,
) -> Option<ClassSetProcedureIdentityRow> {
    if snapshot.value().procedure().durable_key() != procedure.durable_key() {
        return None;
    }
    let key = procedure.artifact().key();
    Some(ClassSetProcedureIdentityRow {
        procedure_lineage: *key
            .procedure_lineage_fingerprint(procedure.semantics().locator().declaration())
            .as_bytes(),
        rel_path: key.path().as_str().to_owned(),
        language: key.language().language(),
        artifact_public_identity: *key.public_fingerprint().as_bytes(),
        artifact_content_identity: *key.revision().content().as_bytes(),
        local_structure_digest: *class_set_local_structure_digest(snapshot).ok()?.as_bytes(),
    })
}

fn class_set_procedure_surface(
    workspace: &WorkspaceAnalyzer,
    plan: &TypeFlowPlan,
    procedure: &ProcedureHandle,
    behavior: SummaryBehaviorKey,
    contract: &ClassSetProcedureContract,
) -> Result<Option<ClassSetProcedureSurfaceRow>, StoreError> {
    let Some(owner) = class_set_surface_identity(plan, procedure) else {
        return Ok(None);
    };
    let ProcedureDispatchReadContract::Complete(reads) = plan
        .dispatch_read_contract(&procedure.durable_key())
        .expect("a prepared procedure has a dispatch-read contract")
    else {
        return Ok(None);
    };
    let mut calls = Vec::with_capacity(procedure.semantics().call_sites().len());
    for semantic_call in procedure.semantics().call_sites() {
        let Some(coverage) = plan.coverage_of(procedure, semantic_call.id) else {
            return Ok(None);
        };
        if !call_coverage_is_summary_eligible(Some(coverage)) {
            return Ok(None);
        }
        let dispatch = match coverage.dispatch {
            DispatchStatus::Resolved { status, coverage } => {
                ClassSetProcedureSurfaceDispatchRow::Resolved {
                    status: class_set_surface_status(status)
                        .expect("eligible dispatch status is persistable"),
                    coverage,
                }
            }
            DispatchStatus::Unavailable { status } => {
                ClassSetProcedureSurfaceDispatchRow::Unavailable {
                    status: class_set_surface_status(status)
                        .expect("eligible dispatch status is persistable"),
                }
            }
            DispatchStatus::ProviderError { .. } => return Ok(None),
        };
        let binding_statuses = coverage
            .bindings
            .iter()
            .map(|binding| match binding {
                BindingCoverage::Answered { status } => class_set_surface_status(*status),
                BindingCoverage::ProviderError { .. } => None,
            })
            .collect::<Option<Vec<_>>>();
        let Some(binding_statuses) = binding_statuses else {
            return Ok(None);
        };
        let entered = coverage
            .entered
            .iter()
            .map(|target| class_set_surface_identity(plan, target))
            .collect::<Option<Vec<_>>>();
        let Some(entered) = entered else {
            return Ok(None);
        };
        calls.push(ClassSetProcedureSurfaceCallRow {
            call_ordinal: semantic_call.id.get(),
            has_uncovered_boundary: coverage.has_uncovered_boundary,
            truncated: coverage.truncated,
            complete_receiver_hint_refinable: coverage.complete_receiver_hint_refinable,
            dispatch,
            binding_statuses,
            entered,
        });
    }
    let lexical_children = procedure
        .artifact()
        .lexical_children(procedure.id())
        .iter()
        .map(|&id| procedure.artifact().procedure_handle(id))
        .map(|child| child.and_then(|child| class_set_surface_identity(plan, &child)))
        .collect::<Option<Vec<_>>>();
    let Some(lexical_children) = lexical_children else {
        return Ok(None);
    };
    let attachment = workspace
        .semantic_artifact_store_attachment(procedure.artifact().key())
        .map_err(|error| StoreError::new(format!("capturing class-set surface source: {error}")))?;
    let owner_blob_oid = attachment
        .as_ref()
        .map_or_else(|| "runtime-only".to_owned(), |row| row.blob_oid.clone());
    let identity = ProcedureSummaryIdentity::new(
        procedure.artifact().key().clone(),
        procedure.semantics().locator().declaration().clone(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(CLASS_SET_SUMMARY_SEMANTICS),
        SummaryContextKey::hash_bytes(CLASS_SET_SUMMARY_CONTEXT),
        behavior,
        SummaryOrigin::Inferred,
    );
    ClassSetProcedureSurfaceRow::try_new(
        ClassSetProcedureSurfaceHeaderRow {
            key: ClassSetProcedureSurfaceKey {
                procedure_lineage: *identity.read_lineage_fingerprint().as_bytes(),
                owner_rel_path: owner.rel_path,
                language: owner.language,
                schema_version: identity.schema().get(),
                local_structure_digest: owner.local_structure_digest,
                behavior_read_digest: *identity.behavior().read_bytes(),
            },
            owner_blob_oid,
            artifact_public_identity: owner.artifact_public_identity,
            artifact_content_identity: owner.artifact_content_identity,
            exact_behavior_digest: *identity.behavior().as_bytes(),
            carrier_semantics_digest: *contract.carrier_semantics.as_bytes(),
            direct_calls_digest: *contract.direct_calls.as_bytes(),
        },
        calls,
        lexical_children,
        reads.to_vec(),
    )
    .map(Some)
}

fn class_set_procedure_contract(
    plan: &TypeFlowPlan,
    field_slots: &FieldSlotIndex,
    procedure: &ProcedureHandle,
    carrier: &ValueFlowCarrierSummaryIdentity,
    identities: &HashMap<ProcedureHandle, ProcedureSummaryIdentity>,
    internal_source_owners: &HashMap<ValueFlowEventKey, crate::analyzer::semantic::SemanticLocator>,
) -> ClassSetProcedureContract {
    let value_flow = plan.value_flow();
    let mut direct_calls = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_CALL_CONTRACT);
    direct_calls.push(
        &u64::try_from(procedure.semantics().call_sites().len())
            .expect("semantic call-site count fits in u64")
            .to_le_bytes(),
    );
    for call in procedure.semantics().call_sites() {
        direct_calls.push(&call.id.get().to_le_bytes());
        let Some(coverage) = plan.coverage_of(procedure, call.id) else {
            direct_calls.push(b"missing-coverage");
            continue;
        };
        push_call_coverage_contract(&mut direct_calls, coverage);
        let mut entered = coverage
            .entered
            .iter()
            .map(|callee| {
                identities
                    .get(callee)
                    .expect("an eligible entered callee has summary identity")
            })
            .map(ProcedureSummaryIdentity::read_lineage_fingerprint)
            .collect::<Vec<_>>();
        entered.sort_unstable();
        entered.dedup();
        direct_calls.push(
            &u64::try_from(entered.len())
                .expect("entered callee count fits in u64")
                .to_le_bytes(),
        );
        for lineage in entered {
            direct_calls.push(lineage.as_bytes());
        }
        let mut bindings = coverage
            .bindings
            .iter()
            .map(|binding| {
                let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_BINDING_CONTRACT);
                match binding {
                    BindingCoverage::Answered { status } => {
                        digest.push(b"answered");
                        push_semantic_input_status(&mut digest, *status);
                    }
                    BindingCoverage::ProviderError { detail } => {
                        digest.push(b"provider-error");
                        digest.push(detail.as_bytes());
                    }
                }
                digest.finish()
            })
            .collect::<Vec<_>>();
        bindings.sort_unstable();
        direct_calls.push(
            &u64::try_from(bindings.len())
                .expect("binding coverage count fits in u64")
                .to_le_bytes(),
        );
        for binding in bindings {
            direct_calls.push(binding.as_bytes());
        }
    }
    let mut sources = value_flow
        .sources()
        .filter(|(_, source)| source.point().procedure() == procedure)
        .map(|(source, spec)| (spec.key().clone(), plan.atom(source).clone()))
        .collect::<Vec<_>>();
    sources.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut sinks = value_flow
        .sinks()
        .filter(|(_, sink)| sink.point().procedure() == procedure)
        .map(|(_, sink)| sink.key().clone())
        .collect::<Vec<_>>();
    sinks.sort_unstable();
    sinks.dedup();
    ClassSetProcedureContract {
        carrier_semantics: carrier
            .procedure_closure_fingerprint(procedure.semantics().locator(), internal_source_owners),
        field_slots: field_slots.digest(),
        direct_calls: direct_calls.finish(),
        sources: sources.into_boxed_slice(),
        sinks: sinks.into_boxed_slice(),
    }
}

/// Whether discovery supplied exact dispatch reads and complete entered-callee
/// bindings for every semantic call made by this procedure.
///
/// A stable open or unresolved boundary is part of a reusable procedure's
/// behavior: type flow seeds its call result with `Unknown(UnresolvedCall)`.
/// It remains eligible when the dispatch question and answer were fully
/// attributed. Missing/truncated coverage, provider errors, resource outcomes,
/// or any incomplete entered-callee binding still fail closed.
fn procedure_call_contract_is_complete(plan: &TypeFlowPlan, procedure: &ProcedureHandle) -> bool {
    if !matches!(
        plan.dispatch_read_contract(&procedure.durable_key()),
        Some(ProcedureDispatchReadContract::Complete(_))
    ) {
        return false;
    }
    procedure
        .semantics()
        .call_sites()
        .iter()
        .all(|call| call_coverage_is_summary_eligible(plan.coverage_of(procedure, call.id)))
}

/// Query-local live remapping over workspace-owned stable summary rows.
pub(crate) struct PreparedClassSetSummaries<'plan> {
    state: TypeFlowSummaryState,
    workspace: &'plan WorkspaceAnalyzer,
    store: Option<Arc<AnalyzerStore>>,
    type_plan: &'plan TypeFlowPlan,
    plan: &'plan ValueFlowPlan,
    procedures: HashMap<ProcedureHandle, PreparedProcedureSummary>,
    surfaces: HashMap<ProcedureHandle, ClassSetProcedureSurfaceRow>,
    mandatory_cut_surfaces: HashMap<DurableProcedureKey, StableDigest>,
    procedures_by_lineage: HashMap<StableDigest, Option<ProcedureHandle>>,
    source_behavior_cache:
        HashMap<(ProcedureHandle, crate::value_flow::ValueFlowSourceId), StableDigest>,
    source_witnesses: HashMap<[u8; 32], Option<crate::value_flow::ValueFlowSourceId>>,
    used: HashMap<ClassSetRuntimeLookupKey, Arc<ClassSetProcedureSummary>>,
    maintenance: SummaryMaintenanceMetrics,
    profile: TypeFlowSummaryProfile,
    retained_maintenance_writes: bool,
    retained_publication_writes: bool,
    preloaded_root_row: Option<(StableDigest, ClassSetSummaryRow)>,
    pending_root_summary: Option<PendingRootSummary>,
    root_observation_rejections: usize,
}

struct StagedSourceBehavior {
    source: crate::value_flow::ValueFlowSourceId,
    source_key: ValueFlowEventKey,
    procedures: Vec<ProcedureHandle>,
    work: usize,
}

enum RootObservationPreflight {
    Covered(Option<Box<ClassSetSummaryRow>>),
    Rejected,
    Absent,
    Indeterminate,
}

enum RootObservationCoverage {
    Complete,
    Missing,
    Unremappable,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SummaryMaintenanceMetrics {
    pub(crate) hits: usize,
    pub(crate) misses: usize,
    pub(crate) publications: usize,
}

impl<'plan> PreparedClassSetSummaries<'plan> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        state: TypeFlowSummaryState,
        workspace: &'plan WorkspaceAnalyzer,
        plan: &'plan TypeFlowPlan,
        field_slots: &FieldSlotIndex,
        provider_behavior: IcfgProviderBehaviorIdentity,
    ) -> Self {
        Self::new_with_cuts(
            state,
            workspace,
            plan,
            field_slots,
            provider_behavior,
            ClassSetCutManifest::default(),
        )
    }

    pub(crate) fn new_with_cuts(
        state: TypeFlowSummaryState,
        workspace: &'plan WorkspaceAnalyzer,
        plan: &'plan TypeFlowPlan,
        field_slots: &FieldSlotIndex,
        provider_behavior: IcfgProviderBehaviorIdentity,
        cuts: ClassSetCutManifest,
    ) -> Self {
        let value_flow = plan.value_flow();
        let mut entry_carriers = value_flow.summary_entry_carriers_by_procedure();
        let behavior = class_set_behavior(provider_behavior, field_slots.digest());
        let mut carrier_contracts = value_flow
            .carrier_summary_identities()
            .into_iter()
            .collect::<Vec<_>>();
        carrier_contracts.sort_unstable_by_key(|(procedure, _)| procedure.durable_key());
        let index_by_procedure = carrier_contracts
            .iter()
            .enumerate()
            .map(|(index, (procedure, _))| (procedure.clone(), index))
            .collect::<HashMap<_, _>>();
        let mut identities = Vec::with_capacity(carrier_contracts.len());
        for (procedure, _) in &carrier_contracts {
            identities.push(ProcedureSummaryIdentity::new(
                procedure.artifact().key().clone(),
                procedure.semantics().locator().declaration().clone(),
                SummarySchemaVersion::CURRENT,
                SummarySemanticsVersion::hash_bytes(CLASS_SET_SUMMARY_SEMANTICS),
                SummaryContextKey::hash_bytes(CLASS_SET_SUMMARY_CONTEXT),
                behavior,
                SummaryOrigin::Inferred,
            ));
        }
        let identities_by_procedure = carrier_contracts
            .iter()
            .map(|(procedure, _)| procedure.clone())
            .zip(identities.iter().cloned())
            .collect::<HashMap<_, _>>();
        let mut preparation_rejections = carrier_contracts
            .iter()
            .map(|(procedure, _)| {
                if plan.procedure_requires_source_refinement(procedure) {
                    Some(SummaryProfileReason::PreparationDependency)
                } else {
                    (!procedure_call_contract_is_complete(plan, procedure))
                        .then_some(SummaryProfileReason::PreparationCallContract)
                }
            })
            .collect::<Vec<_>>();
        let mut locally_complete = carrier_contracts
            .iter()
            .enumerate()
            .map(|(index, _)| preparation_rejections[index].is_none())
            .collect::<Vec<_>>();
        let mut dependencies = vec![Vec::<usize>::new(); carrier_contracts.len()];
        for (index, (procedure, _)) in carrier_contracts.iter().enumerate() {
            for callee in plan.summary_callees_of(procedure) {
                let Some(&callee_index) = index_by_procedure.get(callee) else {
                    locally_complete[index] = false;
                    preparation_rejections[index]
                        .get_or_insert(SummaryProfileReason::PreparationDependency);
                    continue;
                };
                dependencies[index].push(callee_index);
            }
            dependencies[index].sort_unstable();
            dependencies[index].dedup();
        }
        let mut dependents = vec![Vec::<usize>::new(); carrier_contracts.len()];
        for (caller, callees) in dependencies.iter().enumerate() {
            for &callee in callees {
                dependents[callee].push(caller);
            }
        }
        for callers in &mut dependents {
            callers.sort_unstable();
            callers.dedup();
        }
        let mut source_sensitive = carrier_contracts
            .iter()
            .map(|(_, carrier)| carrier.has_source_selective_edge_kills())
            .collect::<Vec<_>>();
        let source_owners = value_flow
            .sources()
            .filter_map(|(_, source)| {
                index_by_procedure
                    .get(source.point().procedure())
                    .copied()
                    .map(|index| {
                        (
                            source.key().clone(),
                            (
                                index,
                                source.point().procedure().semantics().locator().clone(),
                            ),
                        )
                    })
            })
            .collect::<HashMap<_, _>>();
        let mut requested_by_owner = HashMap::<usize, HashSet<usize>>::default();
        let mut requested_memberships = 0usize;
        let mut membership_limit_exhausted = false;
        for (caller, (_, carrier)) in carrier_contracts.iter().enumerate() {
            if membership_limit_exhausted {
                locally_complete[caller] = false;
                preparation_rejections[caller]
                    .get_or_insert(SummaryProfileReason::PreparationSourceLimit);
                continue;
            }
            let mut requested_owners = HashSet::default();
            let mut bounded = true;
            for source in carrier.edge_kill_sources() {
                if requested_memberships == MAX_CLASS_SET_SUMMARY_ROWS {
                    bounded = false;
                    membership_limit_exhausted = true;
                    break;
                }
                requested_memberships += 1;
                let Some((owner, _)) = source_owners.get(source) else {
                    continue;
                };
                requested_owners.insert(*owner);
            }
            if !bounded {
                locally_complete[caller] = false;
                preparation_rejections[caller]
                    .get_or_insert(SummaryProfileReason::PreparationSourceLimit);
                continue;
            }
            for owner in requested_owners {
                requested_by_owner.entry(owner).or_default().insert(caller);
            }
        }
        let mut internal_source_pairs = HashSet::default();
        let mut reachability_work = 0usize;
        let mut requested_by_owner = requested_by_owner.into_iter().collect::<Vec<_>>();
        requested_by_owner.sort_unstable_by_key(|(owner, _)| *owner);
        for (owner, requested_callers) in requested_by_owner {
            let mut pending = vec![owner];
            let mut ancestors = HashSet::default();
            let mut bounded = true;
            while let Some(current) = pending.pop() {
                if !ancestors.insert(current) {
                    continue;
                }
                reachability_work = reachability_work.saturating_add(1);
                if reachability_work > MAX_CLASS_SET_SUMMARY_ROWS {
                    bounded = false;
                    break;
                }
                reachability_work = reachability_work.saturating_add(dependents[current].len());
                if reachability_work > MAX_CLASS_SET_SUMMARY_ROWS {
                    bounded = false;
                    break;
                }
                pending.extend(dependents[current].iter().copied());
            }
            if bounded {
                for caller in requested_callers {
                    if ancestors.contains(&caller) {
                        internal_source_pairs.insert((caller, owner));
                    }
                }
            } else {
                for caller in requested_callers {
                    locally_complete[caller] = false;
                    preparation_rejections[caller]
                        .get_or_insert(SummaryProfileReason::PreparationSourceLimit);
                }
            }
        }

        let contracts = carrier_contracts
            .iter()
            .enumerate()
            .map(|(index, (procedure, carrier))| {
                if !locally_complete[index] {
                    return None;
                }
                let internal_source_owners = carrier
                    .edge_kill_sources()
                    .filter_map(|source| {
                        let (owner, locator) = source_owners.get(source)?;
                        internal_source_pairs
                            .contains(&(index, *owner))
                            .then(|| (source.clone(), locator.clone()))
                    })
                    .collect::<HashMap<_, _>>();
                Some(class_set_procedure_contract(
                    plan,
                    field_slots,
                    procedure,
                    carrier,
                    &identities_by_procedure,
                    &internal_source_owners,
                ))
            })
            .collect::<Vec<_>>();

        let mut procedures = HashMap::default();
        let mut semantic_rows = Vec::new();
        let mut components = Vec::new();
        let mut key_by_procedure = vec![None::<ProcedureSummaryKey>; carrier_contracts.len()];
        let mut remaining_dependencies = dependencies.iter().map(Vec::len).collect::<Vec<_>>();
        let mut ready = remaining_dependencies
            .iter()
            .enumerate()
            .filter_map(|(index, &remaining)| (remaining == 0).then_some(Reverse(index)))
            .collect::<BinaryHeap<_>>();
        while let Some(Reverse(index)) = ready.pop() {
            source_sensitive[index] |= dependencies[index]
                .iter()
                .any(|&callee| source_sensitive[callee]);
            let eligible = locally_complete[index]
                && dependencies[index]
                    .iter()
                    .all(|&callee| key_by_procedure[callee].is_some());
            if eligible {
                let contract = contracts[index]
                    .clone()
                    .expect("an eligible procedure has a local surface contract");
                let procedure_semantics = class_set_procedure_semantics_key(
                    &contract,
                    carrier_contracts[index].0.semantics().locator(),
                );
                let mut semantic_dependencies = dependencies[index]
                    .iter()
                    .filter_map(|&callee| key_by_procedure[callee].clone())
                    .map(SummaryDependencyKey::complete)
                    .collect::<Vec<_>>();
                semantic_dependencies.sort_unstable();
                semantic_dependencies.dedup();
                let key = ProcedureSummaryKey::try_new(
                    identities[index].clone(),
                    &semantic_dependencies,
                    None,
                )
                .expect("an acyclic class-set dependency closure is valid");
                let effects = semantic_dependencies
                    .iter()
                    .map(|dependency| {
                        let mut event =
                            LengthDelimitedDigest::new(b"bifrost-class-set-summary-call-effect-v1");
                        event.push(identities[index].fingerprint().as_bytes());
                        event.push(dependency.identity().fingerprint().as_bytes());
                        SummaryEffect::new(
                            SummaryEffectKey::Call {
                                event: SummaryEventKey::from_digest(event.finish()),
                                callee: Box::new(dependency.clone()),
                            },
                            Default::default(),
                        )
                    })
                    .collect();
                let semantic = SemanticProcedureSummary::try_new(
                    key.clone(),
                    Vec::new(),
                    effects,
                    semantic_dependencies,
                    SummaryCompleteness::Complete,
                )
                .expect("an acyclic class-set semantic summary is structurally valid");
                let publication_rank = semantic_rows.len();
                let procedure = carrier_contracts[index].0.clone();
                procedures.insert(
                    procedure,
                    PreparedProcedureSummary {
                        semantic: semantic.clone(),
                        procedure_semantics,
                        contract,
                        publication_rank,
                        source_sensitive: source_sensitive[index],
                        source_behavior: carrier_contracts[index].1.source_behavior_identity(),
                        source_behavior_dependencies: dependencies[index]
                            .iter()
                            .map(|&callee| {
                                (
                                    identities[callee].read_lineage_fingerprint(),
                                    carrier_contracts[callee].0.clone(),
                                )
                            })
                            .collect(),
                        entry_carriers: entry_carriers
                            .remove(&carrier_contracts[index].0)
                            .unwrap_or_default()
                            .into_vec()
                            .into_iter()
                            .fold(HashMap::default(), |mut carriers, carrier| {
                                insert_stable_key(
                                    &mut carriers,
                                    *procedure_local_carrier_fingerprint(
                                        &carrier,
                                        carrier_contracts[index].0.semantics().locator(),
                                    )
                                    .as_bytes(),
                                    carrier,
                                );
                                carriers
                            }),
                    },
                );
                key_by_procedure[index] = Some(key);
                semantic_rows.push(semantic);
                components.push(publication_rank..publication_rank + 1);
            } else if preparation_rejections[index].is_none() {
                preparation_rejections[index] = Some(SummaryProfileReason::PreparationDependency);
            }
            for &dependent in &dependents[index] {
                remaining_dependencies[dependent] = remaining_dependencies[dependent]
                    .checked_sub(1)
                    .expect("an entry-DAG dependent is released once per child");
                if remaining_dependencies[dependent] == 0 {
                    ready.push(Reverse(dependent));
                }
            }
        }

        for index in 0..carrier_contracts.len() {
            if key_by_procedure[index].is_none() && preparation_rejections[index].is_none() {
                preparation_rejections[index] =
                    Some(SummaryProfileReason::PreparationRecursiveDependency);
            }
        }

        let mut profile = TypeFlowSummaryProfile::default();
        for reason in preparation_rejections.into_iter().flatten() {
            profile.record(reason);
        }

        let retained_semantic_publication = if semantic_rows.is_empty() {
            false
        } else {
            match state
                .semantic
                .publish_components(&semantic_rows, &components)
            {
                Ok(SummaryPublicationOutcome::Inserted) => true,
                Ok(SummaryPublicationOutcome::AlreadyPresent) => false,
                Err(_) => {
                    for _ in 0..procedures.len() {
                        profile.record(SummaryProfileReason::PreparationRepositoryFailure);
                    }
                    procedures.clear();
                    // Component publication is not transactional: an earlier
                    // component can remain visible when a later one fails.
                    true
                }
            }
        };

        let mut procedures_by_lineage = HashMap::default();
        for (procedure, prepared) in &procedures {
            let lineage = prepared
                .semantic
                .key()
                .identity()
                .read_lineage_fingerprint();
            if let Some(existing) = procedures_by_lineage.get_mut(&lineage) {
                *existing = None;
            } else {
                procedures_by_lineage.insert(lineage, Some(procedure.clone()));
            }
        }

        let mut source_witnesses = HashMap::default();
        for (source, _) in value_flow.sources() {
            insert_stable_key(
                &mut source_witnesses,
                *source_witness_fingerprint(value_flow, source)
                    .expect("an indexed source has a source specification")
                    .as_bytes(),
                source,
            );
        }

        let surfaces = carrier_contracts
            .iter()
            .enumerate()
            .filter_map(|(index, (procedure, _))| {
                let contract = contracts[index].as_ref()?;
                match class_set_procedure_surface(workspace, plan, procedure, behavior, contract) {
                    Ok(Some(surface)) => Some((procedure.clone(), surface)),
                    Ok(None) => {
                        profile.record(SummaryProfileReason::PreparationSurface);
                        None
                    }
                    Err(error) => {
                        profile.record(SummaryProfileReason::PreparationSurface);
                        workspace.analyzer().record_query_failure(error);
                        None
                    }
                }
            })
            .collect();

        Self {
            state,
            workspace,
            store: workspace.store().cloned(),
            type_plan: plan,
            plan: value_flow,
            procedures,
            surfaces,
            mandatory_cut_surfaces: cuts.expected_surfaces,
            procedures_by_lineage,
            source_behavior_cache: HashMap::default(),
            source_witnesses,
            used: HashMap::default(),
            maintenance: SummaryMaintenanceMetrics::default(),
            profile,
            retained_maintenance_writes: false,
            retained_publication_writes: retained_semantic_publication,
            preloaded_root_row: None,
            pending_root_summary: None,
            root_observation_rejections: 0,
        }
    }

    #[cfg(test)]
    fn source_behavior_for(
        &mut self,
        procedure: &ProcedureHandle,
        source: crate::value_flow::ValueFlowSourceId,
    ) -> Option<StableDigest> {
        let root = (procedure.clone(), source);
        if let Some(behavior) = self.cached_source_behavior(&root) {
            return Some(behavior);
        }
        let staged = self.stage_source_behavior(procedure, source)?;
        self.commit_source_behavior(staged)?;
        self.cached_source_behavior(&root)
    }

    fn charged_source_behavior_for(
        &mut self,
        procedure: &ProcedureHandle,
        source: crate::value_flow::ValueFlowSourceId,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<StableDigest>, SolverTermination> {
        let root = (procedure.clone(), source);
        if let Some(behavior) = self.cached_source_behavior(&root) {
            return Ok(Some(behavior));
        }
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        let Some(staged) = self.stage_source_behavior(procedure, source) else {
            return Ok(None);
        };
        if let Some(termination) = request.reserve(SolverWork {
            flow_evaluations: staged.work,
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        if self.commit_source_behavior(staged).is_none() {
            return Ok(None);
        }
        Ok(self.cached_source_behavior(&root))
    }

    fn cached_source_behavior(
        &self,
        key: &(ProcedureHandle, crate::value_flow::ValueFlowSourceId),
    ) -> Option<StableDigest> {
        self.pending_root_summary
            .as_ref()
            .and_then(|pending| pending.source_behaviors.get(key))
            .or_else(|| self.source_behavior_cache.get(key))
            .copied()
    }

    fn stage_source_behavior(
        &self,
        procedure: &ProcedureHandle,
        source: crate::value_flow::ValueFlowSourceId,
    ) -> Option<StagedSourceBehavior> {
        let source_key = self.plan.source(source)?.key().clone();
        let mut stack = vec![(procedure.clone(), false)];
        let mut scheduled = HashSet::default();
        let mut procedures = Vec::new();
        let mut work = 0usize;
        while let Some((current, expanded)) = stack.pop() {
            let cache_key = (current.clone(), source);
            if self.cached_source_behavior(&cache_key).is_some() {
                continue;
            }
            let prepared = self.procedures.get(&current)?;
            if !prepared.source_sensitive {
                continue;
            }
            if !expanded {
                if !scheduled.insert(current.clone()) {
                    continue;
                }
                if self.source_behavior_count().saturating_add(scheduled.len())
                    > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES
                {
                    return None;
                }
                work = work
                    .checked_add(prepared.source_behavior.work_units())?
                    .checked_add(prepared.source_behavior_dependencies.len())?;
                if work > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES {
                    return None;
                }
                if stack
                    .len()
                    .checked_add(prepared.source_behavior_dependencies.len())?
                    > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES
                {
                    return None;
                }
                stack.push((current, true));
                for (_, child) in prepared.source_behavior_dependencies.iter().rev() {
                    if self
                        .procedures
                        .get(child)
                        .is_some_and(|child| child.source_sensitive)
                        && self
                            .cached_source_behavior(&(child.clone(), source))
                            .is_none()
                        && !scheduled.contains(child)
                    {
                        stack.push((child.clone(), false));
                    }
                }
                continue;
            }
            procedures.push(current);
        }
        if self.source_behavior_count().checked_add(procedures.len())?
            > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES
            || work > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES
        {
            return None;
        }
        Some(StagedSourceBehavior {
            source,
            source_key,
            procedures,
            work,
        })
    }

    fn source_behavior_count(&self) -> usize {
        self.source_behavior_cache.len().saturating_add(
            self.pending_root_summary
                .as_ref()
                .map_or(0, |pending| pending.source_behaviors.len()),
        )
    }

    fn commit_source_behavior(&mut self, staged: StagedSourceBehavior) -> Option<()> {
        let mut computed = HashMap::default();
        for current in &staged.procedures {
            let prepared = self.procedures.get(current)?;
            let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_SOURCE_BEHAVIOR);
            digest.push(
                prepared
                    .source_behavior
                    .fingerprint(current.semantics().locator(), &staged.source_key)
                    .as_bytes(),
            );
            digest.push(
                &u64::try_from(prepared.source_behavior_dependencies.len())
                    .expect("class-set child count fits in u64")
                    .to_le_bytes(),
            );
            for (lineage, child) in &prepared.source_behavior_dependencies {
                digest.push(lineage.as_bytes());
                if self.procedures.get(child)?.source_sensitive {
                    let behavior = computed
                        .get(child)
                        .copied()
                        .or_else(|| self.cached_source_behavior(&(child.clone(), staged.source)))?;
                    digest.push(behavior.as_bytes());
                } else {
                    digest.push(b"source-independent");
                }
            }
            computed.insert(current.clone(), digest.finish());
        }
        if let Some(pending) = self.pending_root_summary.as_mut() {
            for (procedure, behavior) in computed {
                pending
                    .source_behaviors
                    .insert((procedure, staged.source), behavior);
            }
        } else {
            for (procedure, behavior) in computed {
                self.source_behavior_cache
                    .insert((procedure, staged.source), behavior);
            }
        }
        Some(())
    }

    fn resolve_dependency_entry(
        &mut self,
        procedure: &ProcedureHandle,
        dependency: &ClassSetRelationDependency,
        parent_entry_source: Option<crate::value_flow::ValueFlowSourceId>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<
        Option<(
            StableEntryFact,
            Option<crate::value_flow::ValueFlowSourceId>,
        )>,
        SolverTermination,
    > {
        let Some(prepared) = self.procedures.get(procedure) else {
            return Ok(None);
        };
        let source_sensitive = prepared.source_sensitive;
        let Some(entry) = dependency_entry_fact(
            &dependency.entry,
            &prepared.entry_carriers,
            procedure.semantics().locator(),
        ) else {
            return Ok(None);
        };
        if stable_entry_fingerprint(&entry, procedure.semantics().locator())
            != dependency.entry_selector
        {
            return Ok(None);
        }
        if matches!(entry, StableEntryFact::Zero) {
            return Ok(dependency
                .source_witnesses
                .is_empty()
                .then_some((entry, None)));
        }
        if dependency.source_witnesses.is_empty() {
            return Ok(None);
        }
        if dependency.source_witnesses.len() > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES {
            return Ok(None);
        }
        if let Some(termination) = request.reserve(SolverWork {
            flow_evaluations: dependency.source_witnesses.len(),
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        let expected_partition = match &entry {
            StableEntryFact::Carrier {
                source_partition, ..
            } => *source_partition,
            StableEntryFact::Zero => unreachable!("zero entries returned above"),
        };
        if source_sensitive != expected_partition.is_some() {
            return Ok(None);
        }
        let mut representative = None;
        for witness in &dependency.source_witnesses {
            let source = if *witness == entry_source_witness_fingerprint() {
                let Some(source) = parent_entry_source else {
                    return Ok(None);
                };
                source
            } else {
                let Some(Some(source)) = self.source_witnesses.get(witness.as_bytes()).copied()
                else {
                    return Ok(None);
                };
                source
            };
            if source_sensitive
                && self.charged_source_behavior_for(procedure, source, request)?
                    != expected_partition
            {
                return Ok(None);
            }
            representative.get_or_insert(source);
        }
        Ok(Some((entry, representative)))
    }

    fn maintenance_entry_fact(
        &mut self,
        entry: &StableEntryFact,
        source: Option<crate::value_flow::ValueFlowSourceId>,
    ) -> Option<ValueFlowFact> {
        let StableEntryFact::Carrier {
            carrier, uncertain, ..
        } = entry
        else {
            return Some(ValueFlowFact::zero());
        };
        Some(ValueFlowFact::carrier_fact(
            source?,
            self.plan.carrier_id_for_key(carrier)?,
            ValueFlowUncertainty::from_semantic_uncertainty(*uncertain),
        ))
    }

    fn dependencies_are_live(
        &mut self,
        dependencies: &[ClassSetRelationDependency],
        parent_rank: usize,
        parent_entry_source: Option<crate::value_flow::ValueFlowSourceId>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<bool, SolverTermination> {
        for dependency in dependencies {
            let Some(child) = self
                .procedures_by_lineage
                .get(&dependency.procedure_lineage)
                .and_then(Option::as_ref)
                .cloned()
            else {
                return Ok(false);
            };
            if self
                .procedures
                .get(&child)
                .is_none_or(|prepared| prepared.publication_rank >= parent_rank)
                || self
                    .resolve_dependency_entry(&child, dependency, parent_entry_source, request)?
                    .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn has_reusable_rows(&mut self) -> bool {
        if self.type_plan.has_summary_cuts() {
            return true;
        }
        let root = self.plan.root();
        if let Some(key) = self.lookup_key(root, StableEntryFact::Zero) {
            if self
                .state
                .class_set
                .get_runtime(class_set_runtime_lookup_key(&key))
                .is_some()
            {
                return true;
            }
            if let Some(store) = &self.store {
                let lookup = class_set_lookup_fingerprint(&key);
                match store.class_set_summary_for_digest(*lookup.as_bytes()) {
                    Ok(Some(row)) => {
                        self.preloaded_root_row = Some((lookup, row));
                        return true;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.workspace
                            .analyzer()
                            .record_query_failure(store_error_context(
                                error,
                                "probing an exact persisted root class-set summary",
                            ));
                    }
                }
            }
        }
        self.plan.bound_callees().any(|procedure| {
            if procedure == root {
                return false;
            }
            let Some(prepared) = self.procedures.get(procedure) else {
                return false;
            };
            if self.state.class_set.contains_runtime_procedure(
                prepared
                    .semantic
                    .key()
                    .identity()
                    .procedure_read_fingerprint(prepared.procedure_semantics),
            ) {
                return true;
            }
            let Some(store) = &self.store else {
                return false;
            };
            match store.contains_class_set_summary_procedure(
                *prepared
                    .semantic
                    .key()
                    .identity()
                    .read_lineage_fingerprint()
                    .as_bytes(),
            ) {
                Ok(present) => present,
                Err(error) => {
                    self.workspace
                        .analyzer()
                        .record_query_failure(store_error_context(
                            error,
                            "probing persisted class-set summaries",
                        ));
                    false
                }
            }
        })
    }

    pub(crate) const fn maintenance_metrics(&self) -> SummaryMaintenanceMetrics {
        self.maintenance
    }

    pub(crate) const fn profile(&self) -> TypeFlowSummaryProfile {
        self.profile
    }

    pub(crate) const fn retained_maintenance_writes(&self) -> bool {
        self.retained_maintenance_writes
    }

    pub(crate) const fn root_observation_rejections(&self) -> usize {
        self.root_observation_rejections
    }

    pub(crate) fn take_retained_publication_writes(&mut self) -> bool {
        std::mem::take(&mut self.retained_publication_writes)
    }

    pub(crate) fn finish_maintenance_publications(&mut self) {
        self.retained_maintenance_writes |= self.take_retained_publication_writes();
    }

    pub(crate) fn prepare_fallback_after_maintenance(&mut self) {
        // A failed closure-wide attempt may already have published complete,
        // validated descendant rows or rebound equal-output dependency
        // evidence. Those monotonic cache improvements stay retained and
        // their work stays charged; only the internal reads from the abandoned
        // exact-entry solve must not influence the ordinary root trial.
        self.used.clear();
    }

    /// Refresh the persisted entry DAG reachable from this exact root before
    /// the ordinary root trial consults it.
    ///
    /// The retained root row defines the demand boundary. Old child lookups
    /// are followed only inside that closure; reverse-index answers are then
    /// intersected with the same set, so an edit never validates or mutates an
    /// unrelated stored summary. The current store query can still read
    /// unrelated reverse-index rows sharing the same callee lineage and entry;
    /// that full fanout is charged before filtering. Dirty entries are solved
    /// bottom-up against the already-built plan. An equal typed output merely
    /// rewrites the parent's consumed-child provenance and stops there. A
    /// changed output dirties the exact demanded parents, which are recomputed
    /// only after all lower-ranked children have stabilized.
    ///
    /// `false` is a conservative fallback request. Missing rows, ambiguous
    /// lineage, corrupt reverse evidence, cycles, cancellation, exhausted
    /// budgets, provider failures, and CAS conflicts all leave the ordinary
    /// root solve responsible for the answer.
    pub(crate) fn stabilize_demanded_closure<Provider>(
        &mut self,
        root: &ProcedureHandle,
        provider: &Provider,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> bool
    where
        Provider: IcfgProvider + ?Sized,
    {
        #[derive(Clone)]
        struct DemandNode {
            procedure: ProcedureHandle,
            entry: StableEntryFact,
            entry_source: Option<crate::value_flow::ValueFlowSourceId>,
            old_lookup: StableDigest,
            current_lookup: StableDigest,
            old_output: ClassSetSummaryOutputDigest,
            publication_rank: usize,
            parents: Vec<usize>,
            dirty: bool,
        }

        if request.cancellation.is_cancelled() {
            return false;
        }
        let Some(store) = self.store.clone() else {
            return true;
        };
        let Some(root_key) = self.lookup_key(root, StableEntryFact::Zero) else {
            return true;
        };
        let root_lookup = class_set_lookup_fingerprint(&root_key);
        let root_row = match store.class_set_summary_for_digest(*root_lookup.as_bytes()) {
            Ok(Some(row)) => row,
            Ok(None) => return true,
            Err(error) => {
                self.workspace
                    .analyzer()
                    .record_query_failure(store_error_context(
                        error,
                        "loading demanded class-set root summary",
                    ));
                return false;
            }
        };
        let Some(root_prepared) = self.procedures.get(root) else {
            return true;
        };
        let mut nodes = vec![DemandNode {
            procedure: root.clone(),
            entry: StableEntryFact::Zero,
            entry_source: None,
            old_lookup: root_lookup,
            current_lookup: root_lookup,
            old_output: root_row.output_digest(),
            publication_rank: root_prepared.publication_rank,
            parents: Vec::new(),
            dirty: false,
        }];
        let mut rows = vec![root_row];
        let root_identity = (
            root_prepared
                .semantic
                .key()
                .identity()
                .read_lineage_fingerprint(),
            stable_entry_fingerprint(&StableEntryFact::Zero, root.semantics().locator()),
        );
        let mut by_identity = HashMap::default();
        by_identity.insert(root_identity, 0usize);
        let mut cursor = 0usize;
        while cursor < nodes.len() {
            if request.cancellation.is_cancelled() {
                return false;
            }
            let parent_rank = nodes[cursor].publication_rank;
            let dependency_count = rows[cursor].dependencies.len();
            if request
                .reserve(SolverWork {
                    summary_applications: 1,
                    flow_evaluations: dependency_count,
                    ..SolverWork::default()
                })
                .is_some()
            {
                return false;
            }
            let dependencies = rows[cursor].dependencies.clone();
            for dependency in dependencies {
                let lineage = StableDigest::from_array(dependency.callee_procedure_lineage);
                let selector = StableDigest::from_array(dependency.callee_entry_selector_digest);
                let Some(child) = self
                    .procedures_by_lineage
                    .get(&lineage)
                    .and_then(Option::as_ref)
                    .cloned()
                else {
                    return false;
                };
                let Some(child_rank) = self
                    .procedures
                    .get(&child)
                    .map(|prepared| prepared.publication_rank)
                else {
                    return false;
                };
                if child_rank >= parent_rank {
                    return false;
                }
                let runtime_dependency = relation_dependency_from_row(&dependency);
                let (entry, entry_source) = match self.resolve_dependency_entry(
                    &child,
                    &runtime_dependency,
                    nodes[cursor].entry_source,
                    request,
                ) {
                    Ok(Some(entry)) => entry,
                    Ok(None) | Err(_) => return false,
                };
                let old_lookup = StableDigest::from_array(dependency.consumed_child_lookup_digest);
                let old_row = match store.class_set_summary_for_digest(*old_lookup.as_bytes()) {
                    Ok(Some(row)) => row,
                    Ok(None) => return false,
                    Err(error) => {
                        self.workspace
                            .analyzer()
                            .record_query_failure(store_error_context(
                                error,
                                "loading demanded class-set dependency",
                            ));
                        return false;
                    }
                };
                let Some(current_key) = self.lookup_key(&child, entry.clone()) else {
                    return false;
                };
                let current_lookup = class_set_lookup_fingerprint(&current_key);
                if old_row.header.key.procedure_lineage != dependency.callee_procedure_lineage
                    || old_row.output_digest() != dependency.expected_output_digest
                {
                    return false;
                }
                let identity = (lineage, selector);
                let child_index = if let Some(&index) = by_identity.get(&identity) {
                    if nodes[index].old_lookup != old_lookup {
                        return false;
                    }
                    index
                } else {
                    let index = nodes.len();
                    nodes.push(DemandNode {
                        procedure: child,
                        entry,
                        entry_source,
                        old_lookup,
                        current_lookup,
                        old_output: old_row.output_digest(),
                        publication_rank: child_rank,
                        parents: Vec::new(),
                        dirty: false,
                    });
                    rows.push(old_row);
                    by_identity.insert(identity, index);
                    index
                };
                nodes[child_index].parents.push(cursor);
            }
            cursor = cursor.saturating_add(1);
        }
        for node in &mut nodes {
            node.parents.sort_unstable();
            node.parents.dedup();
        }
        let demanded_by_lookup = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.old_lookup, index))
            .collect::<HashMap<_, _>>();
        if demanded_by_lookup.len() != nodes.len() {
            return false;
        }
        let mut order = (0..nodes.len()).collect::<Vec<_>>();
        order.sort_unstable_by_key(|&index| nodes[index].publication_rank);
        let mut stabilized =
            HashMap::<(StableDigest, StableDigest), Arc<ClassSetProcedureSummary>>::default();

        for index in order {
            if request.cancellation.is_cancelled() {
                return false;
            }
            let current_key = self
                .lookup_key(&nodes[index].procedure, nodes[index].entry.clone())
                .expect("a demanded prepared procedure retains its lookup key");
            debug_assert_eq!(
                class_set_lookup_fingerprint(&current_key),
                nodes[index].current_lookup
            );
            let reads = match self
                .type_plan
                .dispatch_read_contract(&nodes[index].procedure.durable_key())
            {
                Some(ProcedureDispatchReadContract::Complete(reads)) => reads.clone(),
                Some(ProcedureDispatchReadContract::Unattributed(_)) | None => return false,
            };
            let current =
                match store.class_set_summary_for_digest(*nodes[index].current_lookup.as_bytes()) {
                    Ok(Some(row)) => {
                        match restore_persisted_summary(self.plan, &current_key, &reads, row) {
                            Ok(summary) => {
                                let dependencies_live = match self.dependencies_are_live(
                                    &summary.dependencies,
                                    nodes[index].publication_rank,
                                    nodes[index].entry_source,
                                    request,
                                ) {
                                    Ok(live) => live,
                                    Err(_) => return false,
                                };
                                (dependencies_live
                                    && current_dependencies_match_stabilized(
                                        &summary,
                                        &rows[index].dependencies,
                                        &stabilized,
                                    ))
                                .then_some(summary)
                            }
                            Err(error) => {
                                self.workspace.analyzer().record_query_failure(
                                    store_error_context(
                                        error,
                                        "validating current demanded class-set summary",
                                    ),
                                );
                                return false;
                            }
                        }
                    }
                    Ok(None) => None,
                    Err(error) => {
                        self.workspace
                            .analyzer()
                            .record_query_failure(store_error_context(
                                error,
                                "loading current demanded class-set summary",
                            ));
                        return false;
                    }
                };
            let current = if let (false, Some(current)) = (nodes[index].dirty, current) {
                Arc::new(current)
            } else {
                if index == 0 {
                    continue;
                }
                let Some(entry_fact) =
                    self.maintenance_entry_fact(&nodes[index].entry, nodes[index].entry_source)
                else {
                    return false;
                };
                if self.type_plan.is_summary_cut(&nodes[index].procedure) {
                    // A cut surface deliberately has no outgoing discovery.
                    // Rooting maintenance there would bypass reusable lookup
                    // and execute an incomplete mounted body.
                    return false;
                }
                // Reusable-provider validation inside the solve can publish
                // validated runtime rows and rewrite persisted equal-output
                // evidence before the solve itself reports a miss, budget
                // stop, or provider error. Conservatively retain the outer
                // semantic charges before entering that mutating path.
                self.retained_maintenance_writes = true;
                let result = match solve_value_flow_entry_with_reusable_summaries(
                    &nodes[index].procedure,
                    entry_fact,
                    provider,
                    self,
                    self.plan,
                    semantic_budget,
                    request,
                ) {
                    Ok(result) => result,
                    Err(_) => return false,
                };
                let metrics = result.result().metrics();
                self.maintenance.hits = self
                    .maintenance
                    .hits
                    .saturating_add(metrics.reusable_summary_hits);
                self.maintenance.misses = self
                    .maintenance
                    .misses
                    .saturating_add(metrics.reusable_summary_misses);
                if !result.result().termination().is_fixed_point()
                    || result
                        .result()
                        .coverage()
                        .semantic_status()
                        .budget_exceeded()
                        .is_some()
                    || result.result().coverage().semantic_status()
                        == SemanticInputStatus::Cancelled
                    || metrics.reusable_summary_misses > 0
                {
                    return false;
                }
                let publications = self.publish_complete(&result, request);
                self.maintenance.publications =
                    self.maintenance.publications.saturating_add(publications);
                let runtime_key = class_set_runtime_lookup_key(&current_key);
                let Some(current) = self.state.class_set.get_runtime(runtime_key) else {
                    return false;
                };
                if current.key != current_key {
                    return false;
                }
                current
            };
            let current_identity = (
                current.key.procedure.identity().read_lineage_fingerprint(),
                stable_entry_fingerprint(&current.key.entry, &current.key.procedure_locator),
            );
            if stabilized
                .insert(current_identity, Arc::clone(&current))
                .is_some()
            {
                return false;
            }
            let output_changed = current.output_digest != nodes[index].old_output;
            let reverse = match store.class_set_summary_dependents_of_lineage_entry(
                *current
                    .key
                    .procedure
                    .identity()
                    .read_lineage_fingerprint()
                    .as_bytes(),
                *stable_entry_fingerprint(&current.key.entry, &current.key.procedure_locator)
                    .as_bytes(),
            ) {
                Ok(rows) => rows,
                Err(error) => {
                    self.workspace
                        .analyzer()
                        .record_query_failure(store_error_context(
                            error,
                            "loading demanded reverse class-set dependencies",
                        ));
                    return false;
                }
            };
            // The current store API scopes reverse evidence by callee
            // lineage and entry, but not by this root's demanded parent
            // lookups. Charge the full returned fanout before intersecting it
            // in memory. A future store-side demanded-lookup filter can make
            // the SQL read itself demand-bounded without a schema change.
            if request.cancellation.is_cancelled()
                || request
                    .reserve(SolverWork {
                        flow_evaluations: reverse.len(),
                        ..SolverWork::default()
                    })
                    .is_some()
            {
                return false;
            }
            let reverse = reverse
                .into_iter()
                .filter_map(|row| {
                    demanded_by_lookup
                        .get(&StableDigest::from_array(row.dependent_lookup_digest))
                        .copied()
                        .map(|parent| (parent, row))
                })
                .collect::<Vec<_>>();
            let parents = nodes[index].parents.clone();
            for parent in parents {
                let Some((_, evidence)) = reverse.iter().find(|(candidate, evidence)| {
                    *candidate == parent
                        && evidence.dependency.consumed_child_lookup_digest
                            == *nodes[index].old_lookup.as_bytes()
                }) else {
                    return false;
                };
                if output_changed {
                    nodes[parent].dirty = true;
                    continue;
                }
                if evidence.dependency.consumed_child_lookup_digest
                    == *nodes[index].current_lookup.as_bytes()
                {
                    continue;
                }
                match rebind_equal_output_dependency(
                    &store,
                    evidence,
                    nodes[index].current_lookup,
                    request.cancellation,
                ) {
                    Ok(replaced) => self.retained_maintenance_writes |= replaced,
                    Err(error) => {
                        self.workspace
                            .analyzer()
                            .record_query_failure(store_error_context(
                                error,
                                "rebinding equal-output class-set dependency",
                            ));
                        return false;
                    }
                }
            }
        }
        true
    }

    fn lookup_key(
        &self,
        procedure: &ProcedureHandle,
        entry: StableEntryFact,
    ) -> Option<ClassSetSummaryLookupKey> {
        let prepared = self.procedures.get(procedure)?;
        let surface = self.surfaces.get(procedure)?;
        let root_surface = StableDigest::from_array(*surface.surface_digest());
        if self.type_plan.is_summary_cut(procedure)
            && self
                .mandatory_cut_surfaces
                .get(&procedure.durable_key())
                .is_none_or(|expected| *expected != root_surface)
        {
            return None;
        }
        let ProcedureDispatchReadContract::Complete(reads) = self
            .type_plan
            .dispatch_read_contract(&procedure.durable_key())?
        else {
            return None;
        };
        Some(ClassSetSummaryLookupKey {
            procedure: prepared.semantic.key().clone(),
            procedure_locator: procedure.semantics().locator().clone(),
            procedure_semantics: prepared.procedure_semantics,
            contract: prepared.contract.clone(),
            entry,
            dispatch_reads: read_set_digest(reads).digest(),
            root_surface,
        })
    }

    fn runtime_lookup_key_for(
        &self,
        procedure: &ProcedureHandle,
        entry_selector: StableDigest,
    ) -> Option<ClassSetRuntimeLookupKey> {
        let prepared = self.procedures.get(procedure)?;
        let surface = self.surfaces.get(procedure)?;
        Some(ClassSetRuntimeLookupKey {
            procedure: prepared
                .semantic
                .key()
                .identity()
                .procedure_read_fingerprint(prepared.procedure_semantics),
            entry_selector,
            root_surface: StableDigest::from_array(*surface.surface_digest()),
        })
    }

    fn root_observation_coverage(
        &self,
        procedure: &ProcedureHandle,
        summary: &ClassSetProcedureSummary,
    ) -> RootObservationCoverage {
        if summary
            .exits
            .iter()
            .any(|row| live_fact(self.plan, &row.exit_fact, None).is_none())
        {
            return RootObservationCoverage::Unremappable;
        }
        let mut reached_sinks = HashSet::default();
        for row in &summary.reached {
            if procedure.point_handle(row.point).is_none() {
                return RootObservationCoverage::Unremappable;
            }
            let Some(fact) = live_fact(self.plan, &row.fact, None) else {
                return RootObservationCoverage::Unremappable;
            };
            if let Some(sink) = fact.sink() {
                reached_sinks.insert(sink);
            }
        }
        // `all` intentionally admits an empty sink universe: there is no
        // absent observation whose negative meaning must be reconstructed.
        if self
            .plan
            .sinks()
            .all(|(sink, _)| reached_sinks.contains(&sink))
        {
            RootObservationCoverage::Complete
        } else {
            RootObservationCoverage::Missing
        }
    }

    /// Decide whether an optional zero-entry root row observes every current
    /// sink before replay validation reserves solver work or publishes a
    /// rebound dependency closure. An absent exact row is also conclusive, so
    /// a cold root does not pay a second store lookup. Corrupt or otherwise
    /// indeterminate persisted rows continue through the ordinary validator,
    /// which owns their typed diagnostic and repair behavior.
    fn preflight_root_observations(
        &mut self,
        procedure: &ProcedureHandle,
        key: &ClassSetSummaryLookupKey,
    ) -> RootObservationPreflight {
        if let Some(summary) = self
            .state
            .class_set
            .get_runtime(class_set_runtime_lookup_key(key))
        {
            return match self.root_observation_coverage(procedure, &summary) {
                RootObservationCoverage::Complete => RootObservationPreflight::Covered(None),
                RootObservationCoverage::Missing => RootObservationPreflight::Rejected,
                RootObservationCoverage::Unremappable => RootObservationPreflight::Indeterminate,
            };
        }
        let Some(store) = &self.store else {
            return RootObservationPreflight::Absent;
        };
        let lookup = class_set_lookup_fingerprint(key);
        let row = match self.preloaded_root_row.take() {
            Some((preloaded_lookup, row)) if preloaded_lookup == lookup => row,
            Some((preloaded_lookup, _)) => {
                debug_assert_eq!(
                    preloaded_lookup, lookup,
                    "one plan has one exact root lookup"
                );
                return RootObservationPreflight::Indeterminate;
            }
            None => match store.class_set_summary_for_digest(*lookup.as_bytes()) {
                Ok(Some(row)) => row,
                Ok(None) => return RootObservationPreflight::Absent,
                Err(_) => return RootObservationPreflight::Indeterminate,
            },
        };
        let reads = match self
            .type_plan
            .dispatch_read_contract(&procedure.durable_key())
        {
            Some(ProcedureDispatchReadContract::Complete(reads)) => reads,
            Some(ProcedureDispatchReadContract::Unattributed(_)) | None => {
                return RootObservationPreflight::Indeterminate;
            }
        };
        let restored = match restore_persisted_summary(self.plan, key, reads, row.clone()) {
            Ok(summary) => summary,
            Err(_) => return RootObservationPreflight::Indeterminate,
        };
        match self.root_observation_coverage(procedure, &restored) {
            RootObservationCoverage::Complete => {
                RootObservationPreflight::Covered(Some(Box::new(row)))
            }
            RootObservationCoverage::Missing => RootObservationPreflight::Rejected,
            RootObservationCoverage::Unremappable => RootObservationPreflight::Indeterminate,
        }
    }

    /// Validate a runtime row and its output-addressed child closure against
    /// the current plan without recursive Rust calls. Rebound rows are staged
    /// until the complete requested closure validates, so an optional root
    /// miss cannot retain cache writes whose solver charge is rolled back.
    fn validated_runtime_summary(
        &mut self,
        procedure: &ProcedureHandle,
        key: &ClassSetSummaryLookupKey,
        entry_source: Option<crate::value_flow::ValueFlowSourceId>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ValidatedClassSetSummary>, SolverTermination> {
        #[derive(Clone)]
        struct Pending {
            procedure: ProcedureHandle,
            key: ClassSetRuntimeLookupKey,
            entry_source: Option<crate::value_flow::ValueFlowSourceId>,
            expanded: bool,
        }

        let root = class_set_runtime_lookup_key(key);
        let mut pending = vec![Pending {
            procedure: procedure.clone(),
            key: root,
            entry_source,
            expanded: false,
        }];
        let mut active = HashSet::default();
        let mut validated =
            HashMap::<ClassSetRuntimeLookupKey, Arc<ClassSetProcedureSummary>>::default();
        let mut publications = Vec::new();
        while let Some(row) = pending.pop() {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled);
            }
            if validated.contains_key(&row.key) {
                continue;
            }
            let publication_rank = match self.procedures.get(&row.procedure) {
                Some(prepared) => prepared.publication_rank,
                None => return Ok(None),
            };
            let summary = match self.state.class_set.get_runtime(row.key) {
                Some(summary) => summary,
                None => return Ok(None),
            };
            if class_set_runtime_lookup_key(&summary.key) != row.key {
                return Ok(None);
            }
            if !matches!(
                self.type_plan
                    .dispatch_read_contract(&row.procedure.durable_key()),
                Some(ProcedureDispatchReadContract::Complete(reads))
                    if reads.as_ref() == summary.reads.as_ref()
            ) {
                return Ok(None);
            }
            if !row.expanded
                && let Some(termination) = request.reserve(SolverWork {
                    summary_applications: 1,
                    flow_evaluations: summary.dependencies.len(),
                    ..SolverWork::default()
                })
            {
                return Err(termination);
            }
            if row.expanded {
                let Some(current_key) = self.lookup_key(&row.procedure, summary.key.entry.clone())
                else {
                    return Ok(None);
                };
                if class_set_runtime_lookup_key(&current_key) != row.key {
                    return Ok(None);
                }
                let mut rebound = summary.as_ref().clone();
                rebound.key = current_key;
                let mut dependencies = rebound.dependencies.into_vec();
                for dependency in &mut dependencies {
                    let Some(child) = self
                        .procedures_by_lineage
                        .get(&dependency.procedure_lineage)
                        .and_then(Option::as_ref)
                    else {
                        return Ok(None);
                    };
                    let child = child.clone();
                    let Some((entry, _)) = self.resolve_dependency_entry(
                        &child,
                        dependency,
                        row.entry_source,
                        request,
                    )?
                    else {
                        return Ok(None);
                    };
                    if self
                        .procedures
                        .get(&child)
                        .is_none_or(|prepared| prepared.publication_rank >= publication_rank)
                    {
                        return Ok(None);
                    }
                    let Some(child_key) =
                        self.runtime_lookup_key_for(&child, dependency.entry_selector)
                    else {
                        return Ok(None);
                    };
                    let Some(child_summary) = validated.get(&child_key) else {
                        return Ok(None);
                    };
                    if child_summary.output_digest != dependency.output {
                        return Ok(None);
                    }
                    if child_summary.key.entry != entry {
                        return Ok(None);
                    }
                    dependency.consumed_lookup = class_set_lookup_fingerprint(&child_summary.key);
                }
                let dependency_count = dependencies.len();
                dependencies.sort_unstable_by(compare_relation_dependencies);
                dependencies
                    .dedup_by(|left, right| relation_dependency_without_witnesses(left, right));
                if dependencies.len() != dependency_count {
                    return Ok(None);
                }
                rebound.dependencies = dependencies.into_boxed_slice();
                active.remove(&row.key);
                let rebound = Arc::new(rebound);
                publications.push(Arc::clone(&rebound));
                validated.insert(row.key, rebound);
                continue;
            }
            if !active.insert(row.key) {
                return Ok(None);
            }
            pending.push(Pending {
                expanded: true,
                ..row.clone()
            });
            for dependency in summary.dependencies.iter().rev() {
                let Some(child) = self
                    .procedures_by_lineage
                    .get(&dependency.procedure_lineage)
                    .and_then(Option::as_ref)
                else {
                    return Ok(None);
                };
                let child = child.clone();
                let Some((_, child_entry_source)) =
                    self.resolve_dependency_entry(&child, dependency, row.entry_source, request)?
                else {
                    return Ok(None);
                };
                if self
                    .procedures
                    .get(&child)
                    .is_none_or(|prepared| prepared.publication_rank >= publication_rank)
                {
                    return Ok(None);
                }
                let Some(key) = self.runtime_lookup_key_for(&child, dependency.entry_selector)
                else {
                    return Ok(None);
                };
                pending.push(Pending {
                    procedure: child,
                    key,
                    entry_source: child_entry_source,
                    expanded: false,
                });
            }
        }
        let Some(summary) = validated.remove(&root) else {
            return Ok(None);
        };
        if summary.key != *key {
            return Ok(None);
        }
        Ok(Some(ValidatedClassSetSummary {
            summary,
            publications: publications
                .into_iter()
                .map(ValidatedClassSetPublication::Runtime)
                .collect(),
        }))
    }

    /// Restore one exact persisted entry relation and its dependency closure.
    ///
    /// Every child is located by its stable lineage and entry selector, loaded
    /// through its current owner-local lookup, and checked for the expected
    /// typed output before any row becomes visible in the runtime repository.
    /// The recorded child lookup remains provenance and is
    /// rewritten after an equal-output child revision. The walk is iterative
    /// so a deep acyclic call chain cannot consume the Rust stack.
    fn validated_persisted_summary(
        &mut self,
        procedure: &ProcedureHandle,
        key: &ClassSetSummaryLookupKey,
        entry_source: Option<crate::value_flow::ValueFlowSourceId>,
        preloaded_root: Option<ClassSetSummaryRow>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ValidatedClassSetSummary>, SolverTermination> {
        #[derive(Clone)]
        struct Pending {
            procedure: ProcedureHandle,
            key: ClassSetSummaryLookupKey,
            entry_source: Option<crate::value_flow::ValueFlowSourceId>,
            expanded: bool,
        }

        let Some(store) = self.store.clone() else {
            return Ok(None);
        };
        let root_lookup = class_set_lookup_fingerprint(key);
        let mut pending = vec![Pending {
            procedure: procedure.clone(),
            key: key.clone(),
            entry_source,
            expanded: false,
        }];
        let mut loaded = HashMap::<StableDigest, ClassSetSummaryRow>::default();
        if let Some(row) = preloaded_root {
            loaded.insert(root_lookup, row);
        }
        let mut candidates = HashMap::<StableDigest, Arc<ClassSetProcedureSummary>>::default();
        let mut active = HashSet::default();
        let mut validated = HashMap::<StableDigest, Arc<ClassSetProcedureSummary>>::default();
        let mut publications = Vec::new();

        while let Some(frame) = pending.pop() {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled);
            }
            let lookup = class_set_lookup_fingerprint(&frame.key);
            if validated.contains_key(&lookup) {
                continue;
            }
            let Some(prepared) = self.procedures.get(&frame.procedure) else {
                return Ok(None);
            };
            let publication_rank = prepared.publication_rank;
            let semantic_dependencies = prepared.semantic.dependencies().to_vec();
            if frame.expanded {
                let Some(summary) = candidates.get(&lookup).cloned() else {
                    return Ok(None);
                };
                for dependency in &summary.dependencies {
                    let Some(child) = validated.get(&dependency.consumed_lookup) else {
                        return Ok(None);
                    };
                    if child.output_digest != dependency.output
                        || child.key.procedure.identity().read_lineage_fingerprint()
                            != dependency.procedure_lineage
                        || stable_entry_fingerprint(&child.key.entry, &child.key.procedure_locator)
                            != dependency.entry_selector
                    {
                        return Ok(None);
                    }
                }
                active.remove(&lookup);
                publications.push(Arc::clone(&summary));
                validated.insert(lookup, summary);
                continue;
            }
            if !active.insert(lookup) {
                return Ok(None);
            }

            let row = if let Some(row) = loaded.remove(&lookup) {
                row
            } else {
                match store.class_set_summary_for_digest(*lookup.as_bytes()) {
                    Ok(Some(row)) => row,
                    Ok(None) => return Ok(None),
                    Err(error) => {
                        self.workspace
                            .analyzer()
                            .record_query_failure(store_error_context(
                                error,
                                "loading persisted class-set summary",
                            ));
                        return Ok(None);
                    }
                }
            };
            let reads = match self
                .type_plan
                .dispatch_read_contract(&frame.procedure.durable_key())
            {
                Some(ProcedureDispatchReadContract::Complete(reads)) => reads.clone(),
                Some(ProcedureDispatchReadContract::Unattributed(_)) | None => return Ok(None),
            };
            if row.reads.iter().map(|read| &read.key).ne(reads.iter()) {
                return Ok(None);
            }
            let mut summary = match restore_persisted_summary(self.plan, &frame.key, &reads, row) {
                Ok(summary) => summary,
                Err(error) => {
                    self.workspace
                        .analyzer()
                        .record_query_failure(store_error_context(
                            error,
                            "validating persisted class-set summary",
                        ));
                    return Ok(None);
                }
            };
            let mut children = Vec::with_capacity(summary.dependencies.len());
            for dependency in &mut summary.dependencies {
                let Some(child) = self
                    .procedures_by_lineage
                    .get(&dependency.procedure_lineage)
                    .and_then(Option::as_ref)
                    .cloned()
                else {
                    return Ok(None);
                };
                let Some(child_rank) = self
                    .procedures
                    .get(&child)
                    .map(|prepared| prepared.publication_rank)
                else {
                    return Ok(None);
                };
                if child_rank >= publication_rank {
                    return Ok(None);
                }
                let Some((entry, child_entry_source)) =
                    self.resolve_dependency_entry(&child, dependency, frame.entry_source, request)?
                else {
                    return Ok(None);
                };
                let Some(child_key) = self.lookup_key(&child, entry) else {
                    return Ok(None);
                };
                if stable_entry_fingerprint(&child_key.entry, &child_key.procedure_locator)
                    != dependency.entry_selector
                    || !semantic_dependencies.iter().any(|candidate| {
                        matches!(
                            candidate,
                            SummaryDependencyKey::Complete(candidate)
                                if candidate.as_ref() == &child_key.procedure
                        )
                    })
                {
                    return Ok(None);
                }
                let current_lookup = class_set_lookup_fingerprint(&child_key);
                let current_child =
                    match store.class_set_summary_for_digest(*current_lookup.as_bytes()) {
                        Ok(Some(row)) => row,
                        Ok(None) => return Ok(None),
                        Err(error) => {
                            self.workspace
                                .analyzer()
                                .record_query_failure(store_error_context(
                                    error,
                                    "loading current class-set summary dependency",
                                ));
                            return Ok(None);
                        }
                    };
                dependency.consumed_lookup = current_lookup;
                if !validated.contains_key(&current_lookup) {
                    if let Some(existing) = loaded.insert(current_lookup, current_child) {
                        assert_eq!(
                            existing, loaded[&current_lookup],
                            "one persisted class-set lookup has one complete row"
                        );
                    }
                    children.push(Pending {
                        procedure: child,
                        key: child_key,
                        entry_source: child_entry_source,
                        expanded: false,
                    });
                }
            }
            let dependency_count = summary.dependencies.len();
            let mut dependencies = summary.dependencies.into_vec();
            dependencies.sort_unstable_by(compare_relation_dependencies);
            dependencies.dedup_by(|left, right| relation_dependency_without_witnesses(left, right));
            if dependencies.len() != dependency_count {
                return Ok(None);
            }
            summary.dependencies = dependencies.into_boxed_slice();
            if let Some(termination) = request.reserve(SolverWork {
                summary_applications: 1,
                flow_evaluations: summary.dependencies.len(),
                ..SolverWork::default()
            }) {
                return Err(termination);
            }
            let summary = Arc::new(summary);
            candidates.insert(lookup, Arc::clone(&summary));
            pending.push(Pending {
                expanded: true,
                ..frame.clone()
            });

            for child in children.into_iter().rev() {
                pending.push(child);
            }
        }

        let Some(root) = validated.remove(&root_lookup) else {
            return Ok(None);
        };
        Ok(Some(ValidatedClassSetSummary {
            summary: root,
            publications: publications
                .into_iter()
                .map(ValidatedClassSetPublication::Persisted)
                .collect(),
        }))
    }

    pub(crate) fn publish_complete(
        &mut self,
        result: &crate::value_flow::ValueFlowSummaryResult,
        request: &mut DataflowRequest<'_>,
    ) -> usize {
        if !result.result().termination().is_fixed_point()
            || result
                .result()
                .coverage()
                .semantic_status()
                .budget_exceeded()
                .is_some()
            || result.result().coverage().semantic_status() == SemanticInputStatus::Cancelled
        {
            self.profile
                .record(SummaryProfileReason::PublicationIncompleteResult);
            return 0;
        }
        let Ok(flattened) = project_flattened_class_set_observations(self.plan, result.result())
        else {
            self.profile
                .record(SummaryProfileReason::PublicationProjection);
            return 0;
        };
        self.publish_surfaces(request.cancellation);

        struct ProjectedEntry {
            entry: SummaryEntry,
            summary: ClassSetProcedureSummary,
            required_children: Vec<(usize, Option<StableDigest>)>,
            valid: bool,
            publication_rank: usize,
        }

        let mut projected = Vec::new();
        for flattened_entry in flattened {
            let entry = flattened_entry.entry;
            let Some(source_sensitive) = self
                .procedures
                .get(entry.procedure())
                .map(|prepared| prepared.source_sensitive)
            else {
                self.profile.record(SummaryProfileReason::PublicationEntry);
                continue;
            };
            let Some(entry_fact) = result.result().fact(entry.entry_fact()).copied() else {
                self.profile.record(SummaryProfileReason::PublicationEntry);
                continue;
            };
            let source_partition = match (source_sensitive, entry_fact.source()) {
                (true, Some(source)) => {
                    match self.charged_source_behavior_for(entry.procedure(), source, request) {
                        Ok(Some(behavior)) => Some(behavior),
                        Ok(None) => {
                            self.profile.record(SummaryProfileReason::PublicationEntry);
                            continue;
                        }
                        Err(_) => {
                            self.profile.record(SummaryProfileReason::PublicationEntry);
                            return 0;
                        }
                    }
                }
                _ => None,
            };
            let Some(stable_entry) = stable_entry_fact(self.plan, source_partition, entry_fact)
            else {
                self.profile.record(SummaryProfileReason::PublicationEntry);
                continue;
            };
            let prepared = self
                .procedures
                .get(entry.procedure())
                .expect("the projected procedure remains prepared");
            let entry_source = entry_fact.source();
            let mut exits = Vec::new();
            for row in result.result().summaries_for(&entry) {
                let Some(fact) = result.result().fact(row.exit_fact()).copied() else {
                    exits.clear();
                    break;
                };
                let Some(fact) = stable_fact(self.plan, fact, entry_source) else {
                    exits.clear();
                    break;
                };
                exits.push(StableEndSummary {
                    exit_kind: row.exit_kind(),
                    exit_fact: fact,
                    qualities: row.path_qualities().iter().collect(),
                });
            }
            exits.sort_unstable_by(|left, right| {
                return_kind_ordinal(left.exit_kind)
                    .cmp(&return_kind_ordinal(right.exit_kind))
                    .then_with(|| left.exit_fact.cmp(&right.exit_fact))
                    .then_with(|| compare_qualities(&left.qualities, &right.qualities))
            });
            if exits.is_empty()
                || exits.len().saturating_add(flattened_entry.reached.len())
                    > MAX_CLASS_SET_SUMMARY_ROWS
            {
                self.profile
                    .record(SummaryProfileReason::PublicationRelationShape);
                continue;
            }
            let Some(key) = self.lookup_key(entry.procedure(), stable_entry) else {
                self.profile.record(SummaryProfileReason::PublicationEntry);
                continue;
            };
            let reads = match self
                .type_plan
                .dispatch_read_contract(&entry.procedure().durable_key())
            {
                Some(ProcedureDispatchReadContract::Complete(reads)) => reads.clone(),
                Some(ProcedureDispatchReadContract::Unattributed(_)) | None => {
                    self.profile
                        .record(SummaryProfileReason::PublicationDispatchReads);
                    continue;
                }
            };
            let exits = exits.into_boxed_slice();
            let reached = flattened_entry.reached;
            let output_digest = class_set_output_digest(&key, &exits, &reached);
            projected.push(ProjectedEntry {
                summary: ClassSetProcedureSummary {
                    key,
                    exits,
                    reached,
                    dependencies: Box::default(),
                    reads,
                    output_digest,
                },
                entry,
                required_children: Vec::new(),
                valid: true,
                publication_rank: prepared.publication_rank,
            });
        }

        let entry_index = projected
            .iter()
            .enumerate()
            .map(|(index, projected)| (projected.entry.clone(), index))
            .collect::<HashMap<_, _>>();
        for row in &mut projected {
            let runtime_key = class_set_runtime_lookup_key(&row.summary.key);
            let Some(used) = self.used.get(&runtime_key) else {
                continue;
            };
            if used.key != row.summary.key
                || used.exits != row.summary.exits
                || used.reached != row.summary.reached
            {
                row.valid = false;
                continue;
            }
            row.summary.dependencies = used.dependencies.clone();
        }
        for transfer in result.result().entry_transfers() {
            let Some(&source) = entry_index.get(transfer.source()) else {
                continue;
            };
            let Some(&target) = entry_index.get(transfer.target()) else {
                projected[source].valid = false;
                self.profile
                    .record(SummaryProfileReason::PublicationTransfer);
                continue;
            };
            let Some(source_prepared) = self.procedures.get(transfer.source().procedure()) else {
                projected[source].valid = false;
                self.profile
                    .record(SummaryProfileReason::PublicationTransfer);
                continue;
            };
            let Some(target_prepared) = self.procedures.get(transfer.target().procedure()) else {
                projected[source].valid = false;
                self.profile
                    .record(SummaryProfileReason::PublicationTransfer);
                continue;
            };
            if !source_prepared
                .semantic
                .dependencies()
                .iter()
                .any(|dependency| {
                    matches!(
                        dependency,
                        SummaryDependencyKey::Complete(key)
                            if key.as_ref() == target_prepared.semantic.key()
                    )
                })
            {
                projected[source].valid = false;
                self.profile
                    .record(SummaryProfileReason::PublicationTransfer);
                continue;
            }
            let target_fact = result
                .result()
                .fact(transfer.target().entry_fact())
                .copied();
            let witness = match (&projected[target].summary.key.entry, target_fact) {
                (StableEntryFact::Zero, _) => None,
                (StableEntryFact::Carrier { .. }, Some(fact)) => {
                    let Some(source_id) = fact.source() else {
                        projected[source].valid = false;
                        self.profile
                            .record(SummaryProfileReason::PublicationTransfer);
                        continue;
                    };
                    let parent_entry_source = result
                        .result()
                        .fact(transfer.source().entry_fact())
                        .copied()
                        .and_then(ValueFlowFact::source);
                    let witness = if parent_entry_source == Some(source_id) {
                        Some(entry_source_witness_fingerprint())
                    } else {
                        source_witness_fingerprint(self.plan, source_id)
                    };
                    let Some(witness) = witness else {
                        projected[source].valid = false;
                        self.profile
                            .record(SummaryProfileReason::PublicationTransfer);
                        continue;
                    };
                    Some(witness)
                }
                (StableEntryFact::Carrier { .. }, None) => {
                    projected[source].valid = false;
                    self.profile
                        .record(SummaryProfileReason::PublicationTransfer);
                    continue;
                }
            };
            if projected[source].required_children.len() >= MAX_CLASS_SET_ENTRY_SELECTOR_PROBES {
                projected[source].valid = false;
                self.profile
                    .record(SummaryProfileReason::PublicationTransfer);
                continue;
            }
            projected[source].required_children.push((target, witness));
        }
        for index in 0..projected.len() {
            projected[index].required_children.sort_unstable();
            projected[index].required_children.dedup();
            let mut dependencies = projected[index]
                .summary
                .dependencies
                .iter()
                .cloned()
                .chain(
                    projected[index]
                        .required_children
                        .iter()
                        .map(|&(child, witness)| {
                            let child = &projected[child].summary;
                            ClassSetRelationDependency {
                                procedure_lineage: child
                                    .key
                                    .procedure
                                    .identity()
                                    .read_lineage_fingerprint(),
                                entry_selector: stable_entry_fingerprint(
                                    &child.key.entry,
                                    &child.key.procedure_locator,
                                ),
                                entry: stable_dependency_entry(
                                    &child.key.entry,
                                    &child.key.procedure_locator,
                                ),
                                source_witnesses: witness.into_iter().collect(),
                                output: child.output_digest,
                                consumed_lookup: class_set_lookup_fingerprint(&child.key),
                            }
                        }),
                )
                .collect::<Vec<_>>();
            dependencies.sort_unstable_by(compare_relation_dependencies);
            dependencies = dependencies.into_iter().fold(Vec::new(), |mut rows, row| {
                if let Some(previous) = rows.last_mut()
                    && relation_dependency_without_witnesses(previous, &row)
                {
                    let mut witnesses = previous.source_witnesses.to_vec();
                    witnesses.extend(row.source_witnesses);
                    witnesses.sort_unstable();
                    witnesses.dedup();
                    if witnesses.len() > MAX_CLASS_SET_ENTRY_SELECTOR_PROBES {
                        projected[index].valid = false;
                        self.profile
                            .record(SummaryProfileReason::PublicationTransfer);
                    }
                    previous.source_witnesses = witnesses.into_boxed_slice();
                } else {
                    rows.push(row);
                }
                rows
            });
            projected[index].summary.dependencies = dependencies.into_boxed_slice();
        }
        for row in &mut projected {
            let runtime_key = class_set_runtime_lookup_key(&row.summary.key);
            if self
                .used
                .get(&runtime_key)
                .is_some_and(|used| used.as_ref() != &row.summary)
            {
                row.valid = false;
                self.profile
                    .record(SummaryProfileReason::PublicationReusedConflict);
            }
        }
        projected.sort_unstable_by(|left, right| {
            left.publication_rank
                .cmp(&right.publication_rank)
                .then_with(|| left.summary.key.procedure.cmp(&right.summary.key.procedure))
                .then_with(|| left.summary.key.entry.cmp(&right.summary.key.entry))
        });
        projected.dedup_by(|right, left| {
            if left.summary.key == right.summary.key {
                // Distinct live entry facts can normalize to one stable lookup key
                // while carrying different reached, exit, or dependency relations.
                // Such a collision has no deterministic reusable answer, so retain
                // the row only to invalidate publication for that key.
                let deterministic = left.summary == right.summary;
                left.valid &= right.valid && deterministic;
                true
            } else {
                false
            }
        });
        projected.into_iter().fold(0usize, |published, row| {
            if !row.valid {
                return published;
            }
            for dependency in &row.summary.dependencies {
                let Some(child) = self
                    .procedures_by_lineage
                    .get(&dependency.procedure_lineage)
                    .and_then(Option::as_ref)
                else {
                    self.profile
                        .record(SummaryProfileReason::PublicationDependency);
                    return published;
                };
                let Some(child_runtime) =
                    self.runtime_lookup_key_for(child, dependency.entry_selector)
                else {
                    self.profile
                        .record(SummaryProfileReason::PublicationDependency);
                    return published;
                };
                let Some(child_summary) = self.state.class_set.get_runtime(child_runtime) else {
                    self.profile
                        .record(SummaryProfileReason::PublicationDependency);
                    return published;
                };
                if child_summary.output_digest != dependency.output {
                    self.profile
                        .record(SummaryProfileReason::PublicationDependency);
                    return published;
                }
            }
            let runtime_publication = self.state.class_set.publish_tracked(row.summary.clone());
            let persisted = if self
                .state
                .class_set
                .get_runtime(class_set_runtime_lookup_key(&row.summary.key))
                .is_some_and(|current| current.key == row.summary.key)
            {
                self.persist_summary(&row.summary, request.cancellation)
            } else {
                ClassSetSummaryPersistence::Unavailable
            };
            let published_now = match persisted {
                ClassSetSummaryPersistence::Stored { published, .. } => published,
                ClassSetSummaryPersistence::Unavailable => runtime_publication.published,
            };
            self.retained_publication_writes |=
                runtime_publication.retained_write || persisted.retained_write();
            published.saturating_add(usize::from(published_now))
        })
    }

    fn publish_surfaces(&mut self, cancellation: &CancellationToken) {
        let mut surfaces = self.surfaces.values().cloned().collect::<Vec<_>>();
        surfaces.sort_unstable_by_key(|surface| *surface.surface_digest());
        for surface in surfaces {
            let inserted_in_memory = self.state.class_set.publish_surface(surface.clone());
            self.retained_publication_writes |= inserted_in_memory;
            let Some(store) = &self.store else {
                continue;
            };
            if surface.header.owner_blob_oid == "runtime-only" {
                continue;
            }
            match store.publish_class_set_procedure_surface(surface, cancellation) {
                // `false` conflates an exact no-op with a provenance refresh.
                // Conservatively retain the producing charge for either
                // successful store outcome until that API exposes the
                // difference.
                Ok(_) => self.retained_publication_writes = true,
                Err(error) => {
                    self.workspace
                        .analyzer()
                        .record_query_failure(store_error_context(
                            error,
                            "publishing persisted class-set procedure surface",
                        ));
                }
            }
        }
    }

    fn persist_summary(
        &self,
        summary: &ClassSetProcedureSummary,
        cancellation: &CancellationToken,
    ) -> ClassSetSummaryPersistence {
        if cancellation.is_cancelled() {
            return ClassSetSummaryPersistence::Unavailable;
        }
        let Some(store) = &self.store else {
            return ClassSetSummaryPersistence::Unavailable;
        };
        let attachment = match self
            .workspace
            .semantic_artifact_store_attachment(summary.key.procedure.artifact())
        {
            Ok(Some(attachment)) => attachment,
            Ok(None) => return ClassSetSummaryPersistence::Unavailable,
            Err(error) => {
                self.workspace
                    .analyzer()
                    .record_query_failure(StoreError::new(format!(
                        "capturing persisted class-set summary source: {error}"
                    )));
                return ClassSetSummaryPersistence::Unavailable;
            }
        };
        let row = match persisted_summary_row(summary, attachment) {
            Ok(row) => row,
            Err(error) => {
                self.workspace.analyzer().record_query_failure(error);
                return ClassSetSummaryPersistence::Unavailable;
            }
        };
        let lookup = row.header.key.lookup_digest;
        let publication = match store.class_set_summary_for_digest(lookup) {
            Ok(Some(current)) => {
                let semantic_publication_changed = !current.has_same_semantic_publication(&row);
                store
                    .replace_class_set_summary(*current.content_digest(), row, cancellation)
                    .map(|replaced| (replaced && semantic_publication_changed, replaced))
            }
            Ok(None) => store
                .publish_class_set_summary(row, cancellation)
                .map(|published| (published, published)),
            Err(error) => Err(error),
        };
        match publication {
            Ok((published, retained_write)) => ClassSetSummaryPersistence::Stored {
                published,
                retained_write,
            },
            Err(error) => {
                self.workspace
                    .analyzer()
                    .record_query_failure(store_error_context(
                        error,
                        "publishing persisted class-set summary",
                    ));
                ClassSetSummaryPersistence::Unavailable
            }
        }
    }
}

fn return_kind_ordinal(kind: ReturnTransferKind) -> u8 {
    match kind {
        ReturnTransferKind::Normal => 0,
        ReturnTransferKind::Exceptional => 1,
    }
}

fn compare_qualities(left: &[PathQuality], right: &[PathQuality]) -> std::cmp::Ordering {
    left.iter()
        .map(|quality| quality.ordinal())
        .cmp(right.iter().map(|quality| quality.ordinal()))
}

fn class_atom_fingerprint(atom: &ClassAtom) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_ATOM);
    match atom {
        ClassAtom::Class(ClassIdentity::Workspace(unit)) => {
            digest.push(b"workspace-class");
            digest.push(unit.declaration_id().as_str().as_bytes());
        }
        ClassAtom::Class(ClassIdentity::External {
            qualified_name,
            symbol_id,
        }) => {
            digest.push(b"external-class");
            digest.push(qualified_name.as_bytes());
            digest.push(symbol_id.as_bytes());
        }
        ClassAtom::Unknown(reason) => {
            digest.push(b"unknown");
            digest.push(reason.to_string().as_bytes());
        }
    }
    digest.finish()
}

fn class_set_procedure_semantics_key(
    contract: &ClassSetProcedureContract,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> SummaryProcedureSemanticsKey {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-procedure-semantics-v1");
    digest.push(contract.carrier_semantics.as_bytes());
    digest.push(contract.field_slots.as_bytes());
    digest.push(contract.direct_calls.as_bytes());
    digest.push(
        &u64::try_from(contract.sources.len())
            .expect("class-set source count fits in u64")
            .to_le_bytes(),
    );
    for (event, atom) in &contract.sources {
        event.push_procedure_local_identity(&mut digest, procedure);
        digest.push(class_atom_fingerprint(atom).as_bytes());
    }
    digest.push(
        &u64::try_from(contract.sinks.len())
            .expect("class-set sink count fits in u64")
            .to_le_bytes(),
    );
    for event in &contract.sinks {
        event.push_procedure_local_identity(&mut digest, procedure);
    }
    SummaryProcedureSemanticsKey::from_digest(digest.finish())
}

fn stable_entry_fingerprint(
    entry: &StableEntryFact,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_ENTRY);
    match entry {
        StableEntryFact::Zero => digest.push(b"zero"),
        StableEntryFact::Carrier {
            carrier,
            uncertain,
            source_partition,
        } => {
            digest.push(b"carrier");
            digest.push(procedure_local_carrier_fingerprint(carrier, procedure).as_bytes());
            digest.push(&[u8::from(*uncertain)]);
            match source_partition {
                Some(source_partition) => {
                    digest.push(b"source-selective");
                    digest.push(source_partition.as_bytes());
                }
                None => digest.push(b"source-independent"),
            }
        }
    }
    digest.finish()
}

fn stable_dependency_entry(
    entry: &StableEntryFact,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> StableDependencyEntry {
    match entry {
        StableEntryFact::Zero => StableDependencyEntry::Zero,
        StableEntryFact::Carrier {
            carrier,
            uncertain,
            source_partition,
        } => StableDependencyEntry::Carrier {
            carrier: procedure_local_carrier_fingerprint(carrier, procedure),
            uncertain: *uncertain,
            source_partition: *source_partition,
        },
    }
}

fn dependency_entry_fact(
    entry: &StableDependencyEntry,
    entry_carriers: &HashMap<[u8; 32], Option<ValueFlowCarrierKey>>,
    _procedure: &crate::analyzer::semantic::SemanticLocator,
) -> Option<StableEntryFact> {
    match entry {
        StableDependencyEntry::Zero => Some(StableEntryFact::Zero),
        StableDependencyEntry::Carrier {
            carrier,
            uncertain,
            source_partition,
        } => {
            let carrier = entry_carriers.get(carrier.as_bytes())?.as_ref()?.clone();
            Some(StableEntryFact::Carrier {
                carrier: Box::new(carrier),
                uncertain: *uncertain,
                source_partition: *source_partition,
            })
        }
    }
}

fn relation_dependency_from_row(
    dependency: &ClassSetSummaryDependencyRow,
) -> ClassSetRelationDependency {
    ClassSetRelationDependency {
        procedure_lineage: StableDigest::from_array(dependency.callee_procedure_lineage),
        entry_selector: StableDigest::from_array(dependency.callee_entry_selector_digest),
        entry: match dependency.entry {
            ClassSetSummaryDependencyEntryRow::Zero => StableDependencyEntry::Zero,
            ClassSetSummaryDependencyEntryRow::Carrier {
                carrier_key,
                uncertain,
                source_behavior_digest,
            } => StableDependencyEntry::Carrier {
                carrier: StableDigest::from_array(carrier_key),
                uncertain,
                source_partition: source_behavior_digest.map(StableDigest::from_array),
            },
        },
        source_witnesses: dependency
            .source_witnesses
            .iter()
            .copied()
            .map(StableDigest::from_array)
            .collect(),
        output: dependency.expected_output_digest,
        consumed_lookup: StableDigest::from_array(dependency.consumed_child_lookup_digest),
    }
}

fn source_witness_fingerprint(
    plan: &ValueFlowPlan,
    source: crate::value_flow::ValueFlowSourceId,
) -> Option<StableDigest> {
    let spec = plan.source(source)?;
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-entry-source-witness-v1");
    spec.key()
        .push_procedure_local_identity(&mut digest, spec.point().procedure().semantics().locator());
    Some(digest.finish())
}

fn entry_source_witness_fingerprint() -> StableDigest {
    StableDigest::sha256(b"bifrost-class-set-entry-source-witness-placeholder-v1")
}

fn class_set_lookup_fingerprint(key: &ClassSetSummaryLookupKey) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_LOOKUP);
    digest.push(
        key.procedure
            .identity()
            .procedure_read_fingerprint(key.procedure_semantics)
            .as_bytes(),
    );
    digest.push(stable_entry_fingerprint(&key.entry, &key.procedure_locator).as_bytes());
    digest.push(key.root_surface.as_bytes());
    digest.finish()
}

fn class_set_runtime_lookup_key(key: &ClassSetSummaryLookupKey) -> ClassSetRuntimeLookupKey {
    ClassSetRuntimeLookupKey {
        procedure: key
            .procedure
            .identity()
            .procedure_read_fingerprint(key.procedure_semantics),
        entry_selector: stable_entry_fingerprint(&key.entry, &key.procedure_locator),
        root_surface: key.root_surface,
    }
}

struct NormalizedClassSetRelationRows {
    entry_fact_ordinal: u32,
    facts: Vec<ClassSetSummaryFactRow>,
    exits: Vec<ClassSetSummaryExitRow>,
    reached: Vec<ClassSetSummaryReachedRow>,
}

/// Materialize the single canonical row vocabulary shared by runtime output
/// attestations and persistent class-set summaries.
fn normalized_class_set_relation_rows(
    key: &ClassSetSummaryLookupKey,
    exits: &[StableEndSummary],
    reached: &[StableReachedFact],
) -> Result<NormalizedClassSetRelationRows, StoreError> {
    let procedure_locator = &key.procedure_locator;
    let entry_fact = match &key.entry {
        StableEntryFact::Zero => StableValueFlowFact::Zero,
        StableEntryFact::Carrier {
            carrier, uncertain, ..
        } => StableValueFlowFact::Carrier {
            source: StableSource::Entry,
            carrier: carrier.as_ref().clone(),
            uncertain: *uncertain,
        },
    };
    let mut facts = vec![entry_fact.clone()];
    facts.extend(exits.iter().map(|row| row.exit_fact.clone()));
    facts.extend(reached.iter().map(|row| row.fact.clone()));
    facts.sort_unstable();
    facts.dedup();
    let fact_ordinal = |fact: &StableValueFlowFact| {
        facts
            .binary_search(fact)
            .expect("a collected class-set fact remains in its canonical table")
    };
    let entry_fact_ordinal = u32::try_from(fact_ordinal(&entry_fact))
        .map_err(|_| StoreError::new("class-set entry fact ordinal exceeds u32"))?;
    let fact_rows = facts
        .iter()
        .enumerate()
        .map(|(ordinal, fact)| {
            Ok(ClassSetSummaryFactRow {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| StoreError::new("class-set fact ordinal exceeds u32"))?,
                shape: persisted_fact_shape(fact, procedure_locator),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let exits = exits
        .iter()
        .enumerate()
        .map(|(ordinal, row)| {
            Ok(ClassSetSummaryExitRow {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| StoreError::new("class-set exit ordinal exceeds u32"))?,
                kind: match row.exit_kind {
                    ReturnTransferKind::Normal => ClassSetSummaryExitKindRow::Normal,
                    ReturnTransferKind::Exceptional => ClassSetSummaryExitKindRow::Exceptional,
                },
                fact_ordinal: u32::try_from(fact_ordinal(&row.exit_fact))
                    .map_err(|_| StoreError::new("class-set exit fact ordinal exceeds u32"))?,
                quality_mask: quality_mask(&row.qualities),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let reached = reached
        .iter()
        .enumerate()
        .map(|(ordinal, row)| {
            Ok(ClassSetSummaryReachedRow {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| StoreError::new("class-set reached ordinal exceeds u32"))?,
                point_id: row.point.get(),
                fact_ordinal: u32::try_from(fact_ordinal(&row.fact))
                    .map_err(|_| StoreError::new("class-set reached fact ordinal exceeds u32"))?,
                quality_mask: quality_mask(&row.qualities),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    Ok(NormalizedClassSetRelationRows {
        entry_fact_ordinal,
        facts: fact_rows,
        exits,
        reached,
    })
}

/// Digest only the relation a caller consumes, deliberately excluding the
/// semantic envelope key and the dependency attestations used to validate it.
fn class_set_output_digest(
    key: &ClassSetSummaryLookupKey,
    exits: &[StableEndSummary],
    reached: &[StableReachedFact],
) -> ClassSetSummaryOutputDigest {
    let rows = normalized_class_set_relation_rows(key, exits, reached)
        .expect("a bounded runtime class-set relation has normalized rows");
    class_set_summary_output_digest(&rows.facts, &rows.exits, &rows.reached)
        .expect("normalized runtime class-set rows form a valid complete relation")
}

fn persisted_summary_row(
    summary: &ClassSetProcedureSummary,
    attachment: ClassSetSummaryAttachment,
) -> Result<ClassSetSummaryRow, StoreError> {
    let relation =
        normalized_class_set_relation_rows(&summary.key, &summary.exits, &summary.reached)?;
    let relation_rows = u64::try_from(summary.exits.len().saturating_add(summary.reached.len()))
        .map_err(|_| StoreError::new("class-set relation row count exceeds u64"))?;
    let procedure = &summary.key.procedure;
    let dependencies = summary
        .dependencies
        .iter()
        .enumerate()
        .map(|(ordinal, dependency)| {
            Ok(ClassSetSummaryDependencyRow {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| StoreError::new("class-set dependency ordinal exceeds u32"))?,
                callee_procedure_lineage: *dependency.procedure_lineage.as_bytes(),
                callee_entry_selector_digest: *dependency.entry_selector.as_bytes(),
                expected_output_digest: dependency.output,
                consumed_child_lookup_digest: *dependency.consumed_lookup.as_bytes(),
                entry: match &dependency.entry {
                    StableDependencyEntry::Zero => ClassSetSummaryDependencyEntryRow::Zero,
                    StableDependencyEntry::Carrier {
                        carrier,
                        uncertain,
                        source_partition,
                    } => ClassSetSummaryDependencyEntryRow::Carrier {
                        carrier_key: *carrier.as_bytes(),
                        uncertain: *uncertain,
                        source_behavior_digest: source_partition.map(|digest| *digest.as_bytes()),
                    },
                },
                source_witnesses: dependency
                    .source_witnesses
                    .iter()
                    .map(|digest| *digest.as_bytes())
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let reads = summary
        .reads
        .iter()
        .enumerate()
        .map(|(ordinal, key)| {
            Ok(ClassSetSummaryReadRow {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| StoreError::new("class-set read ordinal exceeds u32"))?,
                key: key.clone(),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let header = ClassSetSummaryHeaderRow {
        key: ClassSetSummaryRowKey {
            lookup_digest: *class_set_lookup_fingerprint(&summary.key).as_bytes(),
            procedure_lineage: *procedure.identity().read_lineage_fingerprint().as_bytes(),
        },
        attachment,
        artifact_public_identity: *procedure.artifact().public_fingerprint().as_bytes(),
        artifact_content_identity: *procedure.artifact().revision().content().as_bytes(),
        schema_version: procedure.schema().get(),
        semantics_digest: *procedure.semantics().as_bytes(),
        context_digest: *procedure.context().as_bytes(),
        behavior_read_digest: *procedure.behavior().read_bytes(),
        dependency_digest: *procedure.dependencies().as_bytes(),
        carrier_digest: *summary.key.contract.carrier_semantics.as_bytes(),
        field_slots_digest: *summary.key.contract.field_slots.as_bytes(),
        root_surface_digest: *summary.key.root_surface.as_bytes(),
        direct_calls_digest: *summary.key.contract.direct_calls.as_bytes(),
        entry_fact_ordinal: relation.entry_fact_ordinal,
    };
    ClassSetSummaryRow::try_new(
        header,
        relation.facts,
        relation.exits,
        relation.reached,
        dependencies,
        reads,
        vec![
            ClassSetSummaryChargeRow {
                kind: "solver.callback_rows".to_owned(),
                amount: relation_rows,
            },
            ClassSetSummaryChargeRow {
                kind: "solver.propagated_outputs".to_owned(),
                amount: relation_rows,
            },
        ],
    )
}

fn persisted_fact_shape(
    fact: &StableValueFlowFact,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> ClassSetSummaryFactShapeRow {
    match fact {
        StableValueFlowFact::Zero => ClassSetSummaryFactShapeRow::Zero,
        StableValueFlowFact::Carrier {
            source,
            carrier,
            uncertain,
        } => ClassSetSummaryFactShapeRow::Carrier {
            source: persisted_fact_source(source, procedure),
            carrier_key: procedure_local_carrier_fingerprint(carrier, procedure)
                .as_bytes()
                .to_vec(),
            uncertain: *uncertain,
        },
        StableValueFlowFact::Meeting {
            source,
            sink,
            uncertain,
        } => ClassSetSummaryFactShapeRow::Meeting {
            source: persisted_fact_source(source, procedure),
            sink_event_key: procedure_local_event_fingerprint(sink, procedure)
                .as_bytes()
                .to_vec(),
            uncertain: *uncertain,
        },
    }
}

fn persisted_fact_source(
    source: &StableSource,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> ClassSetSummaryFactSourceRow {
    match source {
        StableSource::Entry => ClassSetSummaryFactSourceRow::Entry,
        StableSource::Event(event) => ClassSetSummaryFactSourceRow::Event(
            procedure_local_event_fingerprint(event, procedure)
                .as_bytes()
                .to_vec(),
        ),
    }
}

fn procedure_local_carrier_fingerprint(
    carrier: &ValueFlowCarrierKey,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-local-carrier-v1");
    carrier.push_procedure_local_identity(&mut digest, procedure);
    digest.finish()
}

fn procedure_local_event_fingerprint(
    event: &ValueFlowEventKey,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-local-event-v2");
    event.push_procedure_local_identity(&mut digest, procedure);
    digest.finish()
}

fn quality_mask(qualities: &[PathQuality]) -> u8 {
    qualities
        .iter()
        .fold(0, |mask, quality| mask | (1_u8 << quality.ordinal()))
}

struct PersistedFactKeys {
    carriers: HashMap<[u8; 32], Option<ValueFlowCarrierKey>>,
    sources: HashMap<[u8; 32], Option<ValueFlowEventKey>>,
    sinks: HashMap<[u8; 32], Option<ValueFlowEventKey>>,
}

fn persisted_fact_keys(
    plan: &ValueFlowPlan,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> PersistedFactKeys {
    let mut carriers = HashMap::default();
    for carrier in plan.carrier_keys() {
        insert_stable_key(
            &mut carriers,
            *procedure_local_carrier_fingerprint(carrier, procedure).as_bytes(),
            carrier.clone(),
        );
    }
    let mut sources = HashMap::default();
    for (_, source) in plan.sources() {
        insert_stable_key(
            &mut sources,
            *procedure_local_event_fingerprint(source.key(), procedure).as_bytes(),
            source.key().clone(),
        );
    }
    let mut sinks = HashMap::default();
    for (_, sink) in plan.sinks() {
        insert_stable_key(
            &mut sinks,
            *procedure_local_event_fingerprint(sink.key(), procedure).as_bytes(),
            sink.key().clone(),
        );
    }
    PersistedFactKeys {
        carriers,
        sources,
        sinks,
    }
}

fn restore_persisted_summary(
    plan: &ValueFlowPlan,
    expected: &ClassSetSummaryLookupKey,
    expected_reads: &[ReadKey],
    row: ClassSetSummaryRow,
) -> Result<ClassSetProcedureSummary, StoreError> {
    let procedure = &expected.procedure;
    let header = &row.header;
    let expected_lookup = *class_set_lookup_fingerprint(expected).as_bytes();
    if header.key.lookup_digest != expected_lookup
        || header.key.procedure_lineage
            != *procedure.identity().read_lineage_fingerprint().as_bytes()
        || header.schema_version != procedure.schema().get()
        || header.semantics_digest != *procedure.semantics().as_bytes()
        || header.context_digest != *procedure.context().as_bytes()
        || header.behavior_read_digest != *procedure.behavior().read_bytes()
        || header.carrier_digest != *expected.contract.carrier_semantics.as_bytes()
        || header.field_slots_digest != *expected.contract.field_slots.as_bytes()
        || header.root_surface_digest != *expected.root_surface.as_bytes()
        || header.direct_calls_digest != *expected.contract.direct_calls.as_bytes()
        || header.attachment.rel_path != procedure.artifact().path().as_str()
        || header.attachment.language != procedure.artifact().language().language()
    {
        return Err(StoreError::new(
            "persisted class-set summary header does not match the live procedure contract",
        ));
    }
    if row
        .reads
        .iter()
        .map(|read| &read.key)
        .ne(expected_reads.iter())
    {
        return Err(StoreError::new(
            "persisted class-set summary dispatch reads do not match the live plan",
        ));
    }

    let keys = persisted_fact_keys(plan, &expected.procedure_locator);

    let facts = row
        .facts
        .iter()
        .map(|fact| restore_persisted_fact(fact, &keys.carriers, &keys.sources, &keys.sinks))
        .collect::<Result<Vec<_>, StoreError>>()?;
    if facts.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StoreError::new(
            "persisted class-set fact table is not in canonical order",
        ));
    }
    let Some(entry_fact) = facts.get(header.entry_fact_ordinal as usize) else {
        return Err(StoreError::new(
            "persisted class-set entry fact ordinal is absent",
        ));
    };
    let restored_entry = match entry_fact {
        StableValueFlowFact::Zero => StableEntryFact::Zero,
        StableValueFlowFact::Carrier {
            source: StableSource::Entry,
            carrier,
            uncertain,
        } => StableEntryFact::Carrier {
            carrier: Box::new(carrier.clone()),
            uncertain: *uncertain,
            source_partition: match &expected.entry {
                StableEntryFact::Carrier {
                    source_partition, ..
                } => *source_partition,
                StableEntryFact::Zero => {
                    return Err(StoreError::new(
                        "persisted carrier entry does not match a zero lookup",
                    ));
                }
            },
        },
        _ => {
            return Err(StoreError::new(
                "persisted class-set entry ordinal is not an entry fact",
            ));
        }
    };
    if restored_entry != expected.entry {
        return Err(StoreError::new(
            "persisted class-set entry fact does not match the lookup",
        ));
    }

    let exits = row
        .exits
        .iter()
        .map(|exit| {
            Ok(StableEndSummary {
                exit_kind: match exit.kind {
                    ClassSetSummaryExitKindRow::Normal => ReturnTransferKind::Normal,
                    ClassSetSummaryExitKindRow::Exceptional => ReturnTransferKind::Exceptional,
                },
                exit_fact: facts
                    .get(exit.fact_ordinal as usize)
                    .ok_or_else(|| StoreError::new("persisted class-set exit fact is absent"))?
                    .clone(),
                qualities: qualities_from_mask(exit.quality_mask)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let mut canonical_exits = exits.clone();
    canonical_exits.sort_unstable_by(|left, right| {
        return_kind_ordinal(left.exit_kind)
            .cmp(&return_kind_ordinal(right.exit_kind))
            .then_with(|| left.exit_fact.cmp(&right.exit_fact))
            .then_with(|| compare_qualities(&left.qualities, &right.qualities))
    });
    if exits != canonical_exits {
        return Err(StoreError::new(
            "persisted class-set exit relation is not in canonical order",
        ));
    }

    let reached = row
        .reached
        .iter()
        .map(|reached| {
            Ok(StableReachedFact {
                point: ProgramPointId::try_from_index(reached.point_id as usize)
                    .map_err(|_| StoreError::new("persisted class-set point ID exceeds u32"))?,
                fact: facts
                    .get(reached.fact_ordinal as usize)
                    .ok_or_else(|| StoreError::new("persisted reached fact is absent"))?
                    .clone(),
                qualities: qualities_from_mask(reached.quality_mask)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let mut canonical_reached = reached.clone();
    canonical_reached.sort_unstable_by(|left, right| {
        left.point
            .cmp(&right.point)
            .then_with(|| left.fact.cmp(&right.fact))
            .then_with(|| compare_qualities(&left.qualities, &right.qualities))
    });
    if reached != canonical_reached {
        return Err(StoreError::new(
            "persisted class-set reached relation is not in canonical order",
        ));
    }
    let relation_rows = u64::try_from(exits.len().saturating_add(reached.len()))
        .map_err(|_| StoreError::new("persisted class-set relation row count exceeds u64"))?;
    let expected_charges = [
        ("solver.callback_rows", relation_rows),
        ("solver.propagated_outputs", relation_rows),
    ];
    if row.charges.len() != expected_charges.len()
        || row
            .charges
            .iter()
            .zip(expected_charges)
            .any(|(actual, expected)| actual.kind != expected.0 || actual.amount != expected.1)
    {
        return Err(StoreError::new(
            "persisted class-set replay charges do not match the relation",
        ));
    }

    let output_digest = row.output_digest();
    let dependencies = row
        .dependencies
        .into_iter()
        .map(|dependency| ClassSetRelationDependency {
            procedure_lineage: StableDigest::from_array(dependency.callee_procedure_lineage),
            entry_selector: StableDigest::from_array(dependency.callee_entry_selector_digest),
            entry: match dependency.entry {
                ClassSetSummaryDependencyEntryRow::Zero => StableDependencyEntry::Zero,
                ClassSetSummaryDependencyEntryRow::Carrier {
                    carrier_key,
                    uncertain,
                    source_behavior_digest,
                } => StableDependencyEntry::Carrier {
                    carrier: StableDigest::from_array(carrier_key),
                    uncertain,
                    source_partition: source_behavior_digest.map(StableDigest::from_array),
                },
            },
            source_witnesses: dependency
                .source_witnesses
                .into_iter()
                .map(StableDigest::from_array)
                .collect(),
            output: dependency.expected_output_digest,
            consumed_lookup: StableDigest::from_array(dependency.consumed_child_lookup_digest),
        })
        .collect::<Vec<_>>();
    if dependencies
        .windows(2)
        .any(|rows| compare_relation_dependencies(&rows[0], &rows[1]) != Ordering::Less)
    {
        return Err(StoreError::new(
            "persisted class-set dependencies are not in canonical order",
        ));
    }
    Ok(ClassSetProcedureSummary {
        key: expected.clone(),
        exits: exits.into_boxed_slice(),
        reached: reached.into_boxed_slice(),
        dependencies: dependencies.into_boxed_slice(),
        reads: expected_reads.into(),
        output_digest,
    })
}

fn insert_stable_key<T: Clone + Eq>(
    keys: &mut HashMap<[u8; 32], Option<T>>,
    digest: [u8; 32],
    value: T,
) {
    if let Some(existing) = keys.get_mut(&digest) {
        if existing.as_ref() != Some(&value) {
            *existing = None;
        }
    } else {
        keys.insert(digest, Some(value));
    }
}

fn restore_persisted_fact(
    row: &ClassSetSummaryFactRow,
    carriers: &HashMap<[u8; 32], Option<ValueFlowCarrierKey>>,
    sources: &HashMap<[u8; 32], Option<ValueFlowEventKey>>,
    sinks: &HashMap<[u8; 32], Option<ValueFlowEventKey>>,
) -> Result<StableValueFlowFact, StoreError> {
    match &row.shape {
        ClassSetSummaryFactShapeRow::Zero => Ok(StableValueFlowFact::Zero),
        ClassSetSummaryFactShapeRow::Carrier {
            source,
            carrier_key,
            uncertain,
        } => Ok(StableValueFlowFact::Carrier {
            source: restore_persisted_source(source, sources)?,
            carrier: unique_stable_key(carriers, carrier_key, "carrier")?.clone(),
            uncertain: *uncertain,
        }),
        ClassSetSummaryFactShapeRow::Meeting {
            source,
            sink_event_key,
            uncertain,
        } => Ok(StableValueFlowFact::Meeting {
            source: restore_persisted_source(source, sources)?,
            sink: unique_stable_key(sinks, sink_event_key, "sink event")?.clone(),
            uncertain: *uncertain,
        }),
    }
}

fn restore_persisted_source(
    source: &ClassSetSummaryFactSourceRow,
    sources: &HashMap<[u8; 32], Option<ValueFlowEventKey>>,
) -> Result<StableSource, StoreError> {
    match source {
        ClassSetSummaryFactSourceRow::Entry => Ok(StableSource::Entry),
        ClassSetSummaryFactSourceRow::Event(event) => Ok(StableSource::Event(
            unique_stable_key(sources, event, "source event")?.clone(),
        )),
        ClassSetSummaryFactSourceRow::None => Err(StoreError::new(
            "persisted nonzero class-set fact has no source",
        )),
    }
}

fn unique_stable_key<'a, T>(
    keys: &'a HashMap<[u8; 32], Option<T>>,
    encoded: &[u8],
    label: &str,
) -> Result<&'a T, StoreError> {
    let digest: [u8; 32] = encoded.try_into().map_err(|_| {
        StoreError::new(format!(
            "persisted class-set {label} digest is not 32 bytes"
        ))
    })?;
    keys.get(&digest).and_then(Option::as_ref).ok_or_else(|| {
        StoreError::new(format!(
            "persisted class-set {label} does not map uniquely to the live plan"
        ))
    })
}

fn qualities_from_mask(mask: u8) -> Result<Box<[PathQuality]>, StoreError> {
    if !matches!(mask, 1 | 2 | 4 | 6 | 8) {
        return Err(StoreError::new(
            "persisted class-set path-quality mask is not a valid frontier",
        ));
    }
    Ok(PathQuality::ALL
        .into_iter()
        .filter(|quality| mask & (1_u8 << quality.ordinal()) != 0)
        .collect())
}

fn store_error_context(error: StoreError, context: &str) -> StoreError {
    StoreError::new(format!("{context}: {error}"))
}

#[cfg(test)]
fn maintenance_entry_fact(
    plan: &ValueFlowPlan,
    source_sensitive: bool,
    source_partitions: &[(StableDigest, crate::value_flow::ValueFlowSourceId)],
    entry: &StableEntryFact,
) -> Option<ValueFlowFact> {
    match entry {
        StableEntryFact::Zero => Some(ValueFlowFact::zero()),
        // StableEntryFact erases the original source into StableSource::Entry
        // but retains its edge-kill behavior partition. Any matching source
        // is the representational witness for the same transfer relation; it
        // is not claimed to be the original atom.
        StableEntryFact::Carrier {
            carrier,
            uncertain,
            source_partition,
        } => Some(ValueFlowFact::carrier_fact(
            match source_partition {
                Some(partition) if source_sensitive => source_partitions
                    .binary_search_by_key(partition, |(candidate, _)| *candidate)
                    .ok()
                    .map(|index| source_partitions[index].1)?,
                None if !source_sensitive => source_partitions.first()?.1,
                Some(_) | None => return None,
            },
            plan.carrier_id_for_key(carrier)?,
            ValueFlowUncertainty::from_semantic_uncertainty(*uncertain),
        )),
    }
}

fn current_dependencies_match_stabilized(
    summary: &ClassSetProcedureSummary,
    expected: &[ClassSetSummaryDependencyRow],
    stabilized: &HashMap<(StableDigest, StableDigest), Arc<ClassSetProcedureSummary>>,
) -> bool {
    if summary.dependencies.len() != expected.len() {
        return false;
    }
    let expected = expected
        .iter()
        .map(|dependency| {
            (
                StableDigest::from_array(dependency.callee_procedure_lineage),
                StableDigest::from_array(dependency.callee_entry_selector_digest),
            )
        })
        .collect::<HashSet<_>>();
    let actual = summary
        .dependencies
        .iter()
        .map(|dependency| (dependency.procedure_lineage, dependency.entry_selector))
        .collect::<HashSet<_>>();
    if expected.len() != summary.dependencies.len()
        || actual.len() != summary.dependencies.len()
        || actual != expected
    {
        return false;
    }
    summary.dependencies.iter().all(|dependency| {
        let identity = (dependency.procedure_lineage, dependency.entry_selector);
        let Some(child) = stabilized.get(&identity) else {
            return false;
        };
        dependency.output == child.output_digest
            && dependency.consumed_lookup == class_set_lookup_fingerprint(&child.key)
    })
}

fn rebind_equal_output_dependency(
    store: &AnalyzerStore,
    evidence: &ClassSetSummaryDependentRow,
    current_child_lookup: StableDigest,
    cancellation: &CancellationToken,
) -> Result<bool, StoreError> {
    if cancellation.is_cancelled() {
        return Err(StoreError::new(
            "class-set dependency stabilization was cancelled",
        ));
    }
    let Some(row) = store.class_set_summary_for_digest(evidence.dependent_lookup_digest)? else {
        return Err(StoreError::new(
            "demanded reverse class-set dependency has no current parent row",
        ));
    };
    let expected_content = *row.content_digest();
    let expected_output = row.output_digest();
    let mut dependencies = row.dependencies.clone();
    let Some(dependency) = dependencies.get_mut(evidence.dependency.ordinal as usize) else {
        return Err(StoreError::new(
            "demanded reverse class-set dependency ordinal is absent",
        ));
    };
    if dependency != &evidence.dependency {
        return Err(StoreError::new(
            "demanded reverse class-set dependency changed before stabilization",
        ));
    }
    dependency.consumed_child_lookup_digest = *current_child_lookup.as_bytes();
    let replacement = ClassSetSummaryRow::try_new(
        row.header,
        row.facts,
        row.exits,
        row.reached,
        dependencies,
        row.reads,
        row.charges,
    )?;
    if replacement.output_digest() != expected_output {
        return Err(StoreError::new(
            "dependency-only stabilization changed the parent output",
        ));
    }
    store.replace_class_set_summary(expected_content, replacement, cancellation)
}

impl ReusableSummaryProvider<ValueFlowFact> for PreparedClassSetSummaries<'_> {
    fn root_summary_for(
        &mut self,
        root: &ProcedureHandle,
        entry_fact: ValueFlowFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<ValueFlowFact>>, ReusableSummaryError> {
        debug_assert_eq!(entry_fact, ValueFlowFact::zero());
        debug_assert!(self.pending_root_summary.is_none());
        self.pending_root_summary = Some(PendingRootSummary {
            source_behaviors: HashMap::default(),
            admission: None,
        });
        self.summary_for(root, root, entry_fact, request)
    }

    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        root: &ProcedureHandle,
        entry_fact: ValueFlowFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<ValueFlowFact>>, ReusableSummaryError> {
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled.into());
        }
        let root_probe = self.pending_root_summary.is_some()
            && procedure == root
            && entry_fact == ValueFlowFact::zero();
        if self.type_plan.is_summary_cut(procedure) {
            if entry_fact.is_terminal_meeting() {
                // `ValueFlowClient::apply_point` kills a Meeting before it can
                // evaluate the callee entry, so its exact relative relation is
                // empty independently of the persisted summary family. The
                // relation enters neither the body nor any call cycle through
                // it, and its dynamically called-procedure set is empty. It
                // therefore excludes the root and vacuously covers every
                // procedure it can call for this exact entry fact.
                return Ok(Some(ReusableProcedureSummary {
                    exits: Box::default(),
                    reached: Box::default(),
                    call_cycle: SummaryCallCycle::ExcludesRoot,
                    called_procedures: SummaryCalledProcedures::CoveredByContract,
                }));
            }
            let Some(source_sensitive) = self
                .procedures
                .get(procedure)
                .map(|prepared| prepared.source_sensitive)
            else {
                self.profile.record(SummaryProfileReason::LookupProcedure);
                return Err(ReusableSummaryError::MandatoryCutMiss);
            };
            let source_partition = match (source_sensitive, entry_fact.source()) {
                (true, Some(source)) => {
                    let Some(behavior) =
                        self.charged_source_behavior_for(procedure, source, request)?
                    else {
                        self.profile
                            .record(SummaryProfileReason::LookupSourceBehavior);
                        return Err(ReusableSummaryError::MandatoryCutMiss);
                    };
                    Some(behavior)
                }
                (true, None) if entry_fact.carrier().is_none() && entry_fact.sink().is_none() => {
                    None
                }
                (true, None) => {
                    self.profile
                        .record(SummaryProfileReason::LookupSourcePartition);
                    return Err(ReusableSummaryError::MandatoryCutMiss);
                }
                (false, _) => None,
            };
            let Some(entry) = stable_entry_fact(self.plan, source_partition, entry_fact) else {
                self.profile.record(SummaryProfileReason::LookupEntry);
                return Err(ReusableSummaryError::MandatoryCutMiss);
            };
            let Some(key) = self.lookup_key(procedure, entry) else {
                self.profile.record(SummaryProfileReason::LookupEntry);
                return Err(ReusableSummaryError::MandatoryCutMiss);
            };
            let validated = match self.validated_runtime_summary(
                procedure,
                &key,
                entry_fact.source(),
                request,
            )? {
                Some(summary) => summary,
                None => match self.validated_persisted_summary(
                    procedure,
                    &key,
                    entry_fact.source(),
                    None,
                    request,
                )? {
                    Some(summary) => summary,
                    None => {
                        self.profile.record(SummaryProfileReason::LookupRelation);
                        return Err(ReusableSummaryError::MandatoryCutMiss);
                    }
                },
            };
            return self.finish_validated_summary(
                procedure, entry_fact, validated, request, true, root_probe,
            );
        }
        let Some(source_sensitive) = self
            .procedures
            .get(procedure)
            .map(|prepared| prepared.source_sensitive)
        else {
            self.profile.record(SummaryProfileReason::LookupProcedure);
            return Ok(None);
        };
        let source_partition = match (source_sensitive, entry_fact.source()) {
            (true, Some(source)) => {
                let Some(behavior) =
                    self.charged_source_behavior_for(procedure, source, request)?
                else {
                    self.profile
                        .record(SummaryProfileReason::LookupSourceBehavior);
                    return Ok(None);
                };
                Some(behavior)
            }
            // Zero is the mandatory source-independent entry in every IDE
            // tabulation. Publication already records it without a behavior
            // partition, including for a procedure whose carrier entries are
            // source-sensitive. Preserve that same contract at lookup.
            (true, None) if entry_fact.carrier().is_none() && entry_fact.sink().is_none() => None,
            (true, None) => {
                self.profile
                    .record(SummaryProfileReason::LookupSourcePartition);
                return Ok(None);
            }
            (false, _) => None,
        };
        let Some(entry) = stable_entry_fact(self.plan, source_partition, entry_fact) else {
            self.profile.record(SummaryProfileReason::LookupEntry);
            return Ok(None);
        };
        let key = self
            .lookup_key(procedure, entry)
            .expect("a prepared procedure has a lookup key");
        let mut preloaded_root = None;
        if root_probe {
            match self.preflight_root_observations(procedure, &key) {
                RootObservationPreflight::Covered(preloaded) => {
                    preloaded_root = preloaded.map(|row| *row)
                }
                RootObservationPreflight::Rejected => {
                    self.root_observation_rejections =
                        self.root_observation_rejections.saturating_add(1);
                    return Ok(None);
                }
                RootObservationPreflight::Absent => {
                    self.profile.record(SummaryProfileReason::LookupRelation);
                    return Ok(None);
                }
                RootObservationPreflight::Indeterminate => {}
            }
        }
        let validated =
            match self.validated_runtime_summary(procedure, &key, entry_fact.source(), request)? {
                Some(summary) => summary,
                None => match self.validated_persisted_summary(
                    procedure,
                    &key,
                    entry_fact.source(),
                    preloaded_root,
                    request,
                )? {
                    Some(summary) => summary,
                    None => {
                        self.profile.record(SummaryProfileReason::LookupRelation);
                        return Ok(None);
                    }
                },
            };
        self.finish_validated_summary(procedure, entry_fact, validated, request, false, root_probe)
    }

    fn commit_root_summary(
        &mut self,
        root: &ProcedureHandle,
        cancellation: &CancellationToken,
    ) -> Result<(), SolverTermination> {
        debug_assert_eq!(root, self.plan.root());
        let pending = self
            .pending_root_summary
            .take()
            .expect("an accepted class-set root summary has a pending transaction");
        let admission = pending
            .admission
            .expect("an accepted class-set root transaction has an admitted relation");
        if cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        self.commit_validated_publications_after_cancellation(admission.publications, cancellation);
        self.source_behavior_cache.extend(pending.source_behaviors);
        self.record_used_summary(admission.runtime_key, admission.used_summary);
        Ok(())
    }

    fn discard_root_summary(&mut self, root: &ProcedureHandle) {
        debug_assert_eq!(root, self.plan.root());
        self.pending_root_summary = None;
    }
}

impl PreparedClassSetSummaries<'_> {
    fn finish_validated_summary(
        &mut self,
        procedure: &ProcedureHandle,
        entry_fact: ValueFlowFact,
        validated: ValidatedClassSetSummary,
        request: &mut DataflowRequest<'_>,
        mandatory: bool,
        root_probe: bool,
    ) -> Result<Option<ReusableProcedureSummary<ValueFlowFact>>, ReusableSummaryError> {
        let runtime_key = class_set_runtime_lookup_key(&validated.summary.key);
        let used_summary = Arc::clone(&validated.summary);
        let reusable = self.live_reusable_summary(
            procedure,
            entry_fact,
            validated.summary,
            request,
            mandatory,
        )?;
        let Some(reusable) = reusable else {
            return Ok(None);
        };
        if root_probe {
            let pending = self
                .pending_root_summary
                .as_mut()
                .expect("a class-set root lookup begins one pending transaction");
            debug_assert!(pending.admission.is_none());
            pending.admission = Some(PendingRootSummaryAdmission {
                runtime_key,
                used_summary,
                publications: validated.publications,
            });
        } else {
            self.commit_validated_publications(validated.publications, request.cancellation)?;
            self.record_used_summary(runtime_key, used_summary);
        }
        Ok(Some(reusable))
    }

    fn commit_validated_publications(
        &mut self,
        publications: Vec<ValidatedClassSetPublication>,
        cancellation: &CancellationToken,
    ) -> Result<(), SolverTermination> {
        if cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        self.commit_validated_publications_after_cancellation(publications, cancellation);
        Ok(())
    }

    fn commit_validated_publications_after_cancellation(
        &mut self,
        publications: Vec<ValidatedClassSetPublication>,
        cancellation: &CancellationToken,
    ) {
        for publication in publications {
            match publication {
                ValidatedClassSetPublication::Runtime(publication) => {
                    self.retained_publication_writes |= self
                        .state
                        .class_set
                        .publish_tracked(publication.as_ref().clone())
                        .retained_write;
                }
                ValidatedClassSetPublication::Persisted(publication) => {
                    let runtime_publication = self
                        .state
                        .class_set
                        .publish_tracked(publication.as_ref().clone());
                    let persisted = self.persist_summary(&publication, cancellation);
                    self.retained_publication_writes |=
                        runtime_publication.retained_write || persisted.retained_write();
                }
            }
        }
    }

    fn record_used_summary(
        &mut self,
        runtime_key: ClassSetRuntimeLookupKey,
        used_summary: Arc<ClassSetProcedureSummary>,
    ) {
        if let Some(existing) = self.used.get(&runtime_key) {
            assert_eq!(
                existing, &used_summary,
                "one query-local class-set lookup consumes one exact answer"
            );
        } else {
            self.used.insert(runtime_key, used_summary);
        }
    }

    fn live_reusable_summary(
        &mut self,
        procedure: &ProcedureHandle,
        entry_fact: ValueFlowFact,
        summary: Arc<ClassSetProcedureSummary>,
        request: &mut DataflowRequest<'_>,
        mandatory: bool,
    ) -> Result<Option<ReusableProcedureSummary<ValueFlowFact>>, ReusableSummaryError> {
        let rows = summary.exits.len().saturating_add(summary.reached.len());
        if let Some(termination) = request.reserve(SolverWork {
            callback_rows: rows,
            propagated_outputs: rows,
            ..SolverWork::default()
        }) {
            return Err(termination.into());
        }
        let entry_source = entry_fact.source();
        let mut exits = Vec::with_capacity(summary.exits.len());
        for row in &summary.exits {
            let Some(exit_fact) = live_fact(self.plan, &row.exit_fact, entry_source) else {
                self.profile.record(SummaryProfileReason::LookupLiveRemap);
                return if mandatory {
                    Err(ReusableSummaryError::MandatoryCutMiss)
                } else {
                    Ok(None)
                };
            };
            exits.push(ReusableEndSummary {
                exit_kind: row.exit_kind,
                exit_fact,
                qualities: row.qualities.clone(),
            });
        }
        let mut reached = Vec::with_capacity(summary.reached.len());
        for row in &summary.reached {
            let Some(point) = procedure.point_handle(row.point) else {
                self.profile.record(SummaryProfileReason::LookupLiveRemap);
                return if mandatory {
                    Err(ReusableSummaryError::MandatoryCutMiss)
                } else {
                    Ok(None)
                };
            };
            let Some(fact) = live_fact(self.plan, &row.fact, entry_source) else {
                self.profile.record(SummaryProfileReason::LookupLiveRemap);
                return if mandatory {
                    Err(ReusableSummaryError::MandatoryCutMiss)
                } else {
                    Ok(None)
                };
            };
            reached.push(ReusableReachedFact {
                point,
                fact,
                qualities: row.qualities.clone(),
            });
        }
        Ok(Some(ReusableProcedureSummary {
            exits: exits.into_boxed_slice(),
            reached: reached.into_boxed_slice(),
            call_cycle: SummaryCallCycle::ExcludesRoot,
            called_procedures: SummaryCalledProcedures::CoveredByContract,
        }))
    }
}

fn stable_entry_fact(
    plan: &ValueFlowPlan,
    source_partition: Option<StableDigest>,
    fact: ValueFlowFact,
) -> Option<StableEntryFact> {
    match (fact.source(), fact.carrier(), fact.sink()) {
        (None, None, None) => Some(StableEntryFact::Zero),
        (Some(_source), Some(carrier), None) => Some(StableEntryFact::Carrier {
            carrier: Box::new(plan.carrier_key(carrier)?.clone()),
            uncertain: !fact.uncertainty().is_empty(),
            source_partition,
        }),
        _ => None,
    }
}

fn stable_fact(
    plan: &ValueFlowPlan,
    fact: ValueFlowFact,
    entry_source: Option<crate::value_flow::ValueFlowSourceId>,
) -> Option<StableValueFlowFact> {
    let source = |source| {
        if Some(source) == entry_source {
            Some(StableSource::Entry)
        } else {
            Some(StableSource::Event(plan.source(source)?.key().clone()))
        }
    };
    match (fact.source(), fact.carrier(), fact.sink()) {
        (None, None, None) => Some(StableValueFlowFact::Zero),
        (Some(source_id), Some(carrier), None) => Some(StableValueFlowFact::Carrier {
            source: source(source_id)?,
            carrier: plan.carrier_key(carrier)?.clone(),
            uncertain: !fact.uncertainty().is_empty(),
        }),
        (Some(source_id), None, Some(sink)) => Some(StableValueFlowFact::Meeting {
            source: source(source_id)?,
            sink: plan.sink(sink)?.key().clone(),
            uncertain: !fact.uncertainty().is_empty(),
        }),
        _ => None,
    }
}

fn live_fact(
    plan: &ValueFlowPlan,
    fact: &StableValueFlowFact,
    entry_source: Option<crate::value_flow::ValueFlowSourceId>,
) -> Option<ValueFlowFact> {
    let source = |source: &StableSource| match source {
        StableSource::Entry => entry_source,
        StableSource::Event(event) => plan.source_id_for_key(event),
    };
    match fact {
        StableValueFlowFact::Zero => Some(ValueFlowFact::zero()),
        StableValueFlowFact::Carrier {
            source: stable_source,
            carrier,
            uncertain,
        } => Some(ValueFlowFact::carrier_fact(
            source(stable_source)?,
            plan.carrier_id_for_key(carrier)?,
            ValueFlowUncertainty::from_semantic_uncertainty(*uncertain),
        )),
        StableValueFlowFact::Meeting {
            source: stable_source,
            sink,
            uncertain,
        } => Some(ValueFlowFact::meeting_fact(
            source(stable_source)?,
            plan.sink_id_for_key(sink)?,
            ValueFlowUncertainty::from_semantic_uncertainty(*uncertain),
        )),
    }
}

fn class_set_behavior(
    provider: IcfgProviderBehaviorIdentity,
    field_slots: StableDigest,
) -> SummaryBehaviorKey {
    let derive = |provider: &[u8; 32]| {
        let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_BEHAVIOR);
        digest.push(CLASS_SET_SUMMARY_SEMANTICS);
        digest.push(provider);
        digest.push(field_slots.as_bytes());
        digest.finish()
    };
    SummaryBehaviorKey::from_parts(derive(provider.as_bytes()), derive(provider.read_bytes()))
}

pub(super) fn class_set_local_structure_digest(
    snapshot: &ValueFlowInput<ValueFlowSnapshot>,
) -> Result<StableDigest, ValueFlowPlanError> {
    let procedure = snapshot.value().procedure().clone();
    let local_plan = ValueFlowPlan::try_new(
        procedure.clone(),
        vec![super::plan::class_set_snapshot(snapshot.clone())],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    let carrier = local_plan
        .carrier_summary_identities()
        .remove(&procedure)
        .expect("a one-snapshot local plan retains its procedure identity");
    let mut lexical = procedure
        .artifact()
        .lexical_children(procedure.id())
        .iter()
        .map(|&child| {
            let child = procedure
                .artifact()
                .procedure_handle(child)
                .expect("a live artifact owns each lexical child");
            procedure
                .artifact()
                .key()
                .procedure_lineage_fingerprint(child.semantics().locator().declaration())
        })
        .collect::<Vec<_>>();
    lexical.sort_unstable();
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-local-surface-structure-v1");
    digest.push(
        carrier
            .procedure_local_fingerprint(procedure.semantics().locator())
            .as_bytes(),
    );
    push_semantic_input_status(&mut digest, snapshot.status());
    digest.push(snapshot.value().coverage().label().as_bytes());
    let gaps = procedure.semantics().gaps();
    digest.push(
        &u64::try_from(gaps.len())
            .expect("semantic gap count fits in u64")
            .to_le_bytes(),
    );
    for gap in gaps {
        digest.push(if snapshot.value().gap_is_discharged(gap.id) {
            b"discharged"
        } else {
            b"live"
        });
    }
    digest.push(
        &u64::try_from(lexical.len())
            .expect("lexical child count fits in u64")
            .to_le_bytes(),
    );
    for child in lexical {
        digest.push(child.as_bytes());
    }
    Ok(digest.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, AllocationSite, CandidateCoverage, ClassIdentity, ClassSeed,
        DispatchHints, IcfgProvider, MemberAccessQuery, MemberLookup, OracleCallContext,
        ProcedureHandle, SemanticBudget, SemanticCallSite, SemanticCapability, SemanticRequest,
        SemanticValue, SemanticValueKind, SemanticWork, TypeFlowAdapter, UnknownReason,
        WorkspaceIcfgProvider, type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
    use crate::dataflow::{SolverBudget, SolverWork, WitnessRetentionLimits};
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::type_flow::{
        ClassSetStatus, FeedbackLimits, TypeFlowRootPersistenceRejection,
        TypeFlowRootPersistenceStatus, TypeFlowRootResult, solve_type_flow_for_root,
    };
    use crate::value_flow::{
        ClosureLimits, ValueFlowCache, ValueFlowPortKey, ValueFlowProvider, ValueFlowSummaryResult,
        WorkspaceValueFlowProvider, solve_value_flow_entry_with_reusable_summaries,
        solve_value_flow_with_reusable_summaries, solve_value_flow_with_summaries,
    };

    #[test]
    fn named_unknown_guard_payloads_have_distinct_atom_fingerprints() {
        let first = ClassAtom::Unknown(UnknownReason::UnmodeledGuard {
            class: "pkg.First".into(),
        });
        let second = ClassAtom::Unknown(UnknownReason::UnmodeledGuard {
            class: "pkg.Second".into(),
        });

        assert_ne!(
            class_atom_fingerprint(&first),
            class_atom_fingerprint(&second)
        );
    }

    #[test]
    fn summary_profile_is_typed_serializable_and_saturating() {
        let mut profile = TypeFlowSummaryProfile::default();
        profile.record(SummaryProfileReason::LookupRelation);
        profile.record(SummaryProfileReason::PublicationDependency);
        let doubled = profile.saturating_add(profile);
        assert_eq!(doubled.lookup_relation, 2);
        assert_eq!(doubled.publication_dependency, 2);
        assert_eq!(doubled.saturating_sub(profile), profile);
        assert_eq!(
            serde_json::from_str::<TypeFlowSummaryProfile>(
                &serde_json::to_string(&profile).expect("summary profile serializes")
            )
            .expect("summary profile deserializes"),
            profile
        );
    }

    fn projection_fixture(source: &str) -> (TypeFlowPlan, ValueFlowSummaryResult) {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("projection fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("projection fixture semantics remain available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("root")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("projection fixture declares root");
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        let mut field_budget = SemanticBudget::default();
        let field_slots =
            FieldSlotIndex::build(&workspace, adapter, &mut field_budget, &cancellation)
                .expect("projection fixture field slots build");
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let mut plan_budget = SemanticBudget::default();
        let plan = TypeFlowPlan::build(
            &workspace,
            adapter,
            &field_slots,
            &root,
            &provider,
            ClosureLimits { max_procedures: 16 },
            &mut plan_budget,
            &cancellation,
            &mut Default::default(),
        )
        .expect("projection fixture plan builds");
        let mut solve_budget = SemanticBudget::default();
        let mut solver_budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut solver_budget, &cancellation);
        let result = solve_value_flow_with_summaries(
            &root,
            &workspace.icfg_provider(),
            plan.value_flow(),
            &mut solve_budget,
            &mut request,
        )
        .expect("projection fixture solves");
        (plan, result)
    }

    fn entry_name(entry: &SummaryEntry) -> &str {
        entry
            .procedure()
            .semantics()
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .expect("projection fixture procedures are named")
    }

    fn nonempty_entry<'a>(
        entries: &'a [FlattenedClassSetEntry],
        name: &str,
    ) -> &'a FlattenedClassSetEntry {
        let matches = entries
            .iter()
            .filter(|entry| entry_name(&entry.entry) == name && !entry.reached.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "one live {name} entry carries projected meetings: {entries:#?}"
        );
        matches[0]
    }

    fn meeting_shape(fact: &StableValueFlowFact) -> (&ValueFlowEventKey, bool) {
        let StableValueFlowFact::Meeting {
            sink, uncertain, ..
        } = fact
        else {
            panic!("projected class-set observation is a meeting: {fact:#?}");
        };
        (sink, *uncertain)
    }

    fn runtime_fixture(
        source: &str,
    ) -> (
        BuiltInlineTestProject,
        WorkspaceAnalyzer,
        FieldSlotIndex,
        HashMap<Box<str>, ProcedureHandle>,
    ) {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        runtime_fixture_from_project(project)
    }

    fn runtime_fixture_from_project(
        project: BuiltInlineTestProject,
    ) -> (
        BuiltInlineTestProject,
        WorkspaceAnalyzer,
        FieldSlotIndex,
        HashMap<Box<str>, ProcedureHandle>,
    ) {
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        runtime_fixture_from_project_with_adapter(project, adapter)
    }

    fn runtime_fixture_from_project_with_adapter(
        project: BuiltInlineTestProject,
        adapter: &dyn TypeFlowAdapter,
    ) -> (
        BuiltInlineTestProject,
        WorkspaceAnalyzer,
        FieldSlotIndex,
        HashMap<Box<str>, ProcedureHandle>,
    ) {
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("runtime fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("runtime fixture semantics remain available");
        let procedures = artifact
            .procedures()
            .iter()
            .filter_map(|procedure| {
                let name = procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())?;
                Some((
                    Box::<str>::from(name),
                    artifact
                        .procedure_handle(procedure.id())
                        .expect("runtime fixture procedure remains live"),
                ))
            })
            .collect();
        let mut field_budget = SemanticBudget::default();
        let field_slots =
            FieldSlotIndex::build(&workspace, adapter, &mut field_budget, &cancellation)
                .expect("runtime fixture field slots build");
        (project, workspace, field_slots, procedures)
    }

    fn solve_runtime_root(
        workspace: &WorkspaceAnalyzer,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        cache: ValueFlowCache,
    ) -> TypeFlowRootResult {
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        solve_runtime_root_with_adapter(workspace, adapter, field_slots, root, state, cache)
    }

    #[test]
    fn computed_result_does_not_inherit_operand_classes() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(
            "class Result:\n    def present(self):\n        pass\n\nclass Operand:\n    def __truediv__(self, other):\n        return Result()\n\ndef root():\n    value = Operand() / Operand()\n    value.present()\n",
        );
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.findings.is_empty(), "{cold:#?}");
        let receiver = cold
            .class_sets
            .iter()
            .find(|set| set.site.member.as_ref() == "present")
            .expect("the computed receiver has a member-access observation");
        assert!(receiver.classes.is_empty(), "{receiver:#?}");
        assert!(
            receiver.unknown.contains(&UnknownReason::UncertainFlow),
            "an unmodeled operator result is explicit, not an empty proof: {receiver:#?}"
        );
        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);
        assert_eq!(warm.class_sets, cold.class_sets);
        assert!(warm.findings.is_empty(), "{warm:#?}");
    }

    fn solve_runtime_root_with_adapter(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        cache: ValueFlowCache,
    ) -> TypeFlowRootResult {
        let mut semantic_budget = SemanticBudget::default();
        let mut solver_budget = SolverBudget::default();
        solve_runtime_root_with_adapter_and_budgets(
            workspace,
            adapter,
            field_slots,
            root,
            state,
            cache,
            FeedbackLimits::default(),
            &mut semantic_budget,
            &mut solver_budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn solve_runtime_root_with_budgets(
        workspace: &WorkspaceAnalyzer,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        cache: ValueFlowCache,
        feedback_limits: FeedbackLimits,
        semantic_budget: &mut SemanticBudget,
        solver_budget: &mut SolverBudget,
    ) -> TypeFlowRootResult {
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        solve_runtime_root_with_adapter_and_budgets(
            workspace,
            adapter,
            field_slots,
            root,
            state,
            cache,
            feedback_limits,
            semantic_budget,
            solver_budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn solve_runtime_root_with_adapter_and_budgets(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        cache: ValueFlowCache,
        feedback_limits: FeedbackLimits,
        semantic_budget: &mut SemanticBudget,
        solver_budget: &mut SolverBudget,
    ) -> TypeFlowRootResult {
        let cancellation = CancellationToken::default();
        let mut request = DataflowRequest::new(solver_budget, &cancellation);
        solve_type_flow_for_root(
            workspace,
            adapter,
            field_slots,
            root,
            workspace.analyzer().active_semantic_model_snapshot(),
            ClosureLimits { max_procedures: 16 },
            feedback_limits,
            cache,
            state,
            semantic_budget,
            &mut request,
        )
        .expect("runtime fixture root solve succeeds")
    }

    struct OpenBoundSeedAdapter {
        inner: &'static dyn TypeFlowAdapter,
    }

    impl OpenBoundSeedAdapter {
        fn python() -> Self {
            Self {
                inner: type_flow_adapter(Language::Python)
                    .expect("Python registers a type-flow adapter"),
            }
        }
    }

    impl TypeFlowAdapter for OpenBoundSeedAdapter {
        fn language(&self) -> Language {
            self.inner.language()
        }

        fn semantics_version(&self) -> AdapterSemanticsVersion {
            AdapterSemanticsVersion::hash_bytes("open-bound-test", b"v1")
                .expect("test adapter identity is named")
        }

        fn constructed_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            call: &SemanticCallSite,
        ) -> ClassSeed {
            match self.inner.constructed_class(workspace, procedure, call) {
                ClassSeed::Class(class) => ClassSeed::ClassWithOpenBound(class),
                other => other,
            }
        }

        fn constant_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            value: &SemanticValue,
        ) -> ClassSeed {
            self.inner.constant_class(workspace, procedure, value)
        }

        fn allocation_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            allocation: &AllocationSite,
        ) -> ClassSeed {
            self.inner
                .allocation_class(workspace, procedure, allocation)
        }

        fn declared_parameter_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            ordinal: u32,
        ) -> ClassSeed {
            self.inner
                .declared_parameter_class(workspace, procedure, ordinal)
        }

        fn accessed_member(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            site: MemberAccessQuery<'_>,
        ) -> Option<Box<str>> {
            self.inner.accessed_member(workspace, procedure, site)
        }

        fn member_lookup(
            &self,
            workspace: &WorkspaceAnalyzer,
            kind: MemberAccessKind,
            class: &ClassIdentity,
            member: &str,
        ) -> MemberLookup {
            self.inner.member_lookup(workspace, kind, class, member)
        }
    }

    struct RetainedUnknownSeedAdapter {
        inner: &'static dyn TypeFlowAdapter,
    }

    impl RetainedUnknownSeedAdapter {
        fn python() -> Self {
            Self {
                inner: type_flow_adapter(Language::Python)
                    .expect("Python registers a type-flow adapter"),
            }
        }
    }

    impl TypeFlowAdapter for RetainedUnknownSeedAdapter {
        fn language(&self) -> Language {
            self.inner.language()
        }

        fn semantics_version(&self) -> AdapterSemanticsVersion {
            AdapterSemanticsVersion::hash_bytes("retained-unknown-test", b"v1")
                .expect("test adapter identity is named")
        }

        fn constructed_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            call: &SemanticCallSite,
        ) -> ClassSeed {
            self.inner.constructed_class(workspace, procedure, call)
        }

        fn constant_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            value: &SemanticValue,
        ) -> ClassSeed {
            self.inner.constant_class(workspace, procedure, value)
        }

        fn retained_value_class(
            &self,
            _workspace: &WorkspaceAnalyzer,
            _procedure: &ProcedureHandle,
            value: &SemanticValue,
        ) -> ClassSeed {
            if value.kind == SemanticValueKind::Callable {
                ClassSeed::Unknown(UnknownReason::OpenTypeBound)
            } else {
                ClassSeed::NotApplicable
            }
        }

        fn allocation_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            allocation: &AllocationSite,
        ) -> ClassSeed {
            self.inner
                .allocation_class(workspace, procedure, allocation)
        }

        fn declared_parameter_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            ordinal: u32,
        ) -> ClassSeed {
            self.inner
                .declared_parameter_class(workspace, procedure, ordinal)
        }

        fn accessed_member(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            site: MemberAccessQuery<'_>,
        ) -> Option<Box<str>> {
            self.inner.accessed_member(workspace, procedure, site)
        }

        fn member_lookup(
            &self,
            workspace: &WorkspaceAnalyzer,
            kind: MemberAccessKind,
            class: &ClassIdentity,
            member: &str,
        ) -> MemberLookup {
            self.inner.member_lookup(workspace, kind, class, member)
        }
    }

    #[test]
    fn retained_value_unknown_seed_reaches_an_interprocedural_member_sink() {
        let adapter = RetainedUnknownSeedAdapter::python();
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                concat!(
                    "def consume(value):\n",
                    "    return value.member\n",
                    "def root():\n",
                    "    return consume(lambda: None)\n",
                ),
            )
            .build();
        let (_project, workspace, field_slots, procedures) =
            runtime_fixture_from_project_with_adapter(project, &adapter);

        let result = solve_runtime_root_with_adapter(
            &workspace,
            &adapter,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );

        let set = result
            .class_sets
            .iter()
            .find(|set| set.site.member.as_ref() == "member")
            .expect("the callable value reaches the callee's member sink");
        assert_eq!(set.status, ClassSetStatus::Partial, "{set:#?}");
        assert!(
            set.unknown.contains(&UnknownReason::OpenTypeBound),
            "the adapter's typed unknown seed must survive propagation: {set:#?}"
        );
    }

    #[test]
    fn type_flow_persistence_accepts_a_fixed_point_with_typed_open_rows() {
        let (_project, workspace, field_slots, procedures) =
            runtime_fixture(concat!("def root(value):\n", "    return value.missing\n",));

        let result = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );

        assert!(
            result.complete,
            "the open-boundary solve reaches a fixed point"
        );
        assert_eq!(
            result.persistence_status,
            TypeFlowRootPersistenceStatus::Eligible,
            "stable typed uncertainty is durable when the engine reaches a fixed point"
        );
        assert!(
            result
                .class_sets
                .iter()
                .any(|set| !set.unknown.is_empty() && set.status != ClassSetStatus::Known),
            "the fixture must exercise an open typed row: {result:#?}"
        );
    }

    #[test]
    fn type_flow_persistence_rejects_solver_and_semantic_budget_results() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n",
            "    def member(self):\n",
            "        pass\n",
            "def root():\n",
            "    value = Present()\n",
            "    return value.member\n",
        ));

        let mut solver_limits = SolverWork::default_limits();
        solver_limits.reached_states = 1;
        let mut solver_budget = SolverBudget::new(solver_limits);
        let solver_limited = solve_runtime_root_with_budgets(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
            FeedbackLimits::new(1),
            &mut SemanticBudget::default(),
            &mut solver_budget,
        );
        assert!(
            !solver_limited.complete,
            "the solver ceiling stops the fixed point"
        );
        assert_eq!(
            solver_limited.persistence_status,
            TypeFlowRootPersistenceStatus::Ineligible(
                TypeFlowRootPersistenceRejection::SolverIncomplete
            )
        );

        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        let cancellation = CancellationToken::default();
        let mut field_budget =
            SemanticBudget::new(SemanticWork::uniform(1)).expect("positive semantic limits");
        let incomplete_field_slots =
            FieldSlotIndex::build(&workspace, adapter, &mut field_budget, &cancellation)
                .expect("a bounded field-slot build returns its typed incomplete index");
        assert!(incomplete_field_slots.semantic_budget_exhausted());
        let semantic_limited = solve_runtime_root(
            &workspace,
            &incomplete_field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert_eq!(
            semantic_limited.persistence_status,
            TypeFlowRootPersistenceStatus::Ineligible(
                TypeFlowRootPersistenceRejection::SemanticBudget
            )
        );
    }

    #[test]
    fn feedback_persistence_rejects_an_earlier_result_after_a_later_incomplete_pass() {
        let source = concat!(
            "class Present:\n",
            "    def member(self):\n",
            "        pass\n",
            "def root():\n",
            "    value = Present()\n",
            "    return value.member()\n",
        );
        let (_project, measurement_workspace, measurement_field_slots, measurement_procedures) =
            runtime_fixture(source);

        let mut one_pass_semantic_budget = SemanticBudget::default();
        let mut one_pass_solver_budget = SolverBudget::default();
        let one_pass = solve_runtime_root_with_budgets(
            &measurement_workspace,
            &measurement_field_slots,
            &measurement_procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
            FeedbackLimits::new(1),
            &mut one_pass_semantic_budget,
            &mut one_pass_solver_budget,
        );
        assert_eq!(
            one_pass.persistence_status,
            TypeFlowRootPersistenceStatus::Eligible
        );

        // Use a distinct workspace so the calibration solve cannot publish a
        // summary that changes the work shape of the bounded solve.
        let (_project, workspace, field_slots, procedures) = runtime_fixture(source);
        let mut feedback_semantic_budget = SemanticBudget::default();
        let mut feedback_solver_budget = SolverBudget::new(one_pass_solver_budget.used());
        let fallback = solve_runtime_root_with_budgets(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
            FeedbackLimits::default(),
            &mut feedback_semantic_budget,
            &mut feedback_solver_budget,
        );

        assert!(
            fallback.complete,
            "feedback returns the earlier complete result after the refinement stops; one-pass work={:?}; fallback={fallback:#?}",
            one_pass_solver_budget.used(),
        );
        assert_eq!(result_site_shape(&fallback), result_site_shape(&one_pass));
        assert_eq!(
            fallback.persistence_status,
            TypeFlowRootPersistenceStatus::Ineligible(
                TypeFlowRootPersistenceRejection::FeedbackFallback
            )
        );
    }

    fn runtime_plan(
        workspace: &WorkspaceAnalyzer,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
    ) -> (TypeFlowPlan, IcfgProviderBehaviorIdentity) {
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        let cancellation = CancellationToken::default();
        let provider = WorkspaceValueFlowProvider::new(workspace, ValueFlowCache::default());
        let mut semantic_budget = SemanticBudget::default();
        let plan = TypeFlowPlan::build(
            workspace,
            adapter,
            field_slots,
            root,
            &provider,
            ClosureLimits { max_procedures: 16 },
            &mut semantic_budget,
            &cancellation,
            &mut Default::default(),
        )
        .expect("runtime identity fixture plan builds");
        let behavior = WorkspaceIcfgProvider::new(workspace).behavior_identity();
        (plan, behavior)
    }

    fn runtime_cut_plan(
        workspace: &WorkspaceAnalyzer,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        hints: DispatchHints,
    ) -> (TypeFlowPlan, ClassSetCutManifest) {
        runtime_cut_plan_with_cache(
            workspace,
            field_slots,
            root,
            state,
            hints,
            ValueFlowCache::default(),
        )
    }

    fn runtime_cut_plan_with_cache(
        workspace: &WorkspaceAnalyzer,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        hints: DispatchHints,
        cache: ValueFlowCache,
    ) -> (TypeFlowPlan, ClassSetCutManifest) {
        runtime_cut_plan_with_disabled_cuts(
            workspace,
            field_slots,
            root,
            state,
            hints,
            cache,
            HashSet::default(),
        )
    }

    fn runtime_cut_plan_with_disabled_cuts(
        workspace: &WorkspaceAnalyzer,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        state: TypeFlowSummaryState,
        hints: DispatchHints,
        cache: ValueFlowCache,
        disabled_cuts: HashSet<DurableProcedureKey>,
    ) -> (TypeFlowPlan, ClassSetCutManifest) {
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        let cancellation = CancellationToken::default();
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            workspace,
            workspace.analyzer().active_semantic_model_snapshot(),
            hints,
        );
        let discovery = WorkspaceValueFlowProvider::with_oracle(
            provider.oracle().clone(),
            provider.behavior_identity(),
            cache,
        );
        let mut cuts = ClassSetAcquisitionCuts::new(
            state,
            workspace,
            &discovery,
            provider.behavior_identity(),
            field_slots,
            disabled_cuts,
        );
        let mut semantic_budget = SemanticBudget::default();
        let plan = TypeFlowPlan::build_with_summary_cuts(
            workspace,
            adapter,
            field_slots,
            root,
            &discovery,
            ClosureLimits { max_procedures: 16 },
            &mut semantic_budget,
            &cancellation,
            &mut Default::default(),
            &mut cuts,
        )
        .expect("runtime cut fixture plan builds");
        (plan, cuts.take_manifest())
    }

    fn summary_name(summary: &ClassSetProcedureSummary) -> &str {
        summary
            .key
            .procedure_locator
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .expect("runtime fixture summaries are named")
    }

    fn procedure_name(procedure: &ProcedureHandle) -> &str {
        procedure
            .semantics()
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .expect("runtime fixture procedures are named")
    }

    fn result_site_shape(result: &TypeFlowRootResult) -> Vec<(Box<str>, Box<str>)> {
        let mut sites = result
            .class_sets
            .iter()
            .map(|set| {
                (
                    Box::<str>::from(procedure_name(&set.site.procedure)),
                    set.site.member.clone(),
                )
            })
            .collect::<Vec<_>>();
        sites.sort_unstable();
        sites
    }

    fn plan_site_shape(plan: &TypeFlowPlan) -> Vec<(Box<str>, Box<str>)> {
        let mut sites = plan
            .value_flow()
            .sinks()
            .map(|(sink, _)| {
                let site = plan.sink(sink);
                (
                    Box::<str>::from(procedure_name(&site.procedure)),
                    site.member.clone(),
                )
            })
            .collect::<Vec<_>>();
        sites.sort_unstable();
        sites
    }

    #[test]
    fn open_call_eligibility_and_digest_pin_every_coverage_axis() {
        fn digest(coverage: &CallSiteCoverage) -> StableDigest {
            let mut digest = LengthDelimitedDigest::new(b"test-call-coverage-contract");
            push_call_coverage_contract(&mut digest, coverage);
            digest.finish()
        }

        let (_project, _workspace, _field_slots, procedures) =
            runtime_fixture("def root():\n    pass\n");
        let callee = procedures["root"].clone();
        let base = CallSiteCoverage {
            entered: Vec::new(),
            has_uncovered_boundary: true,
            truncated: false,
            complete_receiver_hint_refinable: false,
            dispatch: DispatchStatus::Resolved {
                status: SemanticInputStatus::Unknown,
                coverage: CandidateCoverage::Open,
            },
            bindings: Vec::new(),
        };
        assert!(call_coverage_is_summary_eligible(Some(&base)));
        assert!(!call_coverage_is_summary_eligible(None));

        for status in [
            SemanticInputStatus::Complete,
            SemanticInputStatus::Ambiguous,
            SemanticInputStatus::Unknown,
            SemanticInputStatus::Unsupported {
                capability: SemanticCapability::Calls,
            },
            SemanticInputStatus::Unproven,
        ] {
            let mut coverage = base.clone();
            coverage.entered.push(callee.clone());
            coverage.bindings.push(BindingCoverage::Answered { status });
            assert!(
                call_coverage_is_summary_eligible(Some(&coverage)),
                "stable non-resource binding status remains eligible: {status:?}"
            );
        }
        let mut unavailable_binding = base.clone();
        unavailable_binding
            .bindings
            .push(BindingCoverage::Answered {
                status: SemanticInputStatus::Unknown,
            });
        assert!(
            call_coverage_is_summary_eligible(Some(&unavailable_binding)),
            "a stable answered binding may have no available entered target"
        );

        let mut semantic_limits = SemanticBudget::default().limits();
        semantic_limits.procedures = 1;
        let exceeded = SemanticBudget::new(semantic_limits)
            .expect("positive semantic limits")
            .check(SemanticWork {
                procedures: 2,
                ..SemanticWork::default()
            })
            .expect_err("the test charge exceeds the procedure limit");

        let mut refused = Vec::new();
        let mut truncated_flag = base.clone();
        truncated_flag.truncated = true;
        refused.push(truncated_flag);
        let mut truncated_candidates = base.clone();
        truncated_candidates.dispatch = DispatchStatus::Resolved {
            status: SemanticInputStatus::Complete,
            coverage: CandidateCoverage::Truncated,
        };
        refused.push(truncated_candidates);
        let mut dispatch_error = base.clone();
        dispatch_error.dispatch = DispatchStatus::ProviderError {
            detail: "dispatch failed".to_owned(),
        };
        refused.push(dispatch_error);
        let mut dispatch_budget = base.clone();
        dispatch_budget.dispatch = DispatchStatus::Unavailable {
            status: SemanticInputStatus::ExceededBudget { exceeded },
        };
        refused.push(dispatch_budget);
        let mut dispatch_cancelled = base.clone();
        dispatch_cancelled.dispatch = DispatchStatus::Unavailable {
            status: SemanticInputStatus::Cancelled,
        };
        refused.push(dispatch_cancelled);
        let mut cardinality_mismatch = base.clone();
        cardinality_mismatch.entered.push(callee.clone());
        refused.push(cardinality_mismatch);
        let mut binding_error = base.clone();
        binding_error.entered.push(callee.clone());
        binding_error.bindings.push(BindingCoverage::ProviderError {
            detail: "binding failed".to_owned(),
        });
        refused.push(binding_error);
        for status in [
            SemanticInputStatus::ExceededBudget { exceeded },
            SemanticInputStatus::Cancelled,
        ] {
            let mut coverage = base.clone();
            coverage.entered.push(callee.clone());
            coverage.bindings.push(BindingCoverage::Answered { status });
            refused.push(coverage);
        }
        for coverage in refused {
            assert!(
                !call_coverage_is_summary_eligible(Some(&coverage)),
                "incomplete or resource-limited coverage must refuse: {coverage:#?}"
            );
        }

        let base_digest = digest(&base);
        let mut covered_flag = base.clone();
        covered_flag.has_uncovered_boundary = false;
        assert_ne!(base_digest, digest(&covered_flag));
        let mut truncated_flag = base.clone();
        truncated_flag.truncated = true;
        assert_ne!(base_digest, digest(&truncated_flag));
        let mut receiver_refinable = base.clone();
        receiver_refinable.complete_receiver_hint_refinable = true;
        assert_ne!(base_digest, digest(&receiver_refinable));
        let mut exhaustive = base.clone();
        exhaustive.dispatch = DispatchStatus::Resolved {
            status: SemanticInputStatus::Unknown,
            coverage: CandidateCoverage::Exhaustive,
        };
        assert_ne!(base_digest, digest(&exhaustive));
        let mut unsupported_calls = base.clone();
        unsupported_calls.dispatch = DispatchStatus::Unavailable {
            status: SemanticInputStatus::Unsupported {
                capability: SemanticCapability::Calls,
            },
        };
        let mut unsupported_values = unsupported_calls.clone();
        unsupported_values.dispatch = DispatchStatus::Unavailable {
            status: SemanticInputStatus::Unsupported {
                capability: SemanticCapability::Values,
            },
        };
        assert_ne!(digest(&unsupported_calls), digest(&unsupported_values));
    }

    #[test]
    fn guarded_entries_partition_sources_by_edge_kill_behavior() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class A:\n    def foo(self):\n        pass\n",
            "class B:\n    pass\n",
            "def guarded(value):\n",
            "    if hasattr(value, \"foo\"):\n        return value\n",
            "    return value\n",
            "def root():\n",
            "    guarded(A())\n    guarded(A())\n    guarded(B())\n",
        ));
        let (plan, _behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let carrier = plan
            .value_flow()
            .carrier_keys()
            .first()
            .expect("the guarded fixture has a carrier");
        let carrier_id = plan
            .value_flow()
            .carrier_id_for_key(carrier)
            .expect("the fixture carrier remains bound");
        let guarded_identity = plan
            .value_flow()
            .carrier_summary_identities()
            .remove(&procedures["guarded"])
            .expect("guarded has carrier semantics");
        let source_behavior = guarded_identity.source_behavior_identity();
        let mut a_entries = Vec::new();
        let mut b_entries = Vec::new();
        for (source, spec) in plan
            .value_flow()
            .sources()
            .filter(|(_, spec)| spec.point().procedure() == &procedures["root"])
        {
            let ClassAtom::Class(class) = plan.atom(source) else {
                continue;
            };
            let entry = stable_entry_fact(
                plan.value_flow(),
                Some(
                    source_behavior
                        .fingerprint(procedures["guarded"].semantics().locator(), spec.key()),
                ),
                ValueFlowFact::carrier_fact(source, carrier_id, ValueFlowUncertainty::empty()),
            )
            .expect("one class source and carrier form a stable entry");
            match class.qualified_name() {
                "app.A" => a_entries.push((spec.key().clone(), entry)),
                "app.B" => b_entries.push((spec.key().clone(), entry)),
                _ => {}
            }
        }
        assert!(
            a_entries.len() >= 2,
            "two A call sites remain distinct sources"
        );
        assert_eq!(b_entries.len(), 1, "one B call site supplies one source");
        assert!(
            a_entries.iter().all(|(_, entry)| entry == &a_entries[0].1),
            "equivalent A sources share one symbolic entry: {a_entries:#?}"
        );
        assert_ne!(
            a_entries[0].1, b_entries[0].1,
            "A and B take different hasattr arms"
        );
        assert_eq!(
            stable_entry_fingerprint(&a_entries[0].1, procedures["guarded"].semantics().locator(),),
            stable_entry_fingerprint(&a_entries[1].1, procedures["guarded"].semantics().locator(),),
        );
        assert_ne!(
            stable_entry_fingerprint(&a_entries[0].1, procedures["guarded"].semantics().locator(),),
            stable_entry_fingerprint(&b_entries[0].1, procedures["guarded"].semantics().locator(),),
        );

        let mut partitions = plan
            .value_flow()
            .sources()
            .filter(|(_, spec)| spec.point().procedure() == &procedures["root"])
            .map(|(source, spec)| {
                (
                    source_behavior
                        .fingerprint(procedures["guarded"].semantics().locator(), spec.key()),
                    source,
                )
            })
            .collect::<Vec<_>>();
        partitions.sort_unstable();
        partitions.dedup_by_key(|(partition, _)| *partition);
        let missing = (0_u8..=u8::MAX)
            .map(|byte| StableDigest::from_array([byte; 32]))
            .find(|candidate| {
                partitions
                    .binary_search_by_key(candidate, |row| row.0)
                    .is_err()
            })
            .expect("the finite guard partitions leave an unmatched digest");
        let StableEntryFact::Carrier {
            carrier, uncertain, ..
        } = &a_entries[0].1
        else {
            unreachable!("a class carrier source forms a carrier entry")
        };
        assert!(
            maintenance_entry_fact(
                plan.value_flow(),
                true,
                &partitions,
                &StableEntryFact::Carrier {
                    carrier: carrier.clone(),
                    uncertain: *uncertain,
                    source_partition: Some(missing),
                },
            )
            .is_none(),
            "maintenance fails closed when the stored behavior has no live source"
        );
    }

    #[test]
    fn guard_outcome_edit_rotates_source_behavior_partition() {
        fn guarded_identities(
            source: &str,
        ) -> (
            StableDigest,
            StableDigest,
            StableDigest,
            StableDigest,
            StableDigest,
        ) {
            let (_project, workspace, field_slots, procedures) = runtime_fixture(source);
            let (plan, _behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
            let guarded = &procedures["guarded"];
            let carrier_identity = plan
                .value_flow()
                .carrier_summary_identities()
                .remove(guarded)
                .expect("guarded has carrier semantics");
            let source_behavior = carrier_identity.source_behavior_identity();
            let source_for = |name: &str| {
                plan.value_flow()
                    .sources()
                    .find(|(source, spec)| {
                        spec.point().procedure() == &procedures["root"]
                            && matches!(
                                plan.atom(*source),
                                ClassAtom::Class(class) if class.qualified_name() == name
                            )
                    })
                    .map(|(source, _)| source)
                    .expect("every constructor supplies one class source")
            };
            let a = source_for("app.A");
            let b = source_for("app.B");
            let behavior_for = |source| {
                source_behavior.fingerprint(
                    guarded.semantics().locator(),
                    plan.value_flow()
                        .source(source)
                        .expect("every source remains live")
                        .key(),
                )
            };
            let carrier = plan
                .value_flow()
                .carrier_keys()
                .iter()
                .find(|carrier| {
                    matches!(
                        carrier,
                        ValueFlowCarrierKey::Port {
                            procedure,
                            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
                        } if procedure == guarded.semantics().locator()
                    )
                })
                .expect("guarded retains its parameter carrier");
            let entry = StableEntryFact::Carrier {
                carrier: Box::new(carrier.clone()),
                uncertain: false,
                source_partition: Some(behavior_for(a)),
            };
            let carrier_semantics = carrier_identity
                .procedure_closure_fingerprint(guarded.semantics().locator(), &HashMap::default());
            (
                class_atom_fingerprint(plan.atom(a)),
                behavior_for(a),
                behavior_for(b),
                stable_entry_fingerprint(&entry, guarded.semantics().locator()),
                carrier_semantics,
            )
        }

        let before = guarded_identities(concat!(
            "class A:\n    def foo(self):\n        pass\n",
            "class B:\n    def foo(self):\n        pass\n",
            "class C:\n    def bar(self):\n        pass\n",
            "def guarded(value):\n",
            "    if hasattr(value, \"foo\"):\n        return value\n",
            "    return value\n",
            "def root():\n    guarded(A())\n    guarded(B())\n    guarded(C())\n",
        ));
        let after = guarded_identities(concat!(
            "class A:\n    def bar(self):\n        pass\n",
            "class B:\n    def foo(self):\n        pass\n",
            "class C:\n    def bar(self):\n        pass\n",
            "def guarded(value):\n",
            "    if hasattr(value, \"foo\"):\n        return value\n",
            "    return value\n",
            "def root():\n    guarded(A())\n    guarded(B())\n    guarded(C())\n",
        ));
        assert_eq!(before.0, after.0, "A keeps one declaration identity");
        assert_eq!(
            before.4, after.4,
            "external membership stays out of procedure carrier semantics"
        );
        assert_eq!(
            before.1, before.2,
            "distinct classes taking the same arm share one behavior partition"
        );
        assert_ne!(
            before.1, after.1,
            "changing A's member set changes its exact kill-locus membership"
        );
        assert_ne!(
            before.3, after.3,
            "A's reusable entry selector rotates with its guard outcome"
        );
    }

    #[test]
    fn dependency_rejects_when_one_of_two_equivalent_sources_changes_behavior() {
        let (_project, workspace, slots, procedures) = runtime_fixture(concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def wrapper(value):\n    return guarded(value)\n",
            "def root():\n    wrapper(A())\n    wrapper(None)\n",
        ));
        let (plan, provider) = runtime_plan(&workspace, &slots, &procedures["root"]);
        let mut prepared = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &plan,
            &slots,
            provider,
        );
        let sources = plan
            .value_flow()
            .sources()
            .filter(|(_, spec)| spec.point().procedure() == &procedures["root"])
            .map(|(source, _)| source)
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 2);
        let behaviors = sources
            .iter()
            .map(|source| {
                prepared
                    .source_behavior_for(&procedures["guarded"], *source)
                    .expect("the guarded behavior is bounded")
            })
            .collect::<Vec<_>>();
        assert_ne!(behaviors[0], behaviors[1]);
        let carrier = plan
            .value_flow()
            .carrier_keys()
            .iter()
            .find(|carrier| {
                matches!(
                    carrier,
                    ValueFlowCarrierKey::Port {
                        procedure,
                        kind: ValueFlowPortKey::Parameter { ordinal: 0 },
                    } if procedure == procedures["guarded"].semantics().locator()
                )
            })
            .expect("guarded has a parameter entry")
            .clone();
        let entry = StableEntryFact::Carrier {
            carrier: Box::new(carrier),
            uncertain: false,
            source_partition: Some(behaviors[1]),
        };
        let mut dependency = ClassSetRelationDependency {
            procedure_lineage: prepared.procedures[&procedures["guarded"]]
                .semantic
                .key()
                .identity()
                .read_lineage_fingerprint(),
            entry_selector: stable_entry_fingerprint(
                &entry,
                procedures["guarded"].semantics().locator(),
            ),
            entry: stable_dependency_entry(&entry, procedures["guarded"].semantics().locator()),
            source_witnesses: [
                source_witness_fingerprint(plan.value_flow(), sources[0]).unwrap(),
                source_witness_fingerprint(plan.value_flow(), sources[1]).unwrap(),
            ]
            .into(),
            output: ClassSetSummaryOutputDigest::new([7; 32]),
            consumed_lookup: StableDigest::sha256(b"old-child"),
        };

        let cancellation = CancellationToken::new();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            prepared
                .resolve_dependency_entry(&procedures["guarded"], &dependency, None, &mut request)
                .expect("witness validation is within budget")
                .is_none(),
            "one diverged source invalidates the dependency even while the other retains it"
        );
        dependency.source_witnesses = dependency.source_witnesses[1..].into();
        assert!(
            prepared
                .resolve_dependency_entry(&procedures["guarded"], &dependency, None, &mut request)
                .expect("the matching witness stays within budget")
                .is_some()
        );
    }

    #[test]
    fn source_witness_is_procedure_local_across_preceding_sibling_edits() {
        fn witness(source: &str) -> StableDigest {
            let (_project, workspace, slots, procedures) = runtime_fixture(source);
            let (plan, _provider) = runtime_plan(&workspace, &slots, &procedures["root"]);
            let source = plan
                .value_flow()
                .sources()
                .find(|(_, spec)| spec.point().procedure() == &procedures["root"])
                .map(|(source, _)| source)
                .expect("root has one class source");
            source_witness_fingerprint(plan.value_flow(), source).unwrap()
        }

        let before = witness(concat!(
            "class A:\n    pass\n",
            "def sibling():\n    return None\n",
            "def root():\n    return A()\n",
        ));
        let after = witness(concat!(
            "class A:\n    pass\n",
            "def sibling():\n    value = None\n    return value\n",
            "def root():\n    return A()\n",
        ));
        assert_eq!(before, after);
    }

    #[test]
    fn local_structure_digest_is_relative_and_tracks_local_structure() {
        fn digest(source: &str) -> StableDigest {
            let (_project, workspace, _slots, procedures) = runtime_fixture(source);
            let cancellation = CancellationToken::default();
            let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
            let mut semantic_budget = SemanticBudget::default();
            let outcome = provider
                .procedure_snapshot(
                    &procedures["root"],
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
                )
                .expect("local structure snapshot materializes");
            let status = SemanticInputStatus::from_outcome(&outcome);
            let snapshot = outcome
                .available_value()
                .cloned()
                .expect("local structure snapshot is available");
            class_set_local_structure_digest(&ValueFlowInput::new(snapshot, status))
                .expect("local structure identity builds")
        }

        let before = digest(concat!(
            "def helper(value):\n    return value\n",
            "def sibling():\n    return None\n",
            "def root(value):\n    return helper(value)\n",
        ));
        let shifted = digest(concat!(
            "def helper(value):\n    return value\n",
            "def sibling():\n    value = None\n    return value\n",
            "def root(value):\n    return helper(value)\n",
        ));
        let local_relation_changed = digest(concat!(
            "def helper(value):\n    return value\n",
            "def sibling():\n    return None\n",
            "def root(value):\n    alias = value\n    return helper(alias)\n",
        ));
        let lexical_child_added = digest(concat!(
            "def helper(value):\n    return value\n",
            "def sibling():\n    return None\n",
            "def root(value):\n",
            "    def nested():\n        return None\n",
            "    return helper(value)\n",
        ));
        let call_structure_changed = digest(concat!(
            "def helper(value):\n    return value\n",
            "def sibling():\n    return None\n",
            "def root(value):\n    return value\n",
        ));

        assert_eq!(before, shifted, "preceding sibling edits preserve identity");
        assert_ne!(before, local_relation_changed);
        assert_ne!(before, lexical_child_added);
        assert_ne!(before, call_structure_changed);
    }

    #[test]
    fn descendant_guard_source_identity_is_relative_to_its_owner() {
        fn parent_carrier(source: &str) -> StableDigest {
            let (_project, workspace, field_slots, procedures) = runtime_fixture(source);
            let (plan, _behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
            let carrier = plan
                .value_flow()
                .carrier_summary_identities()
                .remove(&procedures["parent"])
                .expect("parent has carrier semantics");
            let internal_sources = carrier
                .edge_kill_sources()
                .filter(|source| {
                    source
                        .site()
                        .belongs_to_procedure(procedures["make"].semantics().locator())
                })
                .map(|source| {
                    (
                        source.clone(),
                        procedures["make"].semantics().locator().clone(),
                    )
                })
                .collect::<HashMap<_, _>>();
            carrier.procedure_closure_fingerprint(
                procedures["parent"].semantics().locator(),
                &internal_sources,
            )
        }

        let before = parent_carrier(concat!(
            "class A:\n    def foo(self):\n        pass\n",
            "def sibling():\n    return None\n",
            "def make():\n    return A()\n",
            "def parent():\n",
            "    value = make()\n",
            "    if hasattr(value, \"foo\"):\n        return value\n",
            "    return value\n",
            "def root():\n    return parent()\n",
        ));
        let after = parent_carrier(concat!(
            "class A:\n    def foo(self):\n        pass\n",
            "def sibling():\n    value = None\n    return value\n",
            "def make():\n    return A()\n",
            "def parent():\n",
            "    value = make()\n",
            "    if hasattr(value, \"foo\"):\n        return value\n",
            "    return value\n",
            "def root():\n    return parent()\n",
        ));
        assert_eq!(
            before, after,
            "moving a descendant with a preceding sibling preserves owner-relative semantics"
        );
    }

    #[test]
    fn guarded_runtime_warm_replay_preserves_exact_results() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value.__class__\n",
            "    return value.__class__\n",
            "def wrapper(value):\n    guarded(value)\n",
            "def root():\n    wrapper(A())\n    wrapper(None)\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        let mut runtime_before = state.class_set.runtime_snapshot();
        runtime_before.sort_unstable_by_key(|summary| class_set_lookup_fingerprint(&summary.key));
        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache,
        );
        let mut runtime_after = state.class_set.runtime_snapshot();
        runtime_after.sort_unstable_by_key(|summary| class_set_lookup_fingerprint(&summary.key));
        assert!(
            cold.published_summaries > 0,
            "the cold solve publishes summaries"
        );
        assert!(
            warm.reusable_summary_hits > 0,
            "the warm solve reuses summaries"
        );
        assert_eq!(warm.reusable_root_summary_hits, 1, "{warm:#?}");
        assert_eq!(warm.published_summaries, 0, "{warm:#?}");
        assert_eq!(
            warm.reusable_root_summary_observation_rejections, 0,
            "{warm:#?}"
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert_eq!(runtime_after, runtime_before);
        let durable = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(
            durable.reusable_summary_hits > 0,
            "a fresh runtime state restores the source-sensitive rows from the store"
        );
        assert_eq!(durable.reusable_root_summary_hits, 1, "{durable:#?}");
        assert_eq!(durable.published_summaries, 0, "{durable:#?}");
        assert_eq!(durable.class_sets, cold.class_sets);
        assert_eq!(durable.findings, cold.findings);
    }

    #[test]
    fn complete_root_meetings_skip_fresh_solving_with_identical_class_sets() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def root():\n    value = Present()\n    return value.member\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);
        assert_eq!(warm.reusable_root_summary_hits, 1, "{warm:#?}");
        assert_eq!(warm.published_summaries, 0, "{warm:#?}");
        assert_eq!(
            warm.reusable_root_summary_observation_rejections, 0,
            "{warm:#?}"
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert_eq!(warm.complete, cold.complete);
    }

    #[test]
    fn persisted_root_callback_budget_refusal_publishes_nothing() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def root():\n    value = Present()\n    return value.member\n",
        ));
        let cold_state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            cold_state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let root_summary = cold_state
            .class_set
            .runtime_snapshot()
            .into_iter()
            .find(|summary| {
                summary_name(summary) == "root"
                    && matches!(summary.key.entry, StableEntryFact::Zero)
            })
            .expect("the cold solve persists an exact root relation");
        let root_lookup = *class_set_lookup_fingerprint(&root_summary.key).as_bytes();
        let store = workspace
            .store()
            .expect("the inline workspace has a persistent analyzer store");
        let persisted_before = store
            .class_set_summary_for_digest(root_lookup)
            .expect("the persisted root lookup succeeds")
            .expect("the persisted root relation exists");

        let restored_state = TypeFlowSummaryState::default();
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut prepared = PreparedClassSetSummaries::new(
            restored_state.clone(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        prepared.take_retained_publication_writes();
        assert!(prepared.has_reusable_rows());
        let runtime_before = restored_state.class_set.runtime_snapshot();
        let cancellation = CancellationToken::default();
        let provider = WorkspaceIcfgProvider::new(&workspace);
        let mut semantic_budget = SemanticBudget::default();
        let mut limits = SolverWork::default_limits();
        limits.callback_rows = 0;
        let mut solver_budget = SolverBudget::new(limits);
        let result = solve_value_flow_with_reusable_summaries(
            &procedures["root"],
            &provider,
            &mut prepared,
            plan.value_flow(),
            WitnessRetentionLimits::disabled(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("a refused optional root summary falls back to ordinary solving");

        assert_eq!(result.result().metrics().reusable_root_summary_hits, 0);
        assert_eq!(solver_budget.used().summary_applications, 0);
        assert_eq!(restored_state.class_set.runtime_snapshot(), runtime_before);
        assert!(prepared.used.is_empty());
        assert!(prepared.pending_root_summary.is_none());
        assert!(!prepared.take_retained_publication_writes());
        let persisted_after = store
            .class_set_summary_for_digest(root_lookup)
            .expect("the persisted root lookup still succeeds")
            .expect("the persisted root relation remains present");
        assert_eq!(persisted_after, persisted_before);

        let staged_state = TypeFlowSummaryState::default();
        let mut prepared = PreparedClassSetSummaries::new(
            staged_state.clone(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        prepared.take_retained_publication_writes();
        assert!(prepared.has_reusable_rows());
        let mut limits = SolverWork::default_limits();
        limits.reached_states = 1;
        let mut solver_budget = SolverBudget::new(limits);
        let result = solve_value_flow_with_reusable_summaries(
            &procedures["root"],
            &provider,
            &mut prepared,
            plan.value_flow(),
            WitnessRetentionLimits::disabled(),
            &mut SemanticBudget::default(),
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("a root rejected after provider staging falls back");
        assert_eq!(result.result().metrics().reusable_root_summary_hits, 0);
        assert_eq!(solver_budget.used().summary_applications, 0);
        assert!(staged_state.class_set.runtime_snapshot().is_empty());
        assert!(prepared.used.is_empty());
        assert!(prepared.pending_root_summary.is_none());
        assert!(!prepared.take_retained_publication_writes());
    }

    #[test]
    fn source_sensitive_root_late_refusal_does_not_warm_behavior_cache() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class A:\n    def member(self):\n        pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def root():\n",
            "    value = guarded(A())\n",
            "    return value.member\n",
        ));
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let state = TypeFlowSummaryState::default();
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut recursive_callee = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let cancellation = CancellationToken::default();
        let mut callee_budget = SolverBudget::default();
        assert!(
            recursive_callee
                .summary_for(
                    &procedures["root"],
                    &procedures["root"],
                    ValueFlowFact::zero(),
                    &mut DataflowRequest::new(&mut callee_budget, &cancellation),
                )
                .expect("a recursive root callee lookup completes")
                .is_some()
        );
        assert!(
            recursive_callee.pending_root_summary.is_none(),
            "an ordinary recursive callee lookup must not open a root transaction"
        );

        let mut prepared = PreparedClassSetSummaries::new(
            state.clone(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        prepared.take_retained_publication_writes();
        assert!(prepared.has_reusable_rows());
        assert!(prepared.source_behavior_cache.is_empty());
        let mut probe_budget = SolverBudget::default();
        assert!(
            prepared
                .root_summary_for(
                    &procedures["root"],
                    ValueFlowFact::zero(),
                    &mut DataflowRequest::new(&mut probe_budget, &cancellation),
                )
                .expect("the persisted source-sensitive root validates")
                .is_some()
        );
        assert!(
            prepared
                .pending_root_summary
                .as_ref()
                .is_some_and(|pending| !pending.source_behaviors.is_empty()),
            "dependency validation stages source behavior inside the root transaction"
        );
        assert!(prepared.source_behavior_cache.is_empty());
        prepared.discard_root_summary(&procedures["root"]);
        assert!(prepared.pending_root_summary.is_none());
        assert!(prepared.source_behavior_cache.is_empty());
        assert!(prepared.used.is_empty());

        assert!(prepared.has_reusable_rows());
        let provider = WorkspaceIcfgProvider::new(&workspace);
        let mut limits = SolverWork::default_limits();
        limits.reached_states = 1;
        let mut solver_budget = SolverBudget::new(limits);
        let result = solve_value_flow_with_reusable_summaries(
            &procedures["root"],
            &provider,
            &mut prepared,
            plan.value_flow(),
            WitnessRetentionLimits::disabled(),
            &mut SemanticBudget::default(),
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("late root admission refusal falls back to ordinary solving");
        assert_eq!(result.result().metrics().reusable_root_summary_hits, 0);
        assert_eq!(solver_budget.used().summary_applications, 0);
        assert!(prepared.pending_root_summary.is_none());
        assert!(prepared.source_behavior_cache.is_empty());
        assert!(prepared.used.is_empty());
        assert!(state.class_set.runtime_snapshot().is_empty());
        assert!(!prepared.take_retained_publication_writes());
    }

    #[test]
    fn complete_root_replay_preserves_multi_class_order() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class A:\n    def member(self):\n        pass\n",
            "class B:\n    def member(self):\n        pass\n",
            "def root(flag):\n",
            "    if flag:\n        value = B()\n",
            "    else:\n        value = A()\n",
            "    return value.member\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);

        assert_eq!(cold.class_sets.len(), 1, "{cold:#?}");
        assert_eq!(cold.class_sets[0].classes.len(), 2, "{cold:#?}");
        assert_eq!(warm.reusable_root_summary_hits, 1, "{warm:#?}");
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
    }

    #[test]
    fn complete_root_replay_preserves_open_class_and_typed_remainder() {
        let adapter = OpenBoundSeedAdapter::python();
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                concat!(
                    "class Present:\n",
                    "    def known(self):\n",
                    "        pass\n",
                    "def wrapper(value):\n",
                    "    return value.known\n",
                    "def root():\n",
                    "    return wrapper(Present())\n",
                ),
            )
            .build();
        let (_project, workspace, field_slots, procedures) =
            runtime_fixture_from_project_with_adapter(project, &adapter);
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root_with_adapter(
            &workspace,
            &adapter,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        let warm = solve_runtime_root_with_adapter(
            &workspace,
            &adapter,
            &field_slots,
            &procedures["root"],
            state,
            cache,
        );

        assert!(cold.published_summaries > 0, "{cold:#?}");
        assert_eq!(warm.reusable_root_summary_hits, 1, "{warm:#?}");
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        let set = warm
            .class_sets
            .iter()
            .find(|set| set.site.member.as_ref() == "known")
            .expect("the open constructor reaches the wrapper member access");
        assert_eq!(set.status, ClassSetStatus::Partial, "{set:#?}");
        assert!(
            set.classes
                .iter()
                .any(|(class, _)| class.qualified_name() == "app.Present"),
            "{set:#?}"
        );
        assert_eq!(set.unknown, vec![UnknownReason::OpenTypeBound]);
        assert_eq!(
            set.member_declarations.len(),
            1,
            "the known class atom keeps positive member evidence despite its open remainder: {set:#?}"
        );
        assert_eq!(
            set.member_declarations[0].1.dispatch_coverage,
            CandidateCoverage::Exhaustive,
            "the adapter-local declaration proof stays exact; receiver-set openness separately prevents exhaustive feedback"
        );
        assert!(warm.findings.is_empty(), "{warm:#?}");
    }

    #[test]
    fn root_summary_missing_a_current_sink_continues_with_callee_reuse() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf():\n    return 1\n",
            "def root():\n",
            "    leaf()\n",
            "    def inner(value):\n",
            "        return value.missing\n",
            "    return 1\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut prepared = PreparedClassSetSummaries::new(
            state.clone(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let cancellation = CancellationToken::default();
        let mut zero_budget = SolverBudget::new(SolverWork::uniform(0));
        let rejected = prepared
            .root_summary_for(
                &procedures["root"],
                ValueFlowFact::zero(),
                &mut DataflowRequest::new(&mut zero_budget, &cancellation),
            )
            .expect("an incomplete root observation probe falls back");
        assert!(rejected.is_none());
        assert_eq!(prepared.root_observation_rejections(), 1);
        assert_eq!(zero_budget.used(), SolverWork::default());

        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);
        assert_eq!(warm.reusable_root_summary_hits, 0, "{warm:#?}");
        assert_eq!(
            warm.reusable_root_summary_observation_rejections, 1,
            "{warm:#?}"
        );
        assert!(
            warm.reusable_summary_hits > warm.reusable_root_summary_hits,
            "the same witnessless trial continues through the root and reuses the leaf: {warm:#?}"
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(warm.class_sets.iter().any(|set| {
            set.site.member.as_ref() == "missing"
                && set.status == ClassSetStatus::Inconclusive
                && set.unknown.contains(&UnknownReason::IncompleteRoot)
        }));
    }

    #[test]
    fn source_sensitive_procedure_reuses_its_zero_entry() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def root():\n    return guarded(A())\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut prepared =
            PreparedClassSetSummaries::new(state, &workspace, &plan, &field_slots, behavior);
        assert!(
            prepared.procedures[&procedures["guarded"]].source_sensitive,
            "the fixture must exercise a source-sensitive procedure"
        );
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            prepared
                .summary_for(
                    &procedures["guarded"],
                    &procedures["root"],
                    ValueFlowFact::zero(),
                    &mut request,
                )
                .expect("the zero-entry lookup completes")
                .is_some(),
            "a source-sensitive procedure's source-independent zero entry is reusable"
        );
    }

    #[test]
    fn equivalent_guard_entries_keep_lookup_identity_across_caller_edits() {
        fn guarded_lookup(source: &str) -> (StableDigest, StableDigest) {
            let (_project, workspace, field_slots, procedures) = runtime_fixture(source);
            let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
            let state = TypeFlowSummaryState::default();
            let mut prepared =
                PreparedClassSetSummaries::new(state, &workspace, &plan, &field_slots, behavior);
            let guarded = &procedures["guarded"];
            let carrier_semantics = prepared.procedures[guarded].contract.carrier_semantics;
            let carrier = plan
                .value_flow()
                .carrier_keys()
                .iter()
                .find(|carrier| {
                    matches!(
                        carrier,
                        ValueFlowCarrierKey::Port {
                            procedure,
                            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
                        } if procedure == guarded.semantics().locator()
                    )
                })
                .expect("guarded retains its parameter carrier");
            let carrier_id = plan
                .value_flow()
                .carrier_id_for_key(carrier)
                .expect("the guarded parameter carrier remains bound");
            let entry_source = plan
                .value_flow()
                .sources()
                .find(|(source, spec)| {
                    spec.point().procedure() == &procedures["root"]
                        && matches!(
                            plan.atom(*source),
                            ClassAtom::Class(class) if class.qualified_name() == "app.A"
                        )
                })
                .map(|(source, _)| source)
                .expect("the caller constructor supplies one class source");
            let source_partition = prepared
                .source_behavior_for(guarded, entry_source)
                .expect("the guarded source behavior is bounded");
            let entry = stable_entry_fact(
                plan.value_flow(),
                Some(source_partition),
                ValueFlowFact::carrier_fact(
                    entry_source,
                    carrier_id,
                    ValueFlowUncertainty::empty(),
                ),
            )
            .expect("the guarded class entry is stable");
            let key = prepared
                .lookup_key(guarded, entry)
                .expect("the guard-only procedure is reusable");
            (carrier_semantics, class_set_lookup_fingerprint(&key))
        }

        let before_source = concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def root():\n    return guarded(A())\n",
        );
        let after_source = concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def root():\n    unrelated = A()\n    return guarded(A())\n",
        );
        let before = guarded_lookup(before_source);
        let after = guarded_lookup(after_source);
        assert_eq!(
            before.0, after.0,
            "external caller source identities are entry behavior, not callee semantics"
        );
        assert_eq!(
            before.1, after.1,
            "equivalent guard behavior keeps one reusable lookup across caller edits"
        );

        let (_project, workspace, fields, procedures) = runtime_fixture(concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def first_root():\n    return guarded(A())\n",
            "def second_root():\n    unrelated = A()\n    return guarded(A())\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &fields,
            &procedures["first_root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.published_summaries > 0);
        let warm = solve_runtime_root(
            &workspace,
            &fields,
            &procedures["second_root"],
            state,
            cache,
        );
        assert!(
            warm.reusable_summary_hits > 0,
            "an equivalent entry from a different root plan reuses the guarded summary"
        );
    }

    #[test]
    fn persisted_selector_fallback_is_bounded() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class A:\n    pass\n",
            "def guarded(value):\n",
            "    if value is not None:\n        return value\n",
            "    return value\n",
            "def root():\n    return guarded(A())\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0);
        let guarded_summary = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| {
                summary_name(summary) == "guarded"
                    && matches!(summary.key.entry, StableEntryFact::Carrier { .. })
            })
            .cloned()
            .expect("the source-sensitive guarded entry is persisted");
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut prepared = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let mut dependency = ClassSetRelationDependency {
            procedure_lineage: guarded_summary
                .key
                .procedure
                .identity()
                .read_lineage_fingerprint(),
            entry_selector: stable_entry_fingerprint(
                &guarded_summary.key.entry,
                &guarded_summary.key.procedure_locator,
            ),
            entry: stable_dependency_entry(
                &guarded_summary.key.entry,
                &guarded_summary.key.procedure_locator,
            ),
            source_witnesses: Box::default(),
            output: guarded_summary.output_digest,
            consumed_lookup: class_set_lookup_fingerprint(&guarded_summary.key),
        };
        dependency.source_witnesses = (0..=MAX_CLASS_SET_ENTRY_SELECTOR_PROBES)
            .map(|index| StableDigest::sha256(index.to_le_bytes()))
            .collect();
        let cancellation = CancellationToken::new();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            prepared
                .resolve_dependency_entry(&procedures["guarded"], &dependency, None, &mut request)
                .expect("the hard witness cap is not solver exhaustion")
                .is_none(),
            "untrusted dependency witnesses cannot trigger unbounded reconstruction"
        );
    }

    #[test]
    fn projection_flattens_leaf_meeting_through_wrapper_at_each_call_point() {
        let (plan, result) = projection_fixture(concat!(
            "class Missing:\n    pass\n",
            "def leaf(value):\n    value.missing\n",
            "def wrapper(value):\n    leaf(value)\n",
            "def root():\n    wrapper(Missing())\n",
        ));
        let flattened =
            project_flattened_class_set_observations(plan.value_flow(), result.result())
                .expect("the acyclic entry graph projects");
        let leaf = nonempty_entry(&flattened, "leaf");
        let wrapper = nonempty_entry(&flattened, "wrapper");
        let root = nonempty_entry(&flattened, "root");

        assert_eq!(leaf.reached.len(), 1, "{leaf:#?}");
        assert_eq!(wrapper.reached.len(), 1, "{wrapper:#?}");
        assert_eq!(root.reached.len(), 1, "{root:#?}");
        assert_eq!(
            meeting_shape(&wrapper.reached[0].fact),
            meeting_shape(&leaf.reached[0].fact)
        );
        assert_eq!(
            meeting_shape(&root.reached[0].fact),
            meeting_shape(&leaf.reached[0].fact)
        );

        let transfer = |source: &str, target: &str| {
            result
                .result()
                .entry_transfers()
                .iter()
                .find(|transfer| {
                    entry_name(transfer.source()) == source
                        && entry_name(transfer.target()) == target
                })
                .expect("fixture contains the requested entry transfer")
        };
        assert_eq!(
            wrapper.reached[0].point,
            transfer("wrapper", "leaf").call_point().id()
        );
        assert_eq!(
            root.reached[0].point,
            transfer("root", "wrapper").call_point().id()
        );
        assert!(!wrapper.reached[0].qualities.is_empty());
        assert!(!root.reached[0].qualities.is_empty());
    }

    #[test]
    fn projection_is_canonical_and_deduplicates_descendants_rehomed_at_one_call() {
        let (plan, result) = projection_fixture(concat!(
            "class Missing:\n    pass\n",
            "def leaf(value):\n    value.missing\n",
            "def wrapper(value):\n    leaf(value)\n    leaf(value)\n",
            "def root():\n    wrapper(Missing())\n",
        ));
        let first = project_flattened_class_set_observations(plan.value_flow(), result.result())
            .expect("the acyclic entry graph projects");
        let second = project_flattened_class_set_observations(plan.value_flow(), result.result())
            .expect("repeated projection succeeds");
        assert_eq!(first, second, "projection order is deterministic");

        let wrapper = nonempty_entry(&first, "wrapper");
        let root = nonempty_entry(&first, "root");
        assert_eq!(
            wrapper.reached.len(),
            2,
            "the wrapper owns one observation per distinct leaf call: {wrapper:#?}"
        );
        assert_ne!(wrapper.reached[0].point, wrapper.reached[1].point);
        assert_eq!(
            root.reached.len(),
            1,
            "both descendant observations collapse at the wrapper call: {root:#?}"
        );
        for entry in &first {
            assert!(entry.reached.windows(2).all(|rows| {
                rows[0].point < rows[1].point
                    || (rows[0].point == rows[1].point && rows[0].fact < rows[1].fact)
            }));
        }
    }

    #[test]
    fn acyclic_wrapper_summary_is_published_and_reused_with_equal_results() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf():\n",
            "    value = 123\n",
            "    value.__class__\n",
            "    return value\n",
            "def wrapper():\n",
            "    first = leaf()\n",
            "    first.__class__\n",
            "    second = leaf()\n",
            "    second.__eq__\n",
            "    return second\n",
            "def first_root():\n",
            "    value = wrapper()\n",
            "    return value.__class__\n",
            "def second_root():\n",
            "    value = wrapper()\n",
            "    return value.__class__\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let first = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["first_root"],
            state.clone(),
            cache.clone(),
        );
        assert!(first.published_summaries > 0, "{first:#?}");
        {
            let runtime = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                runtime.values().any(|summary| {
                    summary_name(summary) == "wrapper" && !summary.dependencies.is_empty()
                }),
                "the first solve publishes a dependency-bearing wrapper relation: {:?}",
                runtime
                    .values()
                    .map(|summary| (summary_name(summary), summary.dependencies.len()))
                    .collect::<Vec<_>>()
            );
        }

        let reused = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            state.clone(),
            cache,
        );
        let fresh = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(reused.reusable_summary_hits > 0, "{reused:#?}");
        assert_eq!(reused.class_sets, fresh.class_sets);
        assert_eq!(reused.findings, fresh.findings);
        assert_eq!(reused.complete, fresh.complete);
        assert_eq!(
            reused.semantic_budget_exhausted,
            fresh.semantic_budget_exhausted
        );
        assert!(
            state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .values()
                .any(|summary| {
                    summary_name(summary) == "second_root" && !summary.dependencies.is_empty()
                }),
            "a caller above the reused wrapper remains publishable"
        );
    }

    #[test]
    fn open_boundary_wrapper_publishes_nonleaf_and_replays_known_and_unknown_rows() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n",
            "    def known(self):\n",
            "        pass\n",
            "def leaf(value):\n",
            "    return value\n",
            "def wrapper(value):\n",
            "    kept = leaf(value)\n",
            "    opaque = unresolved_external_call()\n",
            "    kept.known\n",
            "    opaque.missing\n",
            "    return kept\n",
            "def first_root():\n",
            "    return wrapper(Present())\n",
            "def second_root():\n",
            "    return wrapper(Present())\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["first_root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let wrapper = {
            let runtime = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let wrapper = runtime
                .values()
                .find(|summary| {
                    summary_name(summary) == "wrapper"
                        && matches!(summary.key.entry, StableEntryFact::Carrier { .. })
                })
                .cloned()
                .expect("the open-boundary wrapper publishes a carrier relation");
            assert_eq!(
                wrapper.dependencies.len(),
                1,
                "the bound leaf remains the wrapper's exact child dependency"
            );
            assert_eq!(
                wrapper.reads.len(),
                2,
                "both the bound and open calls retain exact dispatch reads"
            );
            wrapper
        };

        let (warm_plan, warm_behavior) =
            runtime_plan(&workspace, &field_slots, &procedures["second_root"]);
        let StableEntryFact::Carrier {
            carrier, uncertain, ..
        } = &wrapper.key.entry
        else {
            unreachable!("the retained wrapper relation has a carrier entry")
        };
        let source = warm_plan
            .value_flow()
            .sources()
            .find(|(source, spec)| {
                spec.point().procedure() == &procedures["second_root"]
                    && matches!(
                        warm_plan.atom(*source),
                        ClassAtom::Class(class) if class.qualified_name() == "app.Present"
                    )
            })
            .map(|(source, _)| source)
            .expect("the warm root supplies the Present constructor source");
        let entry_fact = ValueFlowFact::carrier_fact(
            source,
            warm_plan
                .value_flow()
                .carrier_id_for_key(carrier)
                .expect("the wrapper parameter carrier remains live in the warm plan"),
            ValueFlowUncertainty::from_semantic_uncertainty(*uncertain),
        );
        let mut prepared = PreparedClassSetSummaries::new(
            state.clone(),
            &workspace,
            &warm_plan,
            &field_slots,
            warm_behavior,
        );
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            prepared
                .summary_for(
                    &procedures["wrapper"],
                    &procedures["second_root"],
                    entry_fact,
                    &mut request,
                )
                .expect("the exact wrapper summary lookup completes")
                .is_some(),
            "the dependency-bearing wrapper itself is reusable before the warm root solve"
        );

        let reused = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            state,
            cache,
        );
        let fresh = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(reused.reusable_summary_hits > 0, "{reused:#?}");
        assert_eq!(reused.class_sets, fresh.class_sets);
        assert_eq!(reused.findings, fresh.findings);
        assert_eq!(reused.complete, fresh.complete);

        let known = reused
            .class_sets
            .iter()
            .find(|row| row.site.member.as_ref() == "known")
            .expect("the bound leaf result reaches the known member access");
        assert_eq!(known.status, ClassSetStatus::Known, "{known:#?}");
        assert!(known.unknown.is_empty(), "{known:#?}");
        assert!(
            known
                .classes
                .iter()
                .any(|(class, _)| class.qualified_name() == "app.Present"),
            "{known:#?}"
        );
        let unknown = reused
            .class_sets
            .iter()
            .find(|row| row.site.member.as_ref() == "missing")
            .expect("the open call result reaches the unresolved member access");
        assert!(
            unknown.unknown.contains(&UnknownReason::UnresolvedCall),
            "{unknown:#?}"
        );
        assert_ne!(unknown.status, ClassSetStatus::Known, "{unknown:#?}");
    }

    #[test]
    fn changed_open_dispatch_answer_rotates_the_wrapper_and_misses() {
        let source = concat!(
            "def leaf():\n",
            "    return 1\n",
            "def wrapper():\n",
            "    value = leaf()\n",
            "    unresolved_call()\n",
            "    return value\n",
            "def root():\n",
            "    return wrapper()\n",
        );
        let changed_source = format!("{source}def unresolved_call():\n    return 2\n");
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        let retained = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| {
                summary_name(summary) == "wrapper"
                    && matches!(summary.key.entry, StableEntryFact::Zero)
            })
            .cloned()
            .expect("the wrapper with one open call is retained");
        assert_eq!(retained.dependencies.len(), 1, "{retained:#?}");
        assert_eq!(retained.reads.len(), 2, "{retained:#?}");

        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(&changed_source);
        let (second_plan, second_behavior) = runtime_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
        );
        let mut prepared = PreparedClassSetSummaries::new(
            state,
            &second_workspace,
            &second_plan,
            &second_fields,
            second_behavior,
        );
        let changed_key = prepared
            .lookup_key(&second_procedures["wrapper"], StableEntryFact::Zero)
            .expect("the wrapper remains eligible after the call resolves");
        assert_ne!(
            retained.key.dispatch_reads, changed_key.dispatch_reads,
            "the exact open-boundary dispatch answer rotates its read evidence"
        );
        assert_ne!(
            retained.key.contract.direct_calls, changed_key.contract.direct_calls,
            "the v2 direct-call contract pins the changed open-boundary answer"
        );
        assert_ne!(
            class_set_runtime_lookup_key(&retained.key),
            class_set_runtime_lookup_key(&changed_key),
            "the resolved target rotates the supplemental call contract"
        );
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            prepared
                .validated_runtime_summary(
                    &second_procedures["wrapper"],
                    &changed_key,
                    None,
                    &mut request,
                )
                .expect("changed-dispatch validation completes")
                .is_none(),
            "a changed relevant dispatch answer cannot reuse the open-boundary relation"
        );
    }

    #[test]
    fn persisted_nonleaf_summary_restores_with_exact_dependencies_and_reads() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n",
            "    return value\n",
            "def wrapper(value):\n",
            "    return leaf(value)\n",
            "def first_root():\n",
            "    return wrapper(1)\n",
            "def second_root():\n",
            "    return wrapper(2)\n",
        ));
        let cold_state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["first_root"],
            cold_state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let wrapper = cold_state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| summary_name(summary) == "wrapper")
            .cloned()
            .expect("the cold solve publishes a wrapper relation");
        assert!(!wrapper.dependencies.is_empty(), "{wrapper:#?}");
        assert!(!wrapper.reads.is_empty(), "{wrapper:#?}");
        let store = workspace
            .store()
            .expect("the inline workspace has a persistent analyzer store");
        let wrapper_lookup = *class_set_lookup_fingerprint(&wrapper.key).as_bytes();
        let persisted = store
            .class_set_summary_for_digest(*class_set_lookup_fingerprint(&wrapper.key).as_bytes())
            .expect("the wrapper lookup succeeds")
            .expect("the wrapper is persisted");
        assert_eq!(persisted.dependencies.len(), wrapper.dependencies.len());
        assert_eq!(persisted.reads.len(), wrapper.reads.len());

        let mut stale_evidence = wrapper.as_ref().clone();
        stale_evidence.dependencies[0].consumed_lookup = StableDigest::sha256(b"retired-child");
        let attachment = workspace
            .semantic_artifact_store_attachment(wrapper.key.procedure.artifact())
            .expect("the wrapper attachment lookup succeeds")
            .expect("the wrapper artifact is attached to the store");
        let stale_row = persisted_summary_row(&stale_evidence, attachment)
            .expect("stale dependency provenance forms a valid store row");
        store
            .replace_class_set_summary(
                *persisted.content_digest(),
                stale_row,
                &CancellationToken::default(),
            )
            .expect("stale dependency provenance replaces atomically");

        let restored_state = TypeFlowSummaryState::default();
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["second_root"]);
        let mut prepared = PreparedClassSetSummaries::new(
            restored_state,
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let key = prepared
            .lookup_key(&procedures["wrapper"], wrapper.key.entry.clone())
            .expect("the warm wrapper remains eligible");
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        let entry_source = plan
            .value_flow()
            .sources()
            .find(|(_, source)| source.point().procedure() == &procedures["second_root"])
            .map(|(source, _)| source);
        let validated = prepared
            .validated_persisted_summary(
                &procedures["wrapper"],
                &key,
                entry_source,
                None,
                &mut request,
            )
            .expect("persisted validation completes")
            .expect("the persisted wrapper dependency closure validates");
        let ValidatedClassSetSummary {
            summary: restored,
            publications,
        } = validated;
        prepared
            .commit_validated_publications(publications, &cancellation)
            .expect("validated persisted publications commit");
        assert_eq!(restored.dependencies, wrapper.dependencies);
        assert_eq!(restored.reads, wrapper.reads);
        let rewritten = store
            .class_set_summary_for_digest(wrapper_lookup)
            .expect("the rewritten wrapper lookup succeeds")
            .expect("the rewritten wrapper remains present");
        assert_eq!(
            rewritten.dependencies[0].consumed_child_lookup_digest,
            *wrapper.dependencies[0].consumed_lookup.as_bytes(),
            "recorded child provenance is not required to locate the current equal output"
        );

        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(warm.reusable_summary_hits > 0, "{warm:#?}");

        let child_lookup = *wrapper.dependencies[0].consumed_lookup.as_bytes();
        let child = store
            .class_set_summary_for_digest(child_lookup)
            .expect("the child lookup succeeds")
            .expect("the persisted child remains present");
        let mut changed_exits = child.exits.clone();
        changed_exits[0].quality_mask = if changed_exits[0].quality_mask == 1 {
            2
        } else {
            1
        };
        let changed_child = ClassSetSummaryRow::try_new(
            child.header.clone(),
            child.facts.clone(),
            changed_exits,
            child.reached.clone(),
            child.dependencies.clone(),
            child.reads.clone(),
            child.charges.clone(),
        )
        .expect("the changed child remains a valid complete relation");
        store
            .replace_class_set_summary(
                *child.content_digest(),
                changed_child,
                &CancellationToken::default(),
            )
            .expect("the changed child replaces atomically");

        let rejected_state = TypeFlowSummaryState::default();
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["second_root"]);
        let mut prepared = PreparedClassSetSummaries::new(
            rejected_state,
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let key = prepared
            .lookup_key(&procedures["wrapper"], wrapper.key.entry.clone())
            .expect("the wrapper remains eligible after its child output changes");
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        let entry_source = plan
            .value_flow()
            .sources()
            .find(|(_, source)| source.point().procedure() == &procedures["second_root"])
            .map(|(source, _)| source);
        assert!(
            prepared
                .validated_persisted_summary(
                    &procedures["wrapper"],
                    &key,
                    entry_source,
                    None,
                    &mut request,
                )
                .expect("changed-output validation completes")
                .is_none(),
            "a persisted parent cannot replay after its child's typed output changes"
        );
    }

    #[test]
    fn exact_entry_maintenance_solve_roots_at_a_demanded_callee() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n",
            "    return value\n",
            "def wrapper(value):\n",
            "    return leaf(value)\n",
            "def root():\n",
            "    return wrapper(1)\n",
        ));
        let source_state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            source_state.clone(),
            ValueFlowCache::default(),
        );
        let demanded_entry = source_state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| {
                summary_name(summary) == "wrapper"
                    && matches!(summary.key.entry, StableEntryFact::Carrier { .. })
            })
            .map(|summary| summary.key.entry.clone())
            .expect("the caller supplies one carrier entry to wrapper");

        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let entry_source = plan
            .value_flow()
            .sources()
            .next()
            .map(|(source, _)| source)
            .expect("the root literal supplies a source");
        let StableEntryFact::Carrier {
            carrier, uncertain, ..
        } = &demanded_entry
        else {
            unreachable!("the demanded wrapper entry was selected as a carrier")
        };
        let entry_fact = ValueFlowFact::carrier_fact(
            entry_source,
            plan.value_flow()
                .carrier_id_for_key(carrier)
                .expect("the demanded wrapper carrier remains in the live plan"),
            ValueFlowUncertainty::from_semantic_uncertainty(*uncertain),
        );
        let state = TypeFlowSummaryState::default();
        let mut prepared =
            PreparedClassSetSummaries::new(state, &workspace, &plan, &field_slots, behavior);
        let wrapper_source_sensitive = prepared.procedures[&procedures["wrapper"]].source_sensitive;
        let provider = WorkspaceIcfgProvider::new(&workspace);
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let mut solver_budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut solver_budget, &cancellation);
        let result = solve_value_flow_entry_with_reusable_summaries(
            &procedures["wrapper"],
            entry_fact,
            &provider,
            &mut prepared,
            plan.value_flow(),
            &mut semantic_budget,
            &mut request,
        )
        .expect("one demanded wrapper entry solves against the existing plan");

        let mut wrapper_entries = Vec::new();
        for row in result
            .result()
            .reached()
            .iter()
            .filter(|row| row.entry().procedure() == &procedures["wrapper"])
        {
            let Some(fact) = result.result().fact(row.entry().entry_fact()).copied() else {
                continue;
            };
            let source_partition = if wrapper_source_sensitive {
                fact.source()
                    .and_then(|source| prepared.source_behavior_for(&procedures["wrapper"], source))
            } else {
                None
            };
            if let Some(entry) = stable_entry_fact(plan.value_flow(), source_partition, fact) {
                wrapper_entries.push(entry);
            }
        }
        wrapper_entries.sort_unstable();
        wrapper_entries.dedup();
        assert_eq!(
            wrapper_entries,
            vec![StableEntryFact::Zero, demanded_entry],
            "maintenance tabulation contains only zero and the demanded explicit entry"
        );
        assert!(
            result.result().termination().is_fixed_point(),
            "{result:#?}"
        );
        assert!(result.result().incoming_calls().is_empty(), "{result:#?}");
        assert!(
            !result.result().witness_retention_truncated(),
            "{result:#?}"
        );
    }

    #[test]
    fn equal_output_rebind_changes_only_demanded_parent_provenance() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n",
            "    return value\n",
            "def wrapper(value):\n",
            "    return leaf(value)\n",
            "def root():\n",
            "    return wrapper(1)\n",
        ));
        let state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        let wrapper = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| summary_name(summary) == "wrapper" && !summary.dependencies.is_empty())
            .cloned()
            .expect("the cold solve publishes a dependency-bearing wrapper");
        let dependency = &wrapper.dependencies[0];
        let store = workspace
            .store()
            .expect("the fixture has a persistent store");
        let evidence = store
            .class_set_summary_dependents_of_lineage_entry(
                *dependency.procedure_lineage.as_bytes(),
                *dependency.entry_selector.as_bytes(),
            )
            .expect("reverse dependency lookup succeeds")
            .into_iter()
            .find(|row| {
                row.dependent_lookup_digest
                    == *class_set_lookup_fingerprint(&wrapper.key).as_bytes()
                    && row.dependency.consumed_child_lookup_digest
                        == *dependency.consumed_lookup.as_bytes()
            })
            .expect("reverse evidence names the demanded wrapper");
        let before = store
            .class_set_summary_for_digest(evidence.dependent_lookup_digest)
            .expect("parent lookup succeeds")
            .expect("parent row is present");
        let leaf = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| {
                summary.key.procedure.identity().read_lineage_fingerprint()
                    == dependency.procedure_lineage
                    && stable_entry_fingerprint(&summary.key.entry, &summary.key.procedure_locator)
                        == dependency.entry_selector
            })
            .cloned()
            .expect("the demanded leaf revision remains current");
        let stabilized = HashMap::from_iter([(
            (dependency.procedure_lineage, dependency.entry_selector),
            Arc::clone(&leaf),
        )]);
        assert!(current_dependencies_match_stabilized(
            &wrapper,
            &before.dependencies,
            &stabilized,
        ));
        let mut stale_wrapper = wrapper.as_ref().clone();
        stale_wrapper.dependencies[0].consumed_lookup = StableDigest::sha256(b"stale-grandchild");
        assert!(
            !current_dependencies_match_stabilized(
                &stale_wrapper,
                &before.dependencies,
                &stabilized,
            ),
            "a current non-leaf row cannot hide stale grandchild provenance"
        );
        let replacement_child = StableDigest::sha256(b"equal-output-child-revision");

        assert!(
            rebind_equal_output_dependency(
                store,
                &evidence,
                replacement_child,
                &CancellationToken::default(),
            )
            .expect("equal-output provenance rebinds atomically"),
            "the first equal-output rebind replaces the persisted row"
        );

        let after = store
            .class_set_summary_for_digest(evidence.dependent_lookup_digest)
            .expect("rebound parent lookup succeeds")
            .expect("rebound parent row is present");
        assert_eq!(after.output_digest(), before.output_digest());
        assert_ne!(after.content_digest(), before.content_digest());
        assert_eq!(
            after.dependencies[evidence.dependency.ordinal as usize].consumed_child_lookup_digest,
            *replacement_child.as_bytes()
        );
    }

    #[test]
    fn demanded_closure_validation_is_bounded_to_the_persisted_root_dag() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n",
            "    return value\n",
            "def wrapper(value):\n",
            "    return leaf(value)\n",
            "def unrelated(value):\n",
            "    return value\n",
            "def root():\n",
            "    return wrapper(1)\n",
        ));
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut limited = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let provider = WorkspaceIcfgProvider::new(&workspace);
        let cancellation = CancellationToken::default();
        let mut limited_semantic_budget = SemanticBudget::default();
        let mut limited_limits = SolverWork::default_limits();
        limited_limits.summary_applications = 1;
        let mut limited_solver_budget = SolverBudget::new(limited_limits);
        let mut limited_request = DataflowRequest::new(&mut limited_solver_budget, &cancellation);
        assert!(
            !limited.stabilize_demanded_closure(
                &procedures["root"],
                &provider,
                &mut limited_semantic_budget,
                &mut limited_request,
            ),
            "the persisted DAG walk stops at its solver-work ceiling"
        );
        assert_eq!(limited_solver_budget.used().summary_applications, 1);
        assert!(limited_solver_budget.used().flow_evaluations > 0);

        let mut prepared = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &plan,
            &field_slots,
            behavior,
        );
        let mut semantic_budget = SemanticBudget::default();
        let mut solver_budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut solver_budget, &cancellation);

        assert!(prepared.stabilize_demanded_closure(
            &procedures["root"],
            &provider,
            &mut semantic_budget,
            &mut request,
        ));
        let maintenance = prepared.maintenance_metrics();
        assert_eq!(maintenance.hits, 0);
        assert_eq!(maintenance.misses, 0);
        assert_eq!(maintenance.publications, 0);
        assert!(
            !prepared.procedures.contains_key(&procedures["unrelated"]),
            "an unrelated procedure is outside the demanded prepared closure"
        );
    }

    #[test]
    fn failed_maintenance_fallback_retains_completed_work_accounting() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n",
            "    return value\n",
            "def root():\n",
            "    return leaf(1)\n",
        ));
        let state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        let retained = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .next()
            .cloned()
            .expect("the cold solve publishes one reusable relation");
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut prepared =
            PreparedClassSetSummaries::new(state, &workspace, &plan, &field_slots, behavior);
        prepared.used.insert(
            class_set_runtime_lookup_key(&retained.key),
            Arc::clone(&retained),
        );
        prepared.maintenance = SummaryMaintenanceMetrics {
            hits: 2,
            misses: 1,
            publications: 1,
        };
        prepared.retained_publication_writes = true;
        prepared.finish_maintenance_publications();
        assert!(!prepared.take_retained_publication_writes());

        prepared.prepare_fallback_after_maintenance();

        assert!(prepared.used.is_empty());
        assert_eq!(
            prepared.maintenance_metrics(),
            SummaryMaintenanceMetrics {
                hits: 2,
                misses: 1,
                publications: 1,
            }
        );
        assert!(prepared.retained_maintenance_writes());
    }

    #[test]
    fn runtime_summary_with_stale_dispatch_reads_fails_closed() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n",
            "    return value\n",
            "def wrapper(value):\n",
            "    return leaf(value)\n",
            "def root():\n",
            "    return wrapper(1)\n",
        ));
        let source_state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            source_state.clone(),
            ValueFlowCache::default(),
        );
        let mut stale = source_state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| summary_name(summary) == "wrapper")
            .map(|summary| summary.as_ref().clone())
            .expect("the source solve publishes a wrapper relation");
        assert!(!stale.reads.is_empty(), "{stale:#?}");
        stale.reads = Box::default();
        stale.key.dispatch_reads = read_set_digest(&stale.reads).digest();

        let state = TypeFlowSummaryState::default();
        assert!(state.class_set.publish(stale.clone()));
        let (plan, behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let mut prepared =
            PreparedClassSetSummaries::new(state, &workspace, &plan, &field_slots, behavior);
        let key = prepared
            .lookup_key(&procedures["wrapper"], stale.key.entry.clone())
            .expect("the wrapper remains eligible");
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            prepared
                .validated_runtime_summary(&procedures["wrapper"], &key, None, &mut request)
                .expect("validation completes")
                .is_none(),
            "a runtime row cannot outlive the exact dispatch reads it recorded"
        );
    }

    #[test]
    fn rotated_provider_read_behavior_separates_and_republishes_a_summary() {
        let source = concat!(
            "def wrapper(value):\n",
            "    unresolved_call()\n",
            "    return value\n",
            "def root():\n",
            "    return wrapper(1)\n",
        );
        let (_source_project, source_workspace, source_fields, source_procedures) =
            runtime_fixture(source);
        let source_state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &source_workspace,
            &source_fields,
            &source_procedures["root"],
            source_state.clone(),
            ValueFlowCache::default(),
        );
        let current = source_state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| summary_name(summary) == "wrapper")
            .map(|summary| summary.as_ref().clone())
            .expect("the source solve publishes a wrapper relation");
        assert!(!current.reads.is_empty(), "{current:#?}");

        let identity = current.key.procedure.identity();
        let legacy_identity = ProcedureSummaryIdentity::new(
            identity.artifact().clone(),
            identity.declaration().clone(),
            identity.schema(),
            identity.semantics(),
            identity.context(),
            SummaryBehaviorKey::hash_bytes(b"pre-procedure-dispatch-answer-v2"),
            identity.origin().clone(),
        );
        let mut legacy = current.clone();
        legacy.key.procedure = ProcedureSummaryKey::try_new(legacy_identity, &[], None)
            .expect("legacy behavior identity is valid");
        assert_eq!(
            legacy.key.procedure.dependencies(),
            current.key.procedure.dependencies(),
            "the open-boundary wrapper has no summary dependencies"
        );
        assert_ne!(
            class_set_runtime_lookup_key(&legacy.key),
            class_set_runtime_lookup_key(&current.key),
            "the provider read-behavior rotation must separate owner-local lookup"
        );
        assert_ne!(
            class_set_lookup_fingerprint(&legacy.key),
            class_set_lookup_fingerprint(&current.key),
            "the provider read-behavior rotation must separate persisted lookup"
        );

        let state = TypeFlowSummaryState::default();
        assert!(state.class_set.publish(legacy));
        assert!(
            state.class_set.publish(current.clone()),
            "the current answer publishes rather than colliding with stale read behavior"
        );
        let runtime = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(runtime.len(), 2);
        assert!(runtime.values().any(|summary| {
            summary.key.procedure.behavior() == identity.behavior() && summary.key == current.key
        }));
    }

    #[test]
    fn repository_restores_an_existing_exact_revision_as_the_runtime_head() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf():\n",
            "    return 123\n",
            "def wrapper():\n",
            "    return leaf()\n",
            "def root():\n",
            "    return wrapper()\n",
        ));
        let state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        let first = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| summary_name(summary) == "wrapper")
            .map(|summary| summary.as_ref().clone())
            .expect("the seed solve publishes the wrapper");
        let mut second = first.clone();
        second.key.procedure =
            ProcedureSummaryKey::try_new(first.key.procedure.identity().clone(), &[], None)
                .expect("an alternate exact revision is valid");
        assert_ne!(first.key, second.key, "the seed wrapper is non-leaf");
        assert_eq!(
            class_set_runtime_lookup_key(&first.key),
            class_set_runtime_lookup_key(&second.key),
            "exact revisions share one owner-local runtime head"
        );
        assert_eq!(
            class_set_lookup_fingerprint(&first.key),
            class_set_lookup_fingerprint(&second.key),
            "persistent lookup excludes mutable dependency evidence"
        );
        let mut evidence_revision = first.clone();
        evidence_revision.reads = Box::default();
        evidence_revision.key.dispatch_reads = read_set_digest(&evidence_revision.reads).digest();
        assert_ne!(
            first.key, evidence_revision.key,
            "the exact in-memory key includes dispatch-read evidence"
        );
        assert_eq!(
            class_set_runtime_lookup_key(&first.key),
            class_set_runtime_lookup_key(&evidence_revision.key),
            "dispatch-read evidence remains outside the owner-local runtime selector"
        );
        assert_eq!(
            class_set_lookup_fingerprint(&first.key),
            class_set_lookup_fingerprint(&evidence_revision.key),
            "dispatch-read evidence is mutable persisted provenance"
        );

        let repository = ClassSetSummaryRepository::default();
        assert!(repository.publish(first.clone()));
        assert!(repository.publish(evidence_revision));
        assert!(
            repository.publish(first.clone()),
            "restoring exact dispatch reads is a semantic publication"
        );
        let revision = repository.publish_tracked(second.clone());
        assert!(
            !revision.published,
            "dependency-revision evidence alone is not a semantic publication"
        );
        assert!(
            revision.retained_write,
            "dependency-revision evidence still replaces the shared runtime head"
        );
        assert_eq!(
            repository
                .get_runtime(class_set_runtime_lookup_key(&first.key))
                .expect("the second revision is current")
                .key,
            second.key
        );
        let restored = repository.publish_tracked(first.clone());
        assert!(!restored.published);
        assert!(
            restored.retained_write,
            "restoring exact dependency evidence replaces the shared runtime head"
        );
        assert_eq!(
            repository
                .get_runtime(class_set_runtime_lookup_key(&first.key))
                .expect("republishing restores the first revision")
                .key,
            first.key
        );
        assert_eq!(
            repository.publish_tracked(first),
            RuntimeSummaryPublication {
                published: false,
                retained_write: false,
            },
            "an exact runtime head is a true no-op"
        );
    }

    #[test]
    fn recursive_procedure_stays_ineligible_and_fresh() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def recursive(value):\n    recursive(value)\n    value.member\n",
            "def first_root():\n    recursive(Present())\n",
            "def second_root():\n    recursive(Present())\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["first_root"],
            state.clone(),
            cache.clone(),
        );
        assert!(
            state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .values()
                .all(|summary| summary_name(summary) != "recursive"),
            "recursive SCC members are not published"
        );
        let second = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            state,
            cache,
        );
        assert_eq!(second.reusable_summary_hits, 0, "{second:#?}");
        assert!(
            second.summary_profile.preparation_recursive_dependency > 0,
            "recursive key rejection is attributed: {second:#?}"
        );
    }

    #[test]
    fn carrierless_direct_call_target_rotates_owner_local_runtime_key() {
        let (_first_project, first_workspace, first_fields, first_procedures) = runtime_fixture(
            "def leaf():\n    pass\ndef peer():\n    pass\ndef wrapper():\n    leaf()\ndef root():\n    wrapper()\n",
        );
        let (_second_project, second_workspace, second_fields, second_procedures) = runtime_fixture(
            "def leaf():\n    pass\ndef peer():\n    pass\ndef wrapper():\n    peer()\ndef root():\n    wrapper()\n",
        );
        let (first_plan, first_behavior) =
            runtime_plan(&first_workspace, &first_fields, &first_procedures["root"]);
        let (second_plan, second_behavior) = runtime_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
        );
        let first = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &first_workspace,
            &first_plan,
            &first_fields,
            first_behavior,
        );
        let second = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &second_workspace,
            &second_plan,
            &second_fields,
            second_behavior,
        );
        let first_wrapper = &first.procedures[&first_procedures["wrapper"]];
        let second_wrapper = &second.procedures[&second_procedures["wrapper"]];
        assert_ne!(
            first_wrapper.contract.direct_calls, second_wrapper.contract.direct_calls,
            "the exact direct-call target must rotate the supplemental topology contract"
        );
        let first_key = first
            .lookup_key(&first_procedures["wrapper"], StableEntryFact::Zero)
            .expect("first wrapper is eligible");
        let second_key = second
            .lookup_key(&second_procedures["wrapper"], StableEntryFact::Zero)
            .expect("second wrapper is eligible");
        assert_ne!(
            class_set_runtime_lookup_key(&first_key),
            class_set_runtime_lookup_key(&second_key),
            "owner-local runtime lookup includes direct call topology"
        );
    }

    #[test]
    fn unrelated_sibling_preserves_owner_local_summary_identity() {
        let source = concat!(
            "def sibling():\n    return 1\n\n",
            "def leaf(value):\n    return value\n\n",
            "def wrapper(value):\n    first = leaf(value)\n    first.__class__\n    second = leaf(value)\n    second.__eq__\n    return second\n\n",
            "def refresh():\n    return leaf(123)\n\n",
            "def root():\n    value = wrapper(123)\n    return value.__class__\n",
        );
        let changed_source = source.replacen(
            "def sibling():\n    return 1\n\n",
            "def sibling():\n    temporary = 2\n    return temporary\n\n",
            1,
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(&changed_source);
        let (first_plan, first_behavior) =
            runtime_plan(&first_workspace, &first_fields, &first_procedures["root"]);
        let (second_plan, second_behavior) = runtime_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
        );
        let first = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &first_workspace,
            &first_plan,
            &first_fields,
            first_behavior,
        );
        let second = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &second_workspace,
            &second_plan,
            &second_fields,
            second_behavior,
        );
        assert_eq!(first_behavior.read_digest(), second_behavior.read_digest());
        for name in ["wrapper", "root"] {
            let first_procedure = &first_procedures[name];
            let second_procedure = &second_procedures[name];
            let first_prepared = &first.procedures[first_procedure];
            let second_prepared = &second.procedures[second_procedure];
            assert!(!first_prepared.source_sensitive);
            assert!(!second_prepared.source_sensitive);
            assert_eq!(
                first_prepared
                    .semantic
                    .key()
                    .identity()
                    .read_lineage_fingerprint(),
                second_prepared
                    .semantic
                    .key()
                    .identity()
                    .read_lineage_fingerprint(),
                "{name} lineage is independent of a preceding sibling"
            );
            assert_eq!(
                first_prepared.contract.carrier_semantics,
                second_prepared.contract.carrier_semantics,
                "{name} carrier contract is procedure-local"
            );
            assert_eq!(
                first_prepared.procedure_semantics, second_prepared.procedure_semantics,
                "{name} local semantics exclude sibling movement"
            );
            assert_eq!(
                first_prepared.contract.field_slots,
                second_prepared.contract.field_slots
            );
            assert_eq!(
                first_prepared.contract.direct_calls,
                second_prepared.contract.direct_calls
            );
            let first_key = first
                .lookup_key(first_procedure, StableEntryFact::Zero)
                .expect("first procedure key");
            let second_key = second
                .lookup_key(second_procedure, StableEntryFact::Zero)
                .expect("second procedure key");
            assert_eq!(first_key.dispatch_reads, second_key.dispatch_reads);
            assert_eq!(
                first
                    .type_plan
                    .dispatch_read_contract(&first_procedure.durable_key()),
                second
                    .type_plan
                    .dispatch_read_contract(&second_procedure.durable_key()),
                "{name} dispatch reads are procedure-local"
            );
            assert_eq!(
                class_set_runtime_lookup_key(&first_key),
                class_set_runtime_lookup_key(&second_key),
                "{name} runtime summary selector survives the sibling edit"
            );
        }
    }

    #[test]
    fn fallback_summary_identity_ignores_disconnected_root_components() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def known(self):\n        pass\n",
            "def wrapper(value):\n",
            "    unresolved_external_call(value)\n",
            "    value.known\n",
            "    return value\n",
            "def first_root():\n",
            "    return wrapper(Present())\n",
            "def second_root():\n",
            "    disconnected = Present()\n",
            "    disconnected.known\n",
            "    return wrapper(Present())\n",
        ));
        let (first_plan, first_behavior) =
            runtime_plan(&workspace, &field_slots, &procedures["first_root"]);
        let (second_plan, second_behavior) =
            runtime_plan(&workspace, &field_slots, &procedures["second_root"]);
        let first_prepared = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &first_plan,
            &field_slots,
            first_behavior,
        );
        let second_prepared = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &second_plan,
            &field_slots,
            second_behavior,
        );
        let wrapper = &procedures["wrapper"];
        let first_contract = &first_prepared.procedures[wrapper].contract;
        let second_contract = &second_prepared.procedures[wrapper].contract;
        assert!(
            first_plan
                .value_flow()
                .fallback_reachable_location_count_of(wrapper)
                > 0,
            "the regression must exercise a fallback component with a location"
        );
        assert_eq!(
            first_plan
                .value_flow()
                .fallback_reachable_location_count_of(wrapper),
            second_plan
                .value_flow()
                .fallback_reachable_location_count_of(wrapper)
        );
        assert_ne!(
            first_plan
                .value_flow()
                .fallback_component_ordinals_of(wrapper),
            second_plan
                .value_flow()
                .fallback_component_ordinals_of(wrapper),
            "the fixture must shift the plan-local union-find roots"
        );
        assert_eq!(
            first_contract.carrier_semantics, second_contract.carrier_semantics,
            "an unrelated root-local component cannot rotate wrapper fallback semantics"
        );
        assert_eq!(
            first_prepared.procedures[wrapper].procedure_semantics,
            second_prepared.procedures[wrapper].procedure_semantics,
            "the exact procedure/read lookup remains stable"
        );

        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["first_root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["second_root"],
            state.clone(),
            cache,
        );
        assert!(
            warm.reusable_summary_hits > 0,
            "the second root reuses the wrapper despite its disconnected carrier: {warm:#?}"
        );
    }

    #[test]
    fn validated_runtime_cut_mounts_a_non_leaf_descendant_surface_and_preserves_result() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def leaf(value):\n    return value.member\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let (cut_plan, _) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["wrapper"]));
        assert!(cut_plan.value_flow().has_snapshot(&procedures["wrapper"]));
        assert!(
            cut_plan.value_flow().has_snapshot(&procedures["leaf"]),
            "runtime cuts use the same certified descendant surface as persisted cuts"
        );
        assert!(cut_plan.is_summary_cut(&procedures["leaf"]));
        assert!(cut_plan.value_flow().sinks().any(|(sink, _)| {
            let site = cut_plan.sink(sink);
            site.procedure == procedures["leaf"] && site.member.as_ref() == "member"
        }));

        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(warm.reusable_summary_hits > 0, "{warm:#?}");
    }

    #[test]
    fn persisted_cut_hydrates_a_descendant_sink_surface_with_fresh_runtime_state() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def leaf(value):\n    return value.member\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        ));
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        assert!(
            workspace
                .store()
                .expect("runtime fixture has a store")
                .contains_class_set_summary_procedure(
                    *procedures["wrapper"]
                        .artifact()
                        .key()
                        .procedure_lineage_fingerprint(
                            procedures["wrapper"].semantics().locator().declaration(),
                        )
                        .as_bytes(),
                )
                .expect("persisted wrapper probe"),
            "the cold state must publish through SQLite"
        );

        let fresh_state = TypeFlowSummaryState::default();
        let (cut_plan, _) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            fresh_state.clone(),
            DispatchHints::empty(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["wrapper"]));
        assert!(
            cut_plan.value_flow().has_snapshot(&procedures["leaf"]),
            "the descendant snapshot is mounted only to invert its sink identity"
        );
        assert!(cut_plan.is_summary_cut(&procedures["leaf"]));

        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            fresh_state,
            ValueFlowCache::default(),
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(warm.reusable_summary_hits > 0, "{warm:#?}");
    }

    #[test]
    fn persisted_cut_preserves_unreachable_post_return_direct_and_transitive_sites() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n",
            "    def direct_member(self):\n        pass\n",
            "    def transitive_member(self):\n        pass\n",
            "def transitive(value):\n    return value.transitive_member\n",
            "def dead_wrapper(value):\n    return transitive(value)\n",
            "def wrapper(value):\n",
            "    return value\n",
            "    value.direct_member\n",
            "    dead_wrapper(value)\n",
            "def root():\n    return wrapper(Present())\n",
        ));
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let expected_sites = vec![
            (
                Box::<str>::from("transitive"),
                Box::<str>::from("transitive_member"),
            ),
            (
                Box::<str>::from("wrapper"),
                Box::<str>::from("direct_member"),
            ),
        ];
        assert_eq!(result_site_shape(&cold), expected_sites, "{cold:#?}");

        // The post-return call targets are structurally discovered but never
        // reached by the root solve. Publish their Zero families explicitly
        // so every identity-only descendant mounted by the wrapper cut is
        // executable under the mandatory-cut contract.
        for name in ["transitive", "dead_wrapper"] {
            let descendant = solve_runtime_root(
                &workspace,
                &field_slots,
                &procedures[name],
                TypeFlowSummaryState::default(),
                ValueFlowCache::default(),
            );
            assert!(
                descendant.published_summaries > 0,
                "{name}: {descendant:#?}"
            );
        }

        let fresh_state = TypeFlowSummaryState::default();
        let cut_cache = ValueFlowCache::default();
        let (cut_plan, _) = runtime_cut_plan_with_cache(
            &workspace,
            &field_slots,
            &procedures["root"],
            fresh_state.clone(),
            DispatchHints::empty(),
            cut_cache.clone(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["wrapper"]));
        for name in ["dead_wrapper", "transitive"] {
            assert!(
                cut_plan.value_flow().has_snapshot(&procedures[name]),
                "the persisted wrapper surface mounts {name}"
            );
            assert!(
                cut_plan.is_summary_cut(&procedures[name]),
                "the mounted {name} body remains identity-only"
            );
        }
        assert_eq!(plan_site_shape(&cut_plan), expected_sites);
        let directly_discovered_calls = procedures["root"].semantics().call_sites().len();
        assert_eq!(
            cut_cache.dispatch_misses(),
            u64::try_from(directly_discovered_calls).expect("fixture call count fits in u64"),
            "exact-workspace hydration does not run cut-root or descendant dispatch"
        );

        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            fresh_state,
            ValueFlowCache::default(),
        );
        assert_eq!(result_site_shape(&warm), expected_sites, "{warm:#?}");
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(warm.reusable_summary_hits > 0, "{warm:#?}");
    }

    #[test]
    fn corrupt_exact_behavior_provenance_falls_back_to_live_surface_validation() {
        let source = concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def leaf(value):\n    return value.member\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let fixture = |unrelated_body: &str| {
            runtime_fixture_from_project(
                InlineTestProject::with_language(Language::Python)
                    .file("app.py", source)
                    .file("unrelated.py", unrelated_body)
                    .build(),
            )
        };
        let (_first_project, first_workspace, first_fields, first_procedures) =
            fixture("def unrelated():\n    return 1\n");
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let (_second_project, second_workspace, second_fields, second_procedures) =
            fixture("def unrelated():\n    return 2\n");
        let (_, second_provider_behavior) = runtime_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
        );
        let second_behavior = class_set_behavior(second_provider_behavior, second_fields.digest());
        let wrapper_lineage = *first_procedures["wrapper"]
            .artifact()
            .key()
            .procedure_lineage_fingerprint(
                first_procedures["wrapper"]
                    .semantics()
                    .locator()
                    .declaration(),
            )
            .as_bytes();
        {
            let mut surfaces = state
                .class_set
                .surfaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (digest, retained) = surfaces
                .iter()
                .find(|(_, surface)| surface.header.key.procedure_lineage == wrapper_lineage)
                .map(|(digest, surface)| (*digest, surface.clone()))
                .expect("the cold solve publishes the wrapper surface");
            assert_ne!(
                retained.header.exact_behavior_digest,
                *second_behavior.as_bytes(),
                "the unrelated file edit rotates the exact workspace behavior"
            );
            assert_eq!(
                retained.header.artifact_public_identity,
                *second_procedures["wrapper"]
                    .artifact()
                    .key()
                    .public_fingerprint()
                    .as_bytes(),
                "the unchanged owner artifact remains eligible for exact replay"
            );
            assert_eq!(
                retained.header.artifact_content_identity,
                *second_procedures["wrapper"]
                    .artifact()
                    .key()
                    .revision()
                    .content()
                    .as_bytes(),
                "the unrelated edit does not change the owner content"
            );
            let mut corrupt = retained.as_ref().clone();
            corrupt.header.exact_behavior_digest = *second_behavior.as_bytes();
            assert!(
                !corrupt.has_valid_exact_provenance(),
                "mutating exact behavior without reconstructing the surface breaks provenance"
            );
            surfaces.insert(digest, Arc::new(corrupt));
        }

        let cut_cache = ValueFlowCache::default();
        let (plan, _) = runtime_cut_plan_with_cache(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state.clone(),
            DispatchHints::empty(),
            cut_cache.clone(),
        );
        assert!(
            plan.is_summary_cut(&second_procedures["wrapper"]),
            "the invalid exact provenance falls back to an equal live-validated surface"
        );
        let live_validated_calls = second_procedures["root"]
            .semantics()
            .call_sites()
            .len()
            .saturating_add(second_procedures["wrapper"].semantics().call_sites().len());
        assert_eq!(
            cut_cache.dispatch_misses(),
            u64::try_from(live_validated_calls).expect("fixture call count fits in u64"),
            "invalid exact provenance must redispatch the wrapper surface"
        );

        let warm = solve_runtime_root(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            ValueFlowCache::default(),
        );
        let fresh = solve_runtime_root(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        assert_eq!(warm.class_sets, fresh.class_sets);
        assert_eq!(warm.findings, fresh.findings);
    }

    #[test]
    fn corrupt_descendant_dispatch_read_prevents_the_ancestor_surface_cut() {
        let source = concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def helper(value):\n    return value.member\n",
            "def leaf(value):\n    return helper(value)\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let leaf = &first_procedures["leaf"];
        let leaf_lineage = *leaf
            .artifact()
            .key()
            .procedure_lineage_fingerprint(leaf.semantics().locator().declaration())
            .as_bytes();
        {
            let mut surfaces = state
                .class_set
                .surfaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (digest, retained) = surfaces
                .iter()
                .find(|(_, surface)| surface.header.key.procedure_lineage == leaf_lineage)
                .map(|(digest, surface)| (*digest, surface.clone()))
                .expect("the cold solve publishes the leaf surface");
            assert_eq!(retained.calls.len(), 1, "{retained:#?}");
            assert_eq!(retained.reads.len(), 1, "{retained:#?}");
            let mut corrupt = retained.as_ref().clone();
            corrupt.reads.clear();
            surfaces.insert(digest, Arc::new(corrupt));
        }

        // A second inline project has an independent SQLite store, so only the
        // deliberately corrupt runtime certificate can satisfy this lookup.
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let (plan, _) = runtime_cut_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(
            plan.value_flow()
                .has_snapshot(&second_procedures["wrapper"])
        );
        assert!(plan.value_flow().has_snapshot(&second_procedures["leaf"]));
        assert!(
            !plan.is_summary_cut(&second_procedures["wrapper"]),
            "a missing descendant dispatch read invalidates the ancestor certificate"
        );
        assert!(
            !plan.is_summary_cut(&second_procedures["leaf"]),
            "the corrupt descendant certificate cannot prune its own body"
        );

        let warm = solve_runtime_root(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            ValueFlowCache::default(),
        );
        let semantic_shape = |result: &TypeFlowRootResult| {
            let mut rows = result
                .class_sets
                .iter()
                .map(|set| {
                    let mut classes = set
                        .classes
                        .iter()
                        .map(|(class, _)| Box::<str>::from(class.qualified_name()))
                        .collect::<Vec<_>>();
                    classes.sort_unstable();
                    let unknown = set
                        .unknown
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    (
                        Box::<str>::from(procedure_name(&set.site.procedure)),
                        set.site.member.clone(),
                        classes,
                        unknown,
                        set.status.label(),
                    )
                })
                .collect::<Vec<_>>();
            rows.sort_unstable();
            rows
        };
        assert_eq!(semantic_shape(&warm), semantic_shape(&cold));
        assert!(cold.findings.is_empty(), "{cold:#?}");
        assert!(warm.findings.is_empty(), "{warm:#?}");
    }

    #[test]
    fn persisted_cut_keeps_an_uncalled_lexical_member_site_fully_discovered() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def leaf(value):\n    return value\n",
            "def wrapper(value):\n",
            "    def nested():\n        return value.member\n",
            "    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        ));
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            TypeFlowSummaryState::default(),
            ValueFlowCache::default(),
        );
        let fresh_state = TypeFlowSummaryState::default();
        let (cut_plan, _) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            fresh_state.clone(),
            DispatchHints::empty(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["wrapper"]));
        assert!(cut_plan.value_flow().has_snapshot(&procedures["nested"]));
        assert!(
            !cut_plan.is_summary_cut(&procedures["nested"]),
            "a lexical child is ordinary independently processed work"
        );

        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            fresh_state,
            ValueFlowCache::default(),
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
    }

    #[test]
    fn immediate_lexical_child_without_zero_does_not_block_ancestor_cut() {
        let source = concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def wrapper(value):\n",
            "    def nested():\n        return value.member\n",
            "    return value\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let nested_lineage = first_procedures["nested"]
            .artifact()
            .key()
            .procedure_lineage_fingerprint(
                first_procedures["nested"]
                    .semantics()
                    .locator()
                    .declaration(),
            );
        {
            let mut summaries = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            summaries.retain(|_, summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() != nested_lineage
                    || !matches!(summary.key.entry, StableEntryFact::Zero)
            });
        }

        // The proposed wrapper cut does not suppress its immediate lexical
        // child: discovery always queues that child ordinarily. Its retained
        // surface therefore needs structural validation, but no executable
        // summary family, to preserve the wrapper cut.
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let (plan, _) = runtime_cut_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(plan.is_summary_cut(&second_procedures["wrapper"]));
        assert!(plan.value_flow().has_snapshot(&second_procedures["nested"]));
        assert!(!plan.is_summary_cut(&second_procedures["nested"]));

        let warm = solve_runtime_root(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            ValueFlowCache::default(),
        );
        assert_eq!(result_site_shape(&warm), result_site_shape(&cold));
        assert_eq!(warm.findings, cold.findings);
    }

    #[test]
    fn acquisition_session_reuses_descendant_validation_with_root_sensitive_lexicals() {
        let source = concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def leaf(value):\n    return value\n",
            "def middle(value):\n",
            "    def lexical(item):\n        return item\n",
            "    return leaf(value)\n",
            "def wrapper(value):\n    return middle(value)\n",
            "def root():\n",
            "    value = wrapper(Present())\n",
            "    return value.member\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let lexical = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["lexical"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(lexical.published_summaries > 0, "{lexical:#?}");

        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &second_workspace,
            second_workspace.analyzer().active_semantic_model_snapshot(),
            DispatchHints::empty(),
        );
        let discovery = WorkspaceValueFlowProvider::with_oracle(
            provider.oracle().clone(),
            provider.behavior_identity(),
            ValueFlowCache::default(),
        );
        let mut cuts = ClassSetAcquisitionCuts::new(
            state,
            &second_workspace,
            &discovery,
            provider.behavior_identity(),
            &second_fields,
            HashSet::default(),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (_, wrapper_snapshot) = cuts
            .acquire_snapshot(
                &second_procedures["wrapper"],
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the wrapper snapshot is available");
        let (_, middle_snapshot) = cuts
            .acquire_snapshot(
                &second_procedures["middle"],
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the middle snapshot is available");
        let (_, _, middle_closure) = cuts
            .validated_surface_closure(
                &second_procedures["middle"],
                &middle_snapshot,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the middle surface closure validates");
        for name in ["middle", "leaf"] {
            assert!(
                middle_closure.contains_key(&second_procedures[name].durable_key()),
                "the middle-rooted closure retains {name}"
            );
        }
        assert!(
            !middle_closure.contains_key(&second_procedures["lexical"].durable_key()),
            "the immediate lexical child is ordinary discovery work when middle is the cut root"
        );
        assert_eq!(cuts.replayed_surfaces.len(), 2);

        let (_, _, wrapper_closure) = cuts
            .validated_surface_closure(
                &second_procedures["wrapper"],
                &wrapper_snapshot,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the wrapper surface closure validates");
        for name in ["wrapper", "middle", "leaf", "lexical"] {
            assert!(
                wrapper_closure.contains_key(&second_procedures[name].durable_key()),
                "the nested middle procedure exposes {name} in the wrapper closure"
            );
        }
        assert_eq!(
            cuts.replayed_surfaces.len(),
            4,
            "the later descendant role expands the lazy lexical edge exactly once"
        );
        let validation_work = cuts.validation_work;
        cuts.validated_surface_closure(
            &second_procedures["middle"],
            &middle_snapshot,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("the fully memoized middle surface closure validates again");
        assert_eq!(cuts.validation_work, validation_work);

        assert!(cuts.disable_cut(&second_procedures["leaf"]));
        assert!(
            cuts.validated_surface_closure(
                &second_procedures["wrapper"],
                &wrapper_snapshot,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .is_none(),
            "an ancestor cut cannot remount a selectively disabled descendant"
        );
    }

    #[test]
    fn acquisition_session_scans_one_artifact_once_for_many_exact_identities() {
        let source = concat!(
            "def first(value):\n    return value\n",
            "def second(value):\n    return value\n",
            "def third(value):\n    return value\n",
            "def fourth(value):\n    return value\n",
            "def fifth(value):\n    return value\n",
            "def root(value):\n    return fifth(fourth(third(second(first(value)))))\n",
        );
        let (project, workspace, field_slots, procedures) = runtime_fixture(source);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &workspace,
            workspace.analyzer().active_semantic_model_snapshot(),
            DispatchHints::empty(),
        );
        let discovery = WorkspaceValueFlowProvider::with_oracle(
            provider.oracle().clone(),
            provider.behavior_identity(),
            ValueFlowCache::default(),
        );
        let mut cuts = ClassSetAcquisitionCuts::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &discovery,
            provider.behavior_identity(),
            &field_slots,
            HashSet::default(),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut identities = Vec::new();
        for procedure in procedures.values() {
            let (procedure, snapshot) = cuts
                .acquire_snapshot(
                    procedure,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("the exact-identity fixture snapshot is available");
            identities.push(
                class_set_surface_identity_from_snapshot(&procedure, &snapshot)
                    .expect("the fixture procedure has a surface identity"),
            );
        }
        assert!(identities.len() > 2);
        workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the many-identity artifact rematerializes")
            .available_value()
            .expect("the many-identity artifact remains available");

        let before_scan = budget.used().procedures;
        cuts.acquire_exact_identity(
            &identities[0],
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("the first exact identity is acquired");
        let after_scan = budget.used().procedures;
        assert_eq!(
            after_scan - before_scan,
            procedures["root"].artifact().procedures().len()
        );
        for identity in &identities[1..] {
            cuts.acquire_exact_identity(
                identity,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("another exact identity from the same artifact is acquired");
        }
        assert_eq!(budget.used().procedures, after_scan);
        assert_eq!(cuts.exact_identity_lineage_indexes.len(), 1);
    }

    #[test]
    fn acquisition_session_does_not_cache_an_incomplete_lineage_scan() {
        let source = concat!(
            "def first(value):\n    return value\n",
            "def second(value):\n    return first(value)\n",
            "def third(value):\n    return second(value)\n",
            "def root(value):\n    return third(value)\n",
        );
        let (project, workspace, field_slots, procedures) = runtime_fixture(source);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &workspace,
            workspace.analyzer().active_semantic_model_snapshot(),
            DispatchHints::empty(),
        );
        let discovery = WorkspaceValueFlowProvider::with_oracle(
            provider.oracle().clone(),
            provider.behavior_identity(),
            ValueFlowCache::default(),
        );
        let mut cuts = ClassSetAcquisitionCuts::new(
            TypeFlowSummaryState::default(),
            &workspace,
            &discovery,
            provider.behavior_identity(),
            &field_slots,
            HashSet::default(),
        );
        let cancellation = CancellationToken::default();
        let mut setup_budget = SemanticBudget::default();
        let (root, snapshot) = cuts
            .acquire_snapshot(
                &procedures["root"],
                &mut SemanticRequest::new(&mut setup_budget, &cancellation),
            )
            .expect("the exact-identity fixture snapshot is available");
        let identity = class_set_surface_identity_from_snapshot(&root, &snapshot)
            .expect("the fixture root has a surface identity");
        let procedure_count = root.artifact().procedures().len();
        assert!(procedure_count > 1);
        workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut setup_budget, &cancellation),
            )
            .expect("the exact-identity artifact rematerializes")
            .available_value()
            .expect("the exact-identity artifact remains available");
        let scope = setup_budget.scope_snapshot();
        let mut tight_limits = SemanticBudget::default().limits();
        tight_limits.procedures = procedure_count - 1;
        let mut tight_budget = SemanticBudget::new_child(tight_limits, &scope);

        assert!(
            cuts.acquire_exact_identity(
                &identity,
                &mut SemanticRequest::new(&mut tight_budget, &cancellation),
            )
            .is_none()
        );
        assert!(cuts.replay_aborted);
        assert!(cuts.exact_identity_lineage_indexes.is_empty());

        let mut retry_budget =
            SemanticBudget::new_child(SemanticBudget::default().limits(), &scope);
        cuts.acquire_exact_identity(
            &identity,
            &mut SemanticRequest::new(&mut retry_budget, &cancellation),
        )
        .expect("a funded retry rescans and acquires the exact identity");
        assert_eq!(retry_budget.used().procedures, procedure_count);
        assert_eq!(cuts.exact_identity_lineage_indexes.len(), 1);
    }

    #[test]
    fn missing_source_partition_under_a_mandatory_cut_selectively_replans_that_cut() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def leaf(value):\n    return value\n",
            "def wrapper(value):\n",
            "    if value is None:\n        return Present()\n",
            "    return leaf(value)\n",
            "def root():\n    value = wrapper(Present())\n    return value.member\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        let (cut_plan, _) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["wrapper"]));

        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(
            warm.reusable_summary_hits > 0,
            "the selective retry may reuse exact rows outside the failed cut: {warm:#?}"
        );
    }

    #[test]
    fn one_missing_carrier_entry_keeps_an_independent_sibling_cut() {
        let source = concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def left_leaf(value):\n    return value\n",
            "def right_leaf():\n    return Present()\n",
            "def left(value):\n    return left_leaf(value)\n",
            "def right():\n    return right_leaf()\n",
            "def root():\n",
            "    first = left(Present())\n",
            "    second = right()\n",
            "    first.member\n",
            "    return second.member\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.findings.is_empty(), "{cold:#?}");

        let left_lineage = first_procedures["left"]
            .artifact()
            .key()
            .procedure_lineage_fingerprint(
                first_procedures["left"].semantics().locator().declaration(),
            );
        {
            let mut summaries = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            summaries.retain(|_, summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() != left_lineage
                    || matches!(summary.key.entry, StableEntryFact::Zero)
            });
        }

        let (first_plan, first_manifest) = runtime_cut_plan_with_cache(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state.clone(),
            DispatchHints::empty(),
            cache.clone(),
        );
        assert!(first_plan.is_summary_cut(&second_procedures["left"]));
        assert!(first_plan.is_summary_cut(&second_procedures["right"]));

        let cancellation = CancellationToken::default();
        let provider = WorkspaceIcfgProvider::new(&second_workspace);
        let mut first_summaries = PreparedClassSetSummaries::new_with_cuts(
            state.clone(),
            &second_workspace,
            &first_plan,
            &second_fields,
            provider.behavior_identity(),
            first_manifest,
        );
        let mut semantic_budget = SemanticBudget::default();
        let mut solver_budget = SolverBudget::default();
        let first_error = solve_value_flow_with_reusable_summaries(
            &second_procedures["root"],
            &provider,
            &mut first_summaries,
            first_plan.value_flow(),
            WitnessRetentionLimits::disabled(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect_err("the left Carrier relation was deliberately removed");
        let failed = first_error
            .mandatory_summary_cut_miss()
            .expect("the missing mandatory relation names its cut");
        assert_eq!(
            failed.durable_key(),
            second_procedures["left"].durable_key()
        );

        let mut disabled = HashSet::default();
        assert!(disabled.insert(failed.durable_key()));
        let mut selective_succeeded = false;
        for attempt in 0..second_procedures.len() {
            let (next_plan, next_manifest) = runtime_cut_plan_with_disabled_cuts(
                &second_workspace,
                &second_fields,
                &second_procedures["root"],
                state.clone(),
                DispatchHints::empty(),
                cache.clone(),
                disabled.clone(),
            );
            assert!(!next_plan.is_summary_cut(&second_procedures["left"]));
            if attempt == 0 {
                assert!(
                    next_plan.is_summary_cut(&second_procedures["right"]),
                    "disabling the failed left cut retains an unrelated right cut"
                );
            }

            let mut next_summaries = PreparedClassSetSummaries::new_with_cuts(
                state.clone(),
                &second_workspace,
                &next_plan,
                &second_fields,
                provider.behavior_identity(),
                next_manifest,
            );
            let mut semantic_budget = SemanticBudget::default();
            let mut solver_budget = SolverBudget::default();
            match solve_value_flow_with_reusable_summaries(
                &second_procedures["root"],
                &provider,
                &mut next_summaries,
                next_plan.value_flow(),
                WitnessRetentionLimits::disabled(),
                &mut semantic_budget,
                &mut DataflowRequest::new(&mut solver_budget, &cancellation),
            ) {
                Ok(result) => {
                    assert_eq!(result.result().termination(), SolverTermination::FixedPoint);
                    assert!(result.result().metrics().reusable_summary_hits > 0);
                    selective_succeeded = true;
                    break;
                }
                Err(error) => {
                    let failed = error
                        .mandatory_summary_cut_miss()
                        .expect("only another mandatory cut may reject this trial");
                    assert!(next_plan.is_summary_cut(failed));
                    assert!(
                        disabled.insert(failed.durable_key()),
                        "each retry expands a new durable cut"
                    );
                }
            }
        }
        assert!(
            selective_succeeded,
            "a finite sequence of selective expansions reaches a valid plan"
        );

        let warm = solve_runtime_root(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            cache,
        );
        assert_eq!(result_site_shape(&warm), result_site_shape(&cold));
        assert!(
            warm.class_sets
                .iter()
                .all(|class_set| class_set.status == ClassSetStatus::Known),
            "the selectively expanded production solve remains complete: {warm:#?}"
        );
        assert_eq!(warm.findings, cold.findings);
        assert!(warm.reusable_summary_hits > 0, "{warm:#?}");
    }

    #[test]
    fn carrier_only_surface_family_is_not_selected_as_a_mandatory_cut() {
        let source = concat!(
            "class Present:\n    pass\n",
            "def wrapper(value):\n    return value\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let wrapper_lineage = first_procedures["wrapper"]
            .artifact()
            .key()
            .procedure_lineage_fingerprint(
                first_procedures["wrapper"]
                    .semantics()
                    .locator()
                    .declaration(),
            );
        {
            let mut summaries = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            summaries.retain(|_, summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() != wrapper_lineage
                    || !matches!(summary.key.entry, StableEntryFact::Zero)
            });
            assert!(summaries.values().any(|summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() == wrapper_lineage
                    && matches!(summary.key.entry, StableEntryFact::Carrier { .. })
            }));
        }

        // Use an independent store so persisted Zero rows from the cold solve
        // cannot satisfy this deliberately carrier-only runtime family.
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let (plan, _) = runtime_cut_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            DispatchHints::empty(),
        );
        assert!(
            !plan.is_summary_cut(&second_procedures["wrapper"]),
            "every procedure receives the mandatory Zero seed before carrier entries"
        );
    }

    #[test]
    fn descendant_without_zero_summary_prevents_the_ancestor_surface_cut() {
        let source = concat!(
            "class Present:\n    pass\n",
            "def leaf(value):\n    return value\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let lineage = |procedure: &ProcedureHandle| {
            procedure
                .artifact()
                .key()
                .procedure_lineage_fingerprint(procedure.semantics().locator().declaration())
        };
        let wrapper_lineage = lineage(&first_procedures["wrapper"]);
        let leaf_lineage = lineage(&first_procedures["leaf"]);
        {
            let mut summaries = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(summaries.values().any(|summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() == wrapper_lineage
                    && matches!(summary.key.entry, StableEntryFact::Zero)
            }));
            summaries.retain(|_, summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() != leaf_lineage
                    || !matches!(summary.key.entry, StableEntryFact::Zero)
            });
            assert!(!summaries.values().any(|summary| {
                summary.key.procedure.identity().read_lineage_fingerprint() == leaf_lineage
                    && matches!(summary.key.entry, StableEntryFact::Zero)
            }));
        }
        assert!(
            state
                .class_set
                .surfaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .values()
                .any(|surface| surface.header.key.procedure_lineage == *leaf_lineage.as_bytes())
        );

        // A second inline project has an independent SQLite store, so the
        // descendant has a surface certificate but no persisted Zero row.
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let (plan, _) = runtime_cut_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(
            plan.value_flow()
                .has_snapshot(&second_procedures["wrapper"])
        );
        assert!(plan.value_flow().has_snapshot(&second_procedures["leaf"]));
        assert!(
            !plan.is_summary_cut(&second_procedures["wrapper"]),
            "the ancestor cut requires a Zero row for every hydrated descendant"
        );
        assert!(
            !plan.is_summary_cut(&second_procedures["leaf"]),
            "the surface-only descendant cannot prune its own body"
        );

        let warm = solve_runtime_root(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            ValueFlowCache::default(),
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
    }

    #[test]
    fn terminal_meeting_at_a_mandatory_cut_uses_the_exact_empty_relation() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    def member(self):\n        pass\n",
            "def consume(value):\n    return value\n",
            "def root():\n",
            "    value = Present()\n",
            "    return consume(value.member)\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.findings.is_empty(), "{cold:#?}");

        let cancellation = CancellationToken::default();
        let (cut_plan, cut_manifest) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["consume"]));
        let source = cut_plan
            .value_flow()
            .sources()
            .next()
            .map(|(source, _)| source)
            .expect("the constructor produces a class source");
        let sink = cut_plan
            .value_flow()
            .sinks()
            .next()
            .map(|(sink, _)| sink)
            .expect("the member access produces a receiver sink");
        let meeting = ValueFlowFact::meeting_fact(source, sink, ValueFlowUncertainty::empty());
        let behavior = WorkspaceIcfgProvider::new(&workspace).behavior_identity();
        let mut prepared = PreparedClassSetSummaries::new_with_cuts(
            state.clone(),
            &workspace,
            &cut_plan,
            &field_slots,
            behavior,
            cut_manifest,
        );
        let mut solver_budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut solver_budget, &cancellation);
        let terminal = prepared
            .summary_for(
                &procedures["consume"],
                &procedures["root"],
                meeting,
                &mut request,
            )
            .expect("a terminal Meeting cannot miss a mandatory summary cut")
            .expect("the terminal Meeting has an exact reusable relation");
        assert!(terminal.exits.is_empty());
        assert!(terminal.reached.is_empty());
        assert_eq!(terminal.call_cycle, SummaryCallCycle::ExcludesRoot);
        assert_eq!(
            terminal.called_procedures,
            SummaryCalledProcedures::CoveredByContract
        );

        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state,
            ValueFlowCache::default(),
        );
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(
            warm.reusable_summary_hits > 0,
            "the cut-backed trial completes without a full-plan retry: {warm:#?}"
        );
    }

    #[test]
    fn surface_only_candidate_does_not_make_an_executable_family_ambiguous() {
        let source = concat!(
            "class Present:\n    pass\n",
            "def leaf(value):\n    return value\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");

        let wrapper_lineage = *first_procedures["wrapper"]
            .artifact()
            .key()
            .procedure_lineage_fingerprint(
                first_procedures["wrapper"]
                    .semantics()
                    .locator()
                    .declaration(),
            )
            .as_bytes();
        let retained = state
            .class_set
            .surfaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|surface| surface.header.key.procedure_lineage == wrapper_lineage)
            .cloned()
            .expect("the cold solve publishes the wrapper surface");
        let mut surface_only_header = retained.header.clone();
        surface_only_header.carrier_semantics_digest[0] ^= u8::MAX;
        let surface_only = ClassSetProcedureSurfaceRow::try_new(
            surface_only_header,
            retained.calls.clone(),
            retained.lexical_children.clone(),
            retained.reads.clone(),
        )
        .expect("the alternate candidate is a valid structural surface");
        assert_ne!(surface_only.surface_digest(), retained.surface_digest());
        assert!(state.class_set.publish_surface(surface_only));

        // The alternate candidate shares the live structural family but has
        // no Zero summary. It is not executable and therefore cannot make the
        // single executable surface ambiguous.
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let (plan, _) = runtime_cut_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
            state,
            DispatchHints::empty(),
        );
        assert!(
            plan.is_summary_cut(&second_procedures["wrapper"]),
            "surface-only historical candidates are filtered before replay ambiguity"
        );
    }

    #[test]
    fn indeterminate_later_candidate_aborts_surface_selection() {
        let source = concat!(
            "class Present:\n    pass\n",
            "def wrapper(value):\n    return value\n",
            "def root():\n    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(source);
        let populated = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            populated.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let wrapper_lineage = *first_procedures["wrapper"]
            .artifact()
            .key()
            .procedure_lineage_fingerprint(
                first_procedures["wrapper"]
                    .semantics()
                    .locator()
                    .declaration(),
            )
            .as_bytes();
        let surface = populated
            .class_set
            .surfaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|surface| surface.header.key.procedure_lineage == wrapper_lineage)
            .cloned()
            .expect("the cold solve publishes the wrapper surface");
        let surface_digest = *surface.surface_digest();
        let surface_only = (1_u32..=10_000)
            .find_map(|salt| {
                let mut header = surface.header.clone();
                header.carrier_semantics_digest[..4].copy_from_slice(&salt.to_le_bytes());
                let candidate = ClassSetProcedureSurfaceRow::try_new(
                    header,
                    surface.calls.clone(),
                    surface.lexical_children.clone(),
                    surface.reads.clone(),
                )
                .expect("the alternate candidate is a valid structural surface");
                (candidate.surface_digest() > &surface_digest).then_some(candidate)
            })
            .expect("a bounded deterministic salt produces a later candidate digest");
        assert!(populated.class_set.publish_surface(surface_only));

        // Use an independent empty store so the surface-only runtime candidate
        // must consult persistence after the executable runtime family misses.
        // Exhaust the validation cap after selecting the earlier executable
        // candidate but before proving the later candidate absent. Inability
        // to classify it must abort the whole closure instead of hiding
        // possible ambiguity.
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(source);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &second_workspace,
            second_workspace.analyzer().active_semantic_model_snapshot(),
            DispatchHints::empty(),
        );
        let discovery = WorkspaceValueFlowProvider::with_oracle(
            provider.oracle().clone(),
            provider.behavior_identity(),
            ValueFlowCache::default(),
        );
        let mut cuts = ClassSetAcquisitionCuts::new(
            populated,
            &second_workspace,
            &discovery,
            provider.behavior_identity(),
            &second_fields,
            HashSet::default(),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (_, wrapper_snapshot) = cuts
            .acquire_snapshot(
                &second_procedures["wrapper"],
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the live wrapper snapshot is available");
        let family = cuts
            .surface_family_key(&second_procedures["wrapper"], &wrapper_snapshot)
            .expect("the wrapper has a stable surface family");
        let before_probe = cuts.validation_work;
        let candidates = cuts
            .surface_candidates(
                &family,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the two-candidate family is bounded");
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].surface_digest(), &surface_digest);
        let candidate_loading_work = cuts.validation_work - before_probe;
        let runtime_summary_work = cuts.repository.runtime_snapshot().len();
        let work_before_later_preflight = 1usize
            .checked_add(candidate_loading_work)
            .and_then(|work| work.checked_add(runtime_summary_work))
            .expect("fixture validation work does not overflow");
        cuts.validation_work = MAX_CLASS_SET_SUMMARY_ROWS
            .checked_sub(work_before_later_preflight)
            .expect("fixture leaves room to select the first candidate");

        assert!(
            cuts.validated_surface_closure(
                &second_procedures["wrapper"],
                &wrapper_snapshot,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .is_none(),
            "an indeterminate later candidate cannot be treated as proven absent"
        );
    }

    #[test]
    fn finding_from_a_cut_trial_retries_fresh_and_preserves_its_witness() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Missing:\n    pass\n",
            "def leaf(value):\n    return value\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    value = wrapper(Missing())\n    return value.absent\n",
        ));
        let state = TypeFlowSummaryState::default();
        let cache = ValueFlowCache::default();
        let cold = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            cache.clone(),
        );
        assert_eq!(cold.findings.len(), 1, "{cold:#?}");
        assert!(cold.findings[0].witness.is_ok(), "{cold:#?}");
        let (cut_plan, _) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(cut_plan.is_summary_cut(&procedures["wrapper"]));

        let warm = solve_runtime_root(&workspace, &field_slots, &procedures["root"], state, cache);
        assert_eq!(warm.class_sets, cold.class_sets);
        assert_eq!(warm.findings, cold.findings);
        assert!(warm.findings[0].witness.is_ok(), "{warm:#?}");
    }

    #[test]
    fn mixed_runtime_summary_cannot_poison_a_certified_surface_cut() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "def leaf(value):\n    return value\n",
            "def wrapper(value):\n    return leaf(value)\n",
            "def root():\n    return wrapper(1)\n",
        ));
        let state = TypeFlowSummaryState::default();
        solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        {
            let mut runtime = state
                .class_set
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (_, row) = runtime
                .iter_mut()
                .find(|(_, row)| {
                    summary_name(row) == "wrapper"
                        && !matches!(row.key.entry, StableEntryFact::Zero)
                })
                .expect("the wrapper publishes a carrier entry");
            let mut mixed = row.as_ref().clone();
            mixed.key.contract.direct_calls = StableDigest::sha256(b"mixed-call-contract");
            *row = Arc::new(mixed);
        }

        let (plan, _) = runtime_cut_plan(
            &workspace,
            &field_slots,
            &procedures["root"],
            state.clone(),
            DispatchHints::empty(),
        );
        assert!(plan.is_summary_cut(&procedures["wrapper"]));
        assert!(plan.value_flow().has_snapshot(&procedures["leaf"]));
        let warm = solve_runtime_root(
            &workspace,
            &field_slots,
            &procedures["root"],
            state,
            ValueFlowCache::default(),
        );
        assert!(warm.reusable_summary_hits > 0, "{warm:#?}");
    }

    #[test]
    fn new_reachable_fallback_location_rotates_lookup_and_misses() {
        let first_source = concat!(
            "class Present:\n    def known(self):\n        pass\n",
            "def wrapper(value):\n",
            "    unresolved_external_call(value)\n",
            "    value.known\n",
            "    return value\n",
            "def root():\n",
            "    return wrapper(Present())\n",
        );
        let second_source = concat!(
            "class Present:\n    def known(self):\n        pass\n",
            "def wrapper(value):\n",
            "    value.extra\n",
            "    unresolved_external_call(value)\n",
            "    value.known\n",
            "    return value\n",
            "def root():\n",
            "    return wrapper(Present())\n",
        );
        let (_first_project, first_workspace, first_fields, first_procedures) =
            runtime_fixture(first_source);
        let (_second_project, second_workspace, second_fields, second_procedures) =
            runtime_fixture(second_source);
        let (first_plan, first_behavior) =
            runtime_plan(&first_workspace, &first_fields, &first_procedures["root"]);
        let (second_plan, second_behavior) = runtime_plan(
            &second_workspace,
            &second_fields,
            &second_procedures["root"],
        );
        let first_wrapper = &first_procedures["wrapper"];
        let second_wrapper = &second_procedures["wrapper"];
        assert_eq!(
            second_plan
                .value_flow()
                .fallback_reachable_location_count_of(second_wrapper),
            first_plan
                .value_flow()
                .fallback_reachable_location_count_of(first_wrapper)
                .saturating_add(1),
            "the added structured field access is a new fallback-reachable location"
        );

        let state = TypeFlowSummaryState::default();
        let cold = solve_runtime_root(
            &first_workspace,
            &first_fields,
            &first_procedures["root"],
            state.clone(),
            ValueFlowCache::default(),
        );
        assert!(cold.published_summaries > 0, "{cold:#?}");
        let retained = state
            .class_set
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|summary| {
                summary_name(summary) == "wrapper"
                    && matches!(summary.key.entry, StableEntryFact::Carrier { .. })
            })
            .cloned()
            .expect("the first solve publishes a wrapper carrier relation");
        let first_prepared = PreparedClassSetSummaries::new(
            TypeFlowSummaryState::default(),
            &first_workspace,
            &first_plan,
            &first_fields,
            first_behavior,
        );
        let mut second_prepared = PreparedClassSetSummaries::new(
            state,
            &second_workspace,
            &second_plan,
            &second_fields,
            second_behavior,
        );
        assert_ne!(
            first_prepared.procedures[first_wrapper]
                .contract
                .carrier_semantics,
            second_prepared.procedures[second_wrapper]
                .contract
                .carrier_semantics,
            "the exact carrier contract pins the new reachable location"
        );

        let StableEntryFact::Carrier { uncertain, .. } = retained.key.entry else {
            unreachable!("the retained wrapper relation has a carrier entry")
        };
        let parameter = second_plan
            .value_flow()
            .carrier_keys()
            .iter()
            .find(|carrier| {
                matches!(
                    carrier,
                    ValueFlowCarrierKey::Port {
                        procedure,
                        kind: ValueFlowPortKey::Parameter { ordinal: 0 },
                    } if procedure == second_wrapper.semantics().locator()
                )
            })
            .expect("the changed wrapper retains its parameter carrier");
        let source = second_plan
            .value_flow()
            .sources()
            .find(|(_, spec)| spec.point().procedure() == &second_procedures["root"])
            .map(|(source, _)| source)
            .expect("the changed root supplies one constructor source");
        let entry_fact = ValueFlowFact::carrier_fact(
            source,
            second_plan
                .value_flow()
                .carrier_id_for_key(parameter)
                .expect("the changed wrapper parameter remains bound"),
            ValueFlowUncertainty::from_semantic_uncertainty(uncertain),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut budget, &cancellation);
        assert!(
            second_prepared
                .summary_for(
                    second_wrapper,
                    &second_procedures["root"],
                    entry_fact,
                    &mut request,
                )
                .expect("the changed wrapper lookup completes")
                .is_none(),
            "the relation published without the new target cannot satisfy the changed lookup"
        );
        assert_eq!(
            second_prepared.profile().lookup_relation,
            1,
            "the non-hit is attributed to the unavailable exact relation"
        );
    }

    #[test]
    fn shared_large_fallback_component_is_canonicalized_once() {
        let (_project, workspace, field_slots, procedures) = runtime_fixture(concat!(
            "class Present:\n    pass\n",
            "def wrapper(value):\n",
            "    value.first\n",
            "    value.second\n",
            "    value.third\n",
            "    value.fourth\n",
            "    unresolved_one(value)\n",
            "    unresolved_two(value)\n",
            "    unresolved_three(value)\n",
            "    unresolved_four(value)\n",
            "    return value\n",
            "def root():\n",
            "    return wrapper(Present())\n",
        ));
        let (plan, _behavior) = runtime_plan(&workspace, &field_slots, &procedures["root"]);
        let wrapper = &procedures["wrapper"];
        let component_ordinals = plan.value_flow().fallback_component_ordinals_of(wrapper);
        assert_eq!(component_ordinals.len(), 4, "one component per call input");
        assert!(
            component_ordinals.windows(2).all(|pair| pair[0] == pair[1]),
            "all four calls share one live fallback component: {component_ordinals:?}"
        );
        let location_rows = plan
            .value_flow()
            .fallback_reachable_location_count_of(wrapper);
        assert_eq!(location_rows, 4, "the shared component has four locations");

        let identity = plan
            .value_flow()
            .carrier_summary_identities()
            .remove(wrapper)
            .expect("the wrapper has carrier identity");
        assert_eq!(
            identity.fallback_component_reference_count(),
            component_ordinals.len(),
            "each call stores one fixed-size component digest"
        );
        assert_eq!(
            plan.value_flow()
                .fallback_component_identity_rows_of(wrapper),
            1 + location_rows,
            "component hashing charges its envelope and locations once"
        );
        assert!(
            identity.fallback_component_reference_count() + location_rows
                < component_ordinals.len() * location_rows,
            "identity storage and hashing stay linear instead of expanding every location per call"
        );
    }
}
