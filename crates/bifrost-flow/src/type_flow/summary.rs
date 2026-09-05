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
    sync::{Arc, Mutex},
};

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, IcfgProviderBehaviorIdentity,
    LengthDelimitedDigest, ProcedureHandle, ProgramPointId, ReturnTransferKind, StableDigest,
};
use crate::analyzer::store::class_set_summaries::{
    ClassSetSummaryAttachment, ClassSetSummaryChargeRow, ClassSetSummaryExitKindRow,
    ClassSetSummaryExitRow, ClassSetSummaryFactRow, ClassSetSummaryFactShapeRow,
    ClassSetSummaryFactSourceRow, ClassSetSummaryHeaderRow, ClassSetSummaryOutputDigest,
    ClassSetSummaryReachedRow, ClassSetSummaryRow, ClassSetSummaryRowKey,
    class_set_summary_output_digest,
};
use crate::analyzer::store::{AnalyzerStore, StoreError};
use crate::dataflow::{
    DataflowRequest, FactId, PathQuality, PathQualityFrontier, ProcedureSummaryIdentity,
    ProcedureSummaryKey, ProductionSemanticSummaryRepository, ReusableEndSummary,
    ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryProvider, SemanticInputStatus,
    SemanticProcedureSummary, SolverTermination, SolverWork, SummaryBehaviorKey, SummaryCallCycle,
    SummaryCalledProcedures, SummaryCompleteness, SummaryContextKey, SummaryDataflowResult,
    SummaryDependencyKey, SummaryEffect, SummaryEffectKey, SummaryEntry, SummaryEventKey,
    SummaryOrigin, SummaryProcedureSemanticsKey, SummarySchemaVersion, SummarySemanticsVersion,
};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    BindingCoverage, ValueFlowCarrierKey, ValueFlowCarrierSummaryIdentity, ValueFlowEventKey,
    ValueFlowFact, ValueFlowPlan, ValueFlowUncertainty,
};

use super::plan::{ProcedureDispatchReadContract, uncovered_reason};
use super::{FieldSlotIndex, TypeFlowPlan};

const CLASS_SET_SUMMARY_SEMANTICS: &[u8] = b"bifrost-class-set-summary-semantics-v1";
const CLASS_SET_SUMMARY_CONTEXT: &[u8] = b"bifrost-class-set-summary-context-v1";
const CLASS_SET_SUMMARY_BEHAVIOR: &[u8] = b"bifrost-class-set-summary-behavior-v1";
const CLASS_SET_SUMMARY_ATOM: &[u8] = b"bifrost-class-set-summary-atom-v1";
const CLASS_SET_SUMMARY_ENTRY: &[u8] = b"bifrost-class-set-summary-entry-v1";
const CLASS_SET_SUMMARY_LOOKUP: &[u8] = b"bifrost-class-set-summary-lookup-v1";
const CLASS_SET_SUMMARY_CALL_CONTRACT: &[u8] = b"bifrost-class-set-summary-call-contract-v1";
const MAX_CLASS_SET_SUMMARIES: usize = 16_384;
const MAX_CLASS_SET_SUMMARY_ROWS: usize = 262_144;

/// Workspace-owned in-memory state for the class-set summary dimension.
#[derive(Debug, Clone)]
pub struct TypeFlowSummaryState {
    semantic: Arc<ProductionSemanticSummaryRepository>,
    class_set: Arc<ClassSetSummaryRepository>,
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
        }
    }

    #[cfg(test)]
    pub(crate) fn semantic(&self) -> &Arc<ProductionSemanticSummaryRepository> {
        &self.semantic
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClassSetProcedureContract {
    carrier: ValueFlowCarrierSummaryIdentity,
    field_slots: StableDigest,
    direct_calls: StableDigest,
    sources: Box<[(ValueFlowEventKey, ClassAtom)]>,
    sinks: Box<[ValueFlowEventKey]>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum StableEntryFact {
    Zero,
    Carrier {
        carrier: Box<ValueFlowCarrierKey>,
        uncertain: bool,
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
    output_digest: ClassSetSummaryOutputDigest,
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
    output: ClassSetSummaryOutputDigest,
}

/// Runtime lookup independent of the common envelope's dependency keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClassSetRuntimeLookupKey {
    procedure: StableDigest,
    entry_selector: StableDigest,
}

#[derive(Debug, Default)]
struct ClassSetSummaryRepository {
    entries: Mutex<HashMap<ClassSetSummaryLookupKey, Arc<ClassSetProcedureSummary>>>,
    runtime: Mutex<HashMap<ClassSetRuntimeLookupKey, Arc<ClassSetProcedureSummary>>>,
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

    fn publish(&self, summary: ClassSetProcedureSummary) -> bool {
        let summary = Arc::new(summary);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (summary, inserted) = if let Some(existing) = entries.get(&summary.key) {
            assert_eq!(
                existing.as_ref(),
                summary.as_ref(),
                "one class-set summary key has one deterministic relation"
            );
            (Arc::clone(existing), false)
        } else {
            if entries.len() >= MAX_CLASS_SET_SUMMARIES {
                return false;
            }
            entries.insert(summary.key.clone(), Arc::clone(&summary));
            (summary, true)
        };
        drop(entries);
        let runtime_key = class_set_runtime_lookup_key(&summary.key);
        let mut runtime = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = runtime.get(&runtime_key)
            && existing.key == summary.key
        {
            assert_eq!(
                existing.as_ref(),
                summary.as_ref(),
                "one exact class-set key has one deterministic relation"
            );
        }
        // A child semantic key may move while this owner's local body remains
        // unchanged. The full-key map retains both exact revisions; this map
        // advances the owner-local current head after publication validated
        // the new child-output attestations.
        runtime.insert(runtime_key, summary);
        inserted
    }
}

#[derive(Debug, Clone)]
struct PreparedProcedureSummary {
    semantic: SemanticProcedureSummary,
    procedure_semantics: SummaryProcedureSemanticsKey,
    contract: ClassSetProcedureContract,
    publication_rank: usize,
}

fn class_set_procedure_contract(
    plan: &TypeFlowPlan,
    field_slots: &FieldSlotIndex,
    procedure: &ProcedureHandle,
    carrier: &ValueFlowCarrierSummaryIdentity,
    identities: &HashMap<ProcedureHandle, ProcedureSummaryIdentity>,
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
        let mut entered = coverage
            .entered
            .iter()
            .filter_map(|callee| identities.get(callee))
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
            .map(|binding| match binding {
                BindingCoverage::Answered { status } => {
                    [b"answered:".as_slice(), status.label().as_bytes()]
                        .concat()
                        .into_boxed_slice()
                }
                BindingCoverage::ProviderError { detail } => {
                    [b"provider-error:".as_slice(), detail.as_bytes()]
                        .concat()
                        .into_boxed_slice()
                }
            })
            .collect::<Vec<_>>();
        bindings.sort_unstable();
        direct_calls.push(
            &u64::try_from(bindings.len())
                .expect("binding coverage count fits in u64")
                .to_le_bytes(),
        );
        for binding in bindings {
            direct_calls.push(&binding);
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
        carrier: carrier.clone(),
        field_slots: field_slots.digest(),
        direct_calls: direct_calls.finish(),
        sources: sources.into_boxed_slice(),
        sinks: sinks.into_boxed_slice(),
    }
}

/// Whether discovery supplied exact, closed dispatch and bindings for every
/// semantic call made by this procedure.
fn procedure_call_contract_is_complete(plan: &TypeFlowPlan, procedure: &ProcedureHandle) -> bool {
    if !matches!(
        plan.dispatch_read_contract(&procedure.durable_key()),
        Some(ProcedureDispatchReadContract::Complete(_))
    ) {
        return false;
    }
    procedure.semantics().call_sites().iter().all(|call| {
        let Some(coverage) = plan.coverage_of(procedure, call.id) else {
            return false;
        };
        uncovered_reason(Some(coverage)).is_none()
            && coverage.bindings.len() == coverage.entered.len()
            && coverage
                .bindings
                .iter()
                .all(|binding| matches!(binding, BindingCoverage::Answered { .. }))
    })
}

/// Query-local live remapping over workspace-owned stable summary rows.
pub(crate) struct PreparedClassSetSummaries<'plan> {
    state: TypeFlowSummaryState,
    workspace: &'plan WorkspaceAnalyzer,
    store: Option<Arc<AnalyzerStore>>,
    plan: &'plan ValueFlowPlan,
    procedures: HashMap<ProcedureHandle, PreparedProcedureSummary>,
    procedures_by_lineage: HashMap<StableDigest, Option<ProcedureHandle>>,
    used: HashMap<ClassSetRuntimeLookupKey, Arc<ClassSetProcedureSummary>>,
}

impl<'plan> PreparedClassSetSummaries<'plan> {
    pub(crate) fn new(
        state: TypeFlowSummaryState,
        workspace: &'plan WorkspaceAnalyzer,
        plan: &'plan TypeFlowPlan,
        field_slots: &FieldSlotIndex,
        provider_behavior: IcfgProviderBehaviorIdentity,
    ) -> Self {
        let value_flow = plan.value_flow();
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
        let mut contracts = Vec::with_capacity(carrier_contracts.len());
        let mut procedure_semantics = Vec::with_capacity(carrier_contracts.len());
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
        for (procedure, carrier) in &carrier_contracts {
            let contract = class_set_procedure_contract(
                plan,
                field_slots,
                procedure,
                carrier,
                &identities_by_procedure,
            );
            let local_semantics =
                class_set_procedure_semantics_key(&contract, procedure.semantics().locator());
            contracts.push(contract);
            procedure_semantics.push(local_semantics);
        }

        let mut locally_complete = carrier_contracts
            .iter()
            .map(|(procedure, _)| procedure_call_contract_is_complete(plan, procedure))
            .collect::<Vec<_>>();
        let mut dependencies = vec![Vec::<usize>::new(); carrier_contracts.len()];
        for (index, (procedure, _)) in carrier_contracts.iter().enumerate() {
            for callee in value_flow.bound_callees_of(procedure) {
                let Some(&callee_index) = index_by_procedure.get(callee) else {
                    locally_complete[index] = false;
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
            let eligible = locally_complete[index]
                && dependencies[index]
                    .iter()
                    .all(|&callee| key_by_procedure[callee].is_some());
            if eligible {
                let mut semantic_dependencies = dependencies[index]
                    .iter()
                    .map(|&callee| {
                        SummaryDependencyKey::complete(
                            key_by_procedure[callee]
                                .clone()
                                .expect("an eligible caller has an emitted dependency"),
                        )
                    })
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
                        procedure_semantics: procedure_semantics[index],
                        contract: contracts[index].clone(),
                        publication_rank,
                    },
                );
                key_by_procedure[index] = Some(key);
                semantic_rows.push(semantic);
                components.push(publication_rank..publication_rank + 1);
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

        if !semantic_rows.is_empty()
            && state
                .semantic
                .publish_components(&semantic_rows, &components)
                .is_err()
        {
            procedures.clear();
        }

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

        Self {
            state,
            workspace,
            store: workspace.store().cloned(),
            plan: value_flow,
            procedures,
            procedures_by_lineage,
            used: HashMap::default(),
        }
    }

    pub(crate) fn has_reusable_rows(&self) -> bool {
        self.plan.bound_callees().any(|procedure| {
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
            if !prepared.semantic.dependencies().is_empty() {
                return false;
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

    fn lookup_key(
        &self,
        procedure: &ProcedureHandle,
        entry: StableEntryFact,
    ) -> Option<ClassSetSummaryLookupKey> {
        let prepared = self.procedures.get(procedure)?;
        Some(ClassSetSummaryLookupKey {
            procedure: prepared.semantic.key().clone(),
            procedure_locator: procedure.semantics().locator().clone(),
            procedure_semantics: prepared.procedure_semantics,
            contract: prepared.contract.clone(),
            entry,
        })
    }

    /// Validate a runtime row and its output-addressed child closure against
    /// the current plan without recursive Rust calls.
    fn validated_runtime_summary(
        &self,
        procedure: &ProcedureHandle,
        key: &ClassSetSummaryLookupKey,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<Arc<ClassSetProcedureSummary>>, SolverTermination> {
        #[derive(Clone)]
        struct Pending {
            procedure: ProcedureHandle,
            key: ClassSetRuntimeLookupKey,
            expanded: bool,
        }

        let root = class_set_runtime_lookup_key(key);
        let mut pending = vec![Pending {
            procedure: procedure.clone(),
            key: root,
            expanded: false,
        }];
        let mut active = HashSet::default();
        let mut validated =
            HashMap::<ClassSetRuntimeLookupKey, Arc<ClassSetProcedureSummary>>::default();
        while let Some(row) = pending.pop() {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled);
            }
            if validated.contains_key(&row.key) {
                continue;
            }
            let prepared = match self.procedures.get(&row.procedure) {
                Some(prepared) => prepared,
                None => return Ok(None),
            };
            let summary = match self.state.class_set.get_runtime(row.key) {
                Some(summary) => summary,
                None => return Ok(None),
            };
            if class_set_runtime_lookup_key(&summary.key) != row.key {
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
                for dependency in &summary.dependencies {
                    let Some(child) = self
                        .procedures_by_lineage
                        .get(&dependency.procedure_lineage)
                        .and_then(Option::as_ref)
                    else {
                        return Ok(None);
                    };
                    let Some(child_prepared) = self.procedures.get(child) else {
                        return Ok(None);
                    };
                    if child_prepared.publication_rank >= prepared.publication_rank {
                        return Ok(None);
                    }
                    let child_key = ClassSetRuntimeLookupKey {
                        procedure: child_prepared
                            .semantic
                            .key()
                            .identity()
                            .procedure_read_fingerprint(child_prepared.procedure_semantics),
                        entry_selector: dependency.entry_selector,
                    };
                    let Some(child_summary) = validated.get(&child_key) else {
                        return Ok(None);
                    };
                    if child_summary.output_digest != dependency.output {
                        return Ok(None);
                    }
                }
                active.remove(&row.key);
                validated.insert(row.key, summary);
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
                let Some(child_prepared) = self.procedures.get(child) else {
                    return Ok(None);
                };
                if child_prepared.publication_rank >= prepared.publication_rank {
                    return Ok(None);
                }
                pending.push(Pending {
                    procedure: child.clone(),
                    key: ClassSetRuntimeLookupKey {
                        procedure: child_prepared
                            .semantic
                            .key()
                            .identity()
                            .procedure_read_fingerprint(child_prepared.procedure_semantics),
                        entry_selector: dependency.entry_selector,
                    },
                    expanded: false,
                });
            }
        }
        let Some(summary) = validated.remove(&root) else {
            return Ok(None);
        };
        if summary.key == *key {
            return Ok(Some(summary));
        }
        let mut rebound = summary.as_ref().clone();
        rebound.key = key.clone();
        Ok(Some(Arc::new(rebound)))
    }

    pub(crate) fn publish_complete(
        &mut self,
        result: &crate::value_flow::ValueFlowSummaryResult,
        cancellation: &CancellationToken,
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
            return 0;
        }
        let Ok(flattened) = project_flattened_class_set_observations(self.plan, result.result())
        else {
            return 0;
        };

        struct ProjectedEntry {
            entry: SummaryEntry,
            summary: ClassSetProcedureSummary,
            required_children: Vec<usize>,
            valid: bool,
            publication_rank: usize,
        }

        let mut projected = Vec::new();
        for flattened_entry in flattened {
            let entry = flattened_entry.entry;
            let Some(prepared) = self.procedures.get(entry.procedure()) else {
                continue;
            };
            let Some(entry_fact) = result.result().fact(entry.entry_fact()).copied() else {
                continue;
            };
            let Some(stable_entry) = stable_entry_fact(self.plan, entry_fact) else {
                continue;
            };
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
                continue;
            }
            let key = ClassSetSummaryLookupKey {
                procedure: prepared.semantic.key().clone(),
                procedure_locator: entry.procedure().semantics().locator().clone(),
                procedure_semantics: prepared.procedure_semantics,
                contract: prepared.contract.clone(),
                entry: stable_entry,
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
                continue;
            };
            let Some(source_prepared) = self.procedures.get(transfer.source().procedure()) else {
                projected[source].valid = false;
                continue;
            };
            let Some(target_prepared) = self.procedures.get(transfer.target().procedure()) else {
                projected[source].valid = false;
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
                continue;
            }
            projected[source].required_children.push(target);
        }
        for index in 0..projected.len() {
            projected[index].required_children.sort_unstable();
            projected[index].required_children.dedup();
            let mut dependencies = projected[index]
                .summary
                .dependencies
                .iter()
                .cloned()
                .chain(projected[index].required_children.iter().map(|&child| {
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
                        output: child.output_digest,
                    }
                }))
                .collect::<Vec<_>>();
            dependencies.sort_unstable();
            dependencies.dedup();
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
                assert_eq!(
                    left.summary, right.summary,
                    "one normalized entry fact projects one deterministic relation"
                );
                left.valid &= right.valid;
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
                    return published;
                };
                let Some(child_prepared) = self.procedures.get(child) else {
                    return published;
                };
                let child_runtime = ClassSetRuntimeLookupKey {
                    procedure: child_prepared
                        .semantic
                        .key()
                        .identity()
                        .procedure_read_fingerprint(child_prepared.procedure_semantics),
                    entry_selector: dependency.entry_selector,
                };
                let Some(child_summary) = self.state.class_set.get_runtime(child_runtime) else {
                    return published;
                };
                if child_summary.output_digest != dependency.output {
                    return published;
                }
            }
            if !self.state.class_set.publish(row.summary.clone()) {
                return published;
            }
            if row.summary.dependencies.is_empty()
                && self.procedures[row.entry.procedure()]
                    .semantic
                    .dependencies()
                    .is_empty()
            {
                self.persist_summary(&row.summary, cancellation);
            }
            published.saturating_add(1)
        })
    }

    fn persist_summary(
        &self,
        summary: &ClassSetProcedureSummary,
        cancellation: &CancellationToken,
    ) {
        if cancellation.is_cancelled() {
            return;
        }
        let Some(store) = &self.store else {
            return;
        };
        let attachment = match self
            .workspace
            .semantic_artifact_store_attachment(summary.key.procedure.artifact())
        {
            Ok(Some(attachment)) => attachment,
            Ok(None) => return,
            Err(error) => {
                self.workspace
                    .analyzer()
                    .record_query_failure(StoreError::new(format!(
                        "capturing persisted class-set summary source: {error}"
                    )));
                return;
            }
        };
        let row = match persisted_summary_row(summary, attachment) {
            Ok(row) => row,
            Err(error) => {
                self.workspace.analyzer().record_query_failure(error);
                return;
            }
        };
        if let Err(error) = store.publish_class_set_summary(row, cancellation) {
            self.workspace
                .analyzer()
                .record_query_failure(store_error_context(
                    error,
                    "publishing persisted class-set summary",
                ));
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
            digest.push(reason.label().as_bytes());
        }
    }
    digest.finish()
}

fn class_set_procedure_semantics_key(
    contract: &ClassSetProcedureContract,
    procedure: &crate::analyzer::semantic::SemanticLocator,
) -> SummaryProcedureSemanticsKey {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-procedure-semantics-v1");
    digest.push(
        contract
            .carrier
            .procedure_local_fingerprint(procedure)
            .as_bytes(),
    );
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
        StableEntryFact::Carrier { carrier, uncertain } => {
            digest.push(b"carrier");
            digest.push(procedure_local_carrier_fingerprint(carrier, procedure).as_bytes());
            digest.push(&[u8::from(*uncertain)]);
        }
    }
    digest.finish()
}

fn class_set_lookup_fingerprint(key: &ClassSetSummaryLookupKey) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(CLASS_SET_SUMMARY_LOOKUP);
    digest.push(
        key.procedure
            .identity()
            .procedure_read_fingerprint(key.procedure_semantics)
            .as_bytes(),
    );
    digest.push(key.procedure.dependencies().as_bytes());
    digest.push(stable_entry_fingerprint(&key.entry, &key.procedure_locator).as_bytes());
    digest.finish()
}

fn class_set_runtime_lookup_key(key: &ClassSetSummaryLookupKey) -> ClassSetRuntimeLookupKey {
    ClassSetRuntimeLookupKey {
        procedure: key
            .procedure
            .identity()
            .procedure_read_fingerprint(key.procedure_semantics),
        entry_selector: stable_entry_fingerprint(&key.entry, &key.procedure_locator),
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
        StableEntryFact::Carrier { carrier, uncertain } => StableValueFlowFact::Carrier {
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
    if !summary.dependencies.is_empty() {
        return Err(StoreError::new(
            "non-leaf class-set summaries are not persistable yet",
        ));
    }
    let relation =
        normalized_class_set_relation_rows(&summary.key, &summary.exits, &summary.reached)?;
    let relation_rows = u64::try_from(summary.exits.len().saturating_add(summary.reached.len()))
        .map_err(|_| StoreError::new("class-set relation row count exceeds u64"))?;
    let procedure = &summary.key.procedure;
    let procedure_locator = &summary.key.procedure_locator;
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
        carrier_digest: *summary
            .key
            .contract
            .carrier
            .procedure_local_fingerprint(procedure_locator)
            .as_bytes(),
        field_slots_digest: *summary.key.contract.field_slots.as_bytes(),
        entry_fact_ordinal: relation.entry_fact_ordinal,
    };
    ClassSetSummaryRow::try_new(
        header,
        relation.facts,
        relation.exits,
        relation.reached,
        Vec::new(),
        Vec::new(),
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
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-local-event-v1");
    event.push_procedure_local_identity(&mut digest, procedure);
    digest.finish()
}

fn quality_mask(qualities: &[PathQuality]) -> u8 {
    qualities
        .iter()
        .fold(0, |mask, quality| mask | (1_u8 << quality.ordinal()))
}

fn restore_persisted_summary(
    plan: &ValueFlowPlan,
    expected: &ClassSetSummaryLookupKey,
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
        || header.dependency_digest != *procedure.dependencies().as_bytes()
        || header.carrier_digest
            != *expected
                .contract
                .carrier
                .procedure_local_fingerprint(&expected.procedure_locator)
                .as_bytes()
        || header.field_slots_digest != *expected.contract.field_slots.as_bytes()
        || header.attachment.rel_path != procedure.artifact().path().as_str()
        || header.attachment.language != procedure.artifact().language().language()
    {
        return Err(StoreError::new(
            "persisted class-set summary header does not match the live procedure contract",
        ));
    }
    if !row.dependencies.is_empty() || !row.reads.is_empty() {
        return Err(StoreError::new(
            "leaf class-set summary unexpectedly carries dependencies or reads",
        ));
    }

    let mut carriers = HashMap::default();
    for carrier in plan.carrier_keys() {
        insert_stable_key(
            &mut carriers,
            *procedure_local_carrier_fingerprint(carrier, &expected.procedure_locator).as_bytes(),
            carrier.clone(),
        );
    }
    let mut sources = HashMap::default();
    for (_, source) in plan.sources() {
        insert_stable_key(
            &mut sources,
            *procedure_local_event_fingerprint(source.key(), &expected.procedure_locator)
                .as_bytes(),
            source.key().clone(),
        );
    }
    let mut sinks = HashMap::default();
    for (_, sink) in plan.sinks() {
        insert_stable_key(
            &mut sinks,
            *procedure_local_event_fingerprint(sink.key(), &expected.procedure_locator).as_bytes(),
            sink.key().clone(),
        );
    }

    let facts = row
        .facts
        .iter()
        .map(|fact| restore_persisted_fact(fact, &carriers, &sources, &sinks))
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
    Ok(ClassSetProcedureSummary {
        key: expected.clone(),
        exits: exits.into_boxed_slice(),
        reached: reached.into_boxed_slice(),
        dependencies: Box::default(),
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

impl ReusableSummaryProvider<ValueFlowFact> for PreparedClassSetSummaries<'_> {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        _root: &ProcedureHandle,
        entry_fact: ValueFlowFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<ValueFlowFact>>, SolverTermination> {
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        let Some(prepared) = self.procedures.get(procedure) else {
            return Ok(None);
        };
        let Some(entry) = stable_entry_fact(self.plan, entry_fact) else {
            return Ok(None);
        };
        let key = self
            .lookup_key(procedure, entry)
            .expect("a prepared procedure has a lookup key");
        let summary = match self.validated_runtime_summary(procedure, &key, request)? {
            Some(summary) => summary,
            None => {
                if !prepared.semantic.dependencies().is_empty() {
                    return Ok(None);
                }
                let Some(store) = &self.store else {
                    return Ok(None);
                };
                let lookup = *class_set_lookup_fingerprint(&key).as_bytes();
                let row = match store.class_set_summary_for_digest(lookup) {
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
                };
                let summary = match restore_persisted_summary(self.plan, &key, row) {
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
                self.state.class_set.publish(summary.clone());
                Arc::new(summary)
            }
        };
        let runtime_key = class_set_runtime_lookup_key(&key);
        let used_summary = summary.clone();
        let rows = summary.exits.len().saturating_add(summary.reached.len());
        if let Some(termination) = request.reserve(SolverWork {
            callback_rows: rows,
            propagated_outputs: rows,
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        let entry_source = entry_fact.source();
        let mut exits = Vec::with_capacity(summary.exits.len());
        for row in &summary.exits {
            let Some(exit_fact) = live_fact(self.plan, &row.exit_fact, entry_source) else {
                return Ok(None);
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
                return Ok(None);
            };
            let Some(fact) = live_fact(self.plan, &row.fact, entry_source) else {
                return Ok(None);
            };
            reached.push(ReusableReachedFact {
                point,
                fact,
                qualities: row.qualities.clone(),
            });
        }
        if let Some(existing) = self.used.get(&runtime_key) {
            assert_eq!(
                existing, &used_summary,
                "one query-local class-set lookup consumes one exact answer"
            );
        } else {
            self.used.insert(runtime_key, used_summary);
        }
        Ok(Some(ReusableProcedureSummary {
            exits: exits.into_boxed_slice(),
            reached: reached.into_boxed_slice(),
            call_cycle: SummaryCallCycle::ExcludesRoot,
            called_procedures: SummaryCalledProcedures::CoveredByContract,
        }))
    }
}

fn stable_entry_fact(plan: &ValueFlowPlan, fact: ValueFlowFact) -> Option<StableEntryFact> {
    match (fact.source(), fact.carrier(), fact.sink()) {
        (None, None, None) => Some(StableEntryFact::Zero),
        (Some(_), Some(carrier), None) => Some(StableEntryFact::Carrier {
            carrier: Box::new(plan.carrier_key(carrier)?.clone()),
            uncertain: !fact.uncertainty().is_empty(),
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
        digest.push(provider);
        digest.push(field_slots.as_bytes());
        digest.finish()
    };
    SummaryBehaviorKey::from_parts(derive(provider.as_bytes()), derive(provider.read_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        IcfgProvider, ProcedureHandle, SemanticBudget, SemanticRequest, WorkspaceIcfgProvider,
        type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
    use crate::dataflow::SolverBudget;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::type_flow::{FeedbackLimits, TypeFlowRootResult, solve_type_flow_for_root};
    use crate::value_flow::{
        ClosureLimits, ValueFlowCache, ValueFlowSummaryResult, WorkspaceValueFlowProvider,
        solve_value_flow_with_summaries,
    };

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
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
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
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let mut solver_budget = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut solver_budget, &cancellation);
        solve_type_flow_for_root(
            workspace,
            adapter,
            field_slots,
            root,
            workspace.analyzer().active_semantic_model_snapshot(),
            ClosureLimits { max_procedures: 16 },
            FeedbackLimits::default(),
            cache,
            state,
            &mut semantic_budget,
            &mut request,
        )
        .expect("runtime fixture root solve succeeds")
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
        )
        .expect("runtime identity fixture plan builds");
        let behavior = WorkspaceIcfgProvider::new(workspace).behavior_identity();
        (plan, behavior)
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

        let repository = ClassSetSummaryRepository::default();
        assert!(repository.publish(first.clone()));
        assert!(repository.publish(second.clone()));
        assert_eq!(
            repository
                .get_runtime(class_set_runtime_lookup_key(&first.key))
                .expect("the second revision is current")
                .key,
            second.key
        );
        assert!(
            !repository.publish(first.clone()),
            "the first exact revision remains retained"
        );
        assert_eq!(
            repository
                .get_runtime(class_set_runtime_lookup_key(&first.key))
                .expect("republishing restores the first revision")
                .key,
            first.key
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
}
