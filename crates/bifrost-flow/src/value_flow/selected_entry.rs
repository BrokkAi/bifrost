//! Request-local selected source-entry products owned by shared discovery.
//!
//! A source starts at an existing guarded binder. Its entry certificate does
//! not establish any aggregate projection or change an ordinary snapshot.

use super::{ValueFlowRetentionScope, ValueFlowRetentionScopeError};
use crate::analyzer::semantic::service::ArtifactRetentionCensus;
use crate::analyzer::store::cache_budget::RetainedHeap;
use brokk_bifrost_core::analyzer::outer_request::{
    RequestEntryKey, RequestResource, RequestResourceError,
};
use brokk_bifrost_core::retention_budget::{
    SharedBackingLease, UNROUNDED_ENTRY_OVERHEAD_BYTES as ENTRY_OVERHEAD_BYTES,
};
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
use brokk_bifrost_analysis::analyzer::languages::SelectedTupleBinding;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    SelectedPatternObservation, WorkspaceSemanticOracle,
};
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;

use crate::analyzer::semantic::{
    DispatchHints, OracleCallContext, SelectedPatternEntry, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, ValueAtPoint, ValueFlowOracle, ValueFlowSnapshot,
};
use crate::dataflow::SemanticInputStatus;
use crate::hash::HashMap;

/// Identity of the exact retained base, not merely its procedure or blob.
#[derive(Clone)]
struct BaseIdentity(Arc<()>);
impl PartialEq for BaseIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for BaseIdentity {}
impl Hash for BaseIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}
impl std::fmt::Debug for BaseIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("query base snapshot")
    }
}

struct EntryBase {
    // Remove keyed pointer records before any actual owner field can drop.
    _retention: Option<RetainedOwners>,
    identity: BaseIdentity,
    snapshot: ValueFlowSnapshot,
    status: SemanticInputStatus,
    receipt: QueryReadReceipt,
}

/// Full query-only identity includes the base snapshot, selected observation,
/// exact procedure-local gap and the source/declaration/model admission reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SelectedSourceEntryIdentity {
    base: BaseIdentity,
    entry: SelectedPatternEntry,
    reads: brokk_bifrost_analysis::analyzer::read_ledger::ReadSetDigest,
}

/// One immutable selected-root product. Every backend retains this same Arc.
/// The projected snapshot is private to the selected source root and is never
/// stored as an ordinary procedure snapshot or partial-flow summary.
/// Query products that clone a borrowed snapshot keep this entry Arc alongside
/// the clone for the product's lifetime, preserving its retention ownership.
pub struct SelectedSourceEntryView {
    // Drop guards before the pinned fields; no address record outlives its owner.
    _retention: Option<RetainedOwners>,
    identity: SelectedSourceEntryIdentity,
    base: Arc<EntryBase>,
    selected: ValueFlowSnapshot,
    proof: Arc<SelectedPatternObservation>,
    scope_id: u64,
}
impl std::fmt::Debug for SelectedSourceEntryView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedSourceEntryView")
            .field("identity", &self.identity)
            .finish()
    }
}
impl PartialEq for SelectedSourceEntryView {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}
impl Eq for SelectedSourceEntryView {}
impl Hash for SelectedSourceEntryView {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}
impl SelectedSourceEntryView {
    /// Sufficient content correspondence only for the same pinned product.
    /// This grants no admission authority. Separately materialized views stay
    /// ineligible until a full typed receipt/content comparison is available.
    #[doc(hidden)]
    pub fn has_same_input_backing(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }

    #[doc(hidden)]
    pub fn retained_heap(self: &Arc<Self>, heap: &mut RetainedHeap) {
        heap.arc(self, |view, heap| {
            if let Some(retained) = &view._retention {
                retained.retained_heap(heap);
            }
            heap.arc(&view.identity.base.0, |_, _| {});
            heap.arc(&view.proof, |proof, heap| proof.retained_heap(heap));
            heap.arc(&view.base, |base, heap| {
                if let Some(retained) = &base._retention {
                    retained.retained_heap(heap);
                }
                heap.arc(&base.identity.0, |_, _| {});
                base.receipt.retained_heap(heap);
            });
            let mut census = crate::analyzer::semantic::service::RetainedArtifactWalker::new(heap);
            view.base.snapshot.retained_artifacts(&mut census);
            view.selected.retained_artifacts(&mut census);
            for observation in [view.observation(), view.proof.observation()] {
                use crate::analyzer::semantic::service::ArtifactRetentionVisitor;
                census.procedure(observation.point().procedure());
                census.procedure(observation.value().procedure());
                census.context(observation.context());
            }
            census.finish();
        });
    }

    pub fn scope_id(&self) -> u64 {
        self.scope_id
    }

    pub(crate) fn retained_artifacts(
        &self,
        census: &mut crate::analyzer::semantic::service::ArtifactRetentionCensus,
    ) {
        self.base.snapshot.retained_artifacts(census);
        self.selected.retained_artifacts(census);
        for observation in [self.observation(), self.proof.observation()] {
            census.procedure(observation.point().procedure());
            census.procedure(observation.value().procedure());
            census.context(observation.context());
        }
    }

    pub fn observation(&self) -> &ValueAtPoint {
        self.identity.entry.observation()
    }
    pub fn matches_source(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: super::ValueFlowObservationPhase,
        carrier: &super::ValueFlowCarrier,
    ) -> bool {
        point == self.observation().point()
            && phase == super::ValueFlowObservationPhase::AfterEffects
            && carrier == &super::ValueFlowCarrier::for_value(self.observation().value().clone())
    }

    pub fn identity(&self) -> &SelectedSourceEntryIdentity {
        &self.identity
    }
    pub(super) fn stored_certificate(&self) -> &SelectedPatternEntry {
        &self.identity.entry
    }
    pub(super) fn admission_read_digest(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::read_ledger::ReadSetDigest {
        self.identity.reads
    }
    pub(super) fn base_read_digest(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::read_ledger::ReadSetDigest {
        self.base.receipt.digest()
    }
    pub fn base_snapshot(&self) -> &ValueFlowSnapshot {
        &self.base.snapshot
    }
    pub fn base_status(&self) -> SemanticInputStatus {
        self.base.status
    }
    /// Only for a product whose sole active source is this certified entry.
    pub fn selected_snapshot(&self) -> &ValueFlowSnapshot {
        &self.selected
    }
    pub fn replay_reads(&self, workspace: &WorkspaceAnalyzer) {
        self.base.receipt.replay(workspace.analyzer());
        self.proof.replay_reads(workspace);
    }
}

/// Canonical discovery for one bound outer request. External view holders keep
/// their allocation leases after the request has closed and cleared its indexes.
pub struct SelectedSourceEntryViews {
    scope: Arc<ValueFlowRetentionScope>,
    state: Mutex<SelectedSourceEntryState>,
    _root: SharedBackingLease,
}

type EntryBaseKey = (
    crate::analyzer::semantic::SemanticArtifactKey,
    crate::analyzer::semantic::ProcedureId,
    Option<String>,
);
type EntryRootKey = (
    crate::analyzer::semantic::SemanticArtifactKey,
    crate::analyzer::semantic::ProcedureId,
    u32,
    crate::analyzer::semantic::SourceSpan,
);

#[derive(Default)]
struct SelectedSourceEntryState {
    closed: bool,
    bases: HashMap<EntryBaseKey, Arc<EntryBase>>,
    views: HashMap<EntryRootKey, Arc<SelectedSourceEntryView>>,
    // Index allocations are dropped before their guards, including plain Drop.
    bases_capacity: Option<SharedBackingLease>,
    views_capacity: Option<SharedBackingLease>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedSourceEntryRetentionError {
    Scope(ValueFlowRetentionScopeError),
    Capacity,
}

/// An admission keeps its semantic outcome and any actual funding refusal.
#[doc(hidden)]
pub type SelectedSourceEntryAdmission = (
    SemanticOutcome<Arc<SelectedSourceEntryView>>,
    Option<SelectedSourceEntryRetentionError>,
);

/// Guard storage is funded before allocation; guards never point at the factory.
struct RetainedOwners {
    _leases: Vec<SharedBackingLease>,
    _storage: SharedBackingLease,
}

impl RetainedOwners {
    fn retained_heap(&self, heap: &mut RetainedHeap) {
        heap.vec(&self._leases);
        for lease in self._leases.iter().chain(std::iter::once(&self._storage)) {
            let (identity, bytes) = lease.retained_control_allocation();
            heap.allocation(identity, bytes);
        }
    }

    fn acquire(
        scope: &ValueFlowRetentionScope,
        plans: impl IntoIterator<Item = (usize, usize)>,
        artifacts: impl IntoIterator<Item = (usize, u64)>,
    ) -> Option<Self> {
        // Private transient records do not escape an admission.
        let plans = plans.into_iter().collect::<Vec<_>>();
        let artifacts = artifacts.into_iter().collect::<Vec<_>>();
        let count = plans.len().checked_add(artifacts.len())?;
        let storage = scope.plan_allocation(
            count
                .checked_mul(size_of::<SharedBackingLease>())?
                .checked_add(ENTRY_OVERHEAD_BYTES)?,
        )?;
        let mut leases = Vec::with_capacity(count);
        for (allocation, bytes) in plans {
            leases.push(scope.plan_backing(allocation, bytes)?);
        }
        for (allocation, bytes) in artifacts {
            leases.push(scope.artifact_backing(allocation, usize::try_from(bytes).ok()?)?);
        }
        Some(Self {
            _leases: leases,
            _storage: storage,
        })
    }
}

fn retain_base(
    base: &Arc<EntryBase>,
    key: &EntryBaseKey,
    scope: &ValueFlowRetentionScope,
) -> Option<(RetainedOwners, usize)> {
    let mut heap = RetainedHeap::default();
    heap.arc(base, |base, heap| {
        heap.owned_slice(base.snapshot.context().calls());
        heap.arc(&base.identity.0, |_, _| {});
        base.receipt.retained_heap(heap);
        heap.add(key_heap(&key.0).saturating_add(key.2.as_ref().map_or(0, String::capacity)));
    });
    let mut census = ArtifactRetentionCensus::default();
    base.snapshot.retained_artifacts(&mut census);
    let plans = heap
        .shared_allocations()
        .chain(census.shared_allocation_records())
        .collect::<Vec<_>>();
    let (_, entries) = heap.totals();
    let retained = RetainedOwners::acquire(scope, plans, census.artifact_allocation_records())?;
    Some((retained, entries))
}

#[derive(Debug, PartialEq, Eq)]
enum IndexAdmissionRefusal {
    FundingRefused,
    AllocatorFailed,
}

// Hash-map growth reserves a conservative full replacement table before reserve.
// The old table remains funded until allocation and replacement have completed.
fn reserve_index<K: Eq + Hash, V>(
    map: &mut HashMap<K, V>,
    charge: &mut Option<SharedBackingLease>,
    scope: &ValueFlowRetentionScope,
) -> Result<(), IndexAdmissionRefusal> {
    use IndexAdmissionRefusal::{AllocatorFailed, FundingRefused};
    if map.len() < map.capacity() {
        return Ok(());
    }
    let buckets = map
        .len()
        .checked_add(1)
        .and_then(usize::checked_next_power_of_two)
        .and_then(|buckets| buckets.checked_mul(2))
        .ok_or(FundingRefused)?
        .max(4);
    let bytes = size_of::<(K, V)>()
        .checked_add(1)
        .and_then(|entry| buckets.checked_mul(entry))
        .and_then(|bytes| bytes.checked_add(ENTRY_OVERHEAD_BYTES))
        .ok_or(FundingRefused)?;
    let next = scope.plan_allocation(bytes).ok_or(FundingRefused)?;
    // An allocator failure after successful funding is operational, not a
    // refused budget charge. Returning here drops next, preserving rollback.
    map.try_reserve(1).map_err(|_| AllocatorFailed)?;
    assert!(
        map.capacity()
            .saturating_mul(8)
            .div_ceil(7)
            .next_power_of_two()
            <= buckets,
        "reserved index capacity is funded before publication"
    );
    *charge = Some(next);
    Ok(())
}

fn key_heap(key: &crate::analyzer::semantic::SemanticArtifactKey) -> usize {
    key.path()
        .as_str()
        .len()
        .saturating_add(key.adapter().name().len())
        .saturating_add(4 * size_of::<usize>())
}

impl RequestResource for SelectedSourceEntryViews {
    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .expect("query selected-entry owner lock poisoned");
        state.closed = true;
        // Retire pointer-bearing indexes before releasing their capacity guards.
        drop(std::mem::take(&mut state.views));
        drop(std::mem::take(&mut state.bases));
        state.views_capacity = None;
        state.bases_capacity = None;
    }
}

impl SelectedSourceEntryViews {
    pub fn for_request(
        scope: Arc<ValueFlowRetentionScope>,
    ) -> Result<Arc<Self>, SelectedSourceEntryRetentionError> {
        let request = scope
            .outer_request()
            .map_err(SelectedSourceEntryRetentionError::Scope)?;
        let existing =
            || request.resource_if_present::<Self>(&RequestEntryKey::SelectedSourceEntries);
        let factory = if let Some(factory) = existing() {
            factory
        } else {
            // Fund before the first resource call can grow its slot. Existing
            // request-framework bookkeeping is not a new factory-owned ledger.
            let root =
                scope.plan_allocation(size_of::<Self>().saturating_add(ENTRY_OVERHEAD_BYTES));
            if let Some(root) = root {
                request
                    .resource(RequestEntryKey::SelectedSourceEntries, || {
                        Ok::<_, SelectedSourceEntryRetentionError>(Arc::new(Self {
                            scope: Arc::clone(&scope),
                            state: Mutex::default(),
                            _root: root,
                        }))
                    })
                    .map_err(|error| match error {
                        RequestResourceError::Closed => SelectedSourceEntryRetentionError::Scope(
                            ValueFlowRetentionScopeError::Closed,
                        ),
                        RequestResourceError::Open(error) => error,
                    })?
            } else {
                existing().ok_or(SelectedSourceEntryRetentionError::Capacity)?
            }
        };
        if factory.scope.scope_id() != scope.scope_id()
            || factory.scope.request_id() != request.id()
        {
            return Err(SelectedSourceEntryRetentionError::Scope(
                ValueFlowRetentionScopeError::BudgetMismatch,
            ));
        }
        Ok(factory)
    }

    // Funding APIs return None for both closure and capacity refusal. Record
    // only these transient admission failures, never ordinary semantic Unknown.
    fn retention_unavailable(&self, work: SemanticWork) -> SelectedSourceEntryAdmission {
        use brokk_bifrost_core::analyzer::carried_context;
        let refusal = if self.scope.is_closed() {
            carried_context::mark_execution_dependent();
            SelectedSourceEntryRetentionError::Scope(ValueFlowRetentionScopeError::Closed)
        } else {
            carried_context::mark_budget_refusal();
            SelectedSourceEntryRetentionError::Capacity
        };
        (
            SemanticOutcome::Unknown {
                partial: None,
                work,
            },
            Some(refusal),
        )
    }

    fn index_unavailable(
        &self,
        cause: IndexAdmissionRefusal,
        work: SemanticWork,
    ) -> SelectedSourceEntryAdmission {
        match cause {
            IndexAdmissionRefusal::FundingRefused => self.retention_unavailable(work),
            IndexAdmissionRefusal::AllocatorFailed => {
                brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
                (
                    SemanticOutcome::Unknown {
                        partial: None,
                        work,
                    },
                    None,
                )
            }
        }
    }

    pub fn admit(
        &self,
        workspace: &WorkspaceAnalyzer,
        mut proof: Arc<SelectedPatternObservation>,
        materialization: SemanticInputStatus,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SelectedSourceEntryAdmission, SemanticProviderError> {
        fn unavailable(work: SemanticWork) -> SelectedSourceEntryAdmission {
            (
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                None,
            )
        }
        let mut work = SemanticWork::default();
        if self.scope.is_closed() {
            return Ok(self.retention_unavailable(work));
        }
        if request.cancellation.is_cancelled() {
            return Ok((
                SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                },
                None,
            ));
        }
        if matches!(
            materialization,
            SemanticInputStatus::Cancelled | SemanticInputStatus::ExceededBudget { .. }
        ) {
            return Ok(unavailable(work));
        }
        let SelectedTupleBinding::Observed(source) = &proof.projection().binding else {
            return Ok(unavailable(work));
        };
        let models = snapshot
            .as_ref()
            .map(|snapshot| snapshot.active_models().active_model_set_hash().to_owned());
        let procedure = proof.observation().point().procedure();
        if source.binding.reads.model_set_hash != models {
            return Ok(unavailable(work));
        }
        let Some((current, bytes)) = workspace.semantic_artifact_key_is_current_with_source_bytes(
            procedure.artifact().key(),
            1_048_576,
        )?
        else {
            return Ok(unavailable(work));
        };
        work = SemanticWork {
            source_bytes: bytes,
            ..SemanticWork::default()
        };
        request.budget.charge_work(work);
        if let Err(exceeded) = request.budget.check_admission(SemanticWork::default()) {
            return Ok((
                SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                },
                None,
            ));
        }
        if !current {
            return Ok(unavailable(work));
        }
        let Ok(mut entry) = proof.entry_certificate() else {
            return Ok(unavailable(work));
        };
        let field = source.field;
        let ordinal = proof.projection().candidate.ordinal;
        let root_key = (
            procedure.artifact().key().clone(),
            procedure.id(),
            ordinal,
            field,
        );
        let base_key = (procedure.artifact().key().clone(), procedure.id(), models);
        let mut state = self
            .state
            .lock()
            .expect("query selected-entry owner lock poisoned");
        if state.closed || self.scope.is_closed() {
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            return Ok((
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                Some(SelectedSourceEntryRetentionError::Scope(
                    ValueFlowRetentionScopeError::Closed,
                )),
            ));
        }
        if let Some(view) = state.views.get(&root_key) {
            // A changed admission in this request cannot inherit an earlier
            // certificate, even when it selected the same written field.
            if view.identity.reads != proof.projection().receipt_id()
                || view.identity.entry.gap() != entry.gap()
            {
                return Ok(unavailable(work));
            }
            view.replay_reads(workspace);
            return Ok((
                SemanticOutcome::Complete {
                    value: Arc::clone(view),
                    work,
                },
                None,
            ));
        }
        let cached = state.bases.get(&base_key).cloned();
        let base = match cached {
            Some(base) => {
                base.receipt.replay(workspace.analyzer());
                base
            }
            None => {
                let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
                    workspace,
                    snapshot.clone(),
                    DispatchHints::empty(),
                );
                let (outcome, mut receipt) =
                    QueryReadReceipt::capture_deferred(workspace.analyzer(), || {
                        oracle.procedure_relations(procedure, &OracleCallContext::empty(), request)
                    });
                let outcome = outcome?;
                work = work.conservative_add(outcome.work());
                match &outcome {
                    SemanticOutcome::Cancelled { .. } => {
                        return Ok((
                            SemanticOutcome::Cancelled {
                                partial: None,
                                work,
                            },
                            None,
                        ));
                    }
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        return Ok((
                            SemanticOutcome::ExceededBudget {
                                partial: None,
                                exceeded: *exceeded,
                                work,
                            },
                            None,
                        ));
                    }
                    _ => {}
                }
                let Some(value) = outcome.available_value() else {
                    return Ok(unavailable(work));
                };
                // One canonical root per retained base, shared by all entries
                // and plans for this request/procedure/model combination.
                let receipt_work = receipt.retain_root();
                request.budget.charge_work(receipt_work);
                work = work.conservative_add(receipt_work);
                if let Err(exceeded) = request.budget.check_admission(SemanticWork::default()) {
                    return Ok((
                        SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        },
                        None,
                    ));
                }
                let mut base = Arc::new(EntryBase {
                    identity: BaseIdentity(Arc::new(())),
                    snapshot: value.clone(),
                    status: SemanticInputStatus::from_outcome(&outcome),
                    receipt,
                    _retention: None,
                });
                let Some((retention, entries)) = retain_base(&base, &base_key, &self.scope) else {
                    return Ok(self.retention_unavailable(work));
                };
                let census_work = SemanticWork {
                    nested_entries: entries,
                    ..SemanticWork::default()
                };
                request.budget.charge_work(census_work);
                work = work.conservative_add(census_work);
                if let Err(exceeded) = request.budget.check_admission(SemanticWork::default()) {
                    return Ok((
                        SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        },
                        None,
                    ));
                }
                Arc::get_mut(&mut base)
                    .expect("private base construction")
                    ._retention = Some(retention);
                let SelectedSourceEntryState {
                    bases,
                    bases_capacity,
                    ..
                } = &mut *state;
                if let Err(cause) = reserve_index(bases, bases_capacity, &self.scope) {
                    return Ok(self.index_unavailable(cause, work));
                }
                base.receipt.replay(workspace.analyzer());
                state.bases.insert(base_key, Arc::clone(&base));
                base
            }
        };
        if base.snapshot.procedure() != proof.observation().point().procedure() {
            // A plain artifact cache may rematerialize identical rows. Rebind
            // admission to the ONE retained base before validating scoped IDs.
            let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
                workspace,
                snapshot,
                DispatchHints::empty(),
            );
            let Some(selected) = oracle.selected_pattern_source_at(
                base.snapshot.procedure(),
                ordinal,
                field.start_byte() as usize..field.end_byte() as usize,
                request,
            )?
            else {
                return Ok(unavailable(work));
            };
            let Some(observation) = selected.into_binding_observation() else {
                return Ok(unavailable(work));
            };
            proof = Arc::new(observation);
            let Ok(rebound) = proof.entry_certificate() else {
                return Ok(unavailable(work));
            };
            entry = rebound;
        }
        let identity = SelectedSourceEntryIdentity {
            base: base.identity.clone(),
            entry,
            reads: proof.projection().receipt_id(),
        };
        let Ok(selected) = identity.entry.project(&base.snapshot) else {
            return Ok(unavailable(work));
        };
        // project only clones the same immutable backing and changes its gap.
        // Proof construction derives both handles from one procedure/empty context.
        assert!(selected.shares_backing_with(&base.snapshot));
        assert_eq!(
            proof.observation().point().procedure(),
            base.snapshot.procedure()
        );
        assert!(proof.observation().context().calls().is_empty());
        let mut view = Arc::new(SelectedSourceEntryView {
            identity,
            base,
            selected,
            proof,
            scope_id: self.scope.scope_id(),
            _retention: None,
        });
        let mut heap = RetainedHeap::default();
        heap.arc(&view, |view, heap| {
            heap.owned_slice(view.selected.context().calls());
            heap.owned_slice(view.observation().context().calls());
            heap.arc(&view.proof, |proof, heap| proof.retained_heap(heap));
            heap.add(key_heap(&root_key.0));
        });
        let records = heap.shared_allocations().collect::<Vec<_>>();
        let (_, entries) = heap.totals();
        let census_work = SemanticWork {
            nested_entries: entries,
            ..SemanticWork::default()
        };
        request.budget.charge_work(census_work);
        work = work.conservative_add(census_work);
        if let Err(exceeded) = request.budget.check_admission(SemanticWork::default()) {
            return Ok((
                SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                },
                None,
            ));
        }
        let Some(retention) = RetainedOwners::acquire(&self.scope, records, std::iter::empty())
        else {
            return Ok(self.retention_unavailable(work));
        };
        Arc::get_mut(&mut view)
            .expect("private view construction")
            ._retention = Some(retention);
        let SelectedSourceEntryState {
            views,
            views_capacity,
            ..
        } = &mut *state;
        if let Err(cause) = reserve_index(views, views_capacity, &self.scope) {
            return Ok(self.index_unavailable(cause, work));
        }
        view.replay_reads(workspace);
        state.views.insert(root_key, Arc::clone(&view));
        Ok((SemanticOutcome::Complete { value: view, work }, None))
    }
}

/// Independent source-root products. Ordinary roots keep their existing group;
/// each selected entry has a singleton group and its own immutable view.
pub struct SourceRootPartition {
    pub indices: Vec<usize>,
    pub entry: Option<Arc<SelectedSourceEntryView>>,
}

pub fn partition_source_roots(
    entries: impl IntoIterator<Item = Option<Arc<SelectedSourceEntryView>>>,
) -> Vec<SourceRootPartition> {
    let mut ordinary = Vec::new();
    let mut selected = Vec::new();
    for (index, entry) in entries.into_iter().enumerate() {
        match entry {
            Some(entry) => selected.push(SourceRootPartition {
                indices: vec![index],
                entry: Some(entry),
            }),
            None => ordinary.push(index),
        }
    }
    if !ordinary.is_empty() || selected.is_empty() {
        selected.insert(
            0,
            SourceRootPartition {
                indices: ordinary,
                entry: None,
            },
        );
    }
    selected
}

#[cfg(test)]
mod retention_tests {
    use super::super::ValueFlowRetentionBudget;
    use super::*;
    use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#9925: a factory with no plan or sink must retain funded request state")]
    fn no_plan_factory_is_canonical_and_closed_request_refuses() {
        let outer = OuterRequest::new();
        let budget = ValueFlowRetentionBudget::new(1 << 20, 1 << 20);
        let scope = ValueFlowRetentionScope::bind(&outer, &budget).unwrap();
        let before = budget.retained_plan_bytes();
        let first = SelectedSourceEntryViews::for_request(Arc::clone(&scope)).unwrap();
        let charged = budget.retained_plan_bytes();
        assert!(charged > before);
        let alias = SelectedSourceEntryViews::for_request(Arc::clone(&scope)).unwrap();
        assert!(Arc::ptr_eq(&first, &alias));
        assert_eq!(budget.retained_plan_bytes(), charged);
        outer.close();
        assert!(matches!(
            SelectedSourceEntryViews::for_request(Arc::clone(&scope)),
            Err(SelectedSourceEntryRetentionError::Scope(
                ValueFlowRetentionScopeError::Closed
            ))
        ));
        drop(first);
        drop(alias);
        drop(outer);
        assert_eq!(budget.retained_plan_bytes(), before);
    }

    #[test]
    #[hardwon("#9925: base/index admission refusal must not leak a partial retained owner")]
    fn rejected_growth_and_partial_owner_admission_roll_back() {
        let outer = OuterRequest::new();
        let budget = ValueFlowRetentionBudget::new(2048, 1);
        let scope = ValueFlowRetentionScope::bind(&outer, &budget).unwrap();
        let before = budget.retained_plan_bytes();
        let mut map: HashMap<u64, [u8; 4096]> = HashMap::default();
        let mut charge = None;
        assert_eq!(
            reserve_index(&mut map, &mut charge, &scope),
            Err(IndexAdmissionRefusal::FundingRefused)
        );
        assert_eq!((map.len(), map.capacity()), (0, 0));
        assert!(charge.is_none());
        // The first payload can be funded; the later artifact must refuse.
        let payload = Arc::new([0u8; 64]);
        assert!(
            RetainedOwners::acquire(&scope, [(Arc::as_ptr(&payload) as usize, 64)], [(12345, 2)])
                .is_none()
        );
        assert_eq!(budget.retained_plan_bytes(), before);
        assert_eq!(budget.retained_artifact_bytes(), 0);
    }

    #[test]
    #[hardwon(
        "#9925: aliases and external holders must preserve one shared charge until final drop"
    )]
    fn shared_owner_aliases_and_separate_scopes_follow_actual_holders() {
        let outer = OuterRequest::new();
        let first = ValueFlowRetentionBudget::new(1 << 20, 1 << 20);
        let scope = ValueFlowRetentionScope::bind(&outer, &first).unwrap();
        let payload = Arc::new([0u8; 64]);
        let identity = Arc::as_ptr(&payload) as usize;
        let base = Arc::new((
            RetainedOwners::acquire(&scope, [(identity, 64)], []).unwrap(),
            Arc::clone(&payload),
        ));
        let charged = first.retained_plan_bytes();
        let root_one = Arc::clone(&base);
        let root_two = Arc::clone(&base);
        let registration_alias = Arc::clone(&root_one);
        assert_eq!(first.retained_plan_bytes(), charged);
        let other_outer = OuterRequest::new();
        let other_budget = ValueFlowRetentionBudget::new(1 << 20, 1 << 20);
        let other_scope = ValueFlowRetentionScope::bind(&other_outer, &other_budget).unwrap();
        let other = RetainedOwners::acquire(&other_scope, [(identity, 64)], []).unwrap();
        assert_ne!(scope.scope_id(), other_scope.scope_id());
        assert!(other_budget.retained_plan_bytes() > 0);
        drop(base);
        drop(root_one);
        drop(root_two);
        outer.close();
        assert_eq!(first.retained_plan_bytes(), charged);
        drop(registration_alias);
        assert_eq!(first.retained_plan_bytes(), 0);
        assert!(other_budget.retained_plan_bytes() > 0);
        drop(other);
        assert_eq!(other_budget.retained_plan_bytes(), 0);
    }

    #[test]
    #[hardwon("#9925: an admitted base can outlive indexes without any published value-flow plan")]
    fn actual_base_closure_survives_factory_close_until_final_holder() {
        use crate::analyzer::semantic::SemanticBudget;
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::cancellation::CancellationToken;
        use crate::inline_project::InlineTestProject;
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"retained-base\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "pub fn run(x: u8) -> u8 { x }")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut semantic_budget, &cancellation);
        let artifact = workspace
            .materialize_program_semantics(&project.file("src/lib.rs"), &mut request)
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|p| {
                p.locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some("run")
            })
            .unwrap();
        let root = artifact.procedure_handle(procedure.id()).unwrap();
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let (outcome, mut receipt) =
            QueryReadReceipt::capture_deferred(workspace.analyzer(), || {
                oracle.procedure_relations(&root, &OracleCallContext::empty(), &mut request)
            });
        let outcome = outcome.unwrap();
        receipt.retain_root();
        let mut base = Arc::new(EntryBase {
            identity: BaseIdentity(Arc::new(())),
            snapshot: outcome.available_value().cloned().unwrap(),
            status: SemanticInputStatus::from_outcome(&outcome),
            receipt,
            _retention: None,
        });
        let key = (artifact.key().clone(), root.id(), None);
        let outer = OuterRequest::new();
        let budget = ValueFlowRetentionBudget::new(16 << 20, 16 << 20);
        let scope = ValueFlowRetentionScope::bind(&outer, &budget).unwrap();
        let factory = SelectedSourceEntryViews::for_request(Arc::clone(&scope)).unwrap();
        let retention = retain_base(&base, &key, &scope).unwrap().0;
        Arc::get_mut(&mut base).unwrap()._retention = Some(retention);
        {
            let mut state = factory.state.lock().unwrap();
            let SelectedSourceEntryState {
                bases,
                bases_capacity,
                ..
            } = &mut *state;
            reserve_index(bases, bases_capacity, &scope).unwrap();
            bases.insert(key, Arc::clone(&base));
        }
        assert!(budget.retained_artifact_bytes() > 0);
        outer.close();
        assert!(factory.state.lock().unwrap().bases.is_empty());
        drop(factory);
        drop(outer);
        assert!(budget.retained_artifact_bytes() > 0);
        drop(base);
        assert_eq!(budget.retained_plan_bytes(), 0);
        assert_eq!(budget.retained_artifact_bytes(), 0);
    }
}

#[cfg(test)]
mod projection_backing_test {
    use super::*;
    use crate::analyzer::semantic::{
        GapKey, ObservationPhase, SemanticBudget, SourcePosition, SourceSpan,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::cancellation::CancellationToken;
    use crate::inline_project::InlineTestProject;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: selected roots must share the charged base allocation, not recensus or substitute rows"
    )]
    fn actual_selected_projections_share_one_base_and_keep_other_gaps() {
        let source = "pub struct Pair(pub u8, pub u8); pub fn run(Pair(a, b): Pair) -> u8 { a }";
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"selected-projection\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let artifact = workspace
            .materialize_program_semantics(&project.file("src/lib.rs"), &mut request)
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|p| {
                p.locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some("run")
            })
            .unwrap();
        let root = artifact.procedure_handle(procedure.id()).unwrap();
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let plain = oracle
            .procedure_relations(&root, &OracleCallContext::empty(), &mut request)
            .unwrap();
        let base = plain.available_value().unwrap();
        let start = source.find("Pair(a, b)").unwrap() as u32;
        let constructor = SourceSpan::new(
            SourcePosition::new(start, 0, start),
            SourcePosition::new(start + 4, 0, start + 4),
        )
        .unwrap();
        let mut selected = Vec::new();
        for candidate in procedure.guarded_pattern_projections() {
            let field = procedure
                .source_mapping(candidate.binder_source)
                .unwrap()
                .locator
                .anchor()
                .span();
            let observation = ValueAtPoint::new(
                root.value_handle(candidate.binder).unwrap(),
                root.point_handle(candidate.point).unwrap(),
                ObservationPhase::AfterEffects,
                OracleCallContext::empty(),
            )
            .unwrap();
            let entry = SelectedPatternEntry::validate(
                observation,
                candidate.ordinal,
                constructor,
                field,
                &[],
                &candidate.path,
            )
            .unwrap();
            let view = entry.project(base).unwrap();
            assert!(view.shares_backing_with(base));
            assert!(view.gap_is_discharged(GapKey::Gap(entry.gap())));
            selected.push((entry, view));
        }
        assert_eq!(selected.len(), 2);
        assert!(selected[0].1.shares_backing_with(&selected[1].1));
        assert!(
            !selected[0]
                .1
                .gap_is_discharged(GapKey::Gap(selected[1].0.gap()))
        );
        assert!(!base.gap_is_discharged(GapKey::Gap(selected[0].0.gap())));
    }
}
