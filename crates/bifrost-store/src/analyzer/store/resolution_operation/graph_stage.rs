//! File-major, unit-scoped staging for native workspace graphs.
//!
//! The unit key and helper table are language-owned. The driver owns the
//! common selected-operation read-memo lifetime, unit/file ordering,
//! cancellation propagation, and summary accumulation.

use super::{
    FactResolutionBatchSummary, SelectedResolutionContextMetrics, SelectedResolutionOperation,
    SelectedResolutionOperationOutcome,
};
use crate::CancellationToken;
use crate::analyzer::ProjectFile;
use crate::analyzer::resolution::worker_transport::{WorkerAnswer, schedule_selected_queue};
use crate::analyzer::resolution::{MAX_REFERENCE_SEEDS_PER_BATCH, ResolutionIdentityTranslation};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_lexical::{
    GraphStageReaderStats, UnconditionalCandidateCache,
};

// Test processes isolate these counts; snapshots avoid resetting concurrent workers.
#[cfg(any(test, feature = "test-support"))]
static GRAPH_STAGE_WORKER_ITEMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn graph_stage_worker_items_for_test() -> usize {
    GRAPH_STAGE_WORKER_ITEMS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(any(test, feature = "test-support"))]
static GRAPH_STAGE_CHUNKED_UNITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn graph_stage_chunked_units_for_test() -> usize {
    GRAPH_STAGE_CHUNKED_UNITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Maximum request slice in graph-stage candidate and context-path reads.
/// The selected operation still admits up to `MAX_REFERENCE_SEEDS_PER_BATCH`
/// requests; readers split those requests into this bounded chunk size.
#[doc(hidden)]
pub const MAX_GRAPH_STAGE_READ_BATCH_SIZE: usize = 64;

/// Upper bound on graph-stage worker readers, whatever the configured
/// parallelism. Each worker holds its own selected operation, which costs
/// about 0.37 GB of peak memory on the measured Go corpora (cli, CLIProxyAPI
/// and OTel whole graphs, 2026-10-24), so an uncapped width on a many-core
/// host could add tens of GB to one request. On an 8-core VM, cli's whole
/// graph took 29 s wall at 8 workers and 23 s at 16, for 45% more CPU.
const MAX_GRAPH_STAGE_WORKERS: usize = 8;
// At total/32 bytes, the simulated W=8 greedy schedule reaches the CPU/8
// bound; per-request context preparation rises from about 2.1 to 4.1 CPU s.
const CHUNKS_PER_WORKER: usize = 4;

/// Why a requested caller does not participate in the selected graph.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum GraphFileSkipReason {
    ExcludedBuildSelection,
    OutsideSelectedModules {
        module_path: String,
    },
    DomainDiscoveryFailed {
        domain_dir: String,
        gowork_path: String,
        message: String,
    },
    Unplaced,
}

impl GraphFileSkipReason {
    #[doc(hidden)]
    pub fn opens_incompleteness(&self) -> bool {
        !matches!(self, Self::ExcludedBuildSelection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct GraphBuildSelectionUnavailable {
    #[doc(hidden)]
    pub discovery_error: String,
}

#[doc(hidden)]
pub type GraphSkippedCallers = std::collections::BTreeMap<ProjectFile, GraphFileSkipReason>;

#[doc(hidden)]
pub struct GraphStageAdmission<U> {
    #[doc(hidden)]
    pub units: Vec<(U, Vec<ProjectFile>)>,
    #[doc(hidden)]
    pub skipped: GraphSkippedCallers,
}

/// Every requested file is accounted for, including empty and skipped files.
#[doc(hidden)]
pub fn certify_graph_callers(
    requested: &crate::hash::HashSet<ProjectFile>,
    admitted: &crate::hash::HashSet<ProjectFile>,
    skipped: &GraphSkippedCallers,
) {
    assert!(
        skipped.keys().all(|file| !admitted.contains(file)),
        "admitted and skipped graph callers must be disjoint"
    );
    let accounted = admitted
        .iter()
        .chain(skipped.keys())
        .cloned()
        .collect::<crate::hash::HashSet<_>>();
    assert_eq!(
        &accounted, requested,
        "graph admission must account for every requested caller"
    );
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct GraphStageMemoStats {
    pub(crate) hits: u64,
    pub(crate) distinct_keys: usize,
}

impl GraphStageMemoStats {
    fn accumulate(&mut self, other: Self) {
        self.hits = self
            .hits
            .checked_add(other.hits)
            .expect("graph stage memo hit count fits u64");
        self.distinct_keys = self
            .distinct_keys
            .checked_add(other.distinct_keys)
            .expect("graph stage memo key count fits usize");
    }
}

/// A failed discovery domain can still admit its source-inventory edges.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[doc(hidden)]
pub struct GraphDomainDiscoveryFailure {
    pub domain_dir: String,
    pub gowork_path: String,
    pub discovery_error: String,
}

/// An adapter-owned helper table whose lifetime is one graph unit.
#[doc(hidden)]
pub trait GraphStageHelperTables {
    fn memo_stats(&self) -> GraphStageMemoStats {
        GraphStageMemoStats::default()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct GraphStageMetrics {
    pub(crate) units: usize,
    pub(crate) files: usize,
    pub(crate) contexts_prepared: usize,
    pub(crate) shared_memo_hits: u64,
    pub(crate) shared_distinct_keys: usize,
    pub(crate) adapter_memo_hits: u64,
    pub(crate) adapter_distinct_keys: usize,
    pub(crate) readers: GraphStageReaderStats,
}

#[doc(hidden)]
pub struct GraphStageResult {
    #[doc(hidden)]
    pub summary: FactResolutionBatchSummary,
    pub(crate) metrics: GraphStageMetrics,
    #[doc(hidden)]
    pub skipped: GraphSkippedCallers,
}

/// Language-specific graph stage contract.
///
/// `Unit` deliberately belongs to the adapter. It can be a Rust crate key, a
/// Go selected package instance plus source role, or a JVM project/source-set
/// and selected-language context tuple without teaching this driver those
/// concepts.
#[doc(hidden)]
pub trait GraphStageAdapter: Sync {
    /// Running a unit's files in contiguous chunks and concatenating their
    /// output must reproduce the unit's output. Batches must follow the given
    /// file order, and each file's results must be independent of which other
    /// files are included in the call.
    const FILE_CHUNKS_REPRODUCE_UNIT: bool;

    type Payload: WorkerAnswer;
    type Unit: Ord + Sync;
    type HelperTables<'stage>: GraphStageHelperTables;

    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<Self::Unit>>>;

    fn helper_tables<'stage>(
        &self,
        operation: &'stage SelectedResolutionOperation<'_, '_>,
        unit: &Self::Unit,
    ) -> Result<Self::HelperTables<'stage>>;

    #[allow(clippy::too_many_arguments)]
    fn run_unit<'operation, 'store, 'input>(
        &self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        unit: &Self::Unit,
        files: &[ProjectFile],
        guard: &mut GraphStageGuard<'operation, 'store, Self::HelperTables<'operation>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<(Self::Payload, FactResolutionBatchSummary)>>;
}

/// Batches retained in their original callback emission order.
#[doc(hidden)]
pub struct GraphStageBatches<B>(pub Vec<B>);

impl<B: WorkerAnswer> WorkerAnswer for GraphStageBatches<B> {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self(
            self.0
                .into_iter()
                .map(|batch| batch.translate(translation))
                .collect(),
        )
    }
}

impl<B> GraphStageBatches<B> {
    /// Replay one item in emission order. A cancelling callback publishes no
    /// further batches, even though this item's kernel has already finished.
    pub fn replay(
        self,
        cancellation: &CancellationToken,
        mut stage: impl FnMut(B) -> Result<()>,
    ) -> Result<bool> {
        for batch in self.0 {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            stage(batch)?;
            if cancellation.is_cancelled() {
                return Ok(false);
            }
        }
        Ok(!cancellation.is_cancelled())
    }

    /// Attach batches only to a successful item; failures discard their prefix.
    pub fn finish(
        self,
        outcome: SelectedResolutionOperationOutcome<FactResolutionBatchSummary>,
    ) -> SelectedResolutionOperationOutcome<(Self, FactResolutionBatchSummary)> {
        match outcome {
            SelectedResolutionOperationOutcome::Native(summary) => {
                SelectedResolutionOperationOutcome::Native((self, summary))
            }
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                SelectedResolutionOperationOutcome::Cancelled(completion)
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                SelectedResolutionOperationOutcome::Stale(reason)
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                SelectedResolutionOperationOutcome::Unavailable(reason)
            }
        }
    }
}

/// Owned output of one item. Only the owner replays batches into the consumer.
/// Nothing here survives the graph request or requires other items to finish.
#[doc(hidden)]
pub struct GraphStageItemPayload<P> {
    pub payload: P,
    pub summary: FactResolutionBatchSummary,
    pub metrics: GraphStageMetrics,
}

impl<P: WorkerAnswer> WorkerAnswer for GraphStageItemPayload<P> {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self {
            payload: self.payload.translate(translation),
            summary: self.summary.translate(translation),
            // Metrics contain no runtime aliases.
            metrics: self.metrics,
        }
    }
}

/// Run one item on either the owner's operation or an independent worker.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn run_graph_stage_item<Adapter: GraphStageAdapter>(
    operation: &SelectedResolutionOperation<'_, '_>,
    adapter: &Adapter,
    unit: &Adapter::Unit,
    files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
) -> Result<SelectedResolutionOperationOutcome<GraphStageItemPayload<Adapter::Payload>>> {
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut metrics = GraphStageMetrics {
        units: 1,
        files: files.len(),
        contexts_prepared: 1,
        ..Default::default()
    };
    let helpers = adapter.helper_tables(operation, unit)?;
    let mut guard = GraphStageGuard::install(operation, helpers)?;
    let staged = adapter.run_unit(
        operation,
        unit,
        files,
        &mut guard,
        maximum_batch_size,
        cancellation,
        &mut context_metrics,
        &mut metrics,
    )?;
    let shared = guard.shared_memo_stats();
    metrics.shared_memo_hits = shared.hits;
    metrics.shared_distinct_keys = shared.distinct_keys;
    let adapter_stats = guard.helper_tables().memo_stats();
    metrics.adapter_memo_hits = adapter_stats.hits;
    metrics.adapter_distinct_keys = adapter_stats.distinct_keys;
    metrics.readers.accumulate(guard.reader_stats());
    drop(guard);
    Ok(match staged {
        SelectedResolutionOperationOutcome::Native((payload, summary)) => {
            SelectedResolutionOperationOutcome::Native(GraphStageItemPayload {
                payload,
                summary,
                metrics,
            })
        }
        SelectedResolutionOperationOutcome::Cancelled(completion) => {
            SelectedResolutionOperationOutcome::Cancelled(completion)
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            SelectedResolutionOperationOutcome::Stale(reason)
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            SelectedResolutionOperationOutcome::Unavailable(reason)
        }
    })
}

/// Common memo and transaction boundary for one selected graph unit.
///
/// The language helper field drops before the common guard, so helper-table
/// teardown can still use the stage's selected reader transaction.
#[doc(hidden)]
pub struct GraphStageGuard<'operation, 'store, Helpers> {
    helper_tables: Helpers,
    shared: GraphStageReadMemoGuard<'operation, 'store>,
}

impl<'operation, 'store, Helpers> GraphStageGuard<'operation, 'store, Helpers> {
    fn install(
        operation: &'operation SelectedResolutionOperation<'store, '_>,
        helper_tables: Helpers,
    ) -> Result<Self> {
        let shared = GraphStageReadMemoGuard::install(
            &operation.ready.inventory,
            &operation.ready.graph_stage_candidate_cache,
        )?;
        Ok(Self {
            helper_tables,
            shared,
        })
    }

    pub(crate) fn helper_tables(&self) -> &Helpers {
        &self.helper_tables
    }

    #[doc(hidden)]
    pub fn helper_tables_mut(&mut self) -> &mut Helpers {
        &mut self.helper_tables
    }

    fn shared_memo_stats(&self) -> GraphStageMemoStats {
        self.shared.memo_stats()
    }

    fn reader_stats(&self) -> GraphStageReaderStats {
        self.shared.reader_stats()
    }
}

struct GraphStageReadMemoGuard<'operation, 'store> {
    inventory:
        &'operation super::super::resolution_selection::SelectedResolutionMountInventory<'store>,
    candidate_cache:
        &'operation std::cell::RefCell<Option<std::rc::Rc<UnconditionalCandidateCache>>>,
}

impl<'operation, 'store> GraphStageReadMemoGuard<'operation, 'store> {
    fn install(
        inventory: &'operation super::super::resolution_selection::SelectedResolutionMountInventory<
            'store,
        >,
        candidate_cache: &'operation std::cell::RefCell<
            Option<std::rc::Rc<UnconditionalCandidateCache>>,
        >,
    ) -> Result<Self> {
        let previous = inventory
            .authority_validations()
            .replace(Some(Default::default()));
        assert!(previous.is_none(), "graph stages do not nest");
        let previous = candidate_cache.replace(Some(std::rc::Rc::new(
            UnconditionalCandidateCache::for_graph_stage(MAX_GRAPH_STAGE_READ_BATCH_SIZE),
        )));
        assert!(previous.is_none(), "graph-stage reader memos do not nest");
        if let Err(error) = inventory.begin_stage_read() {
            inventory.authority_validations().take();
            candidate_cache.take();
            return Err(error);
        }
        Ok(Self {
            inventory,
            candidate_cache,
        })
    }

    fn memo_stats(&self) -> GraphStageMemoStats {
        let (hits, distinct_keys) = self.inventory.authority_validation_memo_stats();
        GraphStageMemoStats {
            hits,
            distinct_keys,
        }
    }

    fn reader_stats(&self) -> GraphStageReaderStats {
        self.candidate_cache
            .borrow()
            .as_ref()
            .expect("graph stage reader memo lives for the guard")
            .graph_stage_reader_stats()
    }
}

impl Drop for GraphStageReadMemoGuard<'_, '_> {
    fn drop(&mut self) {
        self.candidate_cache.take();
        self.inventory.authority_validations().take();
        if let Err(error) = self.inventory.end_stage_read() {
            eprintln!("analyzer store could not end a graph stage's read: {error}");
            if let Err(error) = self.inventory.connection().execute_batch("ROLLBACK") {
                eprintln!("analyzer store could not roll back a graph stage's read: {error}");
            }
        }
        assert!(
            std::thread::panicking() || self.inventory.connection().is_autocommit(),
            "a graph stage left its reader inside a transaction"
        );
    }
}

impl GraphStageMetrics {
    fn accumulate(&mut self, other: Self) {
        self.units += other.units;
        self.files += other.files;
        self.contexts_prepared += other.contexts_prepared;
        self.shared_memo_hits = self
            .shared_memo_hits
            .checked_add(other.shared_memo_hits)
            .expect("graph stage shared memo hit count fits u64");
        self.shared_distinct_keys = self
            .shared_distinct_keys
            .checked_add(other.shared_distinct_keys)
            .expect("graph stage shared memo key count fits usize");
        self.adapter_memo_hits = self
            .adapter_memo_hits
            .checked_add(other.adapter_memo_hits)
            .expect("graph stage adapter memo hit count fits u64");
        self.adapter_distinct_keys = self
            .adapter_distinct_keys
            .checked_add(other.adapter_distinct_keys)
            .expect("graph stage adapter memo key count fits usize");
        self.readers.accumulate(other.readers);
    }
}

/// Partition files in order against cumulative equal-share byte boundaries.
/// Empty input has no chunks; zero-byte files still occupy a non-empty range.
/// An all-zero unit stays whole. A positive target is required, including when
/// test mode selects one byte (one chunk per file when total bytes >= files).
fn chunk_boundaries(sizes: &[u64], target: u64) -> Vec<std::ops::Range<usize>> {
    assert!(target > 0, "graph chunk target must be positive");
    let total: u128 = sizes.iter().map(|&size| u128::from(size)).sum();
    let count = if total <= u128::from(target) {
        usize::from(!sizes.is_empty())
    } else {
        total.div_ceil(u128::from(target)).min(sizes.len() as u128) as usize
    };
    let mut ranges = Vec::with_capacity(count);
    let mut start = 0;
    let mut cumulative = 0u128;
    for chunk in 0..count {
        // Compute ceil((chunk + 1) * total / count) without multiplying total.
        let divisor = count as u128;
        let ordinal = (chunk + 1) as u128;
        let boundary =
            (total / divisor) * ordinal + ((total % divisor) * ordinal).div_ceil(divisor);
        let limit = sizes.len() - (count - chunk - 1);
        let mut end = start;
        loop {
            cumulative += u128::from(sizes[end]);
            end += 1;
            if end == limit || (chunk + 1 < count && cumulative >= boundary) {
                break;
            }
        }
        assert!(start < end && end <= limit);
        ranges.push(start..end);
        start = end;
    }
    assert_eq!(start, sizes.len(), "graph chunks must cover every file");
    assert_eq!(cumulative, total, "graph chunks must cover every byte");
    ranges
}

/// Run ordered unit stages while keeping each unit's helper state bounded by
/// its guard. A single operation context and graph summary remain request
/// scoped, but no adapter table crosses a unit boundary.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn run_graph_stages<Adapter: GraphStageAdapter>(
    operation: &SelectedResolutionOperation<'_, '_>,
    adapter: &Adapter,
    files: &[ProjectFile],
    maximum_batch_size: usize,
    worker_count: usize,
    cancellation: &CancellationToken,
    _context_metrics: &mut SelectedResolutionContextMetrics,
    mut replay: impl FnMut(Adapter::Payload) -> Result<bool>,
) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
    assert!(
        (1..=MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size),
        "reference batch size must be in 1..={MAX_REFERENCE_SEEDS_PER_BATCH}"
    );
    assert!(worker_count > 0, "graph worker count must be positive");
    let admission = match adapter.units(operation, files, cancellation)? {
        SelectedResolutionOperationOutcome::Native(groups) => groups,
        SelectedResolutionOperationOutcome::Cancelled(completion) => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(SelectedResolutionOperationOutcome::Stale(reason));
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
        }
    };
    let GraphStageAdmission {
        units: mut groups,
        skipped,
    } = admission;
    let requested = files.iter().cloned().collect();
    let admitted = groups
        .iter()
        .flat_map(|(_, files)| files.iter().cloned())
        .collect();
    certify_graph_callers(&requested, &admitted, &skipped);
    groups.sort_by(|left, right| left.0.cmp(&right.0));
    let mut summary = FactResolutionBatchSummary::empty();
    let mut metrics = GraphStageMetrics::default();
    for (_, files) in &mut groups {
        files.sort();
    }
    groups.retain(|(_, files)| !files.is_empty());
    // The cap applies before chunking, so the chunk target and the worker
    // path both use the width that can actually run.
    let worker_count = worker_count.min(MAX_GRAPH_STAGE_WORKERS);
    // Borrow the admitted units and contiguous file slices only for this request.
    // Metadata is a scheduling proxy, never a source of resolution authority.
    let use_workers = worker_count > 1 && !operation.worker_store().uses_single_connection_reads();
    let file_sizes = use_workers.then(|| {
        groups.iter().map(|(_, files)| {
            files.iter().map(|file| match std::fs::metadata(file.abs_path()) {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    crate::profiling::note_with(|| format!(
                        "graph scheduling metadata unavailable for {file:?}: {error}; using zero bytes"
                    ));
                    0
                }
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>()
    });
    let mut items = Vec::new();
    if let Some(file_sizes) = &file_sizes {
        let total = file_sizes
            .iter()
            .flatten()
            .fold(0u64, |sum, size| sum.saturating_add(*size));
        let target = (total / (worker_count * CHUNKS_PER_WORKER) as u64).max(1);
        #[cfg(any(test, feature = "test-support"))]
        let target = if std::env::var("BIFROST_GRAPH_TEST_MAXIMAL_CHUNKS").as_deref() == Ok("1") {
            1
        } else {
            target
        };
        for ((unit, files), sizes) in groups.iter().zip(file_sizes) {
            let bytes = sizes
                .iter()
                .fold(0u64, |sum, size| sum.saturating_add(*size));
            #[cfg(any(test, feature = "test-support"))]
            let before = items.len();
            if Adapter::FILE_CHUNKS_REPRODUCE_UNIT {
                for range in chunk_boundaries(sizes, target) {
                    let chunk_bytes = sizes[range.clone()]
                        .iter()
                        .fold(0u64, |sum, size| sum.saturating_add(*size));
                    items.push((unit, &files[range], chunk_bytes));
                }
            } else {
                items.push((unit, files.as_slice(), bytes));
            }
            #[cfg(any(test, feature = "test-support"))]
            if items.len() - before > 1 {
                GRAPH_STAGE_CHUNKED_UNITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    } else {
        items.extend(
            groups
                .iter()
                .map(|(unit, files)| (unit, files.as_slice(), 0)),
        );
    }
    let item_count = items.len();
    let worker_count = worker_count.min(item_count.max(1));
    if worker_count == 1 || !use_workers {
        for (unit, unit_files, _) in items {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    super::cancelled_completion(),
                ));
            }
            let staged = run_graph_stage_item(
                operation,
                adapter,
                unit,
                unit_files,
                maximum_batch_size,
                cancellation,
            )?;
            match staged {
                SelectedResolutionOperationOutcome::Native(staged) => {
                    if !replay(staged.payload)? || cancellation.is_cancelled() {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            super::cancelled_completion(),
                        ));
                    }
                    summary.accumulate(staged.summary);
                    metrics.accumulate(staged.metrics);
                }
                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
                }
                SelectedResolutionOperationOutcome::Stale(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Stale(reason));
                }
                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
                }
            }
        }
    } else {
        let mut dispatch_order = (0..items.len()).collect::<Vec<_>>();
        dispatch_order.sort_unstable_by_key(|&index| (std::cmp::Reverse(items[index].2), index));
        let mut replay_cancelled = false;
        let statuses = schedule_selected_queue(
            operation.worker_store(),
            operation.worker_input(),
            &items,
            &dispatch_order,
            worker_count,
            cancellation,
            |worker, item| {
                let (unit, files, bytes) = item;
                #[cfg(any(test, feature = "test-support"))]
                GRAPH_STAGE_WORKER_ITEMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let timing = crate::profiling::enabled().then(|| {
                    let index = items
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, item))
                        .expect("the scheduler borrows an item from this request");
                    (
                        index,
                        std::time::Instant::now(),
                        crate::profiling::thread_cpu_time(),
                    )
                });
                let result = run_graph_stage_item(
                    worker,
                    adapter,
                    unit,
                    files,
                    maximum_batch_size,
                    cancellation,
                );
                if let Some((index, wall, cpu)) = timing {
                    let thread_cpu = crate::profiling::thread_cpu_time() - cpu;
                    crate::profiling::note(format!(
                        "graph stage item index={index} files={} bytes={bytes} wall_ms={:.3} thread_cpu_ms={:.3}",
                        files.len(),
                        wall.elapsed().as_secs_f64() * 1000.0,
                        thread_cpu.as_secs_f64() * 1000.0,
                    ));
                }
                result
            },
            |_, answer| {
                if replay_cancelled || cancellation.is_cancelled() {
                    replay_cancelled = true;
                    return Ok(());
                }
                // A graph has no caller-supplied target alias to anchor.
                // Persisted ids are verified and supplemental ids are interned
                // by canonical digest, exactly as in file prefetch.
                let staged = answer.reintern(operation, [], cancellation)?;
                if !replay(staged.payload)? || cancellation.is_cancelled() {
                    replay_cancelled = true;
                    return Ok(());
                }
                summary.accumulate(staged.summary);
                metrics.accumulate(staged.metrics);
                Ok(())
            },
        )?;
        // Delivery is provisional: reader finish can invalidate an already
        // replayed item. No accumulated output escapes before this check.
        for status in statuses {
            match status.transpose()? {
                Some(SelectedResolutionOperationOutcome::Native(())) => {}
                Some(SelectedResolutionOperationOutcome::Cancelled(completion)) => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
                }
                Some(SelectedResolutionOperationOutcome::Stale(reason)) => {
                    return Ok(SelectedResolutionOperationOutcome::Stale(reason));
                }
                Some(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
                }
                None => {
                    // Graph request tokens have only a hard deadline. An
                    // undispatched item therefore meets the inline cancel path.
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        super::cancelled_completion(),
                    ));
                }
            }
        }
        if replay_cancelled || cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                super::cancelled_completion(),
            ));
        }
    }
    if crate::profiling::enabled() {
        crate::profiling::note(format!(
            "graph stage request items={item_count} units={} files={} contexts_prepared={} shared_memo_hits={} shared_distinct_keys={} adapter_memo_hits={} adapter_distinct_keys={} forward_reader_executions={} forward_decoded_rows={} forward_memo_hits={} forward_max_batch={} context_reader_executions={} context_decoded_rows={} context_memo_hits={} context_max_batch={}",
            metrics.units,
            metrics.files,
            metrics.contexts_prepared,
            metrics.shared_memo_hits,
            metrics.shared_distinct_keys,
            metrics.adapter_memo_hits,
            metrics.adapter_distinct_keys,
            metrics.readers.forward_executions,
            metrics.readers.forward_decoded_rows,
            metrics.readers.forward_memo_hits,
            metrics.readers.forward_max_batch,
            metrics.readers.context_executions,
            metrics.readers.context_decoded_rows,
            metrics.readers.context_memo_hits,
            metrics.readers.context_max_batch,
        ));
    }
    Ok(SelectedResolutionOperationOutcome::Native(
        GraphStageResult {
            summary,
            metrics,
            skipped,
        },
    ))
}

#[cfg(test)]
mod graph_stage_chunk_properties {
    use super::chunk_boundaries;
    use brokk_bifrost_test_macros::hardwon;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(384))]
        #[test]
        fn contiguous_balanced_cover(
            sizes in prop_oneof![
                prop::collection::vec(Just(0u64), 0..128),
                prop::collection::vec(prop_oneof![Just(0u64), 1u64..1_000_000], 0..128),
                prop::collection::vec(any::<u64>(), 0..128),
            ],
            target in prop_oneof![Just(1u64), 1u64..1_000_000, 1u64..=u64::MAX],
        ) {
            let chunks = chunk_boundaries(&sizes, target);
            let total: u128 = sizes.iter().map(|&size| u128::from(size)).sum();
            let expected = if sizes.is_empty() { 0 } else if total <= u128::from(target) { 1 } else {
                ((total - 1) / u128::from(target) + 1).min(sizes.len() as u128) as usize
            };
            prop_assert_eq!(chunks.len(), expected);
            let largest = u128::from(sizes.iter().copied().max().unwrap_or(0));
            let mut cursor = 0;
            for chunk in chunks {
                prop_assert_eq!(chunk.start, cursor);
                prop_assert!(chunk.start < chunk.end && chunk.end <= sizes.len());
                let bytes: u128 = sizes[chunk.clone()].iter().map(|&size| u128::from(size)).sum();
                prop_assert!(bytes * expected as u128 <= total + largest * expected as u128);
                cursor = chunk.end;
            }
            prop_assert_eq!(cursor, sizes.len());
        }
    }

    #[test]
    #[hardwon("#5671: add-then-close chunking never split a unit between one and two targets")]
    fn executor_splits_before_the_last_file() {
        // CLIProxyAPI internal/runtime/executor in persisted file order.
        let sizes = [
            18_556, 97_527, 20_380, 90_388, 2_659, 68_350, 40_163, 54_468, 33_868, 42_664, 23_786,
            28_280, 2_074, 53_481, 5_339, 46_471,
        ];
        let target = 588_965;
        assert_eq!(sizes[..15].iter().sum::<u64>(), 581_983);
        assert!(sizes[..15].iter().sum::<u64>() < target);
        assert_eq!(chunk_boundaries(&sizes, target), vec![0..7, 7..16]);
    }
}
