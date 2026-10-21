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
use crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH;
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_lexical::{
    GraphStageReaderStats, UnconditionalCandidateCache,
};

/// Maximum request slice in graph-stage candidate and context-path reads.
/// The selected operation still admits up to `MAX_REFERENCE_SEEDS_PER_BATCH`
/// requests; readers split those requests into this bounded chunk size.
pub(crate) const MAX_GRAPH_STAGE_READ_BATCH_SIZE: usize = 64;

/// Why a requested caller does not participate in the selected graph.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum GraphFileSkipReason {
    ExcludedBuildSelection,
    OutsideSelectedModules { module_path: String },
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

pub(crate) struct GraphStageAdmission<U> {
    pub(crate) units: Vec<(U, Vec<ProjectFile>)>,
    pub(crate) skipped: GraphSkippedCallers,
}

/// Every requested file is accounted for, including empty and skipped files.
pub(crate) fn certify_graph_callers(
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
pub(crate) struct GraphStageMemoStats {
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

/// An adapter-owned helper table whose lifetime is one graph unit.
pub(crate) trait GraphStageHelperTables {
    fn memo_stats(&self) -> GraphStageMemoStats {
        GraphStageMemoStats::default()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GraphStageMetrics {
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
pub(crate) trait GraphStageAdapter {
    type Unit: Ord;
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
        &mut self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        unit: &Self::Unit,
        files: &[ProjectFile],
        guard: &mut GraphStageGuard<'operation, 'store, Self::HelperTables<'operation>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>>;
}

/// Common memo and transaction boundary for one selected graph unit.
///
/// The language helper field drops before the common guard, so helper-table
/// teardown can still use the stage's selected reader transaction.
pub(crate) struct GraphStageGuard<'operation, 'store, Helpers> {
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

    pub(crate) fn helper_tables_mut(&mut self) -> &mut Helpers {
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

/// Run ordered unit stages while keeping each unit's helper state bounded by
/// its guard. A single operation context and graph summary remain request
/// scoped, but no adapter table crosses a unit boundary.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_graph_stages<Adapter: GraphStageAdapter>(
    operation: &SelectedResolutionOperation<'_, '_>,
    adapter: &mut Adapter,
    files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    context_metrics: &mut SelectedResolutionContextMetrics,
) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
    assert!(
        (1..=MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size),
        "reference batch size must be in 1..={MAX_REFERENCE_SEEDS_PER_BATCH}"
    );
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
    for (unit, mut unit_files) in groups {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                super::cancelled_completion(),
            ));
        }
        unit_files.sort();
        if unit_files.is_empty() {
            continue;
        }
        metrics.units += 1;
        metrics.files += unit_files.len();
        metrics.contexts_prepared += 1;
        let helpers = adapter.helper_tables(operation, &unit)?;
        let mut guard = GraphStageGuard::install(operation, helpers)?;
        let staged = adapter.run_unit(
            operation,
            &unit,
            &unit_files,
            &mut guard,
            maximum_batch_size,
            cancellation,
            context_metrics,
            &mut metrics,
        )?;
        metrics
            .shared_memo_hits
            .checked_add(guard.shared_memo_stats().hits)
            .map(|hits| metrics.shared_memo_hits = hits)
            .expect("graph stage shared memo hit count fits u64");
        metrics
            .shared_distinct_keys
            .checked_add(guard.shared_memo_stats().distinct_keys)
            .map(|keys| metrics.shared_distinct_keys = keys)
            .expect("graph stage shared memo key count fits usize");
        let adapter_stats = guard.helper_tables().memo_stats();
        metrics
            .adapter_memo_hits
            .checked_add(adapter_stats.hits)
            .map(|hits| metrics.adapter_memo_hits = hits)
            .expect("graph stage adapter memo hit count fits u64");
        metrics
            .adapter_distinct_keys
            .checked_add(adapter_stats.distinct_keys)
            .map(|keys| metrics.adapter_distinct_keys = keys)
            .expect("graph stage adapter memo key count fits usize");
        metrics.readers.accumulate(guard.reader_stats());
        drop(guard);
        match staged {
            SelectedResolutionOperationOutcome::Native(staged) => summary.accumulate(staged),
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
    if crate::profiling::enabled() {
        crate::profiling::note(format!(
            "graph stage request units={} files={} contexts={} shared_memo_hits={} shared_distinct_keys={} adapter_memo_hits={} adapter_distinct_keys={} forward_reader_executions={} forward_decoded_rows={} forward_memo_hits={} forward_max_batch={} context_reader_executions={} context_decoded_rows={} context_memo_hits={} context_max_batch={}",
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
