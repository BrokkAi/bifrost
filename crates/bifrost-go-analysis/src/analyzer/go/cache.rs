use crate::analyzer::go::imports::{GoImportFacts, GoReverseImports};
use brokk_bifrost_analysis::analyzer::common::QueryCacheCell;
use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    ReplayingMemo, ReplayingMemoEntry, WorkspaceAuthorityMemo,
};
use brokk_bifrost_analysis::analyzer::{ReadKey, WorkspaceFactFamily};

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_go::graph::resolver::GoWorkspaceIndexes;
use brokk_bifrost_go::packages::GoWorkspacePathIndex;
use moka::sync::Cache;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

type GoMemoEntry<T> = ReplayingMemoEntry<T, ReadKey>;
type GoFileMemo<T> = ReplayingMemo<Cache<ProjectFile, Arc<GoMemoEntry<T>>>>;
pub(crate) type GoSourceMemo = ReplayingMemo<
    Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            git2::Oid,
            ProjectFile,
        ),
        Arc<GoMemoEntry<Arc<brokk_bifrost_go::source_facts::GoFileSourceFacts>>>,
    >,
>;

type WorkspacePathSnapshot = (Arc<GoWorkspacePathIndex>, StableDigest);

#[derive(Clone)]
pub(crate) struct GoMemoCaches {
    budget_bytes: u64,
    pub(crate) imported_code_units: GoFileMemo<Arc<HashSet<CodeUnit>>>,
    pub(crate) source_facts: GoSourceMemo,
    pub(crate) referencing_files: GoFileMemo<Arc<HashSet<ProjectFile>>>,
    pub(crate) reverse_import_index: WorkspaceAuthorityMemo<Arc<PoolSafeMemo<GoReverseImports>>>,
    pub(crate) workspace_indexes: WorkspaceAuthorityMemo<Arc<PoolSafeMemo<GoWorkspaceIndexes>>>,
    pub(crate) workspace_indexes_build_count: Arc<AtomicUsize>,
    /// Canonical Go fact files consumed by completed shared workspace builds.
    /// The source-authoritative path does not run a parser pass, so this is the
    /// meaningful per-file cost metric that replaces the old parse counter.
    pub(crate) workspace_source_fact_load_count: Arc<AtomicUsize>,
    pub(crate) workspace_path_index:
        WorkspaceAuthorityMemo<Arc<QueryCacheCell<WorkspacePathSnapshot>>>,
    pub(crate) workspace_path_index_build_count: Arc<AtomicUsize>,
    pub(crate) import_facts: WorkspaceAuthorityMemo<Arc<QueryCacheCell<Arc<GoImportFacts>>>>,
}

impl GoMemoCaches {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            imported_code_units: ReplayingMemo::new(build_weighted_cache(
                budget_bytes / 4,
                |_, entry: &Arc<GoMemoEntry<Arc<HashSet<CodeUnit>>>>| memo_weight(entry),
            )),
            source_facts: ReplayingMemo::new(build_weighted_cache(
                budget_bytes / 8,
                |_,
                 entry: &Arc<
                    GoMemoEntry<Arc<brokk_bifrost_go::source_facts::GoFileSourceFacts>>,
                >| memo_weight(entry),
            )),
            referencing_files: ReplayingMemo::new(build_weighted_cache(
                budget_bytes / 8,
                |_, entry: &Arc<GoMemoEntry<Arc<HashSet<ProjectFile>>>>| memo_weight(entry),
            )),
            reverse_import_index: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::GoReverseImports,
                Arc::new(PoolSafeMemo::new()),
            ),
            workspace_indexes: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::GoWorkspaceIndexes,
                Arc::new(PoolSafeMemo::new()),
            ),
            workspace_indexes_build_count: Arc::new(AtomicUsize::new(0)),
            workspace_source_fact_load_count: Arc::new(AtomicUsize::new(0)),
            workspace_path_index: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::GoWorkspacePaths,
                Arc::new(QueryCacheCell::new()),
            ),
            workspace_path_index_build_count: Arc::new(AtomicUsize::new(0)),
            import_facts: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::GoImportFacts,
                Arc::new(QueryCacheCell::new()),
            ),
        }
    }

    pub(crate) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    pub(crate) fn workspace_path_index_build_count(&self) -> usize {
        self.workspace_path_index_build_count
            .load(Ordering::Relaxed)
    }

    pub(crate) fn workspace_indexes_build_count(&self) -> usize {
        self.workspace_indexes_build_count.load(Ordering::Relaxed)
    }

    pub(crate) fn workspace_source_fact_load_count(&self) -> usize {
        self.workspace_source_fact_load_count
            .load(Ordering::Relaxed)
    }
}

fn memo_weight<T>(entry: &GoMemoEntry<T>) -> u32 {
    use brokk_bifrost_analysis::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
    let bytes = entry.retained_bytes(|key| {
        let mut heap = RetainedHeap::default();
        retained_read_key(&mut heap, key);
        heap.total()
    });
    u32::try_from(bytes).unwrap_or(u32::MAX)
}
