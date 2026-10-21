use crate::analyzer::go::imports::GoImportFacts;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_go::graph::resolver::GoWorkspaceIndexes;
use brokk_bifrost_go::packages::GoWorkspacePathIndex;
use moka::sync::Cache;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_set;

use brokk_bifrost_core::analyzer::weighted_cache::weight_project_file_set;

#[derive(Clone)]
pub(crate) struct GoMemoCaches {
    budget_bytes: u64,
    pub(crate) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    pub(crate) source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            git2::Oid,
            ProjectFile,
        ),
        Arc<brokk_bifrost_go::source_facts::GoFileSourceFacts>,
    >,
    pub(crate) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(crate) reverse_import_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    pub(crate) workspace_indexes: Arc<PoolSafeMemo<GoWorkspaceIndexes>>,
    pub(crate) workspace_indexes_build_count: Arc<AtomicUsize>,
    /// Canonical Go fact files consumed by completed shared workspace builds.
    /// The source-authoritative path does not run a parser pass, so this is the
    /// meaningful per-file cost metric that replaces the old parse counter.
    pub(crate) workspace_source_fact_load_count: Arc<AtomicUsize>,
    pub(crate) workspace_path_index: Arc<OnceLock<GoWorkspacePathIndex>>,
    pub(crate) workspace_path_index_build_count: Arc<AtomicUsize>,
    pub(crate) import_facts: Arc<OnceLock<GoImportFacts>>,
}

impl GoMemoCaches {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            imported_code_units: build_weighted_cache(budget_bytes / 4, weight_code_unit_set),
            source_facts: build_weighted_cache(
                budget_bytes / 8,
                |_, value: &Arc<brokk_bifrost_go::source_facts::GoFileSourceFacts>| {
                    u32::try_from(value.estimated_retained_bytes()).unwrap_or(u32::MAX)
                },
            ),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            workspace_indexes: Arc::new(PoolSafeMemo::new()),
            workspace_indexes_build_count: Arc::new(AtomicUsize::new(0)),
            workspace_source_fact_load_count: Arc::new(AtomicUsize::new(0)),
            workspace_path_index: Arc::new(OnceLock::new()),
            workspace_path_index_build_count: Arc::new(AtomicUsize::new(0)),
            import_facts: Arc::new(OnceLock::new()),
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
