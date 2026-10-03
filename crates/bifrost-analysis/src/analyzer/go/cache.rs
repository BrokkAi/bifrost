use super::imports::GoImportFacts;
use crate::analyzer::{CodeUnit, PoolSafeMemo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_go::graph::resolver::GoWorkspaceIndexes;
use brokk_bifrost_go::packages::GoWorkspacePathIndex;
use moka::sync::Cache;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_project_file_set,
};

#[derive(Clone)]
pub(super) struct GoMemoCaches {
    budget_bytes: u64,
    pub(super) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    pub(super) source_facts: Cache<
        (crate::analyzer::store::GenerationId, git2::Oid, ProjectFile),
        Arc<brokk_bifrost_go::source_facts::GoFileSourceFacts>,
    >,
    pub(super) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(super) reverse_import_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    pub(super) workspace_indexes: Arc<PoolSafeMemo<GoWorkspaceIndexes>>,
    pub(super) workspace_indexes_build_count: Arc<AtomicUsize>,
    /// Canonical Go fact files consumed by completed shared workspace builds.
    /// The source-authoritative path does not run a parser pass, so this is the
    /// meaningful per-file cost metric that replaces the old parse counter.
    pub(super) workspace_source_fact_load_count: Arc<AtomicUsize>,
    pub(super) workspace_path_index: Arc<OnceLock<GoWorkspacePathIndex>>,
    pub(super) workspace_path_index_build_count: Arc<AtomicUsize>,
    pub(super) import_facts: Arc<OnceLock<GoImportFacts>>,
}

impl GoMemoCaches {
    pub(super) fn new(budget_bytes: u64) -> Self {
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

    pub(super) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    pub(super) fn workspace_path_index_build_count(&self) -> usize {
        self.workspace_path_index_build_count
            .load(Ordering::Relaxed)
    }

    pub(super) fn workspace_indexes_build_count(&self) -> usize {
        self.workspace_indexes_build_count.load(Ordering::Relaxed)
    }

    pub(super) fn workspace_source_fact_load_count(&self) -> usize {
        self.workspace_source_fact_load_count
            .load(Ordering::Relaxed)
    }
}
