use crate::analyzer::{CodeUnit, PoolSafeMemo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_go::graph::resolver::GoEdgeIndex;
use brokk_bifrost_go::hierarchy::GoHierarchyIndex;
use brokk_bifrost_go::packages::GoWorkspacePathIndex;

use super::imports::GoImportFacts;
use moka::sync::Cache;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_project_file_set,
};

/// Both whole-workspace Go indexes, which one build produces from one parse.
pub(super) struct GoWorkspaceIndexes {
    pub(super) hierarchy: Arc<GoHierarchyIndex>,
    pub(super) edges: Arc<GoEdgeIndex>,
}

#[derive(Clone)]
pub(super) struct GoMemoCaches {
    budget_bytes: u64,
    pub(super) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    pub(super) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(super) reverse_import_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    /// The two whole-workspace Go indexes, built together from one parse.
    ///
    /// They are one memo because they are one pass: each is derived from every
    /// Go file's AST, so building them apart parsed the workspace twice per
    /// request -- the hierarchy sequentially, the edge index again in parallel
    /// (#1748).
    ///
    /// `PoolSafeMemo`, not `OnceLock`: the build walks every workspace Go
    /// declaration and is reached from request-path rayon workers through
    /// `TypeHierarchyProvider`, `member_family` and the usage graph. It runs on
    /// the dedicated build pool so a global-pool worker parks on it instead of
    /// building the whole workspace index inline (#1772).
    pub(super) workspace_indexes: Arc<PoolSafeMemo<GoWorkspaceIndexes>>,
    pub(super) workspace_indexes_build_count: Arc<AtomicUsize>,
    /// Go files the workspace index build parsed, summed over builds. One
    /// parse per Go file per build is the pinned cost (#1748).
    pub(super) workspace_parse_count: Arc<AtomicUsize>,
    pub(super) package_clause_names: Arc<OnceLock<HashMap<ProjectFile, String>>>,
    pub(super) workspace_path_index: Arc<OnceLock<GoWorkspacePathIndex>>,
    pub(super) workspace_path_index_build_count: Arc<AtomicUsize>,
    /// One cell for every workspace import table: they are all derived from
    /// each file's persisted package clause, so three cells meant three passes
    /// that each read it again.
    pub(super) import_facts: Arc<OnceLock<GoImportFacts>>,
}

impl GoMemoCaches {
    pub(super) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            imported_code_units: build_weighted_cache(budget_bytes / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            workspace_indexes: Arc::new(PoolSafeMemo::new()),
            workspace_indexes_build_count: Arc::new(AtomicUsize::new(0)),
            workspace_parse_count: Arc::new(AtomicUsize::new(0)),
            package_clause_names: Arc::new(OnceLock::new()),
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

    pub(super) fn workspace_parse_count(&self) -> usize {
        self.workspace_parse_count.load(Ordering::Relaxed)
    }
}
