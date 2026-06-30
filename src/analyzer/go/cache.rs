use super::hierarchy::GoHierarchyIndex;
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::{Arc, OnceLock};

use crate::analyzer::js_ts::build_weighted_cache;

#[derive(Clone)]
pub(super) struct GoMemoCaches {
    budget_bytes: u64,
    pub(super) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    pub(super) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(super) reverse_import_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    pub(super) hierarchy_index: Arc<OnceLock<GoHierarchyIndex>>,
    pub(super) package_clause_names: Arc<OnceLock<HashMap<ProjectFile, String>>>,
}

impl GoMemoCaches {
    pub(super) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            imported_code_units: build_weighted_cache(budget_bytes / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            reverse_import_index: Arc::new(OnceLock::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            package_clause_names: Arc::new(OnceLock::new()),
        }
    }

    pub(super) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<HashSet<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<HashSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
