use crate::analyzer::usages::js_ts_graph::JsTsUsageIndex;
use crate::analyzer::{CodeUnit, DirectDescendantIndex, PoolSafeMemo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::Arc;

use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_vec_by_unit,
    weight_project_file_set,
};

/// Analyzer-cached query-time state shared by the JavaScript and TypeScript
/// adapters. Both hold this behind a single `Arc<JsTsMemoCaches>` (so every
/// analyzer clone shares one bucket) and replace the whole bucket on
/// `update`/`update_all`, which is what invalidates every cache at once. The
/// two adapters previously kept byte-identical cache fields with different
/// wrappers (JS a private struct, TS flat `Arc<..>`-per-cell fields); this is
/// the reconciled shape.
pub(crate) struct JsTsMemoCaches {
    /// Declarations imported by a file, keyed by importing file.
    pub(crate) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    /// Raw file-path resolution targets of a file's imports (module specifier -> file), keyed by the
    /// importing file. Distinct from `imported_code_units`: this is a file-level check (does an import
    /// statement's path resolve to this file) used by `could_import_file`, not a symbol-level one --
    /// caching it separately avoids re-running `resolve_js_ts_import_paths` for every candidate/target
    /// pair the shared usages candidate walker checks.
    pub(crate) imported_target_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    /// Files that import a given file, keyed by imported file.
    pub(crate) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    /// Import snippets textually relevant to a code unit's source.
    pub(crate) relevant_imports: Cache<CodeUnit, Arc<HashSet<String>>>,
    /// Resolved direct supertypes of a class-like code unit.
    pub(crate) direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// Whole-workspace class descendant index, built once per bucket.
    /// `PoolSafeMemo`, not `OnceLock`: the build walks every workspace class
    /// through `get_direct_ancestors`, whose misses reach `js_ts_usage_index`
    /// and its rayon fan-out -- a blocking `get_or_init` held across that is
    /// the #1416 self-deadlock shape its two sibling cells below already
    /// migrated away from.
    pub(crate) direct_descendant_index: PoolSafeMemo<DirectDescendantIndex>,
    /// Reverse import edges (importer files by imported file), built once per bucket.
    pub(crate) reverse_import_index: PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    /// JS/TS usage-resolution maps, built once per bucket and reused across queries.
    pub(crate) jsts_usage_index: PoolSafeMemo<JsTsUsageIndex>,
}

impl JsTsMemoCaches {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            imported_code_units: build_weighted_cache(budget_bytes / 3, weight_code_unit_set),
            imported_target_files: build_weighted_cache(budget_bytes / 6, weight_project_file_set),
            referencing_files: build_weighted_cache(budget_bytes / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(budget_bytes / 6, weight_string_set),
            direct_ancestors: build_weighted_cache(budget_bytes / 8, weight_code_unit_vec_by_unit),
            direct_descendant_index: PoolSafeMemo::new(),
            reverse_import_index: PoolSafeMemo::new(),
            jsts_usage_index: PoolSafeMemo::new(),
        }
    }
}

pub(crate) fn weight_string_set(_key: &CodeUnit, value: &Arc<HashSet<String>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.len() + size_of::<String>())
        .sum::<usize>()
        + size_of::<HashSet<String>>();
    size.min(u32::MAX as usize) as u32
}
