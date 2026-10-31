use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
use brokk_bifrost_analysis::analyzer::workspace_authority::{ReplayingMemo, ReplayingMemoEntry};
use brokk_bifrost_analysis::analyzer::{WorkspaceAuthorityMemo, WorkspaceFactFamily};

use brokk_bifrost_js_ts::graph::resolver::JsTsUsageIndex;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashSet;
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

pub(crate) type AttributedCache<K, V> =
    ReplayingMemo<Cache<K, Arc<ReplayingMemoEntry<Arc<V>, ReadKey>>>>;

fn attributed_cache<K, V>(budget: u64) -> AttributedCache<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    ReplayingMemo::new(build_weighted_cache(
        budget,
        |_, entry: &Arc<ReplayingMemoEntry<Arc<V>, ReadKey>>| {
            u32::try_from(entry.retained_bytes(|key| {
                let mut heap = RetainedHeap::default();
                retained_read_key(&mut heap, key);
                heap.total()
            }))
            .unwrap_or(u32::MAX)
        },
    ))
}

/// Analyzer-cached query-time state shared by the JavaScript and TypeScript
/// adapters. Both hold this behind a single `Arc<JsTsMemoCaches>` (so every
/// analyzer clone shares one bucket) and replace the whole bucket on
/// `update`/`update_all`, which is what invalidates every cache at once. The
/// two adapters previously kept byte-identical cache fields with different
/// wrappers (JS a private struct, TS flat `Arc<..>`-per-cell fields); this is
/// the reconciled shape.
pub(crate) struct JsTsMemoCaches {
    pub(crate) source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            brokk_bifrost_core::gitblob::BlobKey,
            ProjectFile,
        ),
        Arc<brokk_bifrost_js_ts::source_facts::JsTsFileSourceFacts>,
    >,
    /// Declarations imported by a file, keyed by importing file.
    pub(crate) imported_code_units: AttributedCache<ProjectFile, HashSet<CodeUnit>>,
    /// Raw file-path resolution targets of a file's imports (module specifier -> file), keyed by the
    /// importing file. Distinct from `imported_code_units`: this is a file-level check (does an import
    /// statement's path resolve to this file) used by `could_import_file`, not a symbol-level one --
    /// caching it separately avoids re-running import-path resolution for every candidate/target
    /// pair the shared usages candidate walker checks.
    pub(crate) imported_target_files: AttributedCache<ProjectFile, HashSet<ProjectFile>>,
    /// Files that import a given file, keyed by imported file.
    pub(crate) referencing_files: AttributedCache<ProjectFile, HashSet<ProjectFile>>,
    /// Import snippets textually relevant to a code unit's source.
    pub(crate) relevant_imports: AttributedCache<CodeUnit, HashSet<String>>,
    /// Resolved direct supertypes of a class-like code unit.
    pub(crate) direct_ancestors: AttributedCache<CodeUnit, Vec<CodeUnit>>,
    /// Whole-workspace class descendant index, built once per bucket.
    /// `PoolSafeMemo`, not `OnceLock`: the build walks every workspace class
    /// through `get_direct_ancestors`, whose misses reach `usage_index`
    /// and its rayon fan-out -- a blocking `get_or_init` held across that is
    /// the #1416 self-deadlock shape its two sibling cells below already
    /// migrated away from.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    pub(crate) direct_descendant_index: super::workspace_facts::DescendantMemos,
    /// Reverse import edges (importer files by imported file), built once per bucket.
    pub(crate) reverse_import_index:
        WorkspaceAuthorityMemo<PoolSafeMemo<super::workspace_facts::ReverseImports>>,
    /// JS/TS usage-resolution maps, built once per bucket and reused across queries.
    pub(crate) jsts_usage_index:
        ReplayingMemo<PoolSafeMemo<ReplayingMemoEntry<Arc<JsTsUsageIndex>, ReadKey>>>,
}

impl JsTsMemoCaches {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            source_facts: build_weighted_cache(
                budget_bytes / 8,
                |_, value: &Arc<brokk_bifrost_js_ts::source_facts::JsTsFileSourceFacts>| {
                    u32::try_from(value.estimated_retained_bytes()).unwrap_or(u32::MAX)
                },
            ),
            imported_code_units: attributed_cache(budget_bytes / 3),
            imported_target_files: attributed_cache(budget_bytes / 6),
            referencing_files: attributed_cache(budget_bytes / 6),
            relevant_imports: attributed_cache(budget_bytes / 6),
            direct_ancestors: attributed_cache(budget_bytes / 8),
            direct_descendant_index: super::workspace_facts::DescendantMemos::new(),
            reverse_import_index: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::JsTsReverseImports,
                PoolSafeMemo::new(),
            ),
            jsts_usage_index: ReplayingMemo::new(PoolSafeMemo::new()),
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
