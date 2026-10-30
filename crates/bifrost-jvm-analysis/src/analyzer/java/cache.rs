use crate::analyzer::java::*;

use brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit;

use brokk_bifrost_analysis::analyzer::cache_weight::estimate_project_file;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_bytes;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexVariant;

use brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex;

use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_analysis::analyzer::estimate_collection_bytes;
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::Arc;

pub(crate) struct JavaMemoCaches {
    budget_bytes: u64,
    pub(crate) resolved_imports:
        crate::analyzer::jvm::hierarchy::DerivedMemo<ProjectFile, HashMap<String, CodeUnit>>,
    pub(crate) source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            git2::Oid,
            ProjectFile,
        ),
        Arc<brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts>,
    >,
    pub(crate) statement_facts: crate::analyzer::jvm::hierarchy::DerivedMemo<
        (git2::Oid, ProjectFile),
        brokk_bifrost_core::analyzer::statement_facts::StatementFactRows,
    >,
    pub(crate) package_names: Cache<ProjectFile, Arc<str>>,
    pub(crate) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(crate) relevant_imports:
        crate::analyzer::jvm::hierarchy::DerivedMemo<CodeUnit, HashSet<String>>,
    pub(crate) direct_ancestors: crate::analyzer::jvm::hierarchy::AncestorMemo,
    /// `PoolSafeMemo`, not `OnceLock`, for the same reason as the two sibling
    /// cells below: this whole-workspace build is reached from rayon workers
    /// during cold scans, and a blocking `get_or_init` parks every one of them
    /// behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    pub(crate) direct_descendant_index:
        KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>,
    pub(crate) reverse_import_index: PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    pub(crate) same_package_reference_index:
        PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
}

impl JavaMemoCaches {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            resolved_imports: crate::analyzer::jvm::hierarchy::derived_memo(budget_bytes / 4),
            source_facts: build_weighted_cache(
                budget_bytes / 8,
                |_, value: &Arc<brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts>| {
                    u32::try_from(value.estimated_retained_bytes()).unwrap_or(u32::MAX)
                },
            ),
            statement_facts: crate::analyzer::jvm::hierarchy::derived_memo(budget_bytes / 16),
            package_names: build_weighted_cache(budget_bytes / 16, weight_package_name),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            relevant_imports: crate::analyzer::jvm::hierarchy::derived_memo(budget_bytes / 8),
            direct_ancestors: crate::analyzer::jvm::hierarchy::ancestor_memo(budget_bytes / 8),
            direct_descendant_index: KeyedPoolSafeMemo::new(),
            reverse_import_index: PoolSafeMemo::new(),
            same_package_reference_index: PoolSafeMemo::new(),
        }
    }

    pub(crate) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

pub(super) fn weight_import_map(key: &ProjectFile, value: &Arc<HashMap<String, CodeUnit>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_import_map(value.as_ref()))
}

fn weight_package_name(key: &ProjectFile, value: &Arc<str>) -> u32 {
    weight_bytes(estimate_project_file(key) + value.len() as u64)
}

fn weight_project_file_set(key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_project_file_set(value.as_ref()))
}

pub(super) fn weight_string_set(key: &CodeUnit, value: &Arc<HashSet<String>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_string_set(value.as_ref()))
}

fn estimate_import_map(imports: &HashMap<String, CodeUnit>) -> u64 {
    size_of::<HashMap<String, CodeUnit>>() as u64
        + imports
            .iter()
            .map(|(name, code_unit)| name.len() as u64 + estimate_code_unit(code_unit))
            .sum::<u64>()
}

fn estimate_project_file_set(files: &HashSet<ProjectFile>) -> u64 {
    size_of::<HashSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}

fn estimate_string_set(values: &HashSet<String>) -> u64 {
    estimate_collection_bytes(size_of::<HashSet<String>>() as u64, values, |value| {
        value.len() as u64
    })
}
