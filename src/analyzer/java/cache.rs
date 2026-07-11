use super::*;
use crate::analyzer::PoolSafeMemo;
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::{Arc, OnceLock};

pub(super) struct JavaMemoCaches {
    budget_bytes: u64,
    pub(super) resolved_imports: Cache<ProjectFile, Arc<HashMap<String, CodeUnit>>>,
    pub(super) package_names: Cache<ProjectFile, Arc<str>>,
    pub(super) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(super) relevant_imports: Cache<CodeUnit, Arc<HashSet<String>>>,
    pub(super) direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    pub(super) direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    pub(super) direct_descendant_index: OnceLock<HashMap<String, Arc<HashSet<CodeUnit>>>>,
    pub(super) reverse_import_index: PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    pub(super) same_package_reference_index:
        PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
}

impl JavaMemoCaches {
    pub(super) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            resolved_imports: Self::build_cache(budget_bytes / 4, weight_import_map),
            package_names: Self::build_cache(budget_bytes / 16, weight_package_name),
            referencing_files: Self::build_cache(budget_bytes / 8, weight_project_file_set),
            relevant_imports: Self::build_cache(budget_bytes / 8, weight_string_set),
            direct_ancestors: Self::build_cache(budget_bytes / 8, weight_code_unit_vec),
            direct_descendants: Self::build_cache(budget_bytes / 8, weight_code_unit_set),
            direct_descendant_index: OnceLock::new(),
            reverse_import_index: PoolSafeMemo::new(),
            same_package_reference_index: PoolSafeMemo::new(),
        }
    }

    pub(super) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    fn build_cache<K, V>(
        budget_bytes: u64,
        weigher: impl Fn(&K, &V) -> u32 + Send + Sync + 'static,
    ) -> Cache<K, V>
    where
        K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let capacity = budget_bytes.max(1);
        Cache::builder()
            .max_capacity(capacity)
            .weigher(weigher)
            .build()
    }
}

fn weight_import_map(key: &ProjectFile, value: &Arc<HashMap<String, CodeUnit>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_import_map(value.as_ref()))
}

fn weight_package_name(key: &ProjectFile, value: &Arc<str>) -> u32 {
    weight_bytes(estimate_project_file(key) + value.len() as u64)
}

fn weight_project_file_set(key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_project_file_set(value.as_ref()))
}

fn weight_string_set(key: &CodeUnit, value: &Arc<HashSet<String>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_string_set(value.as_ref()))
}

fn weight_code_unit_vec(key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_code_unit_vec(value.as_ref()))
}

fn weight_code_unit_set(key: &CodeUnit, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_code_unit_set(value.as_ref()))
}

fn weight_bytes(bytes: u64) -> u32 {
    bytes.clamp(1, u32::MAX as u64) as u32
}

fn estimate_path(path: &std::path::Path) -> u64 {
    path.as_os_str().to_string_lossy().len() as u64
}

fn estimate_project_file(file: &ProjectFile) -> u64 {
    size_of::<ProjectFile>() as u64 + estimate_path(file.root()) + estimate_path(file.rel_path())
}

fn estimate_code_unit(code_unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + estimate_project_file(code_unit.source())
        + code_unit.package_name().len() as u64
        + code_unit.short_name().len() as u64
        + code_unit
            .signature()
            .map_or(0, |signature| signature.len() as u64)
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
    size_of::<HashSet<String>>() as u64 + values.iter().map(|value| value.len() as u64).sum::<u64>()
}

fn estimate_code_unit_vec(values: &[CodeUnit]) -> u64 {
    size_of::<Vec<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_code_unit_set(values: &HashSet<CodeUnit>) -> u64 {
    size_of::<HashSet<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}
